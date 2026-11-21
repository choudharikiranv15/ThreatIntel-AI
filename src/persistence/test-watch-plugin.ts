/*
 * The watchlist through the real plugin entry, the way OpenClaw runs it:
 * register(), session-scoped tool factories, the registered background service,
 * and the answer-gate hooks. Real PostgreSQL. Only the network (fetch) and the
 * Discord send are replaced.
 */
import entry from "../index.js";
import { setWatchDelivererForTesting } from "../watch/runtime.js";
import type { Deliverer } from "../watch/delivery.js";
import { db } from "./db.js";

function assert(condition: unknown, message: string): asserts condition {
    if (!condition) {
        throw new Error(`Assertion failed: ${message}`);
    }
}

const CVE = `CVE-2097-${Date.now() % 1_000_000}`;
const OTHER = `CVE-2097-${(Date.now() % 1_000_000) + 1}`;

/* ------------------------------- Fake network ------------------------------ */

const world = { kevListed: false };

globalThis.fetch = (async (input: string | URL | Request) => {
    const url = String(input);

    if (url.includes("nvd.nist.gov")) {
        const id = new URL(url).searchParams.get("cveId");

        return Response.json({
            vulnerabilities: [{
                cve: {
                    id,
                    metrics: {
                        cvssMetricV31: [{
                            source: "nvd@nist.gov",
                            cvssData: { version: "3.1", baseScore: 7.5, baseSeverity: "HIGH", vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" },
                        }],
                    },
                },
            }],
        });
    }

    if (url.includes("cisa.gov")) {
        return Response.json({
            catalogVersion: "2099.01.01",
            vulnerabilities: world.kevListed ? [{ cveID: CVE, dateAdded: "2099-01-01" }] : [],
        });
    }

    if (url.includes("access.redhat.com")) {
        const id = decodeURIComponent(url.split("/").pop() ?? "").replace(".json", "");

        return Response.json({
            name: id,
            package_state: [
                { product_name: "Red Hat OpenShift Container Platform 3.11", package_name: "p", fix_state: "Under investigation" },
                { product_name: "Red Hat Enterprise Linux 9", package_name: "p", fix_state: "Affected" },
            ],
        });
    }

    // As the real EPSS API answers for a CVE it has not scored: an empty list, never a 404.
    if (url.includes("api.first.org/data/v1/epss")) {
        return Response.json({ status: "OK", total: 0, data: [] });
    }

    return new Response("{}", { status: 404 });
}) as typeof fetch;

/* ------------------------------ Fake OpenClaw ----------------------------- */

type AgentTool = {
    name: string;
    execute: (id: string, params: Record<string, unknown>) => Promise<{ content: { text: string }[] }>;
};

type Factory = (context: Record<string, unknown>) => AgentTool | AgentTool[] | null;

const staticTools = new Map<string, AgentTool>();
const factories: Factory[] = [];
const hooks = new Map<string, (event: Record<string, unknown>, context: Record<string, unknown>) => unknown>();
const services: { id: string; start: (ctx: unknown) => Promise<void>; stop: () => Promise<void>; tick: () => Promise<void> }[] = [];

entry.register({
    pluginConfig: {
        watchEnabled: true,
        watchNotifyTarget: "channel:100000000000000001",
        watchTickMinutes: 60,
        requestTimeoutMs: 5000,
    },
    config: {},
    logger: { info: () => undefined, warn: () => undefined },
    registerTool: (tool: AgentTool | Factory) => {
        if (typeof tool === "function") {
            factories.push(tool);
        } else {
            staticTools.set(tool.name, tool);
        }
    },
    on: (name: string, handler: (event: Record<string, unknown>, context: Record<string, unknown>) => unknown) => {
        hooks.set(name, handler);
    },
    registerService: (service: (typeof services)[number]) => {
        services.push(service);
    },
} as unknown as Parameters<typeof entry.register>[0]);

/** Builds the session's tools as OpenClaw does, with that session's trusted identity. */
function sessionTools(senderIsOwner: boolean): Map<string, AgentTool> {
    const tools = new Map(staticTools);

    for (const factory of factories) {
        const built = factory({ senderIsOwner, requesterSenderId: senderIsOwner ? "owner-id" : "stranger-id" });

        for (const tool of Array.isArray(built) ? built : built ? [built] : []) {
            tools.set(tool.name, tool);
        }
    }

    return tools;
}

async function call(tools: Map<string, AgentTool>, name: string, params: Record<string, unknown> = {}) {
    const tool = tools.get(name);

    assert(tool, `${name} should be registered`);

    const result = await tool.execute("call", params);

    return { text: result.content[0].text, json: JSON.parse(result.content[0].text) as Record<string, any> };
}

const WATCH_TOOLS = [
    "threatintel_watch_add",
    "threatintel_watch_remove",
    "threatintel_watch_list",
    "threatintel_watch_set",
    "threatintel_watch_status",
    // The threat feed's tools follow the same owner-only rule.
    "threatintel_feed_status",
    "threatintel_feed_run_now",
];

async function main(): Promise<void> {
    const sent: string[] = [];

    const deliverer: Deliverer = async (text) => {
        sent.push(text);

        return { status: "sent", messageIds: [`13000000000000000${sent.length}`] };
    };

    setWatchDelivererForTesting(deliverer);

    /* Registration */
    assert(services.length === 1 && services[0].id === "threatintel-watch", "the watch service must be registered");

    for (const name of WATCH_TOOLS) {
        assert(sessionTools(true).has(name), `${name} must be registered`);
    }

    console.log("✓ The plugin registers the watch tools and the background service");

    /* Owner only, reads included, enforced by the runtime flag, not by arguments */
    const stranger = sessionTools(false);

    for (const name of WATCH_TOOLS) {
        const denied = await call(stranger, name, { target: CVE, senderIsOwner: true });

        assert(denied.json.error === "owner_only", `${name} must refuse a non-owner, even one claiming ownership in arguments`);
    }

    assert(
        (await db.query("SELECT 1 FROM public.watchlist WHERE target = $1", [CVE])).rows.length === 0,
        "a refused add must not write anything",
    );

    console.log("✓ All five watch tools and both feed tools, reads included, refuse non-owners");

    /* Owner: add establishes a baseline through the real engine and persistence. */
    const owner = sessionTools(true);

    const feedStatus = await call(owner, "threatintel_feed_status");

    assert(
        feedStatus.json.feed === "disabled in config" && /UTC/.test(feedStatus.json.times),
        `the owner can read feed status, which reports the feed as disabled here: ${feedStatus.text}`,
    );

    const feedRun = await call(owner, "threatintel_feed_run_now");

    assert(feedRun.json.status === "not_scheduled", "a disabled feed is never scheduled");

    /* Indicator lookups are for everyone, and private addresses never leave the gateway. */
    const lookupTool = stranger.get("threatintel_lookup_indicator");

    assert(lookupTool, "the lookup tool is registered for non-owners");

    const privateLookup = JSON.parse((await lookupTool.execute("call", { indicator: "169.254.169.254" })).content[0].text);

    assert(privateLookup.error === "not_public", `the cloud metadata address is refused before any call: ${JSON.stringify(privateLookup)}`);

    const realLookup = JSON.parse((await lookupTool.execute("call", { indicator: "44d88612fea8a8f36de82e1278abb02f" })).content[0].text);

    assert(
        realLookup.type === "md5" &&
        Array.isArray(realLookup.sources) &&
        realLookup.sources.map((source: { source: string }) => source.source).sort().join(",") === "otx,virustotal" &&
        realLookup.sources.some((source: { source: string; status: string }) => source.source === "virustotal" && source.status === "not_configured"),
        `a hash lookup reaches the hash services only, and VirusTotal without a key is not called: ${JSON.stringify(realLookup).slice(0, 200)}`,
    );

    const added = await call(owner, "threatintel_watch_add", { target: CVE.toLowerCase() });

    assert(
        added.json.status === "added" &&
        added.json.baseline === "baseline_established" &&
        added.json.entry?.hasBaseline === true &&
        added.json.monitoring === "running" &&
        added.json.notifications === "configured",
        `adding a CVE must establish its baseline: ${added.text}`,
    );

    const duplicate = await call(owner, "threatintel_watch_add", { target: CVE });

    assert(duplicate.json.status === "already_watched", "adding twice must not duplicate the watch");

    const invalid = await call(owner, "threatintel_watch_add", { target: "not-a-cve" });

    assert(invalid.json.error === "invalid_target", "an invalid target must be refused");

    const tooFrequent = await call(owner, "threatintel_watch_add", { target: OTHER, intervalHours: 1 });

    assert(tooFrequent.json.error === "invalid_interval", "an interval below 6 hours must be refused");

    const listed = await call(owner, "threatintel_watch_list");

    assert(listed.json.entries.some((item: { target: string }) => item.target === CVE), "the owner can list the watchlist");

    const updated = await call(owner, "threatintel_watch_set", { target: CVE, intervalHours: 12 });

    assert(updated.json.entry?.intervalHours === 12, "the owner can change the interval");

    console.log("✓ The owner can add, list, and update watches, with validation");

    /* The scheduled service detects a real change and delivers it. */
    const [service] = services;

    await service.tick();

    assert(sent.length === 0, "nothing is due right after the baseline, so nothing is sent");

    world.kevListed = true;

    await db.query("UPDATE public.watchlist SET next_check_at = now() - interval '1 minute' WHERE target = $1", [CVE]);

    await service.tick();

    const alert = sent.find((text) => text.includes(CVE));

    assert(
        alert?.includes("kevStatus") && alert.includes("**listed**") && alert.includes("CISA KEV"),
        `the scheduled check must detect the KEV listing and deliver it: ${JSON.stringify(sent)}`,
    );

    const status = await call(owner, "threatintel_watch_status", { target: CVE });

    const kevEvent = status.json.recentEvents.find((event: { field: string }) => event.field === "kevStatus");

    assert(
        kevEvent?.deliveryStatus === "sent" && kevEvent.messageIds.length === 1,
        `the status tool must show the delivered alert and its message id: ${status.text}`,
    );

    assert(
        /UTC/.test(status.json.times) &&
        typeof kevEvent.explanation === "string" && kevEvent.explanation.length > 0 &&
        typeof kevEvent.comparedWithInvestigationId === "string" &&
        status.json.entry?.baselineInvestigationId === kevEvent.investigationId,
        `the status tool must label times as UTC, explain each alert, and show the current baseline: ${status.text}`,
    );

    await service.tick();

    assert(sent.filter((text) => text.includes(CVE)).length === 1, "a delivered alert is never sent again");

    console.log("✓ The registered service detects a change on schedule and delivers it once");

    /* Product claims, through the real investigate tool and answer-gate hooks */
    const investigate = await call(owner, "threatintel_investigate", { target: OTHER, forceRefresh: true });

    const afterToolCall = hooks.get("after_tool_call");
    const beforeFinalize = hooks.get("before_agent_finalize");

    assert(afterToolCall && beforeFinalize, "answer-gate hooks must be registered");

    const session = { sessionKey: "watch-plugin-session" };

    afterToolCall(
        { toolName: "threatintel_investigate", result: { content: [{ text: investigate.text }], details: investigate.text }, runId: "r1" },
        session,
    );

    const gate = (answer: string) =>
        beforeFinalize(
            { sessionId: "s", sessionKey: session.sessionKey, stopHookActive: false, lastAssistantMessage: answer, runId: "r1" },
            session,
        ) as { action?: string; reason?: string } | undefined;

    const wrong = gate(`${OTHER}: OpenShift Container Platform 3.11 is fixed.`);

    assert(
        wrong?.action === "revise" && wrong.reason?.includes("unknown"),
        `calling an unknown product fixed must be caught: ${JSON.stringify(wrong)}`,
    );

    assert(
        gate(`${OTHER}: Red Hat Enterprise Linux 9 is affected.`) === undefined,
        "a supported product claim must pass",
    );

    console.log("✓ The answer gate checks product claims on the real plugin path");

    /* Removal keeps history */
    const removed = await call(owner, "threatintel_watch_remove", { target: CVE });

    assert(removed.json.removed === true, "the owner can remove a watch");

    const history = await db.query("SELECT count(*)::int AS n FROM public.watch_events WHERE target = $1", [CVE]);

    assert(history.rows[0].n > 0, "removing a watch keeps its alert history");

    await service.stop();

    console.log("Watch plugin-path tests PASSED");
}

main()
    .catch((error: unknown) => {
        console.error("Watch plugin-path tests FAILED");
        console.error(error);
        process.exitCode = 1;
    })
    .finally(async () => {
        setWatchDelivererForTesting(undefined);

        await db.query("DELETE FROM public.watch_events WHERE target = ANY($1::text[])", [[CVE, OTHER]]);
        await db.query("DELETE FROM public.watchlist WHERE target = ANY($1::text[])", [[CVE, OTHER]]);
        await db.query("DELETE FROM public.investigations WHERE target = ANY($1::text[])", [[CVE, OTHER]]);
        await db.end();
    });
