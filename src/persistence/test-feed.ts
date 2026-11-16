/*
 * The threat feed against real PostgreSQL: cycles, persistence across
 * restarts, deduplication, updates, limits, provider failures, leases, and
 * delivery through the shared outbox. Sources are replaced by fixed items.
 */
import type { ScopeConfig } from "../feed/classify.js";
import { runFeedCycleIfDue, type FeedCycleDeps } from "../feed/cycle.js";
import type { FeedSettings } from "../feed/runtime.js";
import { DEFAULT_SELECTION } from "../feed/select.js";
import * as feedStore from "../feed/store.js";
import { buildFeedTools } from "../feed/tools.js";
import type { FeedSourceId, RawItem } from "../feed/types.js";
import type { Deliverer } from "../watch/delivery.js";
import { deliverPending } from "../watch/service.js";
import { db } from "./db.js";

function assert(condition: unknown, message: string): asserts condition {
    if (!condition) {
        throw new Error(`Assertion failed: ${message}`);
    }
}

const SCOPE: ScopeConfig = {
    bioPharmaTerms: [],
    bioPharmaProducts: ["LabWare LIMS"],
    securityProducts: ["FortiGate"],
    logSources: ["Entra ID"],
};

const today = () => new Date().toISOString();

function raw(overrides: Partial<RawItem> & Pick<RawItem, "itemKey" | "title">): RawItem {
    return {
        source: "fortinet",
        url: `https://example.test/${encodeURIComponent(overrides.itemKey)}`,
        publishedAt: today(),
        text: "",
        cves: [],
        severity: "unknown",
        exploitationClaim: null,
        products: [],
        platforms: [],
        sectors: [],
        iocs: [],
        kevListed: false,
        ...overrides,
    };
}

/* What each fake source returns, and which ones fail. */
type World = { items: Partial<Record<FeedSourceId, RawItem[]>>; failing: Set<FeedSourceId>; kev: Set<string>; calls: number };

function world(): World {
    return { items: {}, failing: new Set(), kev: new Set(), calls: 0 };
}

function deps(state: World, overrides: Partial<FeedCycleDeps> = {}): FeedCycleDeps {
    return {
        owner: "feed-worker-a",
        sources: ["cisa-kev", "fortinet", "aws", "cisco"],
        fetchSource: async (source) => {
            state.calls += 1;

            if (state.failing.has(source)) {
                throw new Error(`HTTP 503 from ${source}`);
            }

            return state.items[source] ?? [];
        },
        kevCves: async () => state.kev,
        scope: SCOPE,
        selection: { ...DEFAULT_SELECTION, maxPostsPerCycle: 3 },
        intervalHours: 3,
        ...overrides,
    };
}

async function reset(): Promise<void> {
    await db.query("DELETE FROM public.watch_events WHERE channel = 'feed'");
    await db.query("DELETE FROM public.feed_items");
    await db.query("DELETE FROM public.feed_runs");
    await db.query(
        `UPDATE public.feed_state
         SET next_run_at = now() - interval '1 minute', last_run_at = NULL, last_success_at = NULL,
             last_published_at = NULL, consecutive_failures = 0, last_error = NULL,
             lease_owner = NULL, lease_expires_at = NULL
         WHERE id = 1`,
    );
}

async function makeDue(): Promise<void> {
    await db.query("UPDATE public.feed_state SET next_run_at = now() - interval '1 minute' WHERE id = 1");
}

async function posts(): Promise<Array<{ target: string; message: string; delivery_status: string; message_ids: string[] }>> {
    const { rows } = await db.query("SELECT target, message, delivery_status, message_ids FROM public.watch_events WHERE channel = 'feed' ORDER BY observed_at");

    return rows;
}

/* ------------------------------------------------------------------------- */

async function testFirstCycleAndDedupe(): Promise<void> {
    await reset();

    const state = world();

    state.kev.add("CVE-2026-7001");
    state.items["cisa-kev"] = [raw({ source: "cisa-kev", itemKey: "kev:CVE-2026-7001", title: "CVE-2026-7001 FortiGate SSL-VPN overflow", cves: ["CVE-2026-7001"], kevListed: true, products: ["Fortinet FortiGate"] })];
    state.items.fortinet = [raw({ itemKey: "fortinet:FG-IR-26-001", title: "FortiGate SSL-VPN heap overflow", cves: ["CVE-2026-7001"], severity: "critical" })];
    state.items.aws = [raw({ source: "aws", itemKey: "aws:2026-001-aws", title: "Printer driver note", severity: "low" })];

    const result = await runFeedCycleIfDue(deps(state));

    assert(result?.status === "success", `the first cycle succeeds: ${JSON.stringify(result)}`);
    assert(result.counts.discovered === 3 && result.counts.newItems === 3, "every collected item is recorded");
    assert(result.counts.selected === 1 && result.counts.duplicatesSuppressed === 1 && result.counts.filtered === 1, `one post, one duplicate, one filtered: ${JSON.stringify(result.counts)}`);

    const [post] = await posts();

    assert(post && post.message.includes("**Threat Name:**") && post.message.includes("**IOCs to Hunt:**"), "the post is saved, already formatted, before any send");
    assert(post.delivery_status === "pending", "it waits in the outbox for delivery");

    const { rows: [item] } = await db.query("SELECT * FROM public.feed_items WHERE item_key = $1", [post.target]);

    assert(item.url && item.retrieved_at && item.first_seen_at && item.priority === "P1" && item.exploitation === "confirmed", "provenance, timestamps, priority, and exploitation are stored");

    /* Not due again: nothing runs. */
    assert((await runFeedCycleIfDue(deps(state))) === null, "a cycle runs only when due");

    console.log("✓ A cycle records every item, posts one per threat, and stores provenance");
}

async function testRestartNeverReposts(): Promise<void> {
    /* A different process, as after a gateway restart, sees the same items. */
    const state = world();

    state.kev.add("CVE-2026-7001");
    state.items["cisa-kev"] = [raw({ source: "cisa-kev", itemKey: "kev:CVE-2026-7001", title: "CVE-2026-7001 FortiGate SSL-VPN overflow", cves: ["CVE-2026-7001"], kevListed: true, products: ["Fortinet FortiGate"] })];
    state.items.fortinet = [raw({ itemKey: "fortinet:FG-IR-26-001", title: "FortiGate SSL-VPN heap overflow", cves: ["CVE-2026-7001"], severity: "critical" })];

    await makeDue();

    const result = await runFeedCycleIfDue(deps(state, { owner: "feed-worker-after-restart" }));

    assert(result?.counts.selected === 0, `a restart must not post anything again: ${JSON.stringify(result?.counts)}`);
    assert((await posts()).length === 1, "still exactly one post");

    console.log("✓ After a restart, previously posted items are never posted again");
}

async function testMaterialUpdate(): Promise<void> {
    /* The suppressed vendor advisory now publishes indicators: new hunting value. */
    const state = world();

    state.kev.add("CVE-2026-7001");
    state.items.fortinet = [raw({
        itemKey: "fortinet:FG-IR-26-001",
        title: "FortiGate SSL-VPN heap overflow",
        cves: ["CVE-2026-7001"],
        severity: "critical",
        iocs: [{ type: "ipv4", value: "203.0.113[.]9", source: "https://example.test/fg" }],
    })];

    await makeDue();

    // The first cycle posted this advisory (critical outranks the KEV entry's unknown severity),
    // so new indicators are an update, and updates wait out the cooldown.
    const inCooldown = await runFeedCycleIfDue(deps(state));

    assert(inCooldown?.counts.updatedItems === 1 && inCooldown.counts.deferred === 1 && inCooldown.counts.selected === 0, `an update within the cooldown is reconsidered but waits: ${JSON.stringify(inCooldown?.counts)}`);

    await db.query("UPDATE public.feed_items SET last_published_at = last_published_at - interval '2 days' WHERE last_published_at IS NOT NULL");
    await makeDue();

    const withIocs = await runFeedCycleIfDue(deps(state));

    assert(withIocs?.counts.selected === 1, `after the cooldown, the update with indicators is posted: ${JSON.stringify(withIocs?.counts)}`);
    assert((await posts()).at(-1)?.message.includes("`203.0.113[.]9`"), "the new post carries the indicator exactly");

    /* A posted P2 later confirmed exploited: an urgent update, despite the cooldown. */
    await reset();

    const p2 = world();

    p2.items.fortinet = [raw({ itemKey: "fortinet:FG-IR-26-002", title: "FortiGate admin bypass", cves: ["CVE-2026-7002"], severity: "critical" })];

    await runFeedCycleIfDue(deps(p2));
    assert((await posts()).length === 1, "the P2 is posted");

    p2.kev.add("CVE-2026-7002");
    await makeDue();

    const confirmed = await runFeedCycleIfDue(deps(p2));
    const all = await posts();

    assert(confirmed?.counts.selected === 1 && all.length === 2 && all[1].message.includes("(updated)"), "newly confirmed exploitation is posted as an update");

    /* Unchanged after that: nothing more. */
    await makeDue();
    await runFeedCycleIfDue(deps(p2));
    assert((await posts()).length === 2, "an unchanged item is not posted a third time");

    console.log("✓ Material updates are reconsidered and posted once; unchanged items are not");
}

async function testLimitsAndQueue(): Promise<void> {
    await reset();

    const state = world();

    state.items.fortinet = Array.from({ length: 5 }, (_, index) =>
        raw({ itemKey: `fortinet:FG-LIMIT-${index}`, title: `FortiGate flaw ${index}`, cves: [`CVE-2026-71${index}0`], severity: "critical" }),
    );
    state.items.cisco = [raw({ source: "cisco", itemKey: "cisco:pharma-1", title: "Flaw in LabWare LIMS integration", severity: "high" })];

    const first = await runFeedCycleIfDue(deps(state, { selection: { ...DEFAULT_SELECTION, maxPostsPerCycle: 2 } }));
    const posted = await posts();

    assert(first?.counts.selected === 2 && first.counts.deferred === 4, `the limit holds and the rest wait: ${JSON.stringify(first?.counts)}`);
    assert(posted.some((post) => post.target === "cisco:pharma-1"), "the P1 item is among the posts");

    /* The sources no longer list them; waiting items still get their turn. */
    state.items = {};
    await makeDue();

    const second = await runFeedCycleIfDue(deps(state, { selection: { ...DEFAULT_SELECTION, maxPostsPerCycle: 2 } }));

    assert(second?.counts.selected === 2 && (await posts()).length === 4, "deferred items are posted in a later cycle");

    console.log("✓ The per-cycle limit holds, P1 goes first, and deferred items are kept for later cycles");
}

async function testEmptyCycle(): Promise<void> {
    await reset();

    const state = world();

    state.items.aws = [raw({ source: "aws", itemKey: "aws:noise", title: "Documentation fix", severity: "low" })];

    const result = await runFeedCycleIfDue(deps(state));

    assert(result?.status === "success" && result.counts.selected === 0, "a cycle with nothing worth posting succeeds");
    assert((await posts()).length === 0, "and posts nothing");

    console.log("✓ An empty cycle produces no messages");
}

async function testProviderFailures(): Promise<void> {
    await reset();

    const state = world();

    state.failing.add("cisco");
    state.failing.add("aws");
    state.items.fortinet = [raw({ itemKey: "fortinet:FG-IR-26-003", title: "FortiGate flaw", severity: "critical" })];

    const partial = await runFeedCycleIfDue(deps(state));

    assert(partial?.status === "partial", `a failed source makes the run partial: ${partial?.status}`);
    assert(partial.counts.selected === 1, "the remaining sources are still evaluated and posted");
    assert(
        partial.providers.filter((provider) => provider.status === "failed").every((provider) => /503/.test(provider.error ?? "")),
        "each failure is recorded with its error",
    );

    /* Every source down: a failed run, never an empty success. */
    await reset();

    const down = world();

    for (const source of ["cisa-kev", "fortinet", "aws", "cisco"] as const) {
        down.failing.add(source);
    }

    const failed = await runFeedCycleIfDue(deps(down));
    const stateRow = await feedStore.getFeedState();
    const nextIn = (new Date(stateRow!.nextRunAt).getTime() - Date.now()) / 60_000;

    assert(failed?.status === "failed", "when every source fails, the run is failed");
    assert(stateRow?.consecutiveFailures === 1 && stateRow.lastSuccessAt === null && /every source failed/.test(stateRow.lastError ?? ""), "the failure is recorded");
    assert(nextIn > 25 && nextIn < 35, `a failed run retries in 30 minutes, not 3 hours: ${nextIn}`);
    assert((await posts()).length === 0, "nothing is posted");

    const runs = await feedStore.recentRuns(1);

    assert(runs[0].status === "failed" && runs[0].providers.length === 4, "the run and each source outcome are kept for status");

    console.log("✓ One failing source blocks nothing; all failing is a recorded failure with a retry");
}

async function testLeasesAndRecovery(): Promise<void> {
    await reset();

    const state = world();

    state.items.fortinet = [raw({ itemKey: "fortinet:FG-IR-26-004", title: "FortiGate flaw", severity: "critical" })];

    /* Two gateways at once: one cycle. */
    const [a, b] = await Promise.all([
        runFeedCycleIfDue(deps(state, { owner: "gateway-1" })),
        runFeedCycleIfDue(deps(state, { owner: "gateway-2" })),
    ]);

    assert([a, b].filter(Boolean).length === 1, "only one gateway runs a cycle");
    assert((await posts()).length === 1, "and the item is posted once");

    /* A gateway crashed mid-cycle; after its lease expires, another recovers the schedule. */
    await db.query(
        `UPDATE public.feed_state
         SET next_run_at = now() - interval '2 hours', lease_owner = 'crashed-gateway', lease_expires_at = now() + interval '10 minutes'
         WHERE id = 1`,
    );

    assert((await runFeedCycleIfDue(deps(state, { owner: "gateway-3" }))) === null, "a live lease blocks other gateways");

    await db.query("UPDATE public.feed_state SET lease_expires_at = now() - interval '1 second' WHERE id = 1");

    const recovered = await runFeedCycleIfDue(deps(state, { owner: "gateway-3" }));
    const stateRow = await feedStore.getFeedState();

    assert(recovered?.status === "success" && stateRow?.leaseOwner === null, "after expiry, the overdue cycle runs and releases the lease");
    assert(new Date(stateRow!.nextRunAt).getTime() - Date.now() > 2.5 * 3_600_000, "the next cycle is scheduled one interval ahead, in the database");

    console.log("✓ Leases allow one cycle at a time, and the schedule recovers after a crash or restart");
}

async function testDelivery(): Promise<void> {
    await reset();

    const state = world();

    state.items.fortinet = [raw({ itemKey: "fortinet:FG-IR-26-005", title: "FortiGate flaw", severity: "critical" })];
    await runFeedCycleIfDue(deps(state));

    const watchSent: string[] = [];
    const feedSent: string[] = [];
    const watchDeliverer: Deliverer = async (text) => (watchSent.push(text), { status: "sent", messageIds: ["w1"] });
    const feedDeliverer: Deliverer = async (text) => (feedSent.push(text), { status: "sent", messageIds: [`f${feedSent.length}`] });

    /* Without a feed deliverer, feed posts are left untouched, not leased. */
    await deliverPending({ owner: "d1", check: undefined as never, deliverer: watchDeliverer, feedDeliverer: null });

    const [waiting] = await posts();

    assert(waiting.delivery_status === "pending" && watchSent.every((text) => !text.includes("FortiGate flaw")), "feed posts never go to the watch channel");

    await deliverPending({ owner: "d1", check: undefined as never, deliverer: watchDeliverer, feedDeliverer });

    const [sent] = await posts();

    assert(feedSent.length === 1 && feedSent[0] === sent.message, "the feed channel receives exactly the saved post");
    assert(sent.delivery_status === "sent" && sent.message_ids[0] === "f1", "the message id is recorded");

    await deliverPending({ owner: "d1", check: undefined as never, deliverer: watchDeliverer, feedDeliverer });
    assert(feedSent.length === 1, "a sent post is not sent again");

    /* A failed send is retried by the outbox, as for watch alerts. */
    state.items.fortinet = [raw({ itemKey: "fortinet:FG-IR-26-006", title: "FortiGate second flaw", severity: "critical" })];
    await makeDue();
    await runFeedCycleIfDue(deps(state));

    const failing: Deliverer = async () => ({ status: "failed", error: "Discord 503", sentBeforeError: false });

    await deliverPending({ owner: "d1", check: undefined as never, deliverer: null, feedDeliverer: failing });

    const { rows: [retry] } = await db.query(
        "SELECT delivery_status, attempts, next_attempt_at, last_error FROM public.watch_events WHERE target = 'fortinet:FG-IR-26-006'",
    );

    assert(retry.delivery_status === "pending" && retry.attempts === 1 && retry.next_attempt_at && /503/.test(retry.last_error), "a failed feed post waits for retry with backoff");

    console.log("✓ Feed posts are delivered only to the feed channel, once, with message ids and retries");
}

async function testTools(): Promise<void> {
    const settings = { enabled: true, notifyTarget: "channel:1", intervalHours: 3, sources: ["fortinet"], unknownSources: [], scope: SCOPE, selection: DEFAULT_SELECTION, requestTimeoutMs: 1000, deliveryMode: "direct" } as FeedSettings;

    const stranger = buildFeedTools({ senderIsOwner: false }, settings);
    const denied = JSON.parse((await stranger.status.execute("x", {})).content[0].text);

    assert(denied.error === "owner_only", "feed status is owner only");

    const owner = buildFeedTools({ senderIsOwner: true }, settings);
    const status = JSON.parse((await owner.status.execute("x", {})).content[0].text);

    assert(status.recentRuns.length > 0 && status.state && status.deliveries && Array.isArray(status.recentPosts), "status shows runs, schedule, deliveries, and posts");
    assert(
        Object.keys(status)[0] === "summary" && /last cycle ran at/.test(status.summary) && Array.isArray(status.howToRead),
        `the status starts with a plain summary and reading rules: ${String(status.summary).slice(0, 200)}`,
    );
    assert(
        status.recentPosts.every((post: { title?: string }) => typeof post.title === "string" && post.title.length > 0),
        "recent posts are named by title",
    );
    assert(typeof status.recentRuns[0].durationMs === "number" && "duplicatesSuppressed" in status.recentRuns[0], "each run shows duration and duplicate suppression");

    await db.query("UPDATE public.feed_state SET next_run_at = now() + interval '3 hours' WHERE id = 1");

    const scheduled = JSON.parse((await owner.runNow.execute()).content[0].text);
    const stateRow = await feedStore.getFeedState();

    assert(scheduled.status === "scheduled" && new Date(stateRow!.nextRunAt).getTime() <= Date.now(), "run now makes the next cycle due");

    console.log("✓ Feed tools are owner only and report the operational state");
}

async function main(): Promise<void> {
    try {
        await testFirstCycleAndDedupe();
        await testRestartNeverReposts();
        await testMaterialUpdate();
        await testLimitsAndQueue();
        await testEmptyCycle();
        await testProviderFailures();
        await testLeasesAndRecovery();
        await testDelivery();
        await testTools();

        console.log("Threat feed database tests PASSED");
    } finally {
        await reset().catch(() => undefined);
        await db.end();
    }
}

main().catch((error) => {
    console.error("Threat feed database tests FAILED");
    console.error(error);
    process.exitCode = 1;
});
