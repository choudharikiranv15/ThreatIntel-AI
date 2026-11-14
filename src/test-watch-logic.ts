/*
 * Offline tests for the watchlist's decision logic: retries, alert policy,
 * notification formatting, and product-specific answer checks.
 */
import { decideAlerts, fingerprint } from "./watch/alerts.js";
import { formatNotification, sanitize } from "./watch/notify.js";
import type { WatchEvent } from "./watch/store.js";
import type { InvestigationComparison, InvestigationChange } from "./persistence/investigation-diff.js";
import { fetchWithRetry, INTERACTIVE_RETRY, MONITOR_RETRY } from "./sources/request-signal.js";
import { fetchNvdCve } from "./sources/nvd.js";
import { fetchRedHatCve } from "./sources/redhat.js";
import type { InvestigationResult, ProviderResult } from "./types.js";
import { checkProductClaims } from "./verification/product-claims.js";
import { clearVendorRows, rememberVendorRows, type ProductRow } from "./verification/evidence-cache.js";
import { checkAnswer } from "./verification/check-answer.js";
import { viewFromResult } from "./tool-result.js";
import { investigateCve } from "./engine.js";

function assert(condition: unknown, message: string): asserts condition {
    if (!condition) {
        throw new Error(`Assertion failed: ${message}`);
    }
}

const realFetch = globalThis.fetch;

function scriptFetch(steps: (() => Response | Promise<Response>)[]): { calls: () => number } {
    let calls = 0;

    globalThis.fetch = (async () => {
        const step = steps[Math.min(calls, steps.length - 1)];

        calls += 1;

        return step();
    }) as typeof fetch;

    return { calls: () => calls };
}

function noSleep(record: number[]) {
    return async (ms: number) => {
        record.push(ms);
    };
}

/* --------------------------------- Retries -------------------------------- */

async function testRetries(): Promise<void> {
    const delays: number[] = [];

    let script = scriptFetch([
        () => new Response("busy", { status: 503 }),
        () => new Response("ok", { status: 200 }),
    ]);

    const recovered = await fetchWithRetry("https://x.test", {}, { timeoutMs: 1000, sleep: noSleep(delays) });

    assert(recovered.status === 200 && script.calls() === 2, "a 503 is retried and can recover");

    delays.length = 0;
    script = scriptFetch([
        () => new Response("", { status: 429, headers: { "retry-after": "3" } }),
        () => new Response("ok", { status: 200 }),
    ]);

    await fetchWithRetry("https://x.test", {}, { timeoutMs: 1000, retry: MONITOR_RETRY, sleep: noSleep(delays) });

    assert(delays[0] === 3000, `Retry-After must be respected: ${delays[0]}`);

    delays.length = 0;
    script = scriptFetch([() => new Response("", { status: 429, headers: { "retry-after": "600" } }), () => new Response("ok")]);

    await fetchWithRetry("https://x.test", {}, { timeoutMs: 1000, retry: MONITOR_RETRY, sleep: noSleep(delays) });

    assert(delays[0] === MONITOR_RETRY.maxDelayMs, "a long Retry-After is capped");

    script = scriptFetch([() => new Response("", { status: 404 })]);

    const missing = await fetchWithRetry("https://x.test", {}, { timeoutMs: 1000, sleep: noSleep([]) });

    assert(missing.status === 404 && script.calls() === 1, "a 404 is an answer, never retried");

    script = scriptFetch([() => new Response("", { status: 503 })]);

    const exhausted = await fetchWithRetry("https://x.test", {}, { timeoutMs: 1000, retry: MONITOR_RETRY, sleep: noSleep([]) });

    assert(
        exhausted.status === 503 && script.calls() === MONITOR_RETRY.attempts,
        "attempts are bounded, and the last response is returned",
    );

    script = scriptFetch([() => new Response("", { status: 429, headers: { "retry-after": "5" } })]);

    const overBudget = await fetchWithRetry(
        "https://x.test",
        {},
        { timeoutMs: 1000, retry: { attempts: 5, maxDelayMs: 10_000, budgetMs: 1_000 }, sleep: noSleep([]) },
    );

    assert(overBudget.status === 429 && script.calls() === 1, "no retry may start past the time budget");

    let timeouts = 0;

    globalThis.fetch = (async () => {
        timeouts += 1;

        if (timeouts < 3) {
            throw new DOMException("timed out", "TimeoutError");
        }

        return new Response("ok");
    }) as typeof fetch;

    const afterTimeouts = await fetchWithRetry("https://x.test", {}, { timeoutMs: 1000, retry: MONITOR_RETRY, sleep: noSleep([]) });

    assert(afterTimeouts.status === 200 && timeouts === 3, "timeouts are retried");

    globalThis.fetch = (async () => {
        throw new Error("certificate rejected");
    }) as typeof fetch;

    let permanent = 0;

    try {
        await fetchWithRetry("https://x.test", {}, { timeoutMs: 1000, retry: MONITOR_RETRY, sleep: async () => { permanent += 1; } });
    } catch {
        // expected
    }

    assert(permanent === 0, "an error a retry cannot fix is not retried");

    const controller = new AbortController();

    controller.abort();
    script = scriptFetch([() => { throw new TypeError("fetch failed"); }]);

    let abortedCalls = -1;

    try {
        await fetchWithRetry("https://x.test", {}, { timeoutMs: 1000, signal: controller.signal, retry: MONITOR_RETRY, sleep: noSleep([]) });
    } catch {
        abortedCalls = script.calls();
    }

    assert(abortedCalls === 1, "a caller's abort is never retried");

    /* Through real providers: failure stays failure, absence stays absence. */
    script = scriptFetch([() => new Response("", { status: 503 })]);

    const nvd = await fetchNvdCve("CVE-2099-0001", { timeoutMs: 1000, retry: { attempts: 2, maxDelayMs: 1, budgetMs: 1000 } });

    assert(nvd.status === "error" && script.calls() === 2, "an NVD outage stays an error after retries, never an absence");

    script = scriptFetch([() => new Response("{}", { status: 404 })]);

    const redhat = await fetchRedHatCve("CVE-2099-0001", { timeoutMs: 1000, retry: MONITOR_RETRY });

    assert(redhat.status === "observed_absence" && script.calls() === 1, "a Red Hat 404 is still an absence, without retrying");

    assert(INTERACTIVE_RETRY.attempts === 2, "the interactive tool gets exactly one retry");

    globalThis.fetch = realFetch;

    console.log("✓ Retries are bounded, respect Retry-After, and never turn failure into absence");
}

/* ------------------------------ Alert policy ------------------------------ */

function comparison(
    changes: Partial<InvestigationChange>[],
    overrides: Partial<InvestigationComparison> & { integrity?: Partial<InvestigationComparison["baseline"]["integrity"]> } = {},
): InvestigationComparison {
    const integrity = {
        evidenceRows: "verified" as const,
        recordConsistency: "consistent" as const,
        fullyVerified: true,
        ...overrides.integrity,
    };

    const full = changes.map((change) => ({
        category: "intelligence_change" as const,
        field: "kevStatus",
        before: null,
        after: null,
        beforeBasis: "rederived_baseline" as const,
        afterBasis: "current_result" as const,
        explanation: "",
        sources: ["CISA_KEV"],
        ...change,
    })) as InvestigationChange[];

    return {
        target: "CVE-2099-0001",
        baseline: {
            investigationId: "baseline-id",
            createdAt: "2026-01-01T00:00:00.000Z",
            basis: "rederived_from_stored_evidence",
            recordedEngineVersion: "0.5.0",
            rederivedWithEngineVersion: "0.5.0",
            recorded: { status: "confirmed", severity: null, cvssBaseScore: null, kevStatus: "not-listed" },
            rederived: { status: "confirmed", severity: null, cvssBaseScore: null, kevStatus: "not-listed" },
            integrity,
        },
        current: { investigationId: null, createdAt: null, integrity: null },
        counts: { intelligence_change: 0, collection_difference: 0, processing_difference: 0 },
        noIntelligenceChange: full.some((change) => change.category === "intelligence_change") ? false : true,
        changes: full,
        omittedChanges: 0,
        ...overrides,
    } as InvestigationComparison;
}

function result(statuses: Record<string, ProviderResult["status"]>): InvestigationResult {
    return {
        providerResults: Object.entries(statuses).map(([provider, status]) => ({
            provider,
            status,
            evidence: null,
            error: null,
            checkedAt: "",
        })),
    } as unknown as InvestigationResult;
}

const complete = result({ NVD: "success", CISA_KEV: "success", REDHAT: "success", OSV: "success" });

function testAlertPolicy(): void {
    const alerts = (changes: Partial<InvestigationChange>[], overrides = {}) =>
        decideAlerts(comparison(changes, overrides), complete);

    const listed = alerts([{ field: "kevStatus", before: "not-listed", after: "listed" }]);

    assert(
        listed.outcome === "changes_detected" &&
        listed.events.length === 1 &&
        listed.events[0].deliverable &&
        listed.events[0].explanation.includes("known to be exploited"),
        "a new KEV listing must alert",
    );

    assert(alerts([{ field: "kevStatus", before: "listed", after: "not-listed" }]).events.length === 1, "a KEV removal must alert");
    assert(alerts([{ field: "kevStatus", before: "not-listed", after: "unknown" }]).events.length === 0, "an unknown KEV state never alerts");
    assert(alerts([{ field: "cvss.baseScore", before: 7.5, after: 9.8, sources: ["NVD"] }]).events.length === 1, "a score change must alert");
    assert(alerts([{ field: "cvss.vector", before: "a", after: "b", sources: ["NVD"] }]).events.length === 1, "a vector change must alert");
    assert(alerts([{ field: "cvss.source", before: "a", after: "b", sources: ["NVD"] }]).events.length === 0, "a scoring-source change alone never alerts");
    assert(alerts([{ field: "affectedVersions", before: { removed: [] }, after: { added: ["x"] }, sources: ["NVD"] }]).events.length === 1, "new affected versions must alert");
    assert(alerts([{ field: "packageFixes", before: undefined, after: ["2.0.0"], sources: ["OSV"] }]).events.length === 1, "a new fixed version must alert");
    assert(alerts([{ field: "packageFixes", before: ["2.0.0"], after: null, sources: ["OSV"] }]).events.length === 0, "a fix disappearing is not actionable");
    assert(alerts([{ field: "vendorImpact", before: "affected", after: "fixed", sources: ["REDHAT"] }]).events.length === 1, "a vendor fix must alert");
    assert(alerts([{ field: "vendorImpact", before: "affected", after: "not_affected", sources: ["REDHAT"] }]).events.length === 1, "affected to not affected must alert");
    assert(alerts([{ field: "vendorImpact", before: "affected", after: "unknown", sources: ["REDHAT"] }]).events.length === 0, "a move to unknown never alerts");
    assert(alerts([{ field: "conflict", before: null, after: "x" }]).events.length === 0, "conflicts are history, not alerts");

    /* Suppression */
    for (const category of ["collection_difference", "processing_difference"] as const) {
        const suppressed = decideAlerts(
            comparison([{ category, field: "kevStatus", before: "not-listed", after: "listed" }], { noIntelligenceChange: true }),
            complete,
        );

        assert(suppressed.events.length === 0, `a ${category} must never alert`);
    }

    const unreliable = decideAlerts(
        comparison([{ field: "kevStatus", before: "not-listed", after: "listed" }], { noIntelligenceChange: null }),
        complete,
    );

    assert(unreliable.events.length === 0 && !unreliable.mayAdvanceBaseline, "an unreliable comparison neither alerts nor advances");

    const outage = decideAlerts(
        comparison([{ field: "kevStatus", before: "not-listed", after: "listed" }]),
        result({ NVD: "success", CISA_KEV: "error", REDHAT: "success", OSV: "success" }),
    );

    assert(
        outage.outcome === "core_incomplete" && outage.events.length === 0 && !outage.mayAdvanceBaseline,
        "a KEV outage must not alert or move the baseline",
    );

    const upgraded = alerts([{ field: "kevStatus", before: "not-listed", after: "listed" }], {
        integrity: { recordConsistency: "unverifiable", fullyVerified: false },
    });

    assert(
        upgraded.outcome === "baseline_reset" &&
        upgraded.events.length === 1 &&
        upgraded.events[0].kind === "baseline_reset" &&
        !upgraded.events[0].deliverable,
        "an engine upgrade resets the baseline without alerting",
    );

    for (const damage of [
        { evidenceRows: "tampered" as const },
        { evidenceRows: "missing" as const },
        { evidenceRows: "inconsistent" as const },
        { recordConsistency: "inconsistent" as const },
    ]) {
        const warned = alerts([{ field: "kevStatus", before: "not-listed", after: "listed" }], {
            integrity: { ...damage, fullyVerified: false },
        });

        assert(
            warned.outcome === "integrity_warning" &&
            warned.events.length === 1 &&
            warned.events[0].kind === "integrity_warning" &&
            warned.events[0].deliverable,
            `a damaged baseline (${JSON.stringify(damage)}) must warn instead of alerting changes`,
        );
    }

    /* Fingerprints */
    const event = listed.events[0];

    assert(fingerprint("CVE-1", event, "b1") === fingerprint("CVE-1", { ...event }, "b1"), "the same observation has one fingerprint");
    assert(fingerprint("CVE-1", event, "b1") !== fingerprint("CVE-2", event, "b1"), "fingerprints are per CVE");
    assert(fingerprint("CVE-1", event, "b1") !== fingerprint("CVE-1", { ...event, after: "x" }, "b1"), "a different value is a different observation");
    assert(
        fingerprint("CVE-1", event, "b1") !== fingerprint("CVE-1", event, "b3"),
        "the same change seen again against a newer baseline (listed, unlisted, listed again) is a new observation",
    );

    console.log("✓ Only verified intelligence changes alert; outages, upgrades, and damaged baselines do not");
}

/* ------------------------------ Notifications ----------------------------- */

function event(overrides: Partial<WatchEvent> = {}): WatchEvent {
    return {
        id: "e1",
        target: "CVE-2099-0001",
        checkId: "c1",
        kind: "intelligence_change",
        fingerprint: "f",
        field: "kevStatus",
        scope: null,
        before: "not-listed",
        after: "listed",
        explanation: "CISA KEV now lists this CVE as known to be exploited.",
        sources: ["CISA_KEV", "NVD"],
        baselineInvestigationId: "b1",
        investigationId: "i1",
        deliverable: true,
        observedAt: "2026-11-10T00:00:00.000Z",
        deliveryStatus: "sending",
        attempts: 1,
        nextAttemptAt: null,
        lastError: null,
        sentAt: null,
        messageIds: [],
        possibleDuplicate: false,
        ...overrides,
    };
}

function testNotifications(): void {
    const text = formatNotification([event()]);

    assert(
        text.includes("CVE-2099-0001") &&
        text.includes("not-listed") &&
        text.includes("**listed**") &&
        text.includes("known to be exploited") &&
        text.includes("<https://www.cisa.gov/known-exploited-vulnerabilities-catalog>") &&
        text.includes("<https://nvd.nist.gov/vuln/detail/CVE-2099-0001>") &&
        text.includes("2026-11-10T00:00:00.000Z") &&
        text.includes("investigation i1"),
        `the notification must carry the CVE, values, explanation, sources, time, and reference: ${text}`,
    );

    const hostile = formatNotification([
        event({
            scope: "@everyone <@123> [click](https://evil.test) **bold**",
            after: "@here",
        }),
    ]);

    assert(
        !/@everyone|@here|<@123>/.test(hostile.replace(/​/g, "#")) &&
        !hostile.includes("[click](") &&
        hostile.includes("@​everyone"),
        `mentions, links, and markdown from sources must be neutralised: ${hostile}`,
    );

    assert(sanitize("a".repeat(500), 10).length <= 11, "untrusted text is clipped");

    const many = formatNotification(Array.from({ length: 12 }, (_, index) => event({ id: `e${index}`, scope: `product-${index}` })));

    assert(many.includes("…and 7 more") && many.length <= 1900, "long batches are summarised within Discord's limit");

    const retried = formatNotification([event({ possibleDuplicate: true })]);

    assert(retried.includes("may repeat an earlier delivery"), "a possibly repeated alert must say so");

    console.log("✓ Notifications are complete, bounded, and safe against hostile source text");
}

/* ----------------------------- Product claims ----------------------------- */

const ROWS: ProductRow[] = [
    { productName: "Red Hat Enterprise Linux 8", packageName: "python-requests", status: "fixed", cpe: null },
    { productName: "Red Hat Enterprise Linux 8.6 Extended Update Support", packageName: "python-requests", status: "fixed", cpe: null },
    { productName: "Red Hat Enterprise Linux 9", packageName: "python-requests", status: "affected", cpe: null },
    { productName: "Red Hat Ansible Automation Platform 2.4 for RHEL 8", packageName: "python3x-requests", status: "fixed", cpe: null },
    { productName: "Red Hat OpenShift Container Platform 3.11", packageName: "python-requests", status: "unknown", cpe: null },
    { productName: "Red Hat OpenShift Container Platform 4.12", packageName: "python-requests", status: "fixed", cpe: null },
    { productName: "Red Hat JBoss Enterprise Application Platform 7", packageName: "x", status: "not_affected", cpe: null },
];

function testProductClaims(): void {
    const check = (sentence: string, rows = ROWS) => checkProductClaims("CVE-2099-0001", sentence, rows, true);

    /* The Phase 4 live failure: OpenShift called fixed when it is unknown. */
    const openShiftOnly = ROWS.filter((row) => row.productName.includes("3.11") || !row.productName.includes("OpenShift"));

    const live = check(
        "Red Hat has shipped fixes in 13 product packages (RHEL 8, Ansible Automation Platform, OpenShift, etc.).",
        openShiftOnly,
    );

    assert(
        live.length === 1 && live[0].includes("openshift") && live[0].includes("unknown"),
        `only the unsupported OpenShift claim may be flagged: ${JSON.stringify(live)}`,
    );

    assert(check("OpenShift Container Platform 3.11 is fixed.").length === 1, "an unknown product called fixed must fail");
    assert(check("OpenShift Container Platform 4.12 is fixed.").length === 0, "a supported fixed claim must pass");
    assert(check("RHEL 8 is fixed.").length === 0, "an alias with a supported status must pass");
    assert(check("RHEL 9 is fixed.").length === 1, "an affected product called fixed must fail");
    assert(check("JBoss Enterprise Application Platform 7 is not affected.").length === 0, "a supported not-affected claim must pass");

    const ambiguous = check("OpenShift is fixed.");

    assert(
        ambiguous.length === 1 && ambiguous[0].includes("ambiguous"),
        `a family whose products differ must not get one definitive status: ${JSON.stringify(ambiguous)}`,
    );

    assert(
        check("OpenShift Container Platform 3.11 is fixed.").every((finding) => !finding.includes("ambiguous")),
        "a versioned claim is judged on that version alone, not inferred from 4.12",
    );

    assert(check("RHEL 8 is fixed but RHEL 9 is affected.").length === 0, "a sentence mixing statuses is skipped, not guessed");
    assert(check("Several distributions are affected.").length === 0, "a sentence naming no product is not judged");

    /* Everyday words inside product names must not be read as product mentions. */
    const generic: ProductRow[] = [
        { productName: "Red Hat Software Collections for Red Hat Enterprise Linux 7", packageName: "x", status: "affected", cpe: null },
        { productName: "Red Hat Data Grid 8", packageName: "x", status: "not_affected", cpe: null },
        { productName: "Red Hat Integration Camel Quarkus 2", packageName: "x", status: "affected", cpe: null },
        { productName: "Red Hat Product With A Long Name 0", packageName: "x", status: "not_affected", cpe: null },
    ];

    for (const sentence of [
        "Red Hat has shipped fixes in 13 product packages.",
        "The vulnerable software is fixed upstream.",
        "No data was lost, and the integration tests are fixed.",
        "This product is affected.",
    ]) {
        assert(
            check(sentence, generic).length === 0,
            `an everyday word must not be read as a product: ${sentence} -> ${JSON.stringify(check(sentence, generic))}`,
        );
    }

    assert(check("Red Hat Data Grid 8 is affected.", generic).length === 1, "a full product name is still checked");
    assert(check("Quarkus is fixed.", generic).length === 1, "a brand word is still checked");

    const noData = check("RHEL 8 is fixed.", []);

    assert(noData.length === 1 && noData[0].includes("no Red Hat assessment"), "a claim with no vendor data must say so");

    console.log("✓ Product claims are checked against that product's own rows");
}

async function testProductClaimsThroughGate(): Promise<void> {
    const target = "CVE-2099-0001";
    const now = new Date().toISOString();

    const investigation = await investigateCve(target, {
        requestTimeoutMs: 1000,
        providers: {
            nvd: async () => ({ provider: "NVD", status: "success", error: null, checkedAt: now, evidence: { id: `NVD:${target}`, source: "NVD", sourceType: "primary", retrievedAt: now, url: "https://e.test", title: "t", confidence: "high", facts: { id: target }, extractedFacts: [], references: [] } }),
            cisaKev: async () => ({ provider: "CISA_KEV", status: "observed_absence", error: null, checkedAt: now, evidence: null }),
            redhat: async () => ({
                provider: "REDHAT",
                status: "success",
                error: null,
                checkedAt: now,
                evidence: {
                    id: `REDHAT:${target}`, source: "REDHAT", sourceType: "vendor", retrievedAt: now, url: "https://e.test", title: "t", confidence: "high", extractedFacts: [], references: [],
                    facts: {
                        name: target,
                        // OpenShift sorts last, so the capped tool result never shows it.
                        package_state: [
                            ...Array.from({ length: 40 }, (_, index) => ({ product_name: `Red Hat Enterprise Linux ${index + 10}`, package_name: "p", fix_state: "Affected" })),
                            { product_name: "Red Hat OpenShift Container Platform 3.11", package_name: "p", fix_state: "Not affected" },
                        ],
                    },
                },
            }),
        },
    });

    const view = viewFromResult(investigation);

    assert(
        !view.summary.vendorImpact.items.some((item) => item.product.includes("OpenShift")),
        "fixture: the capped tool result must not show OpenShift",
    );

    const claim = `${target}: OpenShift Container Platform 3.11 is affected.`;

    clearVendorRows();

    assert(
        checkAnswer(claim, [view]).length === 0,
        "without full rows, a product the result does not show cannot be judged",
    );

    rememberVendorRows(target, investigation.summary.vendorImpact);

    assert(
        checkAnswer(claim, [view]).some((finding) => finding.includes("not_affected")),
        "with full rows, the hidden product's real status must be enforced",
    );

    assert(
        checkAnswer(`${target}: OpenShift Container Platform 3.11 is not affected.`, [view]).length === 0,
        "a correct claim about the hidden product must pass",
    );

    assert(
        checkAnswer(`${target}: the claim that OpenShift Container Platform 3.11 is affected is incorrect.`, [view]).length === 0,
        "correcting a wrong product claim must not be flagged",
    );

    clearVendorRows();

    console.log("✓ The answer gate checks product claims against full rows, beyond the capped tool result");
}

async function main(): Promise<void> {
    try {
        await testRetries();
        testAlertPolicy();
        testNotifications();
        testProductClaims();
        await testProductClaimsThroughGate();
        console.log("Watch logic tests PASSED");
    } finally {
        globalThis.fetch = realFetch;
    }
}

main().catch((error: unknown) => {
    console.error("Watch logic tests FAILED");
    console.error(error);
    process.exitCode = 1;
});
