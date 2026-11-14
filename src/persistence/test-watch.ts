/*
 * The watchlist against real PostgreSQL: storage, leases, restart recovery,
 * change detection through Phase 4, deduplication, and delivery recovery.
 * Providers and Discord are faked; everything else is the production code.
 */
import { investigateCve } from "../engine.js";
import type { ProviderResult, SourceId } from "../types.js";
import type { Deliverer, DeliveryResult } from "../watch/delivery.js";
import { defaultCheckDependencies } from "../watch/monitor.js";
import {
    checkAndRecord,
    createWatchService,
    deliverPending,
    runDueChecks,
    type WatchRuntime,
} from "../watch/service.js";
import * as store from "../watch/store.js";
import { db } from "./db.js";
import { persistInvestigation } from "./persist-investigation.js";

function assert(condition: unknown, message: string): asserts condition {
    if (!condition) {
        throw new Error(`Assertion failed: ${message}`);
    }
}

let counter = 0;
const targets: string[] = [];

function newTarget(): string {
    counter += 1;

    const target = `CVE-2098-${Date.now() % 1_000_000}${counter}`;

    targets.push(target);

    return target;
}

/* --------------------------------- Fixtures -------------------------------- */

type World = {
    kevListed: boolean;
    kevFails: boolean;
    redhatFails: boolean;
    osvFails: boolean;
    score: number;
    calls: number;
};

function world(overrides: Partial<World> = {}): World {
    return { kevListed: false, kevFails: false, redhatFails: false, osvFails: false, score: 7.5, calls: 0, ...overrides };
}

function ok(source: SourceId, target: string, facts: Record<string, unknown> | null): ProviderResult {
    const now = new Date().toISOString();

    return {
        provider: source,
        status: facts ? "success" : "observed_absence",
        error: null,
        checkedAt: now,
        evidence: facts
            ? {
                id: `${source}:${target}`,
                source,
                sourceType: source === "REDHAT" ? "vendor" : source === "OSV" ? "community" : "primary",
                retrievedAt: now,
                url: "https://example.test/",
                title: "test",
                confidence: source === "OSV" ? "medium" : "high",
                facts,
                extractedFacts: [],
                references: [],
            }
            : null,
    };
}

function down(source: SourceId): ProviderResult {
    return { provider: source, status: "error", evidence: null, error: "unavailable", checkedAt: new Date().toISOString() };
}

function investigator(state: World) {
    return (target: string) => {
        state.calls += 1;

        return investigateCve(target, {
            requestTimeoutMs: 1000,
            providers: {
                nvd: async () => ok("NVD", target, {
                    id: target,
                    metrics: {
                        cvssMetricV31: [{
                            source: "nvd@nist.gov",
                            cvssData: { version: "3.1", baseScore: state.score, vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" },
                        }],
                    },
                }),
                cisaKev: async () =>
                    state.kevFails ? down("CISA_KEV") : ok("CISA_KEV", target, state.kevListed ? { dateAdded: "2026-11-01" } : null),
                redhat: async () =>
                    state.redhatFails ? down("REDHAT") : ok("REDHAT", target, { name: target, package_state: [] }),
                osv: async () => (state.osvFails ? down("OSV") : ok("OSV", target, null)),
            },
        });
    };
}

function runtime(state: World, deliverer: Deliverer | null = null, owner = "worker-a"): WatchRuntime {
    return {
        owner,
        check: defaultCheckDependencies(investigator(state), persistInvestigation, store.insertEvents),
        deliverer,
        pauseMs: 0,
    };
}

async function add(target: string): Promise<store.WatchEntry> {
    const added = await store.addWatch(target, { intervalHours: 24, createdBy: "test", maxEntries: 1000 });

    assert(added.entry, "fixture watch should be added");

    return added.entry;
}

/** Runs one check of one CVE now, as the scheduler would. */
async function checkNow(target: string, rt: WatchRuntime) {
    const entry = await store.claimWatch(target, rt.owner, 60);

    assert(entry, `${target} should be claimable`);

    return checkAndRecord(entry, rt);
}

async function makeDue(target: string): Promise<void> {
    await db.query("UPDATE public.watchlist SET next_check_at = now() - interval '1 minute' WHERE target = $1", [target]);
}

async function investigationCount(target: string): Promise<number> {
    const { rows } = await db.query<{ n: string }>("SELECT count(*) AS n FROM public.investigations WHERE target = $1", [target]);

    return Number(rows[0].n);
}

async function events(target: string): Promise<store.WatchEvent[]> {
    return store.recentEvents(target, 100);
}

function capture(results: DeliveryResult[] = []) {
    const sent: string[] = [];
    let index = 0;

    const deliverer: Deliverer = async (text) => {
        sent.push(text);

        const result = results[Math.min(index, results.length - 1)] ?? { status: "sent", messageIds: [`m${sent.length}`] };

        index += 1;

        return result;
    };

    return { deliverer, sent };
}

/* ---------------------------------- Tests ---------------------------------- */

async function testWatchlistStorage(): Promise<void> {
    const target = newTarget();

    const first = await store.addWatch(target, { intervalHours: 24, createdBy: "owner", maxEntries: 1000 });
    const duplicate = await store.addWatch(target, { intervalHours: 12, createdBy: "owner", maxEntries: 1000 });

    assert(first.status === "added" && duplicate.status === "exists", "a CVE can be watched only once");
    assert(duplicate.entry?.intervalHours === 24, "a duplicate add must not change the existing watch");

    const { rows } = await db.query<{ n: string }>("SELECT count(*) AS n FROM public.watchlist");
    const full = await store.addWatch(newTarget(), { intervalHours: 24, createdBy: "owner", maxEntries: Number(rows[0].n) });

    assert(full.status === "limit", "the size limit must be enforced");

    let rejected = false;

    try {
        await db.query("INSERT INTO public.watchlist (target, interval_hours) VALUES ($1, 2)", [newTarget()]);
    } catch {
        rejected = true;
    }

    assert(rejected, "the database must reject an interval below 6 hours");

    const disabled = await store.updateWatch(target, { enabled: false });

    assert(disabled?.enabled === false, "monitoring can be disabled");

    const reenabled = await store.updateWatch(target, { enabled: true, intervalHours: 48 });

    assert(
        reenabled?.enabled === true &&
        reenabled.intervalHours === 48 &&
        Date.parse(reenabled.nextCheckAt) <= Date.now() + 1000,
        "re-enabling schedules a check now",
    );

    assert((await store.listWatches()).some((entry) => entry.target === target), "the watch must be listed");
    assert(await store.removeWatch(target), "the watch can be removed");
    assert((await store.getWatch(target)) === null, "a removed watch is gone");
    assert(!(await store.removeWatch(target)), "removing twice reports nothing removed");

    console.log("✓ Watchlist storage prevents duplicates and enforces limits");
}

async function testLeases(): Promise<void> {
    const due = [newTarget(), newTarget(), newTarget(), newTarget()];

    for (const target of due) {
        await add(target);
    }

    const [a, b] = await Promise.all([
        store.claimDueWatches("worker-a", 60, 100),
        store.claimDueWatches("worker-b", 60, 100),
    ]);

    const claimedA = a.filter((entry) => due.includes(entry.target)).map((entry) => entry.target);
    const claimedB = b.filter((entry) => due.includes(entry.target)).map((entry) => entry.target);

    assert(
        claimedA.length + claimedB.length === due.length &&
        claimedA.every((target) => !claimedB.includes(target)),
        `two workers must never claim the same CVE: ${claimedA} / ${claimedB}`,
    );

    const [held] = due;
    const holder = claimedA.includes(held) ? "worker-a" : "worker-b";
    const other = holder === "worker-a" ? "worker-b" : "worker-a";

    assert((await store.claimWatch(held, other, 60)) === null, "a held lease cannot be taken");

    assert(
        (await store.completeCheck(held, other, { success: false, outcome: "x", error: "x" })) === null,
        "only the lease holder can record a result",
    );

    // A worker crashes holding a lease. After expiry, another worker recovers it.
    await db.query(
        "UPDATE public.watchlist SET lease_expires_at = now() - interval '1 second' WHERE target = ANY($1)",
        [due],
    );

    const recovered = await store.claimDueWatches("worker-c", 60, 100);

    assert(
        due.every((target) => recovered.some((entry) => entry.target === target)),
        "expired leases must be recoverable by any worker",
    );

    assert(
        (await store.completeCheck(held, holder, { success: false, outcome: "x", error: "x" })) === null,
        "a worker whose lease expired cannot overwrite a newer result",
    );

    for (const target of due) {
        await store.removeWatch(target);
    }

    console.log("✓ Leases stop overlapping checks and recover from crashed workers");
}

async function testChangeDetection(): Promise<void> {
    const target = newTarget();
    const state = world();
    const rt = runtime(state);

    await add(target);

    const baseline = await checkNow(target, rt);

    assert(
        baseline.outcome.success &&
        baseline.outcome.outcome === "baseline_established" &&
        baseline.entry?.baselineInvestigationId,
        "the first check establishes a baseline",
    );

    /* Nothing changed: no event, and no new investigation stored. */
    const before = await investigationCount(target);
    const quiet = await checkNow(target, rt);

    assert(quiet.outcome.success && quiet.outcome.outcome === "no_change", "an unchanged CVE reports no change");
    assert((await investigationCount(target)) === before, "an unchanged check must not store another investigation");
    assert((await events(target)).length === 0, "an unchanged check must not create events");

    /* A real change */
    state.kevListed = true;

    const changed = await checkNow(target, rt);
    const afterChange = await events(target);

    assert(changed.outcome.outcome === "changes_detected", "a new KEV listing must be detected");
    assert(
        afterChange.some(
            (event) =>
                event.field === "kevStatus" &&
                event.before === "not-listed" &&
                event.after === "listed" &&
                event.deliverable &&
                event.deliveryStatus === "pending" &&
                event.investigationId,
        ),
        `the change must be saved, pending delivery, citing its investigation: ${JSON.stringify(afterChange)}`,
    );
    assert(
        changed.entry?.baselineInvestigationId !== baseline.entry?.baselineInvestigationId,
        "a complete check with a change becomes the new baseline",
    );

    /* The same state again: no duplicate event. */
    const again = await checkNow(target, rt);

    assert(again.outcome.outcome === "no_change", "the new baseline already includes the change");
    assert((await events(target)).length === afterChange.length, "a change must be recorded once");

    /* A change that reverses and then happens again alerts every time. */
    state.kevListed = false;
    await checkNow(target, rt);
    state.kevListed = true;
    await checkNow(target, rt);

    const kevEvents = (await events(target)).filter((event) => event.field === "kevStatus");
    const relisted = kevEvents.filter((event) => event.before === "not-listed" && event.after === "listed");

    assert(
        kevEvents.length === 3 && relisted.length === 2,
        `listed, unlisted, listed again must alert three times: ${JSON.stringify(kevEvents.map((event) => [event.before, event.after]))}`,
    );

    console.log("✓ Real changes are detected once, through the Phase 4 comparison, and again if they recur");
}

async function testSuppression(): Promise<void> {
    /* KEV outage: no alert, baseline unchanged, counted as a failure. */
    const target = newTarget();
    const state = world();
    const rt = runtime(state);

    await add(target);
    await checkNow(target, rt);

    const baselineId = (await store.getWatch(target))?.baselineInvestigationId;

    state.kevFails = true;
    state.kevListed = true;

    const outage = await checkNow(target, rt);

    assert(!outage.outcome.success && outage.outcome.outcome === "core_incomplete", "a KEV outage is a failed check");
    assert((await events(target)).length === 0, "a KEV outage must never alert");
    assert((await store.getWatch(target))?.baselineInvestigationId === baselineId, "a KEV outage must not move the baseline");
    assert((await store.getWatch(target))?.consecutiveFailures === 1, "a failed check is counted");

    /* Enrichment outage: alerts from NVD/KEV still work, but the baseline stays, and dedupe holds. */
    const enrich = newTarget();
    const enrichState = world();
    const enrichRt = runtime(enrichState);

    await add(enrich);
    await checkNow(enrich, enrichRt);

    const enrichBaseline = (await store.getWatch(enrich))?.baselineInvestigationId;

    enrichState.redhatFails = true;
    enrichState.kevListed = true;

    await checkNow(enrich, enrichRt);
    await checkNow(enrich, enrichRt);

    const enrichEvents = await events(enrich);

    assert(
        enrichEvents.filter((event) => event.field === "kevStatus").length === 1,
        `a change seen twice while the baseline cannot move must be stored once: ${JSON.stringify(enrichEvents.map((e) => e.field))}`,
    );
    assert(
        !enrichEvents.some((event) => event.field === "vendorImpact" || event.field === "providerStatus"),
        "a Red Hat outage must not alert",
    );
    assert(
        (await store.getWatch(enrich))?.baselineInvestigationId === enrichBaseline,
        "an incomplete check must not become the baseline",
    );

    /* Engine upgrade: silent reset. */
    const upgraded = newTarget();
    const upgradedRt = runtime(world());

    await add(upgraded);
    await checkNow(upgraded, upgradedRt);

    const oldBaseline = (await store.getWatch(upgraded))?.baselineInvestigationId;

    await db.query("ALTER TABLE public.investigations DISABLE TRIGGER investigations_append_only");
    await db.query("UPDATE public.investigations SET engine_version = '0.4.0' WHERE id = $1", [oldBaseline]);
    await db.query("ALTER TABLE public.investigations ENABLE TRIGGER investigations_append_only");

    const reset = await checkNow(upgraded, upgradedRt);
    const resetEvents = await events(upgraded);

    assert(reset.outcome.outcome === "baseline_reset", "an older engine's baseline is reset");
    assert(
        resetEvents.length === 1 &&
        resetEvents[0].kind === "baseline_reset" &&
        resetEvents[0].deliveryStatus === "not_deliverable",
        "a reset is recorded but never sent",
    );
    assert((await store.getWatch(upgraded))?.baselineInvestigationId !== oldBaseline, "the baseline is replaced");

    /* Tampered baseline: one integrity warning, then a fresh baseline. */
    const tampered = newTarget();
    const tamperedRt = runtime(world());

    await add(tampered);
    await checkNow(tampered, tamperedRt);

    const tamperedBaseline = (await store.getWatch(tampered))?.baselineInvestigationId;

    await db.query("ALTER TABLE public.evidence DISABLE TRIGGER evidence_append_only");
    await db.query(
        "UPDATE public.evidence SET raw_payload = raw_payload || '{\"forged\":true}' WHERE investigation_id = $1 AND source = 'NVD'",
        [tamperedBaseline],
    );
    await db.query("ALTER TABLE public.evidence ENABLE TRIGGER evidence_append_only");

    const warned = await checkNow(tampered, tamperedRt);
    const warnings = await events(tampered);

    assert(warned.outcome.outcome === "integrity_warning", "a tampered baseline must be detected");
    assert(
        warnings.length === 1 && warnings[0].kind === "integrity_warning" && warnings[0].deliverable,
        "a tampered baseline raises one deliverable warning and no change alerts",
    );

    /* Deleted baseline */
    const deleted = newTarget();
    const deletedRt = runtime(world());

    await add(deleted);
    await checkNow(deleted, deletedRt);

    const deletedBaseline = (await store.getWatch(deleted))?.baselineInvestigationId;

    await db.query("DELETE FROM public.investigations WHERE id = $1", [deletedBaseline]);

    const missing = await checkNow(deleted, deletedRt);

    assert(
        missing.outcome.outcome === "baseline_missing" &&
        (await events(deleted)).some((event) => event.kind === "integrity_warning"),
        "a deleted baseline must be reported, not silently replaced",
    );

    console.log("✓ Outages, engine upgrades, and damaged baselines never produce change alerts");
}

async function testMonitorHealth(): Promise<void> {
    const target = newTarget();
    const state = world();
    const rt = runtime(state);

    await add(target);
    await checkNow(target, rt);

    state.kevFails = true;

    for (let attempt = 0; attempt < 4; attempt += 1) {
        await checkNow(target, rt);
    }

    let health = (await events(target)).filter((event) => event.kind === "monitor_failure");

    assert(health.length === 1 && health[0].deliverable, "repeated failures raise one failure alert, not one per check");

    const failing = await store.getWatch(target);

    assert(
        failing?.consecutiveFailures === 4 &&
        Date.parse(failing.nextCheckAt) - Date.now() < 24 * 3_600_000,
        "a failing watch retries sooner than its interval",
    );

    state.kevFails = false;

    await checkNow(target, rt);

    health = (await events(target)).filter((event) => event.kind === "monitor_recovered");

    assert(health.length === 1, "recovery is announced once");
    assert((await store.getWatch(target))?.failureAlerted === false, "the failure episode is closed");

    console.log("✓ Monitoring reports its own failure once, and its recovery once");
}

async function testDelivery(): Promise<void> {
    const target = newTarget();
    const state = world();

    await add(target);
    await checkNow(target, runtime(state));

    state.kevListed = true;
    state.score = 9.8;

    await checkNow(target, runtime(state));

    /* Not configured: events wait, nothing is lost. */
    await deliverPending(runtime(state, null));

    assert(
        (await events(target)).every((event) => event.deliveryStatus === "pending"),
        "without a channel, events stay pending",
    );

    /* Success: one message per check, with Discord's message ids recorded. */
    const success = capture([{ status: "sent", messageIds: ["1300000000000000001"] }]);

    await deliverPending(runtime(state, success.deliverer));

    let saved = await events(target);

    // Earlier tests left other alerts pending; only this CVE's messages count here.
    const forTarget = success.sent.filter((text) => text.includes(target));

    assert(
        forTarget.length === 1 && forTarget[0].includes("2 intelligence changes"),
        `both changes from one check go in one message: ${forTarget.length}`,
    );
    assert(
        saved.every((event) => event.deliveryStatus === "sent" && event.messageIds[0] === "1300000000000000001" && event.sentAt),
        "sent events record their Discord message id",
    );

    const again = capture();

    await deliverPending(runtime(state, again.deliverer));

    assert(again.sent.length === 0, "a sent alert is never sent again");

    /* Failure and recovery */
    const failing = newTarget();
    const failingState = world();

    await add(failing);
    await checkNow(failing, runtime(failingState));

    failingState.kevListed = true;

    await checkNow(failing, runtime(failingState));

    const broken = capture([{ status: "failed", error: "503 Service Unavailable", sentBeforeError: false }]);

    await deliverPending(runtime(failingState, broken.deliverer));

    saved = await events(failing);

    assert(
        saved.every((event) => event.deliveryStatus === "pending" && event.attempts === 1 && event.lastError?.includes("503") && event.nextAttemptAt),
        "a failed send stays pending with a backoff",
    );

    const tooSoon = capture();

    await deliverPending(runtime(failingState, tooSoon.deliverer));

    assert(tooSoon.sent.length === 0, "a retry waits for its backoff");

    await db.query("UPDATE public.watch_events SET next_attempt_at = now() WHERE target = $1", [failing]);

    const fixed = capture();

    await deliverPending(runtime(failingState, fixed.deliverer));

    assert(
        fixed.sent.length === 1 && (await events(failing)).every((event) => event.deliveryStatus === "sent"),
        "a failed alert is delivered once the channel recovers",
    );

    /* Exhausted attempts: kept as failed, and requeueable. */
    const exhausted = newTarget();
    const exhaustedState = world();

    await add(exhausted);
    await checkNow(exhausted, runtime(exhaustedState));

    exhaustedState.kevListed = true;

    await checkNow(exhausted, runtime(exhaustedState));

    const dead = capture([{ status: "failed", error: "401: Unauthorized", sentBeforeError: false }]);

    for (let attempt = 0; attempt < 8; attempt += 1) {
        await db.query("UPDATE public.watch_events SET next_attempt_at = now() WHERE target = $1 AND delivery_status = 'pending'", [exhausted]);
        await deliverPending(runtime(exhaustedState, dead.deliverer));
    }

    assert(dead.sent.length === 6, `delivery stops after 6 attempts: ${dead.sent.length}`);
    assert((await events(exhausted)).every((event) => event.deliveryStatus === "failed"), "an exhausted alert is kept as failed");

    assert((await store.requeueFailed(exhausted)) > 0, "failed alerts can be requeued");

    const requeued = capture();

    await deliverPending(runtime(exhaustedState, requeued.deliverer));

    assert(requeued.sent.length === 1, "a requeued alert is delivered");

    console.log("✓ Deliveries record message ids, retry with backoff, and recover from failures");
}

async function testDuplicateSafety(): Promise<void> {
    /* A crash mid-send: the alert may have reached Discord. */
    const target = newTarget();
    const state = world();

    await add(target);
    await checkNow(target, runtime(state));

    state.kevListed = true;

    await checkNow(target, runtime(state));

    const claimed = await store.claimDeliveries("crashed-worker", 60, 50);

    assert(claimed.some((event) => event.target === target), "fixture: the crashed worker claims the alert");

    await db.query(
        "UPDATE public.watch_events SET lease_expires_at = now() - interval '1 second' WHERE target = $1",
        [target],
    );

    const resumed = capture();

    await deliverPending(runtime(state, resumed.deliverer, "worker-b"));

    const saved = await events(target);

    assert(resumed.sent.length === 1, "an interrupted send is resumed by another worker");
    assert(
        resumed.sent[0].includes("may repeat an earlier delivery") &&
        saved.every((event) => event.possibleDuplicate && event.deliveryStatus === "sent"),
        "a resumed send is labelled as a possible repeat",
    );

    /* A failure after Discord may have accepted it is labelled too. */
    const partial = newTarget();
    const partialState = world();

    await add(partial);
    await checkNow(partial, runtime(partialState));

    partialState.kevListed = true;

    await checkNow(partial, runtime(partialState));
    await deliverPending(runtime(partialState, capture([{ status: "failed", error: "socket closed", sentBeforeError: true }]).deliverer));

    assert(
        (await events(partial)).every((event) => event.possibleDuplicate),
        "a failure after a possible send is remembered for the retry",
    );

    /* Fallback mode: once OpenClaw's queue holds an alert, we never send it again. */
    const handover = newTarget();
    const handoverState = world();

    await add(handover);
    await checkNow(handover, runtime(handoverState));

    handoverState.kevListed = true;

    await checkNow(handover, runtime(handoverState));

    const queued = capture([{ status: "handed_off", note: "OpenClaw's delivery queue now owns retries" }]);

    await deliverPending(runtime(handoverState, queued.deliverer));

    assert(
        (await events(handover)).every((event) => event.deliveryStatus === "handed_off"),
        "an alert handed to OpenClaw is recorded as handed off",
    );

    for (let round = 0; round < 3; round += 1) {
        await db.query("UPDATE public.watch_events SET next_attempt_at = now() WHERE target = $1", [handover]);
    }

    const afterHandover = capture();

    await deliverPending(runtime(handoverState, afterHandover.deliverer));

    assert(afterHandover.sent.length === 0, "our outbox must never resend an alert OpenClaw owns");
    assert((await store.requeueFailed(handover)) === 0, "a handed-off alert cannot be requeued into a second retry system");

    console.log("✓ Interrupted sends are labelled, and one alert never has two retry owners");
}

async function testSchedulerRecovery(): Promise<void> {
    /* A due watch, left mid-check by a crashed gateway, is picked up after restart. */
    const target = newTarget();
    const state = world();

    await add(target);
    await checkNow(target, runtime(state));

    await db.query(
        `UPDATE public.watchlist
         SET next_check_at = now() - interval '2 hours',
             lease_owner = 'gateway-that-crashed',
             lease_expires_at = now() - interval '1 minute'
         WHERE target = $1`,
        [target],
    );

    state.kevListed = true;

    const processed = await runDueChecks(runtime(state, null, "gateway-after-restart"));
    const entry = await store.getWatch(target);

    assert(processed >= 1 && entry?.leaseOwner === null && entry.lastOutcome === "changes_detected", "an overdue watch is processed after a restart");
    assert((await events(target)).some((event) => event.field === "kevStatus"), "the change made while down is detected");

    /* Overlapping cycles in one process run once. */
    const overlap = newTarget();
    const overlapState = world();

    await add(overlap);
    await checkNow(overlap, runtime(overlapState));
    await makeDue(overlap);

    const service = createWatchService(
        { enabled: true, notifyTarget: null, tickMinutes: 60, requestTimeoutMs: 1000 },
        () => null,
        { owner: "service-a", check: runtime(overlapState).check },
    );

    const callsBefore = overlapState.calls;

    await Promise.all([service.tick(), service.tick(), service.tick()]);

    assert(overlapState.calls - callsBefore === 1, `overlapping cycles must check once: ${overlapState.calls - callsBefore}`);

    /* Two gateways at once still check a CVE once. */
    const shared = newTarget();
    const sharedState = world();

    await add(shared);
    await checkNow(shared, runtime(sharedState));
    await makeDue(shared);

    const callsBeforeShared = sharedState.calls;

    await Promise.all([
        runDueChecks(runtime(sharedState, null, "gateway-1")),
        runDueChecks(runtime(sharedState, null, "gateway-2")),
    ]);

    assert(sharedState.calls - callsBeforeShared === 1, "two processes must not check the same CVE twice");

    /*
     * A slow cycle: gateway-1 claims two CVEs, but its first check outlasts the
     * second CVE's lease, and gateway-2 claims that CVE meanwhile. gateway-1 must
     * then skip it instead of checking it a second time.
     */
    const first = newTarget();
    const second = newTarget();
    const slowState = world();

    for (const target of [first, second]) {
        await add(target);
        await checkNow(target, runtime(slowState));
    }

    await db.query("UPDATE public.watchlist SET next_check_at = now() - interval '10 years' WHERE target = $1", [first]);
    await db.query("UPDATE public.watchlist SET next_check_at = now() - interval '9 years' WHERE target = $1", [second]);

    const checked: string[] = [];
    const slowInvestigator = investigator(slowState);

    const slowRuntime: WatchRuntime = {
        owner: "gateway-1",
        check: defaultCheckDependencies(
            async (target) => {
                checked.push(target);

                if (target === first) {
                    await db.query("UPDATE public.watchlist SET lease_expires_at = now() - interval '1 second' WHERE target = $1", [second]);
                    assert(await store.claimWatch(second, "gateway-2", 900), "gateway-2 should take the expired lease");
                }

                return slowInvestigator(target);
            },
            persistInvestigation,
            store.insertEvents,
        ),
        deliverer: null,
        pauseMs: 0,
    };

    await runDueChecks(slowRuntime);

    assert(checked.includes(first), "the first CVE is checked");
    assert(!checked.includes(second), "a CVE whose lease another worker took must be skipped, not checked twice");
    assert((await store.getWatch(second))?.leaseOwner === "gateway-2", "the other worker keeps its lease");

    await db.query("UPDATE public.watchlist SET lease_owner = NULL, lease_expires_at = NULL, next_check_at = now() + interval '1 day' WHERE target = $1", [second]);

    /* Disabled monitoring never runs. */
    const idle = createWatchService(
        { enabled: false, notifyTarget: null, tickMinutes: 1, requestTimeoutMs: 1000 },
        () => null,
        { owner: "idle", check: runtime(world()).check },
    );

    await idle.start({});
    await idle.stop();

    console.log("✓ Scheduling recovers overdue checks after a restart and never overlaps");
}

async function main(): Promise<void> {
    const realFetch = globalThis.fetch;

    globalThis.fetch = (async () => {
        throw new Error("watch tests must not use the network");
    }) as typeof fetch;

    try {
        await testWatchlistStorage();
        await testLeases();
        await testChangeDetection();
        await testSuppression();
        await testMonitorHealth();
        await testDelivery();
        await testDuplicateSafety();
        await testSchedulerRecovery();

        console.log("Watch persistence tests PASSED");
    } finally {
        globalThis.fetch = realFetch;

        await db.query("DELETE FROM public.watch_events WHERE target = ANY($1::text[])", [targets]);
        await db.query("DELETE FROM public.watchlist WHERE target = ANY($1::text[])", [targets]);
        await db.query("DELETE FROM public.investigations WHERE target = ANY($1::text[])", [targets]);
        await db.end();
    }
}

main().catch((error: unknown) => {
    console.error("Watch persistence tests FAILED");
    console.error(error);
    process.exitCode = 1;
});
