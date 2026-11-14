import { randomUUID } from "node:crypto";

import { hashPayload } from "../persistence/evidence-hash.js";
import {
    compareWithBaseline,
    type InvestigationComparison,
} from "../persistence/investigation-diff.js";
import {
    getInvestigationContext,
    type InvestigationContext,
} from "../persistence/investigation-context.js";
import type { InvestigationResult } from "../types.js";
import { ENGINE_VERSION } from "../version.js";
import {
    allChecksComplete,
    coreChecksComplete,
    decideAlerts,
    fingerprint,
    type CandidateEvent,
} from "./alerts.js";
import type { NewWatchEvent, WatchEntry, WatchEvent } from "./store.js";

/*
 * One check of one watched CVE. Every dependency is injected so the same code
 * runs in the gateway and in tests; nothing here keeps state between checks.
 */

export type CheckDependencies = {
    investigate: (target: string) => Promise<InvestigationResult>;
    persist: (result: InvestigationResult) => Promise<string>;
    loadContext: (investigationId: string) => Promise<InvestigationContext | null>;
    compare: (
        baseline: InvestigationContext,
        current: InvestigationResult,
    ) => Promise<InvestigationComparison>;
    insertEvents: (events: NewWatchEvent[]) => Promise<WatchEvent[]>;
};

export const defaultCheckDependencies = (
    investigate: CheckDependencies["investigate"],
    persist: CheckDependencies["persist"],
    insertEvents: CheckDependencies["insertEvents"],
): CheckDependencies => ({
    investigate,
    persist,
    loadContext: getInvestigationContext,
    compare: compareWithBaseline,
    insertEvents,
});

export type CheckOutcome =
    | {
        success: true;
        outcome: string;
        baselineInvestigationId: string | null;
        events: WatchEvent[];
        persistedInvestigationId: string | null;
    }
    | {
        success: false;
        outcome: string;
        error: string;
        events: WatchEvent[];
    };

/* Evidence and provider answers, ignoring when they were fetched. */
function evidenceSignature(
    providerResults: { provider: string; status: string }[],
    evidence: { source: string; facts: unknown }[],
): string {
    return hashPayload({
        providers: providerResults
            .map((item) => [item.provider, item.status])
            .sort(),
        evidence: evidence
            .map((item) => [item.source, hashPayload(item.facts)])
            .sort(),
    });
}

function sameEvidence(
    baseline: InvestigationContext,
    current: InvestigationResult,
): boolean {
    return (
        baseline.investigation.engineVersion === ENGINE_VERSION &&
        evidenceSignature(
            baseline.investigation.providerResults as { provider: string; status: string }[],
            baseline.evidence.map((item) => ({ source: item.source, facts: item.rawPayload })),
        ) ===
        evidenceSignature(current.providerResults, current.evidence)
    );
}

function toNewEvents(
    target: string,
    checkId: string,
    candidates: CandidateEvent[],
    baselineInvestigationId: string | null,
    investigationId: string | null,
): NewWatchEvent[] {
    return candidates.map((candidate) => ({
        target,
        checkId,
        kind: candidate.kind,
        fingerprint: fingerprint(target, candidate, baselineInvestigationId),
        field: candidate.field,
        scope: candidate.scope,
        before: candidate.before,
        after: candidate.after,
        explanation: candidate.explanation,
        sources: candidate.sources,
        baselineInvestigationId,
        investigationId,
        deliverable: candidate.deliverable,
    }));
}

function failure(outcome: string, error: string): CheckOutcome {
    return { success: false, outcome, error, events: [] };
}

export async function runWatchCheck(
    entry: WatchEntry,
    deps: CheckDependencies,
): Promise<CheckOutcome> {
    const checkId = randomUUID();
    let current: InvestigationResult;

    try {
        current = await deps.investigate(entry.target);
    } catch (error) {
        return failure("investigation_error", error instanceof Error ? error.message : String(error));
    }

    // Without both NVD and KEV, nothing can be concluded and the baseline must
    // not move: a provider outage is never treated as a change or an absence.
    if (!coreChecksComplete(current)) {
        const failed = current.providerResults
            .filter((item) => item.status === "error" || item.status === "timeout")
            .map((item) => `${item.provider} ${item.status}`)
            .join(", ");

        return failure("core_incomplete", `NVD or CISA KEV did not answer (${failed || current.status}).`);
    }

    const persistCurrent = async (): Promise<string> => deps.persist(current);

    /* First check: this result becomes the baseline. */
    if (!entry.baselineInvestigationId) {
        if (!allChecksComplete(current)) {
            return failure("baseline_incomplete", "A source did not answer, so no baseline was set yet.");
        }

        try {
            const id = await persistCurrent();

            return {
                success: true,
                outcome: "baseline_established",
                baselineInvestigationId: id,
                events: [],
                persistedInvestigationId: id,
            };
        } catch (error) {
            return failure("persist_error", error instanceof Error ? error.message : String(error));
        }
    }

    let baseline: InvestigationContext | null;

    try {
        baseline = await deps.loadContext(entry.baselineInvestigationId);
    } catch (error) {
        return failure("baseline_load_error", error instanceof Error ? error.message : String(error));
    }

    /* The baseline row is gone: warn once and start again from this result. */
    if (!baseline) {
        try {
            const id = await persistCurrent();

            const events = await deps.insertEvents(toNewEvents(entry.target, checkId, [{
                kind: "integrity_warning",
                field: "baseline",
                scope: entry.baselineInvestigationId,
                before: { baselineInvestigationId: entry.baselineInvestigationId },
                after: null,
                explanation:
                    "The stored baseline investigation no longer exists, so changes since it could not be determined. Monitoring restarted from a fresh baseline.",
                sources: [],
                deliverable: true,
            }], entry.baselineInvestigationId, id));

            return {
                success: true,
                outcome: "baseline_missing",
                baselineInvestigationId: id,
                events,
                persistedInvestigationId: id,
            };
        } catch (error) {
            return failure("persist_error", error instanceof Error ? error.message : String(error));
        }
    }

    let comparison: InvestigationComparison;

    try {
        comparison = await deps.compare(baseline, current);
    } catch (error) {
        return failure("comparison_error", error instanceof Error ? error.message : String(error));
    }

    const decision = decideAlerts(comparison, current);

    // Only a result where every source answered may replace the baseline; with
    // an enrichment source down, alerts still come from completed sources, and
    // dedupe stops them repeating on the next check.
    const advance =
        decision.mayAdvanceBaseline &&
        allChecksComplete(current) &&
        (decision.events.length > 0 || !sameEvidence(baseline, current));

    let persistedInvestigationId: string | null = null;

    if (advance) {
        try {
            persistedInvestigationId = await persistCurrent();
        } catch (error) {
            // Events are not recorded without the investigation they cite; the
            // next check will find the same change again.
            return failure("persist_error", error instanceof Error ? error.message : String(error));
        }
    }

    let events: WatchEvent[] = [];

    try {
        events = await deps.insertEvents(
            toNewEvents(
                entry.target,
                checkId,
                decision.events,
                entry.baselineInvestigationId,
                persistedInvestigationId,
            ),
        );
    } catch (error) {
        return failure("event_store_error", error instanceof Error ? error.message : String(error));
    }

    return {
        success: true,
        outcome: decision.outcome,
        baselineInvestigationId: persistedInvestigationId,
        events,
        persistedInvestigationId,
    };
}

export const FAILURE_ALERT_AFTER = 3;

/**
 * Monitoring's own health. After 3 failed checks in a row, one alert; when
 * checks succeed again, one recovery alert. Silence then means "nothing
 * changed", not "nothing is running".
 */
export function healthEvents(
    before: WatchEntry,
    after: WatchEntry,
    checkId: string,
): { events: NewWatchEvent[]; failureAlerted: boolean | null } {
    const base = {
        target: after.target,
        checkId,
        scope: null,
        sources: [],
        baselineInvestigationId: after.baselineInvestigationId,
        investigationId: null,
        deliverable: true,
    };

    if (
        !after.failureAlerted &&
        after.consecutiveFailures >= FAILURE_ALERT_AFTER
    ) {
        // One alert per failing episode, keyed by when the episode started.
        const episode = after.lastSuccessAt ?? after.createdAt;

        return {
            failureAlerted: true,
            events: [{
                ...base,
                kind: "monitor_failure",
                fingerprint: fingerprint(after.target, {
                    kind: "intelligence_change",
                    field: "monitor_failure",
                    scope: episode,
                    before: null,
                    after: null,
                }, null),
                field: "monitoring",
                before: { lastSuccessAt: after.lastSuccessAt },
                after: { consecutiveFailures: after.consecutiveFailures, lastError: after.lastError },
                explanation: `Monitoring has failed ${after.consecutiveFailures} checks in a row (${after.lastError ?? "unknown error"}). Changes cannot be detected until it recovers.`,
            }],
        };
    }

    if (before.failureAlerted && after.consecutiveFailures === 0) {
        return {
            failureAlerted: false,
            events: [{
                ...base,
                kind: "monitor_recovered",
                fingerprint: fingerprint(after.target, {
                    kind: "intelligence_change",
                    field: "monitor_recovered",
                    scope: after.lastSuccessAt,
                    before: null,
                    after: null,
                }, null),
                field: "monitoring",
                before: { consecutiveFailures: before.consecutiveFailures },
                after: { lastSuccessAt: after.lastSuccessAt },
                explanation: "Monitoring recovered and is checking again.",
            }],
        };
    }

    return { events: [], failureAlerted: null };
}
