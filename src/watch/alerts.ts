import { createHash } from "node:crypto";

import type {
    InvestigationChange,
    InvestigationComparison,
} from "../persistence/investigation-diff.js";
import type { InvestigationResult } from "../types.js";

/*
 * Decides which Phase 4 comparison results deserve a notification. This is a
 * filter over the existing comparison, not a second change-detection engine.
 */

export type CandidateEvent = {
    kind: "intelligence_change" | "integrity_warning" | "baseline_reset";
    field: string | null;
    scope: string | null;
    before: unknown;
    after: unknown;
    explanation: string;
    sources: string[];
    deliverable: boolean;
};

/** NVD and CISA KEV must both have answered for a check to count. */
export function coreChecksComplete(result: InvestigationResult): boolean {
    const completed = (provider: string) =>
        result.providerResults.some(
            (item) =>
                item.provider === provider &&
                (item.status === "success" || item.status === "observed_absence"),
        );

    return completed("NVD") && completed("CISA_KEV");
}

/** Every provider the check asked answered, so the result can be a baseline. */
export function allChecksComplete(result: InvestigationResult): boolean {
    return result.providerResults.every(
        (item) => item.status === "success" || item.status === "observed_absence",
    );
}

const VENDOR_ALERT_STATUSES = new Set(["affected", "fixed"]);

/* Which intelligence changes are worth interrupting an analyst for. */
function alertExplanation(change: InvestigationChange): string | null {
    const { field, before, after } = change;

    switch (field) {
        case "kevStatus":
            if (before === "not-listed" && after === "listed") {
                return "CISA KEV now lists this CVE as known to be exploited.";
            }

            if (before === "listed" && after === "not-listed") {
                return "CISA KEV no longer lists this CVE. Check the catalog before treating exploitation as resolved.";
            }

            // Anything involving "unknown" is about availability, not exploitation.
            return null;

        case "cvss.baseScore":
            return "The CVSS base score changed.";

        case "cvss.vector":
            return "The CVSS vector changed, so the scoring authority assessed the vulnerability differently.";

        case "affectedVersions":
            return "NVD changed the affected products or version ranges.";

        case "packageFixes":
            return Array.isArray(after) && after.length > 0
                ? "A reviewed OSV advisory lists new fixed versions."
                : null;

        case "vendorImpact":
            if (typeof after === "string" && VENDOR_ALERT_STATUSES.has(after)) {
                return `Red Hat now reports this product as ${after}.`;
            }

            if (before === "affected" && after === "not_affected") {
                return "Red Hat now reports this product as not affected.";
            }

            // A move to unknown, or a row disappearing, is not actionable.
            return null;

        default:
            // Conflicts and source revisions with nothing extracted stay in the
            // comparison history without interrupting anyone.
            return null;
    }
}

export type AlertDecision = {
    /** Why nothing, or something, was raised. Stored on the watch row. */
    outcome:
    | "changes_detected"
    | "no_change"
    | "core_incomplete"
    | "baseline_reset"
    | "integrity_warning";
    events: CandidateEvent[];

    /** Whether this check's result may become the next baseline. */
    mayAdvanceBaseline: boolean;
};

/**
 * Applies the suppression rules, in order:
 * 1. No alerts unless NVD and KEV both answered; the baseline stays put.
 * 2. A baseline that fails integrity raises one warning and is replaced.
 * 3. A baseline from another engine version is replaced silently.
 * 4. Only intelligence changes can alert, and only those listed above.
 */
export function decideAlerts(
    comparison: InvestigationComparison,
    current: InvestigationResult,
): AlertDecision {
    if (!coreChecksComplete(current)) {
        return { outcome: "core_incomplete", events: [], mayAdvanceBaseline: false };
    }

    const { integrity } = comparison.baseline;

    const damaged =
        integrity.evidenceRows === "tampered" ||
        integrity.evidenceRows === "missing" ||
        integrity.evidenceRows === "inconsistent" ||
        integrity.recordConsistency === "inconsistent";

    if (damaged) {
        return {
            outcome: "integrity_warning",
            mayAdvanceBaseline: true,
            events: [{
                kind: "integrity_warning",
                field: "baseline",
                scope: comparison.baseline.investigationId,
                before: integrity,
                after: null,
                explanation:
                    "The stored baseline failed its integrity check, so changes could not be determined. Monitoring restarted from a fresh baseline; review the stored investigation.",
                sources: [],
                deliverable: true,
            }],
        };
    }

    if (!integrity.fullyVerified) {
        // Usually an engine upgrade: the old baseline cannot be vouched for, but
        // nothing is wrong with it, so this is recorded without an alert.
        return {
            outcome: "baseline_reset",
            mayAdvanceBaseline: true,
            events: [{
                kind: "baseline_reset",
                field: "baseline",
                scope: comparison.baseline.investigationId,
                before: {
                    recordedEngineVersion: comparison.baseline.recordedEngineVersion,
                    integrity,
                },
                after: { engineVersion: comparison.baseline.rederivedWithEngineVersion },
                explanation:
                    "The baseline could not be fully verified, usually because it was saved by another engine version, so monitoring restarted from a fresh baseline without alerting.",
                sources: [],
                deliverable: false,
            }],
        };
    }

    // A null here means the comparison itself could not be relied on.
    if (comparison.noIntelligenceChange !== false) {
        return {
            outcome: "no_change",
            events: [],
            mayAdvanceBaseline: comparison.noIntelligenceChange === true,
        };
    }

    const events: CandidateEvent[] = [];

    for (const change of comparison.changes) {
        if (change.category !== "intelligence_change") {
            continue;
        }

        const explanation = alertExplanation(change);

        if (!explanation) {
            continue;
        }

        events.push({
            kind: "intelligence_change",
            field: change.field,
            scope: change.scope ?? null,
            before: change.before,
            after: change.after,
            explanation,
            sources: change.sources,
            deliverable: true,
        });
    }

    return {
        outcome: events.length > 0 ? "changes_detected" : "no_change",
        events,
        mayAdvanceBaseline: true,
    };
}

/**
 * One observation of one change. The baseline is part of it: a retried check
 * compares against the same baseline, so its events are not stored twice, but
 * a value that changes back and then changes again is compared against a newer
 * baseline and is a new observation. Health events, which have no baseline,
 * pass null and are scoped by their failure episode instead.
 */
export function fingerprint(
    target: string,
    event: Pick<CandidateEvent, "kind" | "field" | "scope" | "before" | "after">,
    baselineInvestigationId: string | null,
): string {
    return createHash("sha256")
        .update(
            JSON.stringify([
                target,
                baselineInvestigationId,
                event.kind,
                event.field,
                event.scope,
                event.before ?? null,
                event.after ?? null,
            ]),
        )
        .digest("hex");
}
