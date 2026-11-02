import type { InvestigationView } from "../tool-result.js";
import { verifyCvssClaim, verifyKevClaim } from "./verify-claim.js";

/*
 * Deterministic check of the LLM's final answer against the investigation
 * results it was given. It only grades concrete, checkable claims (CVE ids,
 * CVSS score, severity, KEV state, version numbers). It is a floor against
 * fabrication, not a proof that the reasoning is correct.
 */

const CVE_PATTERN = /\bCVE-\d{4}-\d{4,}\b/gi;

const CVSS_SCORE_PATTERN =
    /\b(?:cvss|base\s+score)\b[^a-z0-9]*(?:(?:base\s+)?score\b)?[^a-z0-9]*(?:(?:of|is|was)\b)?[^a-z0-9]*(\d{1,2}(?:\.\d+)?)(?!\d|\.\d)/gi;

const SEVERITY_PATTERN =
    /\bseverity\b[^a-z0-9]*(?:(?:is|of|rating|level)\b[^a-z0-9]*)*(critical|high|medium|low)\b/i;

const VERSION_CONTEXT_PATTERN =
    /\b(?:affected|vulnerable|fixed|patched|versions?|upgrade|update\s+to)\b/i;

const VERSION_PATTERN = /\b\d+\.\d+\.\d+(?:\.\d+)*\b/g;

const KEV_PATTERN = /\bkev\b|known exploited vulnerabilit/i;

const KEV_UNCERTAIN_PATTERN =
    /\b(?:if|whether|would|unknown|unavailable|could\s+not|cannot)\b/i;

const KEV_NEGATIVE_PATTERN =
    /\b(?:not|isn't|aren't|wasn't|absent|absence|no)\b/i;

const KEV_POSITIVE_PATTERN =
    /\b(?:listed|included|added|present|appears)\b/i;

function findCves(text: string): string[] {
    return Array.from(
        new Set(
            (text.match(CVE_PATTERN) ?? []).map((id) => id.toUpperCase()),
        ),
    );
}

/* Version numbers and vector strings must not be mistaken for scores. */
function withoutCvssVersions(text: string): string {
    return text
        .replace(/CVSS:\d\.\d\/\S+/gi, " ")
        .replace(/\bversion\s+\d(?:\.\d)?\b/gi, " ")
        .replace(/\bv\s*\d(?:\.\d)?\b/gi, " ")
        .replace(/\bcvss\s+(?:2\.0|3\.0|3\.1|4\.0)\b/gi, "cvss");
}

function kevClaim(segment: string): boolean | null {
    if (
        !KEV_PATTERN.test(segment) ||
        KEV_UNCERTAIN_PATTERN.test(segment)
    ) {
        return null;
    }

    if (KEV_NEGATIVE_PATTERN.test(segment)) {
        return false;
    }

    return KEV_POSITIVE_PATTERN.test(segment) ? true : null;
}

function checkSegment(
    segment: string,
    view: InvestigationView,
    findings: Set<string>,
): void {
    const { target, summary, facts } = view;
    const factProvenance = facts;
    const text = withoutCvssVersions(segment);

    for (const match of text.matchAll(CVSS_SCORE_PATTERN)) {
        const baseScore = Number(match[1]);

        if (baseScore > 10) {
            continue;
        }

        const { state } = verifyCvssClaim({
            claim: { baseScore },
            observed: summary.cvss,
            factProvenance,
        });

        // Reporting another source's score from a known conflict is accurate.
        const reportedConflict = summary.conflicts.some((conflict) =>
            conflict.values.some((item) => item.value === baseScore),
        );

        if (state !== "confirmed" && !reportedConflict) {
            findings.add(
                `${target}: the answer states CVSS base score ${baseScore}, but the evidence shows ${summary.cvss.baseScore ?? "no score"}.`,
            );
        }
    }

    // Red Hat publishes its own severity scale, separate from CVSS.
    const severity = /red\s*hat/i.test(segment)
        ? null
        : text.match(SEVERITY_PATTERN)?.[1];

    if (severity) {
        const { state } = verifyCvssClaim({
            claim: { severity },
            observed: summary.cvss,
            factProvenance,
        });

        if (state !== "confirmed") {
            findings.add(
                `${target}: the answer states severity ${severity.toUpperCase()}, but the evidence shows ${summary.cvss.severity ?? "no severity"}.`,
            );
        }
    }

    const listed = kevClaim(segment);

    if (listed !== null) {
        const { state } = verifyKevClaim({
            claim: { listed },
            observed: summary.kevStatus,
            factProvenance,
        });

        if (state !== "confirmed") {
            findings.add(
                `${target}: the answer states CISA KEV ${listed ? "listed" : "not listed"}, but the evidence shows ${summary.kevStatus}.`,
            );
        }
    }
}

export function checkAnswer(
    answer: string,
    views: InvestigationView[],
): string[] {
    const viewsByTarget = new Map(
        views.map((view) => [view.target.toUpperCase(), view]),
    );

    const answerCves = findCves(answer);

    const relevant = answerCves.filter((id) => viewsByTarget.has(id));

    // An answer about nothing we investigated is outside this gate's scope.
    if (relevant.length === 0) {
        return [];
    }

    const findings = new Set<string>();

    const evidenceText = JSON.stringify(views).toUpperCase();

    for (const id of answerCves) {
        if (!evidenceText.includes(id)) {
            findings.add(
                `${id} is mentioned in the answer but does not appear in any retrieved evidence.`,
            );
        }
    }

    for (const segment of answer.split(/\n|(?<=[.!?;])\s+/)) {
        for (const version of segment.match(VERSION_PATTERN) ?? []) {
            if (
                VERSION_CONTEXT_PATTERN.test(segment) &&
                !evidenceText.includes(version)
            ) {
                findings.add(
                    `Version ${version} is stated in the answer but does not appear in the retrieved evidence.`,
                );
            }
        }

        // Claims are attributed to the CVE named in the segment. With several
        // investigated CVEs and none named, attribution would be a guess.
        const segmentCves = findCves(segment);

        const owner =
            segmentCves.length === 1
                ? segmentCves[0]
                : segmentCves.length === 0 && relevant.length === 1
                    ? relevant[0]
                    : null;

        const view = owner ? viewsByTarget.get(owner) : undefined;

        if (view) {
            checkSegment(segment, view, findings);
        }
    }

    return Array.from(findings);
}
