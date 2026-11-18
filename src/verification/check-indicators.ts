import { refang } from "../lookup/indicator.js";
import type { LookupPayload } from "../lookup/lookup.js";
import type { LookupSourceId, SourceResult } from "../lookup/sources.js";

/*
 * Checks what an answer says about looked-up indicators against the lookup
 * results from the same session. Deterministic and narrow: it catches the
 * mistakes that mislead an analyst, not every phrasing.
 */

const SOURCE_PATTERNS: Record<LookupSourceId, RegExp> = {
    abuseipdb: /\babuse ?ipdb\b/i,
    greynoise: /\bgrey ?noise\b/i,
    internetdb: /\b(shodan|internetdb)\b/i,
    otx: /\b(otx|alien ?vault)\b/i,
};

const SAFE_CLAIM = /\b(is|are|appears?(?: to be)?|looks?|seems?|considered)\s+(safe|clean|benign|harmless|legitimate|trustworthy|not malicious)\b/i;
// Segments are already single sentences, so the gap may include an indicator's own dots.
const NEGATED_SAFE = /\b(not|never|cannot|can't|isn't|aren't|no proof|not proof|doesn't mean|does not mean|nor)\b[^\n!?]{0,60}\b(safe|clean|benign|harmless|legitimate|trustworthy)\b/i;
const RESULT_WORDS = /\b(score|scores|scored|reported|reports?|flagged|listed|clean|confidence|classified|malicious|pulses?|no record|not found|found)\b/i;
const NOT_CHECKED_WORDS = /\b(not checked|wasn't checked|was not checked|not configured|no api key|unavailable|could not|couldn't|not queried|was not queried|budget|rate.?limit|timed out|skipped)\b/i;

function segments(answer: string): string[] {
    return answer.split(/\n|(?<=[.!?;])\s+/).filter((segment) => segment.trim().length > 0);
}

function sourceOf(lookup: LookupPayload, source: LookupSourceId): SourceResult | undefined {
    return lookup.sources.find((result) => result.source === source);
}

const answered = (result: SourceResult | undefined) => result && (result.status === "success" || result.status === "observed_absence");

export function checkIndicatorAnswer(answer: string, lookups: LookupPayload[]): string[] {
    if (lookups.length === 0) {
        return [];
    }

    const findings = new Set<string>();

    for (const raw of segments(answer)) {
        // Answers quote indicators defanged as often as plain.
        const segment = refang(raw).replace(/\[\.\]/g, ".");
        const lower = segment.toLowerCase();
        const named = lookups.filter((lookup) => lower.includes(lookup.indicator.toLowerCase()));
        const lookup = named.length === 1 ? named[0] : named.length === 0 && lookups.length === 1 ? lookups[0] : undefined;

        if (!lookup) {
            continue;
        }

        const label = lookup.indicator;

        /* 1. "Safe" from absence. */
        if (SAFE_CLAIM.test(segment) && !NEGATED_SAFE.test(segment) && lookup.summary.knownBenign.length === 0) {
            findings.add(
                `${label}: the answer calls it safe or clean, but the lookup only found no reports, which is not proof of safety. Say "no reports" instead.`,
            );
        }

        for (const source of Object.keys(SOURCE_PATTERNS) as LookupSourceId[]) {
            if (!SOURCE_PATTERNS[source].test(segment)) {
                continue;
            }

            const result = sourceOf(lookup, source);

            /* 2. A result described for a service that was not checked. */
            if (!answered(result)) {
                if (RESULT_WORDS.test(segment) && !NOT_CHECKED_WORDS.test(segment)) {
                    findings.add(
                        `${label}: the answer describes a ${source} result, but ${source} was not checked (${result?.status ?? "not queried"}).`,
                    );
                }
                continue;
            }

            const facts = (result?.facts ?? {}) as Record<string, unknown>;

            /* 3. AbuseIPDB score and report count. */
            if (source === "abuseipdb") {
                const score = segment.match(/confidence[^0-9%]{0,30}(\d{1,3})\s*%?|(\d{1,3})\s*%\s*(?:abuse|confidence)/i);
                const quoted = score ? Number(score[1] ?? score[2]) : null;

                if (quoted !== null && quoted !== Number(facts.abuseConfidenceScore ?? 0)) {
                    findings.add(`${label}: the answer gives an AbuseIPDB confidence of ${quoted}%, but the lookup returned ${facts.abuseConfidenceScore ?? 0}%.`);
                }

                const reports = segment.match(/(\d[\d,]*)\s+(?:abuse\s+)?reports?\b/i);

                if (reports && !SOURCE_PATTERNS.otx.test(segment)) {
                    const count = Number(reports[1].replace(/,/g, ""));

                    if (count !== Number(facts.totalReports ?? 0)) {
                        findings.add(`${label}: the answer gives ${count} AbuseIPDB reports, but the lookup returned ${facts.totalReports ?? 0}.`);
                    }
                }
            }

            /* 4. OTX report count. */
            if (source === "otx" && !SOURCE_PATTERNS.abuseipdb.test(segment)) {
                const pulses = segment.match(/(\d[\d,]*)\s+(?:otx\s+|community\s+)?(?:pulses?|reports?)\b/i);

                if (pulses) {
                    const count = Number(pulses[1].replace(/,/g, ""));

                    if (count !== Number(facts.pulseCount ?? 0)) {
                        findings.add(`${label}: the answer gives ${count} OTX reports, but the lookup returned ${facts.pulseCount ?? 0}.`);
                    }
                }
            }
        }
    }

    return Array.from(findings);
}

/** A lookup result as the tool returns it, or null. */
export function extractLookup(payload: unknown): LookupPayload | null {
    const candidate = payload as Partial<LookupPayload> | null;

    return typeof candidate?.indicator === "string" && Array.isArray(candidate.sources) && typeof candidate.summary?.statement === "string"
        ? (candidate as LookupPayload)
        : null;
}
