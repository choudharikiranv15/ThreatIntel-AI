import { randomUUID } from "node:crypto";

import type { Indicator } from "../lookup/indicator.js";
import { runLookup, summarise, type LookupDeps, type LookupPayload, type LookupSettings } from "../lookup/lookup.js";
import { SOURCE_NAMES, type SourceResult } from "../lookup/sources.js";
import * as lookupStore from "../lookup/store.js";
import { extractIndicators, MAX_TRIAGE_INPUT, type Extraction } from "./extract.js";

/*
 * Alert triage: every indicator in a pasted alert, checked within the same
 * caches, budgets, and limits as single lookups, and ranked by what the
 * services said, never by the model. The whole triage counts as one lookup
 * against the per-person hourly limit.
 */

export type TriageSettings = {
    lookup: LookupSettings;
    maxIndicators: number;
    infrastructure: string[];
};

/** flagged: a service reports it. weak: only low-confidence signals. quiet: answered, no reports. unchecked: nothing answered. */
export type Tier = "flagged" | "weak" | "quiet" | "unchecked";

export type TriageEntry = {
    indicator: string;
    type: Indicator["type"];
    tier: Tier;
    statement: string;
    /** Records an analyst can open, for the services that have one. */
    records: { source: string; url: string }[];
};

export type TriagePayload = {
    kind: "triage";
    found: { checked: number; internal: number; skippedInfrastructure: string[]; overCap: string[] };
    lookFirst: string[];
    results: TriageEntry[];
    notes: string[];
};

export type TriageRejection = { error: "invalid_input" | "no_indicators" | "rate_limited"; message: string };

const TIER_ORDER: Record<Tier, number> = { flagged: 0, weak: 1, quiet: 2, unchecked: 3 };
const CONCURRENCY = 4;
const STATEMENT_LIMIT = 320;

const NOTES = [
    "Ranked by what the services reported, flagged first; the ranking is not a verdict.",
    "No reports is not proof an indicator is safe. Indicators under 'unchecked' were not answered by any service.",
    "VirusTotal is asked about file hashes, URLs, and indicators another service flagged, within its per-minute limit; ask about any other indicator on its own for a VirusTotal check.",
    "Internal and private values were kept on the gateway and not sent anywhere.",
];

function tierOf(lookup: LookupPayload): Tier {
    const answered = lookup.sources.some((s) => s.status === "success" || s.status === "observed_absence");

    if (lookup.summary.threatReports.length > 0) return "flagged";
    if (lookup.summary.lowConfidence.length > 0) return "weak";
    return answered ? "quiet" : "unchecked";
}

async function inBatches<T, R>(items: T[], size: number, work: (item: T) => Promise<R>): Promise<R[]> {
    const out: R[] = [];

    for (let i = 0; i < items.length; i += size) {
        out.push(...(await Promise.all(items.slice(i, i + size).map(work))));
    }

    return out;
}

/** Merges the two stages of one indicator into a single lookup, re-summarised. */
function merge(first: LookupPayload, second: LookupPayload | null): LookupPayload {
    if (!second) return first;

    const sources: SourceResult[] = [...first.sources, ...second.sources];

    return { ...first, sources, summary: summarise(sources), notes: first.notes };
}

export async function runTriage(
    raw: unknown,
    requestedBy: string,
    settings: TriageSettings,
    deps: LookupDeps = {},
): Promise<{ payload: TriagePayload; lookups: LookupPayload[] } | TriageRejection> {
    if (typeof raw !== "string" || raw.trim().length === 0) {
        return { error: "invalid_input", message: "Paste the alert, log lines, or email to triage." };
    }

    if (raw.length > MAX_TRIAGE_INPUT) {
        return { error: "invalid_input", message: `Triage takes up to ${MAX_TRIAGE_INPUT / 1000}k characters; paste the relevant part of the alert.` };
    }

    const extraction: Extraction = extractIndicators(raw, { maxIndicators: settings.maxIndicators, infrastructure: settings.infrastructure });

    if (extraction.indicators.length === 0) {
        return {
            error: "no_indicators",
            message: extraction.internal > 0
                ? `Only internal or private values were found (${extraction.internal}); they are not sent anywhere.`
                : "No public IP addresses, domains, URLs, or file hashes were found in the text.",
        };
    }

    if ((await (deps.store ?? lookupStore).lookupsLastHour(requestedBy)) >= settings.lookup.perUserPerHour) {
        return { error: "rate_limited", message: `Lookup limit reached (${settings.lookup.perUserPerHour} per hour). Try again later.` };
    }

    const lookupId = randomUUID();
    const run = (indicator: Indicator, sources: LookupSettings["sources"]) =>
        runLookup(indicator.value, requestedBy, settings.lookup, deps, { lookupId, checkUserLimit: false, sources });

    /* Stage 1: every enabled service except VirusTotal. */
    const free = settings.lookup.sources.filter((s) => s !== "virustotal");
    const firstStage = await inBatches(extraction.indicators, CONCURRENCY, async (indicator) => {
        const result = await run(indicator, free);

        return "error" in result ? null : result;
    });

    /* Stage 2: VirusTotal, in priority order: hashes, URLs, then anything flagged above. */
    const vtEnabled = settings.lookup.sources.includes("virustotal");
    const wantsVt = (indicator: Indicator, first: LookupPayload | null) =>
        indicator.type === "md5" || indicator.type === "sha1" || indicator.type === "sha256" || indicator.type === "url" ||
        Boolean(first && (first.summary.threatReports.length > 0 || first.summary.lowConfidence.length > 0));
    const vtOrder = extraction.indicators
        .map((indicator, i) => ({ indicator, i }))
        .filter(({ indicator, i }) => vtEnabled && wantsVt(indicator, firstStage[i]));
    const secondStage = new Map<number, LookupPayload>();

    for (const { indicator, i } of vtOrder) {
        const result = await run(indicator, ["virustotal"]);

        if (!("error" in result)) secondStage.set(i, result);
    }

    const lookups: LookupPayload[] = [];
    const results: TriageEntry[] = [];

    extraction.indicators.forEach((indicator, i) => {
        const first = firstStage[i];
        const second = secondStage.get(i) ?? null;
        const lookup = first ? merge(first, second) : second;

        if (!lookup) {
            results.push({ indicator: indicator.value, type: indicator.type, tier: "unchecked", statement: "Not checked.", records: [] });
            return;
        }

        lookups.push(lookup);
        results.push({
            indicator: lookup.indicator,
            type: lookup.type,
            tier: tierOf(lookup),
            statement: lookup.summary.statement.slice(0, STATEMENT_LIMIT),
            records: lookup.sources
                .filter((s) => s.status === "success" && s.reference)
                .map((s) => ({ source: SOURCE_NAMES[s.source], url: s.reference as string })),
        });
    });

    const flaggedBy = (entry: TriageEntry) => lookups.find((l) => l.indicator === entry.indicator)?.summary.threatReports.length ?? 0;

    results.sort((a, b) => TIER_ORDER[a.tier] - TIER_ORDER[b.tier] || flaggedBy(b) - flaggedBy(a));

    return {
        payload: {
            kind: "triage",
            found: {
                checked: extraction.indicators.length,
                internal: extraction.internal,
                skippedInfrastructure: extraction.infrastructure,
                overCap: extraction.overCap.slice(0, 20),
            },
            lookFirst: results.filter((r) => r.tier === "flagged").map((r) => r.indicator),
            results,
            notes: [
                ...NOTES,
                ...(extraction.overCap.length ? [`${extraction.overCap.length} more indicators were found than the ${settings.maxIndicators} checked; paste them separately to check them.`] : []),
            ],
        },
        lookups,
    };
}
