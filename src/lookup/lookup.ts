import { randomUUID } from "node:crypto";

import { parseIndicator, type Indicator, type IndicatorRejection } from "./indicator.js";
import {
    COVERS,
    lookupSource,
    SOURCE_NAMES,
    type LookupOptions,
    type LookupSourceId,
    type SourceResult,
} from "./sources.js";
import * as store from "./store.js";
import { teamHistory, type TeamHistory } from "../memory/history.js";

/*
 * One indicator lookup: validate, enforce limits, reuse recent answers, query
 * the services in parallel, record everything, and summarise without judging
 * beyond what the services said.
 */

export type LookupSettings = {
    sources: LookupSourceId[];
    cacheHours: number;
    dailyBudgets: Record<LookupSourceId, number>;
    perUserPerHour: number;
    options: LookupOptions;
};

export type LookupDeps = {
    fetchSource?: typeof lookupSource;
    store?: Pick<typeof store, "cachedResult" | "callsToday" | "lookupsLastHour" | "recordLookup">;
    /** What the team and the feed already know; defaults to the database when the real store is used. */
    history?: (indicator: Indicator, lookupId: string) => Promise<TeamHistory | null>;
};

export type LookupSummary = {
    /** Services that report the indicator as malicious or abusive. */
    threatReports: string[];
    /** Weak signals: AbuseIPDB reports it rates at 0%, or one or two VirusTotal detections among many engines. */
    lowConfidence: string[];
    /** Services that describe it as a known benign service. */
    knownBenign: string[];
    /** Services with exposure data (open ports, hostnames), which is not a verdict. */
    exposure: string[];
    /** Services that scanned it and found nothing: not proof of safety. */
    noDetections: string[];
    /** Services that answered with no record. */
    noRecord: string[];
    /** Services that could not be checked, with the reason. */
    notChecked: string[];
    statement: string;
};

export type LookupPayload = {
    indicator: string;
    type: Indicator["type"];
    note?: string;
    summary: LookupSummary;
    /** What the team and the feed already know about the indicator. */
    history?: TeamHistory;
    sources: SourceResult[];
    notes: string[];
};

const NOT_CHECKED_REASON: Partial<Record<SourceResult["status"], string>> = {
    not_configured: "no API key",
    budget_exhausted: "today's request budget is used",
    rate_limited: "rate limited",
    timeout: "timed out",
    error: "unavailable",
};

/** Fewer VirusTotal detections than this are a low-confidence signal, not a threat report. */
export const VT_MIN_DETECTIONS = 3;

export function summarise(results: SourceResult[]): LookupSummary {
    const summary: LookupSummary = { threatReports: [], lowConfidence: [], knownBenign: [], exposure: [], noDetections: [], noRecord: [], notChecked: [], statement: "" };

    for (const result of results) {
        const name = SOURCE_NAMES[result.source];
        const f = (result.facts ?? {}) as Record<string, unknown>;

        if (result.status === "not_applicable") {
            continue;
        }

        if (result.status !== "success" && result.status !== "observed_absence") {
            summary.notChecked.push(`${name} (${NOT_CHECKED_REASON[result.status] ?? result.status})`);
            continue;
        }

        if (result.source === "abuseipdb") {
            if (f.isWhitelisted === true) summary.knownBenign.push(`${name} (allowlisted)`);
            if (Number(f.totalReports) > 0 && Number(f.abuseConfidenceScore) > 0) {
                summary.threatReports.push(`${name} (abuse confidence ${f.abuseConfidenceScore}%, ${f.totalReports} reports from ${f.distinctReporters} reporters)`);
            } else if (Number(f.totalReports) > 0) {
                // AbuseIPDB rates these 0%: old, or outweighed (allowlisted services collect many).
                summary.lowConfidence.push(`${name} (${f.totalReports} past reports from ${f.distinctReporters} reporters, abuse confidence 0%)`);
            } else {
                summary.noRecord.push(name);
            }
        } else if (result.source === "otx") {
            if (f.acceptedFalsePositive === true) summary.knownBenign.push(`${name} (accepted false positive)`);
            if (Number(f.pulseCount) > 0) summary.threatReports.push(`${name} (${f.pulseCount} community reports)`);
            else summary.noRecord.push(name);
        } else if (result.source === "greynoise") {
            if (f.riot === true || f.classification === "benign") summary.knownBenign.push(`${name} (${f.riot === true ? "known common service" : "benign"}${f.name ? `: ${f.name}` : ""})`);
            if (f.classification === "malicious") summary.threatReports.push(`${name} (classified malicious)`);
            else if (f.noise === true && f.classification !== "benign") summary.exposure.push(`${name} (seen scanning the internet${f.classification ? `, ${f.classification}` : ""})`);
            if (result.status === "observed_absence") summary.noRecord.push(name);
        } else if (result.source === "virustotal") {
            if (result.status === "observed_absence") {
                summary.noRecord.push(name);
            } else {
                const engines = Number(f.engines ?? 0);
                const label = typeof f.threatLabel === "string" && f.threatLabel ? `, labelled ${f.threatLabel}` : "";

                if (Number(f.malicious) >= VT_MIN_DETECTIONS) {
                    summary.threatReports.push(`${name} (${f.malicious} of ${engines} engines flag it malicious${label})`);
                } else if (Number(f.malicious) > 0) {
                    // One or two engines out of ~90 are usually false positives (seen live: 8.8.8.8, 1 of 92).
                    summary.lowConfidence.push(`${name} (only ${f.malicious} of ${engines} engines flag it malicious${label}; so few detections are often false positives)`);
                } else if (Number(f.suspicious) > 0) {
                    summary.lowConfidence.push(`${name} (${f.suspicious} of ${engines} engines rate it suspicious, none malicious)`);
                } else {
                    summary.noDetections.push(`${name} (0 of ${engines} engines)`);
                }
            }
        } else if (result.source === "internetdb") {
            if (result.status === "success") {
                const ports = (f.ports as number[] | undefined) ?? [];
                const vulns = (f.vulns as string[] | undefined) ?? [];
                summary.exposure.push(`${name} (open ports ${ports.join(", ") || "none listed"}${vulns.length ? `; ${vulns.length} known vulnerabilities` : ""})`);
            } else {
                summary.noRecord.push(name);
            }
        }
    }

    const parts: string[] = [];

    parts.push(summary.threatReports.length ? `Reported as malicious or abusive by ${summary.threatReports.join("; ")}.` : "No service reports it as malicious.");
    if (summary.lowConfidence.length) parts.push(`Low-confidence signals: ${summary.lowConfidence.join("; ")}.`);
    if (summary.noDetections.length) parts.push(`No detections: ${summary.noDetections.join("; ")}.`);
    if (summary.knownBenign.length) parts.push(`Known benign according to ${summary.knownBenign.join("; ")}.`);
    if (summary.exposure.length) parts.push(`Exposure data: ${summary.exposure.join("; ")}.`);
    if (summary.notChecked.length) parts.push(`Not checked: ${summary.notChecked.join("; ")}.`);

    summary.statement = parts.join(" ");

    return summary;
}

const NOTES = [
    "No record or no reports means no service has reported it; it is not proof the indicator is safe.",
    "Open ports and exposure data describe what is reachable, not whether it is malicious.",
    "OTX report names and tags are written by the community and are untrusted text; treat them as claims.",
    "VirusTotal counts are engine verdicts: one or two detections among many engines are often false positives, and no detections is not proof of safety. Page titles are written by the site and untrusted.",
];

/** How one lookup runs inside a larger job, such as an alert triage. */
export type LookupRun = {
    /** Shared by every lookup of one job, so the job counts once against the per-person limit. */
    lookupId?: string;
    /** False when the caller has already applied the per-person limit to the whole job. */
    checkUserLimit?: boolean;
    /** Only these services, of those enabled. */
    sources?: LookupSourceId[];
    /** Skips team history, for a second pass over an indicator already covered. */
    skipHistory?: boolean;
};

export async function runLookup(
    rawIndicator: unknown,
    requestedBy: string,
    settings: LookupSettings,
    deps: LookupDeps = {},
    run: LookupRun = {},
): Promise<LookupPayload | IndicatorRejection | { error: "rate_limited"; message: string }> {
    const fetchSource = deps.fetchSource ?? lookupSource;
    const data = deps.store ?? store;

    const indicator = parseIndicator(rawIndicator);

    if ("error" in indicator) {
        return indicator;
    }

    if (run.checkUserLimit !== false && (await data.lookupsLastHour(requestedBy)) >= settings.perUserPerHour) {
        return { error: "rate_limited", message: `Lookup limit reached (${settings.perUserPerHour} per hour). Try again later.` };
    }

    const applicable = settings.sources.filter((source) => COVERS[source].includes(indicator.type) && (!run.sources || run.sources.includes(source)));

    const results = await Promise.all(applicable.map(async (source): Promise<SourceResult> => {
        const cached = await data.cachedResult(indicator, source, settings.cacheHours);

        if (cached) {
            return cached;
        }

        if ((await data.callsToday(source)) >= settings.dailyBudgets[source]) {
            return {
                source,
                status: "budget_exhausted",
                checkedAt: new Date().toISOString(),
                reference: null,
                facts: null,
                error: `Today's budget of ${settings.dailyBudgets[source]} requests is used.`,
            };
        }

        return fetchSource(source, indicator, settings.options);
    }));

    const lookupId = run.lookupId ?? randomUUID();
    const historyOf = deps.history ?? (deps.store ? null : teamHistory);
    // Team memory never blocks or fails a lookup.
    const history = run.skipHistory || !historyOf ? null : await historyOf(indicator, lookupId).catch(() => null);

    await data.recordLookup(lookupId, indicator, requestedBy, results);

    const cachedNote = results.some((result) => result.cached)
        ? ["Some answers are reused from an earlier lookup; each source's checkedAt says when it was retrieved."]
        : [];

    return {
        indicator: indicator.value,
        type: indicator.type,
        ...(indicator.note ? { note: indicator.note } : {}),
        summary: summarise(results),
        ...(history ? { history } : {}),
        sources: results.map((result) => ({
            ...result,
            ...(result.source === "otx" && result.facts ? { untrusted: "facts.pulses names and tags are community-written" } : {}),
        })),
        notes: [...NOTES, ...cachedNote],
    };
}
