import { fetchWithRetry, INTERACTIVE_RETRY, type RetryPolicy } from "../sources/request-signal.js";
import type { Indicator, IndicatorType } from "./indicator.js";

/*
 * One adapter per intelligence service. Each keeps only the facts an analyst
 * needs, never the raw response, and reports a status that keeps "no record"
 * apart from "not checked". API keys travel only in request headers.
 */

export type LookupSourceId = "internetdb" | "greynoise" | "abuseipdb" | "otx";

export const ALL_LOOKUP_SOURCES: LookupSourceId[] = ["internetdb", "greynoise", "abuseipdb", "otx"];

export const SOURCE_NAMES: Record<LookupSourceId, string> = {
    internetdb: "Shodan InternetDB",
    greynoise: "GreyNoise",
    abuseipdb: "AbuseIPDB",
    otx: "AlienVault OTX",
};

/**
 * success: the service has a record. observed_absence: it answered and has none,
 * which is not proof of safety. not_configured: needs an API key that is not set.
 * not_applicable: does not cover this indicator type. budget_exhausted: today's
 * request budget is used. rate_limited, timeout, error: it could not be checked.
 */
export type LookupStatus =
    | "success"
    | "observed_absence"
    | "not_configured"
    | "not_applicable"
    | "budget_exhausted"
    | "rate_limited"
    | "timeout"
    | "error";

export type SourceResult = {
    source: LookupSourceId;
    status: LookupStatus;
    checkedAt: string;
    /** Where an analyst can see the record. */
    reference: string | null;
    facts: Record<string, unknown> | null;
    error: string | null;
    cached?: boolean;
};

export const COVERS: Record<LookupSourceId, IndicatorType[]> = {
    internetdb: ["ipv4"],
    greynoise: ["ipv4"],
    abuseipdb: ["ipv4"],
    otx: ["ipv4", "domain", "md5", "sha1", "sha256"],
};

export type LookupKeys = { abuseipdb?: string; greynoise?: string; otx?: string };

export type LookupOptions = { timeoutMs: number; retry?: RetryPolicy; keys: LookupKeys };

const MAX_LIST = 10;

const str = (value: unknown, limit = 120): string | null =>
    typeof value === "string" && value.trim() ? value.trim().slice(0, limit) : null;

const list = (value: unknown, limit = MAX_LIST): string[] =>
    Array.isArray(value) ? value.filter((item): item is string | number => typeof item === "string" || typeof item === "number").map(String).slice(0, limit) : [];

/* --------------------------------- Parsers -------------------------------- */
/* Pure: tested against recorded responses. */

export function parseInternetDb(status: number, body: unknown): Pick<SourceResult, "status" | "facts"> {
    if (status === 404) {
        return { status: "observed_absence", facts: null };
    }

    const o = (body ?? {}) as Record<string, unknown>;

    return {
        status: "success",
        facts: {
            ports: list(o.ports, 30).map(Number),
            hostnames: list(o.hostnames),
            tags: list(o.tags),
            vulns: list(o.vulns, 20),
            cpes: list(o.cpes),
        },
    };
}

export function parseGreyNoise(status: number, body: unknown): Pick<SourceResult, "status" | "facts"> {
    const o = (body ?? {}) as Record<string, unknown>;
    const facts = {
        noise: o.noise === true,
        riot: o.riot === true,
        classification: str(o.classification, 20),
        name: str(o.name),
        lastSeen: str(o.last_seen, 30),
    };

    // GreyNoise answers 404 with noise and riot false when it has not seen the address.
    if (status === 404 || (!facts.noise && !facts.riot && !facts.classification)) {
        return { status: "observed_absence", facts: { noise: false, riot: false } };
    }

    return { status: "success", facts };
}

export function parseAbuseIpDb(body: unknown): Pick<SourceResult, "status" | "facts"> {
    const d = ((body ?? {}) as { data?: Record<string, unknown> }).data ?? {};
    const totalReports = Number(d.totalReports ?? 0);

    return {
        status: totalReports > 0 ? "success" : "observed_absence",
        facts: {
            abuseConfidenceScore: Number(d.abuseConfidenceScore ?? 0),
            totalReports,
            distinctReporters: Number(d.numDistinctUsers ?? 0),
            lastReportedAt: str(d.lastReportedAt, 30),
            isWhitelisted: d.isWhitelisted === true,
            isTor: d.isTor === true,
            usageType: str(d.usageType, 60),
            isp: str(d.isp, 80),
            countryCode: str(d.countryCode, 4),
        },
    };
}

export function parseOtx(body: unknown): Pick<SourceResult, "status" | "facts"> {
    const o = (body ?? {}) as Record<string, unknown>;
    const info = (o.pulse_info ?? {}) as { count?: unknown; pulses?: unknown };
    const pulses = Array.isArray(info.pulses) ? (info.pulses as Record<string, unknown>[]) : [];
    const count = Number(info.count ?? pulses.length);
    const falsePositive = Array.isArray(o.false_positive)
        ? (o.false_positive as Record<string, unknown>[]).filter((entry) => entry.assessment === "accepted").length
        : 0;
    const validation = Array.isArray(o.validation)
        ? (o.validation as Record<string, unknown>[]).map((entry) => str(entry.name ?? entry.source, 60)).filter(Boolean)
        : [];

    const facts = {
        pulseCount: count,
        // Community-written text: untrusted, kept short.
        pulses: pulses.slice(0, 5).map((pulse) => ({
            name: str(pulse.name, 140),
            modified: str(pulse.modified, 30),
            author: str((pulse.author as Record<string, unknown> | undefined)?.username, 40),
            tags: list(pulse.tags, 6).map((tag) => tag.slice(0, 40)),
            malwareFamilies: Array.isArray(pulse.malware_families)
                ? (pulse.malware_families as Record<string, unknown>[]).map((family) => str(family.display_name, 60)).filter(Boolean).slice(0, 3)
                : [],
            adversary: str(pulse.adversary, 60),
        })),
        acceptedFalsePositive: falsePositive > 0,
        validation,
        reputation: typeof o.reputation === "number" ? o.reputation : null,
        asn: str(o.asn, 80),
        country: str(o.country_code, 4),
    };

    return { status: count > 0 ? "success" : "observed_absence", facts };
}

/* --------------------------------- Fetching ------------------------------- */

const REFERENCES: Record<LookupSourceId, (i: Indicator) => string> = {
    internetdb: (i) => `https://www.shodan.io/host/${i.value}`,
    greynoise: (i) => `https://viz.greynoise.io/ip/${i.value}`,
    abuseipdb: (i) => `https://www.abuseipdb.com/check/${i.value}`,
    otx: (i) => `https://otx.alienvault.com/indicator/${otxType(i)}/${i.value}`,
};

function otxType(indicator: Indicator): string {
    if (indicator.type === "ipv4") return "IPv4";
    if (indicator.type === "domain") return indicator.value.split(".").length > 2 ? "hostname" : "domain";
    return "file";
}

function failure(error: unknown): Pick<SourceResult, "status" | "error"> {
    if (error instanceof DOMException && (error.name === "TimeoutError" || error.name === "AbortError")) {
        return { status: "timeout", error: "The service did not answer in time." };
    }

    // Never echo request details: a URL or header could carry a key.
    return { status: "error", error: "The service could not be reached." };
}

async function request(url: string, headers: Record<string, string>, options: LookupOptions) {
    return fetchWithRetry(
        url,
        { method: "GET", headers: { Accept: "application/json", "User-Agent": "ThreatIntel-AI indicator lookup", ...headers } },
        { timeoutMs: options.timeoutMs, retry: options.retry ?? INTERACTIVE_RETRY },
    );
}

export async function lookupSource(
    source: LookupSourceId,
    indicator: Indicator,
    options: LookupOptions,
): Promise<SourceResult> {
    const base = { source, checkedAt: new Date().toISOString(), reference: REFERENCES[source](indicator), facts: null, error: null };

    if (!COVERS[source].includes(indicator.type)) {
        return { ...base, reference: null, status: "not_applicable" };
    }

    if (source === "abuseipdb" && !options.keys.abuseipdb) {
        return { ...base, status: "not_configured", error: "Needs an AbuseIPDB API key (abuseipdbApiKey)." };
    }

    try {
        let response: Response;

        switch (source) {
            case "internetdb":
                response = await request(`https://internetdb.shodan.io/${indicator.value}`, {}, options);
                break;
            case "greynoise":
                response = await request(
                    `https://api.greynoise.io/v3/community/${indicator.value}`,
                    options.keys.greynoise ? { key: options.keys.greynoise } : {},
                    options,
                );
                break;
            case "abuseipdb":
                response = await request(
                    `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(indicator.value)}&maxAgeInDays=90`,
                    { Key: options.keys.abuseipdb as string },
                    options,
                );
                break;
            case "otx":
                response = await request(
                    `https://otx.alienvault.com/api/v1/indicators/${otxType(indicator)}/${encodeURIComponent(indicator.value)}/general`,
                    options.keys.otx ? { "X-OTX-API-KEY": options.keys.otx } : {},
                    options,
                );
                break;
        }

        if (response.status === 429) {
            return { ...base, status: "rate_limited", error: "The service's rate limit was reached; try again later." };
        }

        if (response.status === 401 || response.status === 403) {
            return { ...base, status: "error", error: "The service refused the request; check the API key." };
        }

        const absentOk = (source === "internetdb" || source === "greynoise") && response.status === 404;

        if (!response.ok && !absentOk) {
            return { ...base, status: "error", error: `The service answered HTTP ${response.status}.` };
        }

        const body = await response.json().catch(() => null);

        if (body === null && !absentOk) {
            return { ...base, status: "error", error: "The service returned an unreadable answer." };
        }

        const parsed =
            source === "internetdb" ? parseInternetDb(response.status, body)
                : source === "greynoise" ? parseGreyNoise(response.status, body)
                    : source === "abuseipdb" ? parseAbuseIpDb(body)
                        : parseOtx(body);

        return { ...base, ...parsed };
    } catch (error) {
        return { ...base, ...failure(error) };
    }
}
