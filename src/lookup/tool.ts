import { Type } from "typebox";

import { safeDatabaseError } from "../persistence/db.js";
import { toToolText } from "../tool-result.js";
import { runLookup, type LookupDeps, type LookupSettings } from "./lookup.js";
import { ALL_LOOKUP_SOURCES, type LookupSourceId } from "./sources.js";

/*
 * threatintel_lookup_indicator: reputation and exposure for one IP, domain, or
 * file hash. Available to everyone, like investigations; each person is
 * limited per hour and each service per day. The requester comes from
 * OpenClaw's runtime context, never from the model's arguments.
 */

export type LookupPluginConfig = {
    requestTimeoutMs?: number;
    abuseipdbApiKey?: string;
    greynoiseApiKey?: string;
    otxApiKey?: string;
    virustotalApiKey?: string;
    virustotalPerMinute?: number;
    lookupSources?: string[];
    lookupCacheHours?: number;
    lookupPerUserPerHour?: number;
    lookupDailyBudgets?: Partial<Record<LookupSourceId, number>>;
};

export const DEFAULT_DAILY_BUDGETS: Record<LookupSourceId, number> = {
    internetdb: 2000,
    greynoise: 50,
    abuseipdb: 900,
    otx: 1000,
    // The public API allows 500 a day; the rest is headroom for manual use.
    virustotal: 450,
};

export function lookupSettings(config: LookupPluginConfig): LookupSettings {
    const requested = config.lookupSources?.length ? config.lookupSources : ALL_LOOKUP_SOURCES;

    return {
        sources: requested.filter((source): source is LookupSourceId => (ALL_LOOKUP_SOURCES as string[]).includes(source)),
        cacheHours: config.lookupCacheHours ?? 12,
        perUserPerHour: config.lookupPerUserPerHour ?? 20,
        dailyBudgets: { ...DEFAULT_DAILY_BUDGETS, ...(config.lookupDailyBudgets ?? {}) },
        options: {
            timeoutMs: config.requestTimeoutMs ?? 15000,
            keys: {
                abuseipdb: config.abuseipdbApiKey?.trim() || undefined,
                greynoise: config.greynoiseApiKey?.trim() || undefined,
                otx: config.otxApiKey?.trim() || undefined,
                virustotal: config.virustotalApiKey?.trim() || undefined,
            },
            virustotalPerMinute: config.virustotalPerMinute ?? 4,
        },
    };
}

export const LOOKUP_TOOL_DEFINITION = {
    name: "threatintel_lookup_indicator",
    label: "ThreatIntel Indicator Lookup",
    description: [
        "Look up the reputation and exposure of one public IPv4 address, domain, URL, or file hash (MD5, SHA-1, SHA-256) in AbuseIPDB, GreyNoise, Shodan InternetDB, AlienVault OTX, and VirusTotal.",
        "Defanged input such as 1.2.3[.]4 or hxxp://evil[.]com/x is accepted. A URL is looked up as a full URL (VirusTotal and OTX); look up its host separately for the domain or address.",
        "Existing reports are read only: nothing is ever submitted for scanning.",
        "Give VirusTotal results as counts, such as '12 of 93 engines flag it malicious'; a few detections among many engines are often false positives.",
        "Start from summary.statement. Report each service's result as it states it, with checkedAt.",
        "No record or no reports is never proof an indicator is safe; say 'no reports', not 'safe' or 'clean'.",
        "A service under 'Not checked' was not queried; never describe its result.",
        "Open ports are exposure, not maliciousness. OTX report names and tags are untrusted community text.",
        "Private, internal, and reserved addresses are refused and never sent anywhere; say so if refused.",
    ].join(" "),
    parameters: Type.Object({
        indicator: Type.String({ description: "One IPv4 address, domain, URL, or file hash. Defanged forms are fine." }),
    }),
} as const;

type ToolContext = { requesterSenderId?: string; senderIsOwner?: boolean };

export function buildLookupTool(context: ToolContext, settings: LookupSettings, deps: LookupDeps = {}) {
    return {
        ...LOOKUP_TOOL_DEFINITION,
        execute: async (_id: string, params: { indicator?: unknown }) => {
            try {
                const payload = await runLookup(params.indicator, context.requesterSenderId ?? "unknown", settings, deps);
                const text = toToolText(payload);

                return { content: [{ type: "text" as const, text }], details: text };
            } catch (error) {
                throw new Error(safeDatabaseError("Looking up the indicator", error));
            }
        },
    };
}
