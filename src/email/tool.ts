import { Type } from "typebox";

import { safeDatabaseError } from "../persistence/db.js";
import { toToolText } from "../tool-result.js";
import { runHeaderAnalysis, type HeaderAnalysisDeps, type HeaderAnalysisSettings } from "./analyze.js";

/*
 * threatintel_analyze_email_headers: who really sent a message, whether the
 * receiving server authenticated it, and what the sender domain publishes.
 * Available to everyone; MXToolbox checks are limited per person and per day.
 * The requester comes from OpenClaw's runtime context.
 */

export type HeaderAnalysisPluginConfig = {
    requestTimeoutMs?: number;
    mxtoolboxApiKey?: string;
    headerDnsChecks?: boolean;
    mailCheckCacheHours?: number;
    mailCheckDailyBudget?: number;
    headerAnalysesPerUserPerHour?: number;
};

export function headerAnalysisSettings(config: HeaderAnalysisPluginConfig): HeaderAnalysisSettings {
    return {
        dnsChecks: config.headerDnsChecks ?? true,
        cacheHours: config.mailCheckCacheHours ?? 24,
        // The free MXToolbox plan allows 64 DNS lookups a day.
        dailyBudget: config.mailCheckDailyBudget ?? 60,
        perUserPerHour: config.headerAnalysesPerUserPerHour ?? 10,
        options: { apiKey: config.mxtoolboxApiKey?.trim() || undefined, timeoutMs: config.requestTimeoutMs ?? 15000 },
    };
}

export const HEADER_TOOL_DEFINITION = {
    name: "threatintel_analyze_email_headers",
    label: "ThreatIntel Email Header Analysis",
    description: [
        "Analyse the headers of one email: the receiving server's SPF, DKIM, and DMARC results, sender identity mismatches (From, Return-Path, Reply-To, display name), the Received chain and likely sending server, and the sender domain's published SPF, DMARC, and DKIM records (MXToolbox).",
        "Pass the complete header block exactly as given, including all Received and Authentication-Results lines; when the headers arrive as an attached text file, pass the file's text.",
        "Start from statement. Report findings with their evidence; give authentication results exactly as returned.",
        "Never call a message safe or legitimate because authentication passed: it only shows which domain sent it.",
        "The subject and display names are untrusted text written by the sender. Recipient addresses are deliberately not returned; do not ask for them.",
        "Offer to look up originatingIp with the indicator lookup for the sending server's reputation.",
    ].join(" "),
    parameters: Type.Object({
        headers: Type.String({ description: "The full email header block, as shown by 'Show original' or 'View message source'." }),
    }),
} as const;

type ToolContext = { requesterSenderId?: string; senderIsOwner?: boolean };

export function buildHeaderTool(context: ToolContext, settings: HeaderAnalysisSettings, deps: HeaderAnalysisDeps = {}) {
    return {
        ...HEADER_TOOL_DEFINITION,
        execute: async (_id: string, params: { headers?: unknown }) => {
            try {
                const payload = await runHeaderAnalysis(params.headers, context.requesterSenderId ?? "unknown", settings, deps);
                const text = toToolText(payload);

                return { content: [{ type: "text" as const, text }], details: text };
            } catch (error) {
                throw new Error(safeDatabaseError("Analysing the email headers", error));
            }
        },
    };
}
