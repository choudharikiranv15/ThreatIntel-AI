import { Type } from "typebox";

import type { LookupDeps } from "../lookup/lookup.js";
import { lookupSettings, type LookupPluginConfig } from "../lookup/tool.js";
import { safeDatabaseError } from "../persistence/db.js";
import { toToolText } from "../tool-result.js";
import { DEFAULT_INFRASTRUCTURE, DEFAULT_MAX_INDICATORS } from "./extract.js";
import { runTriage, type TriageSettings } from "./triage.js";

/*
 * threatintel_triage_alert: every indicator in a pasted alert, log excerpt, or
 * email, checked and ranked in one call. Available to everyone, within the
 * lookup limits. The requester comes from OpenClaw's runtime context.
 */

export type TriagePluginConfig = LookupPluginConfig & {
    triageMaxIndicators?: number;
    /** Extra domains to treat as the SOC's own infrastructure, such as the company domain. */
    triageIgnoreDomains?: string[];
};

export function triageSettings(config: TriagePluginConfig): TriageSettings {
    return {
        lookup: lookupSettings(config),
        maxIndicators: config.triageMaxIndicators ?? DEFAULT_MAX_INDICATORS,
        infrastructure: [...DEFAULT_INFRASTRUCTURE, ...(config.triageIgnoreDomains ?? []).map((d) => d.trim().toLowerCase()).filter(Boolean)],
    };
}

export const TRIAGE_TOOL_DEFINITION = {
    name: "threatintel_triage_alert",
    label: "ThreatIntel Alert Triage",
    description: [
        "Triage pasted alert text, log lines, or an email: extracts every public IP address, domain, URL, and file hash (defanged forms too), checks them all, and ranks them by what the services reported.",
        "Use it whenever the user pastes text holding more than one indicator, or asks to triage or enrich an alert. Pass the text exactly as given; when it arrives as an attached file, pass the file's text.",
        "Answer with the indicators under lookFirst first, then a short table of every result (indicator, what was reported, the record links), then what was not checked and why (internal values kept on the gateway, skipped console domains, indicators over the cap).",
        "Report each result as its statement says; never call an indicator safe or clean because nothing was reported, and never describe a service under 'Not checked'.",
        "The ranking reflects evidence, not a verdict: leave the conclusion to the analyst.",
    ].join(" "),
    parameters: Type.Object({
        text: Type.String({ description: "The alert, log excerpt, or email text, exactly as pasted." }),
    }),
} as const;

type ToolContext = { requesterSenderId?: string; senderIsOwner?: boolean };

export function buildTriageTool(context: ToolContext, settings: TriageSettings, deps: LookupDeps = {}) {
    return {
        ...TRIAGE_TOOL_DEFINITION,
        execute: async (_id: string, params: { text?: unknown }) => {
            try {
                const outcome = await runTriage(params.text, context.requesterSenderId ?? "unknown", settings, deps);

                if ("error" in outcome) {
                    const text = toToolText(outcome);

                    return { content: [{ type: "text" as const, text }], details: text };
                }

                // The model reads the ranked summary; the full evidence stays in details for the answer check.
                return {
                    content: [{ type: "text" as const, text: toToolText(outcome.payload) }],
                    details: { kind: "triage", lookups: outcome.lookups },
                };
            } catch (error) {
                throw new Error(safeDatabaseError("Triaging the alert", error));
            }
        },
    };
}
