import type { OpenClawPluginApi } from "openclaw/plugin-sdk/plugin-entry";

import type { HeaderAnalysisPayload } from "../email/analyze.js";
import type { LookupPayload } from "../lookup/lookup.js";
import type { InvestigationView } from "../tool-result.js";
import {
    checkAnswer,
    claimsFreshRetrieval,
    mentionsInvestigated,
} from "./check-answer.js";
import { checkEmailAnswer, extractHeaderAnalysis } from "./check-email.js";
import { checkIndicatorAnswer, extractLookup, extractTriageLookups } from "./check-indicators.js";

const TOOL_NAMES = new Set([
    "threatintel_investigate",
    "threatintel_prior_investigation",
    "threatintel_lookup_indicator",
    "threatintel_analyze_email_headers",
    "threatintel_triage_alert",
]);

const MAX_SESSIONS = 100;

const WARNING_PREFIX = "⚠️ ThreatIntel evidence check:";

type SessionState = {
    views: Map<string, InvestigationView>;
    lookups: Map<string, LookupPayload>;
    emails: HeaderAnalysisPayload[];

    /** The run that last retrieved data from a provider, not from history. */
    lastRetrievalRunId?: string;
};

function readPayload(result: unknown): unknown {
    const toolResult = (result ?? {}) as {
        details?: unknown;
        content?: { text?: unknown }[];
    };

    // Results are returned as JSON text, so details can hold that same string.
    if (toolResult.details && typeof toolResult.details !== "string") {
        return toolResult.details;
    }

    const text = toolResult.details ?? toolResult.content?.[0]?.text;

    if (typeof text !== "string") {
        return null;
    }

    try {
        return JSON.parse(text);
    } catch {
        return null;
    }
}

function extractView(payload: unknown): InvestigationView | null {
    const record = payload as
        | (Partial<InvestigationView> & { investigation?: unknown })
        | null;

    const candidate = (record?.investigation ?? record) as
        | Partial<InvestigationView>
        | null;

    return typeof candidate?.target === "string" &&
        candidate.summary?.correlations &&
        Array.isArray(candidate.facts)
        ? (candidate as InvestigationView)
        : null;
}

/**
 * Checks answers against the investigation results returned earlier in the same
 * session. Before a final answer is accepted, a conflict asks for one more model
 * pass. Any conflict still present at delivery is shown to the reader, because a
 * log line alone would let a known-wrong answer reach an analyst unmarked.
 *
 * The finalize check requires
 * plugins.entries.threatintel-ai-engine.hooks.allowConversationAccess.
 */
export function registerAnswerGate(
    api: OpenClawPluginApi,
    options: {
        /** Applied to every outgoing reply after the evidence check, such as putting redacted values back. */
        transformOutbound?: (text: string) => string;
    } = {},
): void {
    const finish = (original: string, warned: string | undefined): string | undefined => {
        const base = warned ?? original;
        const out = options.transformOutbound ? options.transformOutbound(base) : base;

        return out !== original ? out : undefined;
    };

    const sessions = new Map<string, SessionState>();

    function withWarning(
        text: string,
        sessionKey: string | undefined,
    ): string | undefined {
        const state = sessionKey ? sessions.get(sessionKey) : undefined;

        if (!state || text.startsWith(WARNING_PREFIX)) {
            return undefined;
        }

        const findings = [
            ...checkAnswer(text, Array.from(state.views.values())),
            ...checkIndicatorAnswer(text, Array.from(state.lookups.values())),
            ...checkEmailAnswer(text, state.emails),
        ];

        if (findings.length === 0) {
            return undefined;
        }

        api.logger.warn(
            `threatintel answer gate: delivered with a warning: ${findings.join(" ")}`,
        );

        return `${WARNING_PREFIX} this answer conflicts with the retrieved evidence. ${findings.join(" ")}\n\n${text}`;
    }

    api.on("after_tool_call", (event, context) => {
        const sessionKey = context.sessionKey ?? context.sessionId;

        if (!sessionKey || !TOOL_NAMES.has(event.toolName)) {
            return;
        }

        const payload = readPayload(event.result);
        const view = extractView(payload);
        const lookup = view ? null : extractLookup(payload);
        const email = view || lookup ? null : extractHeaderAnalysis(payload);
        const triaged = view || lookup || email ? [] : extractTriageLookups(payload);

        if (!view && !lookup && !email && triaged.length === 0) {
            return;
        }

        // Re-inserting keeps the most recently active session last.
        const state: SessionState =
            sessions.get(sessionKey) ?? { views: new Map(), lookups: new Map(), emails: [] };

        if (view) {
            state.views.set(view.target.toUpperCase(), view);
        }

        for (const each of lookup ? [lookup, ...triaged] : triaged) {
            state.lookups.set(each.indicator.toLowerCase(), each);
        }

        if (email) {
            state.emails = [...state.emails.slice(-2), email];
        }

        if ((payload as { mode?: unknown }).mode === "refreshed") {
            state.lastRetrievalRunId = event.runId ?? context.runId;
        }

        sessions.delete(sessionKey);
        sessions.set(sessionKey, state);

        if (sessions.size > MAX_SESSIONS) {
            sessions.delete(sessions.keys().next().value as string);
        }
    });

    api.on("before_agent_finalize", (event, context) => {
        const sessionKey =
            event.sessionKey ??
            context.sessionKey ??
            event.sessionId;

        const state = sessions.get(sessionKey);
        const answer = event.lastAssistantMessage;

        if (event.stopHookActive || !state || !answer) {
            return;
        }

        const findings = [
            ...checkAnswer(answer, Array.from(state.views.values())),
            ...checkIndicatorAnswer(answer, Array.from(state.lookups.values())),
            ...checkEmailAnswer(answer, state.emails),
        ];

        // Only judged when the run is known, so a missing id cannot cause a retry.
        const runId = event.runId ?? context.runId;

        if (
            runId &&
            runId !== state.lastRetrievalRunId &&
            claimsFreshRetrieval(answer) &&
            mentionsInvestigated(
                answer,
                Array.from(state.views.values()),
            )
        ) {
            findings.push(
                "The answer implies the data was just retrieved, but no provider was queried in this turn. State when it was retrieved, using checkedAt.",
            );
        }

        if (findings.length === 0) {
            return;
        }

        api.logger.warn(
            `threatintel answer gate: ${findings.join(" ")}`,
        );

        return {
            action: "revise",
            reason: `Answer conflicts with retrieved evidence: ${findings.join(" ")}`,
            retry: {
                instruction:
                    "Correct or remove these statements using only the structured investigation, lookup, and header analysis results. Do not explain the correction unless it matters to the analyst.",
                idempotencyKey: `threatintel-answer-gate:${event.runId ?? event.sessionId}`,
                maxAttempts: 1,
            },
        };
    });

    // Delivery paths differ by channel; the prefix check stops a double warning.
    api.on("message_sending", (event, context) => {
        const content = finish(event.content, withWarning(event.content, context.sessionKey));

        return content ? { content } : undefined;
    });

    api.on("reply_payload_sending", (event, context) => {
        const text = event.payload.text;

        if (!text) {
            return undefined;
        }

        const out = finish(
            text,
            withWarning(text, event.sessionKey ?? context.sessionKey),
        );

        return out
            ? { payload: { ...event.payload, text: out } }
            : undefined;
    });
}
