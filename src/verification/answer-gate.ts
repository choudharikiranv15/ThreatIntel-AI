import type { OpenClawPluginApi } from "openclaw/plugin-sdk/plugin-entry";

import type { InvestigationView } from "../tool-result.js";
import { checkAnswer } from "./check-answer.js";

const TOOL_NAMES = new Set([
    "threatintel_investigate",
    "threatintel_prior_investigation",
]);

const MAX_SESSIONS = 100;

function readPayload(result: unknown): unknown {
    const toolResult = (result ?? {}) as {
        details?: unknown;
        content?: { text?: unknown }[];
    };

    if (toolResult.details) {
        return toolResult.details;
    }

    const text = toolResult.content?.[0]?.text;

    if (typeof text !== "string") {
        return null;
    }

    try {
        return JSON.parse(text);
    } catch {
        return null;
    }
}

function extractView(result: unknown): InvestigationView | null {
    const payload = readPayload(result) as
        | (Partial<InvestigationView> & { investigation?: unknown })
        | null;

    const candidate = (payload?.investigation ?? payload) as
        | Partial<InvestigationView>
        | null;

    return typeof candidate?.target === "string" &&
        Array.isArray(candidate.summary?.conflicts) &&
        Array.isArray(candidate.facts)
        ? (candidate as InvestigationView)
        : null;
}

/**
 * Asks for one more model pass when the final answer contradicts the
 * investigation results returned earlier in the same session.
 *
 * Requires plugins.entries.threatintel-ai-engine.hooks.allowConversationAccess.
 */
export function registerAnswerGate(api: OpenClawPluginApi): void {
    const sessions = new Map<string, Map<string, InvestigationView>>();

    api.on("after_tool_call", (event, context) => {
        const sessionKey = context.sessionKey ?? context.sessionId;

        if (!sessionKey || !TOOL_NAMES.has(event.toolName)) {
            return;
        }

        const view = extractView(event.result);

        if (!view) {
            return;
        }

        // Re-inserting keeps the most recently active session last.
        const views =
            sessions.get(sessionKey) ??
            new Map<string, InvestigationView>();

        views.set(view.target.toUpperCase(), view);
        sessions.delete(sessionKey);
        sessions.set(sessionKey, views);

        if (sessions.size > MAX_SESSIONS) {
            sessions.delete(sessions.keys().next().value as string);
        }
    });

    api.on("before_agent_finalize", (event, context) => {
        const sessionKey =
            event.sessionKey ??
            context.sessionKey ??
            event.sessionId;

        const views = sessions.get(sessionKey);

        if (
            event.stopHookActive ||
            !views ||
            !event.lastAssistantMessage
        ) {
            return;
        }

        const findings = checkAnswer(
            event.lastAssistantMessage,
            Array.from(views.values()),
        );

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
                    "Correct or remove these statements using only the structured investigation results. Do not explain the correction unless it matters to the analyst.",
                idempotencyKey: `threatintel-answer-gate:${event.runId ?? event.sessionId}`,
                maxAttempts: 1,
            },
        };
    });
}
