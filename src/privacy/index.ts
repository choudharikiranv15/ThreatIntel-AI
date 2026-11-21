import type { OpenClawPluginApi } from "openclaw/plugin-sdk/plugin-entry";

import { createPrivacyGatewayService, upstreamsFrom, type GatewaySettings } from "./gateway.js";
import { PLACEHOLDER, Redactor } from "./redact.js";

/*
 * PII protection for the AI provider. The gateway redacts every request; the
 * real values are put back only in replies posted to the chat the data came
 * from. Both share one redactor, so placeholders resolve.
 */

export type PrivacyPluginConfig = {
    privacyGatewayEnabled?: boolean;
    privacyGatewayPort?: number;
    privacyGatewayUpstreams?: Record<string, string>;
    /** Names and other terms to always replace, such as team members' names. */
    piiTerms?: string[];
    piiRestoreInReplies?: boolean;
};

export type PrivacySettings = GatewaySettings & { enabled: boolean; terms: string[]; restoreInReplies: boolean };

export function privacySettings(config: PrivacyPluginConfig): PrivacySettings {
    return {
        enabled: config.privacyGatewayEnabled === true,
        port: config.privacyGatewayPort ?? 18790,
        upstreams: upstreamsFrom(config.privacyGatewayUpstreams),
        maxBodyBytes: 8 * 1024 * 1024,
        terms: config.piiTerms ?? [],
        restoreInReplies: config.piiRestoreInReplies ?? true,
    };
}

/**
 * Starts the gateway when enabled. Returns the function that puts real values
 * back into an outgoing reply, for the delivery hooks to apply, or undefined
 * when there is nothing to restore.
 */
/** Puts real values back into every string of a tool's arguments. */
function restoreParams(value: unknown, redactor: Redactor): unknown {
    if (typeof value === "string") return redactor.restore(value);
    if (Array.isArray(value)) return value.map((item) => restoreParams(item, redactor));
    if (value && typeof value === "object") {
        return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([k, v]) => [k, restoreParams(v, redactor)]));
    }
    return value;
}

/*
 * Only this plugin's own tools get real values back: they run on this
 * machine, and what they return is redacted again before the model sees it.
 * Tools that reach the internet (web search, web fetch) keep the
 * placeholders, so a query never carries the data out.
 */
const LOCAL_TOOLS = /^threatintel_/;

/*
 * One redactor per process. OpenClaw may run the plugin's register() more than
 * once in a process (discovery, the full runtime, config reloads), and each run
 * must see the same placeholder table: otherwise the gateway fills one table
 * while the reply hooks look in another and cannot put real values back.
 */
const SHARED_REDACTOR = Symbol.for("threatintel-ai.privacy.redactor");

export function processRedactor(terms: string[]): Redactor {
    const holder = globalThis as unknown as Record<symbol, Redactor | undefined>;
    const existing = holder[SHARED_REDACTOR];

    if (existing) {
        existing.setTerms(terms);
        return existing;
    }

    const created = new Redactor({ terms });

    holder[SHARED_REDACTOR] = created;
    return created;
}

export function registerPrivacy(
    api: Pick<OpenClawPluginApi, "registerService" | "on"> & { logger?: { warn: (message: string) => void; info?: (message: string) => void } },
    config: PrivacyPluginConfig,
    shared?: Redactor,
): ((text: string) => string) | undefined {
    const settings = privacySettings(config);

    if (!settings.enabled) {
        return undefined;
    }

    const redactor = shared ?? processRedactor(settings.terms);

    api.registerService(createPrivacyGatewayService(settings, redactor));

    api.on("before_tool_call", (event) => {
        if (!LOCAL_TOOLS.test(event.toolName)) {
            return undefined;
        }

        PLACEHOLDER.lastIndex = 0;

        if (!PLACEHOLDER.test(JSON.stringify(event.params))) {
            return undefined;
        }

        return { params: restoreParams(event.params, redactor) as Record<string, unknown> };
    });

    if (!settings.restoreInReplies) {
        return undefined;
    }

    return (text) => {
        PLACEHOLDER.lastIndex = 0;

        if (!PLACEHOLDER.test(text)) {
            return text;
        }

        const unknown = redactor.unknownPlaceholders(text);

        if (unknown > 0) {
            // Counts only. Expected after a restart for older conversations; otherwise a sign of a second table.
            api.logger?.warn(`threatintel privacy: ${unknown} placeholder(s) in a reply could not be restored`);
        }

        PLACEHOLDER.lastIndex = 0;
        const total = (text.match(PLACEHOLDER) ?? []).length;

        if (total > unknown) {
            api.logger?.info?.(`threatintel privacy: restored ${total - unknown} placeholder(s) in a reply`);
        }

        return redactor.restore(text);
    };
}
