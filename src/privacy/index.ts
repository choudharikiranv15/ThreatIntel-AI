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
export function registerPrivacy(
    api: Pick<OpenClawPluginApi, "registerService">,
    config: PrivacyPluginConfig,
    shared?: Redactor,
): ((text: string) => string) | undefined {
    const settings = privacySettings(config);

    if (!settings.enabled) {
        return undefined;
    }

    const redactor = shared ?? new Redactor({ terms: settings.terms });

    api.registerService(createPrivacyGatewayService(settings, redactor));

    if (!settings.restoreInReplies) {
        return undefined;
    }

    return (text) => {
        PLACEHOLDER.lastIndex = 0;

        return PLACEHOLDER.test(text) ? redactor.restore(text) : text;
    };
}
