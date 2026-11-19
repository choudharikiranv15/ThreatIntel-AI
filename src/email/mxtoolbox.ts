import { fetchWithRetry, INTERACTIVE_RETRY, type RetryPolicy } from "../sources/request-signal.js";

/*
 * MXToolbox DNS checks for a sender domain: the published SPF, DMARC, and DKIM
 * records and MXToolbox's own checks of them. Only these DNS lookups are used;
 * the free plan has no network lookups (blacklists, SMTP), and nothing about
 * the message itself is ever sent, only the domain.
 */

export type MailCheckCommand = "spf" | "dmarc" | "dkim";

export type MailCheckStatus = "success" | "not_configured" | "budget_exhausted" | "rate_limited" | "timeout" | "error";

export type MailCheck = {
    command: MailCheckCommand;
    /** The domain, or "domain:selector" for DKIM. */
    argument: string;
    status: MailCheckStatus;
    checkedAt: string;
    reference: string | null;
    facts: {
        /** The published record(s), as found. */
        records: string[];
        failed: string[];
        warnings: string[];
        passed: string[];
        /** DMARC: the p= and sp= tags. SPF: the "all" qualifier. */
        policy: string | null;
        subdomainPolicy?: string | null;
        allQualifier?: string | null;
    } | null;
    error: string | null;
    cached?: boolean;
};

export type MailCheckOptions = { apiKey?: string; timeoutMs: number; retry?: RetryPolicy };

type Check = { Name?: unknown; Info?: unknown };

const text = (value: unknown, limit: number) => (typeof value === "string" ? value.replace(/&#39;/g, "'").replace(/&amp;/g, "&").replace(/\s+/g, " ").trim().slice(0, limit) : "");

const checks = (value: unknown) =>
    (Array.isArray(value) ? (value as Check[]) : [])
        .map((c) => [text(c.Name, 80), text(c.Info, 160)].filter(Boolean).join(": "))
        .filter(Boolean)
        .slice(0, 10);

/** Pure: tested against recorded responses. */
export function parseMxToolbox(command: MailCheckCommand, body: unknown): NonNullable<MailCheck["facts"]> {
    const o = (body ?? {}) as Record<string, unknown>;
    const info = Array.isArray(o.Information) ? (o.Information as Record<string, unknown>[]) : [];
    const records = (Array.isArray(o.Records) ? o.Records : []).map((r) => text(r, 500)).filter(Boolean).slice(0, 3);
    const tag = (name: string) => text(info.find((i) => i.Tag === name)?.TagValue, 20).toLowerCase() || null;

    const facts: NonNullable<MailCheck["facts"]> = {
        records,
        failed: checks(o.Failed),
        warnings: checks(o.Warnings),
        passed: checks(o.Passed),
        policy: null,
    };

    if (command === "dmarc") {
        facts.policy = tag("p") ?? records[0]?.match(/\bp=([a-z]+)/i)?.[1]?.toLowerCase() ?? null;
        facts.subdomainPolicy = tag("sp");
    } else if (command === "spf") {
        const all = info.find((i) => i.Type === "all");
        facts.allQualifier = all ? `${text(all.Prefix, 2) || "+"}all` : records[0]?.match(/([+~?-]?)all\b/)?.[0] ?? null;
        facts.policy = facts.allQualifier;
    }

    return facts;
}

export async function lookupMailRecord(command: MailCheckCommand, argument: string, options: MailCheckOptions): Promise<MailCheck> {
    const base = {
        command,
        argument,
        checkedAt: new Date().toISOString(),
        reference: `https://mxtoolbox.com/SuperTool.aspx?action=${command}%3a${encodeURIComponent(argument)}&run=toolpage`,
        facts: null,
        error: null,
    };

    if (!options.apiKey) {
        return { ...base, status: "not_configured", error: "No MXToolbox API key is configured on the server." };
    }

    try {
        const response = await fetchWithRetry(
            `https://api.mxtoolbox.com/api/v1/Lookup/${command}/?argument=${encodeURIComponent(argument)}`,
            { method: "GET", headers: { Authorization: options.apiKey, Accept: "application/json", "User-Agent": "ThreatIntel-AI header analysis" } },
            { timeoutMs: options.timeoutMs, retry: options.retry ?? INTERACTIVE_RETRY },
        );

        if (response.status === 429) {
            return { ...base, status: "rate_limited", error: "MXToolbox's daily lookup limit was reached; try again after 00:00 UTC." };
        }

        if (response.status === 401 || response.status === 403) {
            return { ...base, status: "error", error: "MXToolbox refused the request; check the API key." };
        }

        if (!response.ok) {
            return { ...base, status: "error", error: `MXToolbox answered HTTP ${response.status}.` };
        }

        const body = (await response.json().catch(() => null)) as Record<string, unknown> | null;

        if (!body || body.IsError === true) {
            return { ...base, status: "error", error: "MXToolbox could not complete the lookup." };
        }

        return { ...base, status: "success", facts: parseMxToolbox(command, body) };
    } catch (error) {
        if (error instanceof DOMException && (error.name === "TimeoutError" || error.name === "AbortError")) {
            return { ...base, status: "timeout", error: "MXToolbox did not answer in time." };
        }

        // Never echo request details: the key is in a header.
        return { ...base, status: "error", error: "MXToolbox could not be reached." };
    }
}
