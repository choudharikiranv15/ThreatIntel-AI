import { randomUUID } from "node:crypto";

import { parseIndicator } from "../lookup/indicator.js";
import { analyseHeaders, organisationalDomain, type HeaderAnalysis, type HeaderRejection } from "./headers.js";
import { lookupMailRecord, type MailCheck, type MailCheckCommand, type MailCheckOptions } from "./mxtoolbox.js";
import * as store from "./store.js";

/*
 * One header analysis: parse locally, then check the sender domain's published
 * SPF, DMARC, and DKIM records with MXToolbox, within its small daily quota.
 * Only public domains are ever sent; the headers stay on the gateway.
 */

export type HeaderAnalysisSettings = {
    /** False turns the MXToolbox checks off; the local analysis still runs. */
    dnsChecks: boolean;
    cacheHours: number;
    dailyBudget: number;
    perUserPerHour: number;
    options: MailCheckOptions;
};

export type HeaderAnalysisDeps = {
    fetchRecord?: typeof lookupMailRecord;
    store?: Pick<typeof store, "cachedMailCheck" | "mailCallsToday" | "analysesLastHour" | "recordMailChecks">;
};

export type HeaderAnalysisPayload = HeaderAnalysis & {
    kind: "email_headers";
    dnsChecks: MailCheck[];
    statement: string;
    notes: string[];
};

const NOTES = [
    "Authentication results come from the receiving server's topmost Authentication-Results header; lower headers may be forged by the sender and are not used.",
    "Passing SPF, DKIM, and DMARC shows the message really came from that domain, not that the domain or the message is benign: attackers authenticate their own domains.",
    "The subject and display names are written by the sender and are untrusted text.",
    "Recipient addresses are not included, and the headers are not stored or sent anywhere; only the sender domain is checked with MXToolbox.",
    "To check the sending server's reputation, look up originatingIp with the indicator lookup.",
];

/** The DNS checks worth spending quota on: the From domain's SPF and DMARC, and one DKIM key. */
export function plannedChecks(analysis: HeaderAnalysis): { command: MailCheckCommand; argument: string }[] {
    const publicDomain = (domain: string | null) => {
        if (!domain) return null;
        const parsed = parseIndicator(domain);

        return !("error" in parsed) && parsed.type === "domain" ? parsed.value : null;
    };

    const from = publicDomain(analysis.from?.domain ?? null);
    const planned: { command: MailCheckCommand; argument: string }[] = [];

    if (from) {
        planned.push({ command: "spf", argument: from }, { command: "dmarc", argument: from });
    }

    // Prefer the signature for the From domain's organisation.
    const signatures = analysis.dkimSignatures.filter((s) => publicDomain(s.domain) && s.selector && /^[A-Za-z0-9._-]{1,63}$/.test(s.selector));
    const dkim = signatures.find((s) => organisationalDomain(s.domain) === organisationalDomain(from)) ?? signatures[0];

    if (dkim) {
        planned.push({ command: "dkim", argument: `${dkim.domain}:${dkim.selector}` });
    }

    return planned;
}

function describeCheck(check: MailCheck): string {
    if (check.status !== "success" || !check.facts) {
        return `${check.command.toUpperCase()} ${check.argument}: not checked (${check.error ?? check.status})`;
    }

    const f = check.facts;
    const problems = [...f.failed, ...f.warnings].slice(0, 3);
    const record = f.records.length > 0 ? "record published" : "no record found";
    const policy = check.command === "dmarc" && f.policy ? `, policy ${f.policy}` : check.command === "spf" && f.allQualifier ? `, ends ${f.allQualifier}` : "";

    return `${check.command.toUpperCase()} ${check.argument}: ${record}${policy}${problems.length ? `; issues: ${problems.join("; ")}` : ""}`;
}

export function statementFor(analysis: HeaderAnalysis, checks: MailCheck[]): string {
    const auth = analysis.authentication;
    const parts: string[] = [];

    parts.push(
        auth
            ? `Receiving server results${auth.authservId ? ` (${auth.authservId})` : ""}: SPF ${auth.spf?.result ?? "not evaluated"}, DKIM ${auth.dkim.length ? auth.dkim.map((d) => `${d.result}${d.domain ? ` (${d.domain})` : ""}`).join(", ") : "not evaluated"}, DMARC ${auth.dmarc?.result ?? "not evaluated"}.`
            : "No authentication results from the receiving server.",
    );

    const high = analysis.findings.filter((f) => f.severity === "high");
    const medium = analysis.findings.filter((f) => f.severity === "medium");

    if (high.length) parts.push(`High-risk signs: ${high.map((f) => f.message).join(" ")}`);
    if (medium.length) parts.push(`Other concerns: ${medium.map((f) => f.message).join(" ")}`);
    if (!high.length && !medium.length) parts.push("No authentication failures or sender mismatches were found in the headers; that does not make the message safe.");
    if (analysis.originatingIp) parts.push(`Likely sending server: ${analysis.originatingIp}.`);
    if (checks.length) parts.push(`Sender domain DNS (MXToolbox): ${checks.map(describeCheck).join(". ")}.`);

    return parts.join(" ");
}

export async function runHeaderAnalysis(
    raw: unknown,
    requestedBy: string,
    settings: HeaderAnalysisSettings,
    deps: HeaderAnalysisDeps = {},
): Promise<HeaderAnalysisPayload | HeaderRejection> {
    const analysis = analyseHeaders(raw);

    if ("error" in analysis) {
        return analysis;
    }

    const fetchRecord = deps.fetchRecord ?? lookupMailRecord;
    const data = deps.store ?? store;
    const planned = settings.dnsChecks ? plannedChecks(analysis) : [];
    const checks: MailCheck[] = [];

    if (planned.length > 0) {
        const unconfigured = !settings.options.apiKey;
        const limited = !unconfigured && (await data.analysesLastHour(requestedBy)) >= settings.perUserPerHour;
        let spent = unconfigured || limited ? 0 : await data.mailCallsToday();

        for (const { command, argument } of planned) {
            const base = { command, argument, checkedAt: new Date().toISOString(), reference: null, facts: null };

            if (unconfigured) {
                checks.push({ ...base, status: "not_configured", error: "No MXToolbox API key is configured on the server." });
                continue;
            }

            if (limited) {
                checks.push({ ...base, status: "rate_limited", error: `Limit of ${settings.perUserPerHour} analyses with DNS checks per hour reached.` });
                continue;
            }

            const cached = await data.cachedMailCheck(command, argument, settings.cacheHours);

            if (cached) {
                checks.push(cached);
                continue;
            }

            if (spent >= settings.dailyBudget) {
                checks.push({ ...base, status: "budget_exhausted", error: `Today's budget of ${settings.dailyBudget} MXToolbox lookups is used.` });
                continue;
            }

            spent += 1;
            checks.push(await fetchRecord(command, argument, settings.options));
        }

        // Unconfigured checks are reported but not recorded: nothing was sent.
        await data.recordMailChecks(randomUUID(), requestedBy, checks.filter((check) => check.status !== "not_configured"));
    }

    return {
        kind: "email_headers",
        ...analysis,
        dnsChecks: checks,
        statement: statementFor(analysis, checks),
        notes: [...NOTES, ...(checks.some((c) => c.cached) ? ["Some DNS checks are reused from an earlier analysis; checkedAt says when."] : [])],
    };
}
