import { createHmac, randomBytes } from "node:crypto";

import { isPublicIpv4, parseIndicator } from "../lookup/indicator.js";

/*
 * PII redaction for everything sent to the AI provider.
 *
 * Personal and internal details are replaced with stable placeholders such as
 * PII_USER_3f9a1c07: the same value always gets the same placeholder (keyed by
 * a secret that never leaves this process), so the model can still reason
 * about "the same user" or "the same host". Public indicators (external IPs,
 * domains, hashes) are left alone so they can still be investigated.
 * Secrets are removed outright and never restored.
 *
 * Placeholders are turned back into the real values only in replies posted to
 * the chat the data came from; the provider never sees the originals.
 */

export type PiiKind = "EMAILUSER" | "USER" | "HOST" | "IP" | "PHONE" | "NAME";

export type RedactionStats = Partial<Record<PiiKind | "SECRET", number>>;

const MAX_ENTRIES = 20_000;
const SECRET_MARK = "[REDACTED-SECRET]";

export const PLACEHOLDER = /\bPII_(?:EMAILUSER|USER|HOST|IP|PHONE|NAME)_[0-9a-f]{8}\b/g;

/* Path segments that look like DOMAIN\ but are folders, not accounts. */
const NOT_DOMAINS = new Set(["windows", "system32", "syswow64", "appdata", "local", "roaming", "temp", "programdata", "microsoft", "drivers", "etc", "software", "system", "currentcontrolset", "services", "hklm", "hkcu", "hkey_local_machine", "hkey_current_user", "c", "d", "e"]);

/* "From: Jane Doe <jane@example.com>" and the other address headers. */
const ADDRESS_HEADER = /^((?:From|To|Cc|Bcc|Reply-To|Sender|Delivered-To|Resent-From|Resent-To)\s*:\s*)("?)([^"<\n]{1,80}?)\2\s*</gim;

/* Internal DNS suffixes. */
const INTERNAL_HOST = /\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+(?:corp|local|localdomain|internal|intranet|lan|home|private|ad|domain)\b/gi;

const USER_FIELD = /\b(user(?:name)?|user_?id|account(?:_?name)?|target_?user(?:_?name)?|subject_?user(?:_?name)?|sam_?account_?name|logon_?name|login|actor|initiated_?by|caller|src_?user|dst_?user|employee(?:_?name)?|full_?name|display_?name|owner)(\s*[:=]\s*)("[^"\n]{1,80}"|'[^'\n]{1,80}'|[^\s"',;|&<>]{1,80}(?: [A-Z][A-Za-z'-]{1,30})?)/gi;
const HOST_FIELD = /\b(host(?:_?name)?|computer(?:_?name)?|device(?:_?name)?|workstation(?:_?name)?|machine(?:_?name)?|endpoint(?:_?name)?|src_?host|dst_?host|client_?name|agent_?name)(\s*[:=]\s*)("[^"\n]{1,80}"|'[^'\n]{1,80}'|[^\s"',;|&<>]{1,80})/gi;
// DOMAIN\user, and Users\jdoe inside a path; folder names are excluded by NOT_DOMAINS.
const DOMAIN_ACCOUNT = /\b([A-Za-z][A-Za-z0-9_-]{0,14})\\([A-Za-z0-9._$-]{1,64})(?![A-Za-z0-9._$-])/g;
// No "=" in the local part: "smtp.mailfrom=billing@x.com" keeps its label.
const EMAIL = /\b([A-Za-z0-9._%+'-]{1,64})@((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,24})\b/g;
const IPV4 = /(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\d.])/g;
const ONE_IPV4 = new RegExp(`^${IPV4.source}$`);
const PHONE_INTL = /(?<![\w+])\+\d{1,3}[\s.-]?\(?\d{1,4}\)?(?:[\s.-]?\d{2,4}){2,4}(?![\w])/g;
const PHONE_FIELD = /\b(phone|mobile|tel|telephone|cell|contact_?number)(\s*[:=]?\s*)(\+?[\d][\d\s().-]{7,18}\d)/gi;

const SECRETS: RegExp[] = [
    /\b(password|passwd|pwd|pass|secret|client_?secret|api_?key|apikey|access_?key|auth_?token|token|session_?id|cookie)(\s*[:=]\s*)("[^"\n]*"|'[^'\n]*'|[^\s"',;&]+)/gi,
    /\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{8,}/g,
    /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g,
    /\bsk-(?:or-v1-|ant-|proj-)?[A-Za-z0-9_-]{24,}/g,
    /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
    /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g,
    /\bxox[abprs]-[A-Za-z0-9-]{10,}/g,
    /\b[MNO][A-Za-z\d_-]{23,27}\.[A-Za-z\d_-]{6}\.[A-Za-z\d_-]{27,40}\b/g,
    /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)/g,
];

function unquote(value: string): { inner: string; wrap: (s: string) => string } {
    const q = value[0];

    return (q === '"' || q === "'") && value.endsWith(q)
        ? { inner: value.slice(1, -1), wrap: (s) => `${q}${s}${q}` }
        : { inner: value, wrap: (s) => s };
}

const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

export class Redactor {
    private readonly key: Buffer;
    private readonly originals = new Map<string, string>();
    private readonly terms: RegExp | null;

    constructor(options: { terms?: string[]; key?: Buffer } = {}) {
        this.key = options.key ?? randomBytes(32);
        const terms = (options.terms ?? []).map((t) => t.trim()).filter((t) => t.length >= 3);

        this.terms = terms.length ? new RegExp(`\\b(?:${terms.sort((a, b) => b.length - a.length).map(escapeRe).join("|")})\\b`, "gi") : null;
    }

    /** The placeholder for a value; the same value always gets the same one. */
    placeholder(kind: PiiKind, value: string): string {
        const normalised = kind === "NAME" || kind === "USER" || kind === "HOST" || kind === "EMAILUSER" ? value.toLowerCase() : value;
        const token = `PII_${kind}_${createHmac("sha256", this.key).update(`${kind}:${normalised}`).digest("hex").slice(0, 8)}`;

        if (!this.originals.has(token)) {
            if (this.originals.size >= MAX_ENTRIES) {
                this.originals.delete(this.originals.keys().next().value as string);
            }

            this.originals.set(token, value);
        }

        return token;
    }

    redact(text: string, stats: RedactionStats = {}): string {
        if (!text) return text;

        const count = (kind: PiiKind | "SECRET") => (stats[kind] = (stats[kind] ?? 0) + 1);
        const isToken = (s: string) => /^PII_[A-Z]+_[0-9a-f]{8}$/.test(s);
        let out = text;

        /* 1. Secrets go first and never come back. */
        for (const pattern of SECRETS) {
            out = out.replace(pattern, (_match, label?: string, sep?: string) => {
                count("SECRET");
                return typeof sep === "string" && typeof label === "string" && !/^(Bearer|Basic)$/.test(label) ? `${label}${sep}${SECRET_MARK}` : SECRET_MARK;
            });
        }

        /* 2. Named people and other configured terms. */
        if (this.terms) {
            out = out.replace(this.terms, (match) => (count("NAME"), this.placeholder("NAME", match)));
        }

        /* 3a. Display names in address headers: "Jane Doe <jane@example.com>". */
        out = out.replace(ADDRESS_HEADER, (match, head: string, quote: string, display: string) => {
            const name = display.trim();

            if (!name || name.includes("@") || /^PII_/.test(name)) return match;
            count("NAME");
            return `${head}${quote}${this.placeholder("NAME", name)}${quote} <`;
        });

        /* 3b. Email addresses: the person goes, the domain stays (it is often the indicator). */
        out = out.replace(EMAIL, (match, local: string, domain: string) => {
            if (isToken(local)) return match;
            count("EMAILUSER");
            return `${this.placeholder("EMAILUSER", local)}@${domain}`;
        });

        /* 4. DOMAIN\user accounts and user paths (C:\Users\jdoe). */
        out = out.replace(DOMAIN_ACCOUNT, (match, domain: string, user: string) => {
            if (NOT_DOMAINS.has(domain.toLowerCase()) || isToken(user) || user.includes(".exe") || /^(public|default|all users|administrator)$/i.test(user)) return match;
            count("USER");
            return `${domain}\\${this.placeholder("USER", user)}`;
        });

        /* 5. Username and hostname fields in logs and alerts. */
        out = out.replace(USER_FIELD, (match, label: string, sep: string, value: string) => {
            const { inner, wrap } = unquote(value);

            if (!inner || isToken(inner) || /^PII_/.test(inner) || inner.includes("@") || /^(n\/a|null|none|-|system|local service|network service)$/i.test(inner)) return match;
            count("USER");
            return `${label}${sep}${wrap(this.placeholder("USER", inner))}`;
        });

        out = out.replace(HOST_FIELD, (match, label: string, sep: string, value: string) => {
            const { inner, wrap } = unquote(value);

            if (!inner || /^PII_/.test(inner)) return match;

            // A public IP or public domain in a host field is an indicator, not a person's machine.
            const parsed = parseIndicator(inner);

            if (!("error" in parsed) && (parsed.type === "ipv4" || parsed.type === "domain")) return match;
            // A private address is handled by the address rule below.
            if (ONE_IPV4.test(inner)) return match;
            count("HOST");
            return `${label}${sep}${wrap(this.placeholder("HOST", inner))}`;
        });

        /* 6. Internal DNS names anywhere. */
        out = out.replace(INTERNAL_HOST, (match) => (/^PII_/.test(match) ? match : (count("HOST"), this.placeholder("HOST", match))));

        /* 7. Private addresses: the network layout. Public ones are indicators and stay. */
        out = out.replace(IPV4, (match) => {
            if (isPublicIpv4(match) || /^(127\.0\.0\.1|0\.0\.0\.0|169\.254\.169\.254|255\.255\.255\.255)$/.test(match)) return match;
            count("IP");
            return this.placeholder("IP", match);
        });

        /* 8. Phone numbers. */
        out = out.replace(PHONE_FIELD, (_match, label: string, sep: string, value: string) => (count("PHONE"), `${label}${sep}${this.placeholder("PHONE", value)}`));
        out = out.replace(PHONE_INTL, (match) => (count("PHONE"), this.placeholder("PHONE", match)));

        return out;
    }

    /** Puts the real values back, for a reply posted where the data came from. */
    restore(text: string): string {
        return text ? text.replace(PLACEHOLDER, (token) => this.originals.get(token) ?? token) : text;
    }
}

/* ------------------------- Chat-completion bodies ------------------------- */

const SKIP_KEYS = new Set(["role", "tool_call_id", "id", "type", "name", "model"]);

function redactValue(value: unknown, redactor: Redactor, stats: RedactionStats, key?: string): unknown {
    if (typeof value === "string") {
        if (key && SKIP_KEYS.has(key)) return value;

        // Tool-call arguments are JSON text: redact the values inside, where line breaks are real.
        if (key === "arguments") {
            try {
                return JSON.stringify(redactValue(JSON.parse(value), redactor, stats));
            } catch {
                return redactor.redact(value, stats);
            }
        }

        return redactor.redact(value, stats);
    }

    if (Array.isArray(value)) {
        return value.map((item) => redactValue(item, redactor, stats));
    }

    if (value && typeof value === "object") {
        return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([k, v]) => [k, redactValue(v, redactor, stats, k)]));
    }

    return value;
}

/**
 * Redacts the conversation in an OpenAI-style request body: every message
 * (system, user, assistant, tool), including tool-call arguments. Tool
 * definitions, model and sampling settings are left as they are.
 */
export function redactRequestBody(body: Record<string, unknown>, redactor: Redactor): { body: Record<string, unknown>; stats: RedactionStats } {
    const stats: RedactionStats = {};
    const out: Record<string, unknown> = { ...body };

    for (const field of ["messages", "input", "prompt", "system", "instructions"]) {
        if (field in out) {
            out[field] = redactValue(out[field], redactor, stats);
        }
    }

    return { body: out, stats };
}
