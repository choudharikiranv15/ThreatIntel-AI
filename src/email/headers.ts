import { isPublicIpv4 } from "../lookup/indicator.js";

/*
 * Email header analysis, done locally. Nothing here touches the network: the
 * headers are parsed, the authentication results the receiving server wrote
 * are read, and the sender's identities are compared. Raw headers are never
 * stored or sent anywhere, and recipient addresses are left out of the result.
 *
 * Headers are attacker-controlled text. Only the topmost Authentication-Results
 * and Received headers were added by the recipient's own servers; anything
 * further down may have been written by the sender. The result says which is
 * which instead of trusting all of it.
 */

export const MAX_HEADER_INPUT = 64 * 1024;
const MAX_HEADERS = 400;
const MAX_HOPS = 25;

export type Header = { name: string; value: string };

export type AuthVerdict = "pass" | "fail" | "softfail" | "neutral" | "none" | "temperror" | "permerror" | "policy" | "bestguesspass" | "unknown";

export type AuthResults = {
    /** The server that wrote the results, as it names itself. */
    authservId: string | null;
    spf: { result: AuthVerdict; domain: string | null } | null;
    dkim: { result: AuthVerdict; domain: string | null; selector: string | null }[];
    dmarc: { result: AuthVerdict; domain: string | null; policy: string | null } | null;
    /** Microsoft's composite authentication, when present. */
    compauth: AuthVerdict | null;
};

export type Hop = {
    /** 1 is the first server the message passed through. */
    index: number;
    from: string | null;
    fromIp: string | null;
    by: string | null;
    with: string | null;
    at: string | null;
    /** Seconds since the previous hop; negative means the clocks or the headers disagree. */
    delaySeconds: number | null;
};

export type Address = { display: string | null; address: string | null; domain: string | null };

export type Finding = { severity: "high" | "medium" | "info"; code: string; message: string };

export type HeaderAnalysis = {
    from: Address | null;
    returnPath: Address | null;
    replyTo: Address | null;
    sender: Address | null;
    /** Written by the sender: untrusted text. */
    subject: string | null;
    date: string | null;
    messageIdDomain: string | null;
    recipientCount: number;
    authentication: AuthResults | null;
    /** Further Authentication-Results headers: possibly written by the sender, not trusted. */
    otherAuthResults: number;
    dkimSignatures: { domain: string | null; selector: string | null }[];
    receivedSpf: { result: AuthVerdict; clientIp: string | null } | null;
    hops: Hop[];
    /** The earliest public address in the Received chain: the likely sending server. */
    originatingIp: string | null;
    xOriginatingIp: string | null;
    findings: Finding[];
};

export type HeaderRejection = { error: "invalid_headers"; message: string };

/* --------------------------------- Parsing -------------------------------- */

/** Unfolds and splits a header block. Stops at the first blank line, where a body would start. */
export function splitHeaders(raw: string): Header[] {
    const lines = raw.replace(/\r\n?/g, "\n").split("\n");
    const headers: Header[] = [];

    for (const line of lines) {
        if (line.trim() === "") {
            if (headers.length > 0) break;
            continue;
        }

        if (/^[ \t]/.test(line) && headers.length > 0) {
            headers[headers.length - 1].value += ` ${line.trim()}`;
            continue;
        }

        const match = line.match(/^([!-9;-~]+):\s?(.*)$/);

        if (match) {
            headers.push({ name: match[1].toLowerCase(), value: match[2].trim() });

            if (headers.length >= MAX_HEADERS) break;
        }
    }

    return headers;
}

const all = (headers: Header[], name: string) => headers.filter((h) => h.name === name).map((h) => h.value);
const first = (headers: Header[], name: string) => headers.find((h) => h.name === name)?.value ?? null;

const clip = (value: string | null | undefined, limit: number) => (value ? value.replace(/\s+/g, " ").trim().slice(0, limit) : null);

/** Decodes RFC 2047 encoded words, which senders use to hide text in display names and subjects. */
export function decodeWords(value: string): string {
    return value.replace(/=\?([^?]+)\?([bq])\?([^?]*)\?=/gi, (_m, charset: string, encoding: string, text: string) => {
        try {
            const bytes = encoding.toLowerCase() === "b"
                ? Buffer.from(text, "base64")
                : Buffer.from(text.replace(/_/g, " ").replace(/=([0-9a-f]{2})/gi, (_x, hex: string) => String.fromCharCode(parseInt(hex, 16))), "latin1");

            return new TextDecoder(/^utf-?8$/i.test(charset) ? "utf-8" : "latin1").decode(bytes);
        } catch {
            return text;
        }
    });
}

const ADDRESS = /[A-Za-z0-9._%+'=!#$&*/?^`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/;

export function parseAddress(value: string | null): Address | null {
    if (!value) return null;

    const decoded = decodeWords(value);
    const angle = decoded.match(/<([^<>]*)>/);
    const address = (angle?.[1].match(ADDRESS)?.[0] ?? decoded.match(ADDRESS)?.[0] ?? null)?.toLowerCase() ?? null;
    const display = clip(angle ? decoded.slice(0, angle.index).replace(/^["'\s]+|["'\s]+$/g, "") : null, 120) || null;

    return { display, address, domain: address ? address.split("@")[1].replace(/\.$/, "") : null };
}

const VERDICTS: AuthVerdict[] = ["pass", "fail", "softfail", "neutral", "none", "temperror", "permerror", "policy", "bestguesspass"];

function verdict(value: string | undefined): AuthVerdict {
    const v = value?.toLowerCase() as AuthVerdict | undefined;

    return v && VERDICTS.includes(v) ? v : "unknown";
}

/** One Authentication-Results header (RFC 8601). */
export function parseAuthResults(value: string): AuthResults {
    const parts = value.split(";").map((part) => part.trim()).filter(Boolean);
    // Microsoft omits the server's own name and starts with the first result.
    const startsWithResult = /^[a-z-]+\s*=\s*[a-z]+\b/i.test(parts[0] ?? "");
    const authservId = startsWithResult ? null : clip(parts[0]?.split(/\s/)[0], 120);
    const results: AuthResults = { authservId, spf: null, dkim: [], dmarc: null, compauth: null };
    const prop = (part: string, key: string) => part.match(new RegExp(`(?:^|\\s)${key.replace(".", "\\.")}=([^\\s;()]+)`, "i"))?.[1]?.replace(/^@/, "").replace(/^"|"$/g, "").toLowerCase() ?? null;

    for (const part of startsWithResult ? parts : parts.slice(1)) {
        const method = part.match(/^([a-z-]+)\s*=\s*([a-z]+)/i);

        if (!method) continue;

        const [name, result] = [method[1].toLowerCase(), verdict(method[2])];

        if (name === "spf" && !results.spf) {
            results.spf = { result, domain: prop(part, "smtp.mailfrom")?.split("@").pop() ?? prop(part, "smtp.helo") };
        } else if (name === "dkim") {
            results.dkim.push({ result, domain: prop(part, "header.d") ?? prop(part, "header.i")?.split("@").pop() ?? null, selector: prop(part, "header.s") });
        } else if (name === "dmarc" && !results.dmarc) {
            results.dmarc = { result, domain: prop(part, "header.from"), policy: part.match(/\bp=([a-z]+)/i)?.[1]?.toLowerCase() ?? null };
        } else if (name === "compauth") {
            results.compauth = result;
        }
    }

    return results;
}

const IPV4_IN = /(?<![\d.])((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})(?![\d.])/;

/** One Received header: "from X (Y [IP]) by Z with P; date". */
export function parseReceived(value: string): Omit<Hop, "index" | "delaySeconds"> {
    const [route, date] = splitDate(value);
    const fromPart = route.match(/\bfrom\s+([\s\S]*?)(?=\s+by\s|\s+with\s|\s+id\s|\s+for\s|$)/i)?.[1] ?? "";
    const bracketed = fromPart.match(/\[(?:IPv6:)?([^\]]+)\]/i)?.[1];
    const ip = (bracketed && IPV4_IN.test(bracketed) ? bracketed.match(IPV4_IN)?.[1] : fromPart.match(IPV4_IN)?.[1]) ?? null;
    const parsed = date ? Date.parse(date.trim().replace(/\s+\([^)]*\)\s*$/, "")) : NaN;

    return {
        from: clip(fromPart.split(/\s/)[0], 120),
        fromIp: ip,
        by: clip(route.match(/\bby\s+(\S+)/i)?.[1], 120),
        with: clip(route.match(/\bwith\s+(\S+)/i)?.[1], 40),
        at: Number.isNaN(parsed) ? null : new Date(parsed).toISOString(),
    };
}

function splitDate(value: string): [string, string | null] {
    const index = value.lastIndexOf(";");

    return index === -1 ? [value, null] : [value.slice(0, index), value.slice(index + 1)];
}

/* -------------------------------- Comparing ------------------------------- */

/* Second-level registries under which the organisation is one label further down. */
const SECOND_LEVEL = /^(?:co|com|net|org|gov|edu|ac|ltd|plc|me|gen|nic|res|ind|firm|mil|ne|or|go|lg|ed)\.[a-z]{2}$/;

/** The organisational domain, approximately: enough to compare sender identities, not a public-suffix list. */
export function organisationalDomain(domain: string | null): string | null {
    if (!domain) return null;

    const labels = domain.toLowerCase().replace(/\.$/, "").split(".");

    if (labels.length <= 2) return labels.join(".");

    const lastTwo = labels.slice(-2).join(".");

    return SECOND_LEVEL.test(lastTwo) ? labels.slice(-3).join(".") : lastTwo;
}

const sameOrg = (a: string | null, b: string | null) => Boolean(a && b && organisationalDomain(a) === organisationalDomain(b));

/* --------------------------------- Analysis ------------------------------- */

export function analyseHeaders(raw: unknown): HeaderAnalysis | HeaderRejection {
    if (typeof raw !== "string" || raw.trim().length === 0) {
        return { error: "invalid_headers", message: "Paste the full email headers (as shown by 'Show original' or 'View message source')." };
    }

    if (raw.length > MAX_HEADER_INPUT) {
        return { error: "invalid_headers", message: `Headers are limited to ${MAX_HEADER_INPUT / 1024} KB; paste the header block only, without the body.` };
    }

    const headers = splitHeaders(raw);

    if (!headers.some((h) => h.name === "received" || h.name === "from" || h.name === "authentication-results")) {
        return { error: "invalid_headers", message: "No email headers found. Paste the header block, which starts with lines such as 'Received:' and 'From:'." };
    }

    const from = parseAddress(first(headers, "from"));
    const returnPath = parseAddress(first(headers, "return-path"));
    const replyTo = parseAddress(first(headers, "reply-to"));
    const sender = parseAddress(first(headers, "sender"));
    const authHeaders = all(headers, "authentication-results");
    const authentication = authHeaders.length > 0 ? parseAuthResults(authHeaders[0]) : null;

    const dkimSignatures = all(headers, "dkim-signature").slice(0, 5).map((value) => ({
        domain: value.match(/(?:^|;)\s*d=([^;\s]+)/i)?.[1]?.toLowerCase() ?? null,
        selector: value.match(/(?:^|;)\s*s=([^;\s]+)/i)?.[1] ?? null,
    }));

    const spfHeader = first(headers, "received-spf");
    const receivedSpf = spfHeader
        ? { result: verdict(spfHeader.match(/^\s*([a-z]+)/i)?.[1]), clientIp: spfHeader.match(/client-ip=([0-9.]+)/i)?.[1] ?? null }
        : null;

    // Received headers are prepended: the last one is the first hop.
    const received = all(headers, "received").slice(0, MAX_HOPS).reverse().map(parseReceived);
    const hops: Hop[] = received.map((hop, i) => {
        const previous = received[i - 1]?.at;
        const delay = hop.at && previous ? Math.round((Date.parse(hop.at) - Date.parse(previous)) / 1000) : null;

        return { index: i + 1, ...hop, delaySeconds: delay };
    });

    const originatingIp = hops.find((hop) => hop.fromIp && isPublicIpv4(hop.fromIp))?.fromIp ?? null;
    const xOrig = first(headers, "x-originating-ip") ?? first(headers, "x-sender-ip");
    const recipients = [...all(headers, "to"), ...all(headers, "cc")].join(",").match(new RegExp(ADDRESS, "g")) ?? [];

    const analysis: HeaderAnalysis = {
        from,
        returnPath,
        replyTo,
        sender,
        subject: clip(decodeWords(first(headers, "subject") ?? ""), 200),
        date: clip(first(headers, "date"), 60),
        messageIdDomain: first(headers, "message-id")?.match(/@([^>\s]+)>?/)?.[1]?.toLowerCase().slice(0, 120) ?? null,
        recipientCount: new Set(recipients.map((r) => r.toLowerCase())).size,
        authentication,
        otherAuthResults: Math.max(0, authHeaders.length - 1),
        dkimSignatures,
        receivedSpf,
        hops,
        originatingIp,
        xOriginatingIp: xOrig?.match(IPV4_IN)?.[1] ?? null,
        findings: [],
    };

    analysis.findings = findingsFor(analysis);

    return analysis;
}

const BAD: AuthVerdict[] = ["fail", "softfail", "permerror"];

function findingsFor(a: HeaderAnalysis): Finding[] {
    const findings: Finding[] = [];
    const add = (severity: Finding["severity"], code: string, message: string) => findings.push({ severity, code, message });
    const fromDomain = a.from?.domain ?? null;
    const auth = a.authentication;

    if (!fromDomain) {
        add("high", "from_missing", "The From header has no readable address.");
    }

    if (!auth) {
        add("medium", "no_auth_results", "No Authentication-Results header: the receiving server's SPF, DKIM, and DMARC verdicts are not in these headers.");
    } else {
        if (auth.dmarc && BAD.includes(auth.dmarc.result)) {
            add("high", "dmarc_fail", `DMARC ${auth.dmarc.result} for ${auth.dmarc.domain ?? fromDomain ?? "the From domain"}${auth.dmarc.policy ? ` (policy ${auth.dmarc.policy})` : ""}: the From domain is not authenticated.`);
        } else if (!auth.dmarc || auth.dmarc.result === "none") {
            add("medium", "dmarc_none", "No DMARC result: the From domain may publish no DMARC policy, so it can be spoofed more easily.");
        }

        if (auth.spf && BAD.includes(auth.spf.result)) {
            add(auth.spf.result === "softfail" ? "medium" : "high", "spf_fail", `SPF ${auth.spf.result} for ${auth.spf.domain ?? "the envelope sender"}: the sending server is not authorised for that domain.`);
        } else if (!auth.spf || auth.spf.result === "none" || auth.spf.result === "neutral") {
            add("medium", "spf_none", `SPF ${auth.spf?.result ?? "not evaluated"}: no SPF authorisation for the envelope sender.`);
        }

        const dkimPass = auth.dkim.filter((d) => d.result === "pass");

        if (auth.dkim.some((d) => BAD.includes(d.result)) && dkimPass.length === 0) {
            add("high", "dkim_fail", "DKIM failed: the signature does not verify, so the message may have been altered or the signature forged.");
        } else if (auth.dkim.length === 0 || auth.dkim.every((d) => d.result === "none")) {
            add("medium", "dkim_none", "No DKIM signature was verified.");
        } else if (fromDomain && dkimPass.length > 0 && !dkimPass.some((d) => sameOrg(d.domain, fromDomain))) {
            add("medium", "dkim_unaligned", `DKIM passes only for ${dkimPass.map((d) => d.domain).join(", ")}, not for the From domain ${fromDomain}.`);
        }

        if (auth.compauth && BAD.includes(auth.compauth)) {
            add("high", "compauth_fail", `Microsoft composite authentication: ${auth.compauth}.`);
        }
    }

    if (a.otherAuthResults > 0) {
        add("info", "extra_auth_results", `${a.otherAuthResults} further Authentication-Results header(s) were ignored: only the topmost was added by the receiving server; others may have been written by the sender.`);
    }

    if (fromDomain && a.returnPath?.domain && !sameOrg(fromDomain, a.returnPath.domain)) {
        add("medium", "return_path_mismatch", `The envelope sender (Return-Path) domain ${a.returnPath.domain} differs from the From domain ${fromDomain}. Common for bulk mail services; with failed authentication it suggests spoofing.`);
    }

    if (fromDomain && a.replyTo?.domain && !sameOrg(fromDomain, a.replyTo.domain)) {
        add("high", "reply_to_mismatch", `Replies go to ${a.replyTo.domain}, not to the From domain ${fromDomain}: a common sign of phishing and business email compromise.`);
    }

    const displayAddress = a.from?.display?.match(ADDRESS)?.[0]?.toLowerCase();

    if (displayAddress && a.from?.address && displayAddress !== a.from.address) {
        add("high", "display_name_spoof", `The display name shows ${displayAddress}, but the message is from ${a.from.address}.`);
    }

    if (fromDomain && a.messageIdDomain && !sameOrg(fromDomain, a.messageIdDomain)) {
        add("info", "message_id_domain", `The Message-ID was created at ${a.messageIdDomain}, not the From domain; normal for mail sent through a provider.`);
    }

    if (a.hops.some((hop) => hop.delaySeconds !== null && hop.delaySeconds < -300)) {
        add("info", "hop_time_order", "Some Received timestamps go backwards by more than five minutes: clocks differ, or headers were added or altered.");
    }

    if (a.xOriginatingIp && a.originatingIp && a.xOriginatingIp !== a.originatingIp) {
        add("info", "x_originating_ip", `X-Originating-IP names ${a.xOriginatingIp}, the client that submitted the message.`);
    }

    return findings;
}
