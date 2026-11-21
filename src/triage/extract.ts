import { organisationalDomain } from "../email/headers.js";
import { parseIndicator, type Indicator } from "../lookup/indicator.js";

/*
 * Pulls the indicators out of pasted alert text: URLs, IPv4 addresses, file
 * hashes, domains, and the domains of email addresses, defanged or not.
 * Conservative by design: a file name such as svchost.exe or report.py is
 * not a domain, a version number is not an address, and anything internal is
 * kept on the gateway. Every indicator dropped is counted or named, so the
 * analyst knows what was not checked.
 */

export const MAX_TRIAGE_INPUT = 20_000;
export const DEFAULT_MAX_INDICATORS = 25;

/* Domains every alert links to (the security consoles themselves): named as skipped, never sent. */
export const DEFAULT_INFRASTRUCTURE = [
    "microsoft.com", "microsoftonline.com", "windows.com", "office.com", "office365.com", "azure.com",
    "crowdstrike.com", "sentinelone.com", "sentinelone.net", "paloaltonetworks.com", "fluencysecurity.com", "strangebee.com",
];

/* Generic TLDs accepted for bare domains (inside a URL any TLD is accepted). Unusual ones are missed, not guessed. */
const GENERIC_TLDS = new Set(`com net org info biz edu gov mil int app dev xyz top online site club shop store tech live cloud icu buzz
work win bid loan click link best fun vip pro mobi name asia today world space website digital email network services support
solutions agency company center group life news blog page host lol cyber rest wiki ink one cfd sbs bond lat cam beauty hair
quest monster cyou autos boats homes skin makeup gdn bar art men date download review stream trade racing party science
accountant faith cricket webcam kim ltd inc llc global finance bank insure money capital exchange market media social chat
cam email help tools zone systems software solutions security tips guru plus city fit design studio live ninja rocks wtf`.split(/\s+/));

/* Two-letter country TLDs that are far more often file extensions. */
const EXTENSION_LIKE = new Set(["py", "sh", "md", "rs", "pl", "ps", "cs", "so", "mo", "ts", "js", "db", "ko", "gz", "xz", "bz"]);

export type Extraction = {
    indicators: Indicator[];
    /** Private, reserved, or internal values found: kept on the gateway. */
    internal: number;
    /** Console and vendor domains every alert carries, named so nothing is silently dropped. */
    infrastructure: string[];
    /** Found but over the per-triage cap, in the order they would have been checked. */
    overCap: string[];
};

/** Restores defanged text so indicators can be found in it. */
export function refangText(text: string): string {
    return text
        .replace(/\bh[xX]{2}p(s?)(\[?:\]?\/\/|:\/\/)/g, "http$1://")
        .replace(/\bf[xX]p(\[?:\]?\/\/|:\/\/)/g, "ftp://")
        .replace(/\[\s*(?:\.|dot)\s*\]|\(\s*(?:\.|dot)\s*\)|\{\s*(?:\.|dot)\s*\}/gi, ".")
        .replace(/\[:\]/g, ":")
        .replace(/\[\s*@\s*\]|\[at\]/gi, "@");
}

const URL_RE = /\b(?:https?|ftp):\/\/[^\s"'<>()[\]{}|\\^`]+/gi;
const EMAIL_RE = /\b[A-Za-z0-9._%+-]+@((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,24})\b/g;
const HASH_RE = /(?<![A-Fa-f0-9])(?:[A-Fa-f0-9]{64}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{32})(?![A-Fa-f0-9])/g;
const IPV4_RE = /(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\d.])/g;
const DOMAIN_RE = /(?<![A-Za-z0-9_@./\\-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}(?![A-Za-z0-9_\\-]|\.[A-Za-z0-9])/g;

/* Internal host names: counted as kept on the gateway, never sent. */
const INTERNAL_NAME = /\.(?:local|localhost|internal|intranet|lan|home|corp|private)$/i;

function bareDomainTld(domain: string): boolean {
    const tld = domain.split(".").pop()!.toLowerCase();

    return tld.length === 2 ? !EXTENSION_LIKE.has(tld) : GENERIC_TLDS.has(tld);
}

const ORDER: Record<Indicator["type"], number> = { sha256: 0, sha1: 1, md5: 2, url: 3, ipv4: 4, domain: 5 };

export function extractIndicators(raw: string, options: { maxIndicators?: number; infrastructure?: string[] } = {}): Extraction {
    const text = refangText(raw.slice(0, MAX_TRIAGE_INPUT));
    const infrastructure = new Set((options.infrastructure ?? DEFAULT_INFRASTRUCTURE).map((d) => d.toLowerCase()));
    const found = new Map<string, Indicator>();
    const skipped = new Set<string>();
    const internalValues = new Set<string>();

    const isInfrastructure = (host: string) => {
        const org = organisationalDomain(host);

        return Boolean(org && infrastructure.has(org));
    };

    const add = (candidate: string) => {
        const parsed = parseIndicator(candidate);

        if ("error" in parsed) {
            if (parsed.error === "not_public") internalValues.add(candidate.toLowerCase());
            return;
        }

        const host = parsed.type === "url" ? new URL(parsed.value).hostname : parsed.type === "domain" ? parsed.value : null;

        if (host && isInfrastructure(host)) {
            skipped.add(organisationalDomain(host)!);
            return;
        }

        if (!found.has(parsed.value)) {
            found.set(parsed.value, { value: parsed.value, type: parsed.type });
        }
    };

    let rest = text;

    for (const match of text.match(URL_RE) ?? []) {
        const url = match.replace(/[.,;:!?'")\]]+$/, "");

        add(url);

        try {
            add(new URL(url).hostname);
        } catch {
            /* Unreadable URL: already refused by add. */
        }

        rest = rest.replace(match, " ");
    }

    for (const match of rest.matchAll(EMAIL_RE)) add(match[1]);
    rest = rest.replace(EMAIL_RE, " ");

    for (const match of rest.match(HASH_RE) ?? []) {
        // One repeated character is padding, not a hash.
        if (!/^(.)\1+$/.test(match)) add(match);
    }

    rest = rest.replace(HASH_RE, " ");

    for (const match of rest.matchAll(IPV4_RE)) {
        // "Agent version 23.4.2.14" is a version, even though it is a valid address.
        const before = rest.slice(Math.max(0, (match.index ?? 0) - 12), match.index);

        if (!/(?:version|ver\.?|\bv|build|release)\s*[:=]?\s*$/i.test(before)) add(match[0]);
    }

    rest = rest.replace(IPV4_RE, " ");

    for (const match of rest.match(DOMAIN_RE) ?? []) {
        if (bareDomainTld(match)) add(match);
        else if (INTERNAL_NAME.test(match)) internalValues.add(match.toLowerCase());
    }

    const ordered = [...found.values()].sort((a, b) => ORDER[a.type] - ORDER[b.type]);
    const max = options.maxIndicators ?? DEFAULT_MAX_INDICATORS;

    return {
        indicators: ordered.slice(0, max),
        internal: internalValues.size,
        infrastructure: [...skipped].sort(),
        overCap: ordered.slice(max).map((i) => i.value),
    };
}
