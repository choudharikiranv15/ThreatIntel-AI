import type { CisaKevCatalog } from "../sources/cisa-kev.js";
import { fetchWithRetry, MONITOR_RETRY, type RetryPolicy } from "../sources/request-signal.js";
import { extractIocs } from "./iocs.js";
import { htmlToText, parseFeed, type FeedEntry } from "./rss.js";
import type { FeedSourceId, RawItem, Severity } from "./types.js";

/*
 * One adapter per source. Each turns the source's own format into RawItems and
 * reports only what the source states: no product, link, or indicator is
 * inferred. A source that fails throws, and the cycle records it on its own.
 */

const TEXT_LIMIT = 30_000;
const HTML_LIMIT = 1_000_000;

const CVE = /\bCVE-\d{4}-\d{4,}\b/g;

export function cvesIn(text: string): string[] {
    return [...new Set((text.match(CVE) ?? []).map((cve) => cve.toUpperCase()))];
}

/* ------------------------------- Severity ------------------------------- */

function fromScore(score: number): Severity {
    if (score >= 9) return "critical";
    if (score >= 7) return "high";
    if (score >= 4) return "medium";
    if (score > 0) return "low";
    return "unknown";
}

function fromWord(word: string | undefined): Severity {
    const value = word?.toLowerCase();

    return value === "critical" || value === "high" || value === "medium" || value === "low"
        ? value
        : "unknown";
}

/** The highest severity the source states, by word label or CVSS score. */
export function severityIn(text: string): Severity {
    const label = text.match(/\b(?:Severity|Security Impact Rating|Max(?:imum)? Severity Rating)\s*:?\s*(Critical|High|Medium|Moderate|Low)\b/i);
    const scores = [
        // "CVSS v3.1 Base Score: 9.8". A number followed by "/" is a vector's version, not a score.
        ...[...text.matchAll(/\bCVSS\s*(?:v?\d(?:\.\d)?)?\s*(?:Base\s*)?(?:Score)?\s*[:=]?\s*(?:of\s*)?(\d{1,2}\.\d)\b(?![\d.]*\/)/gi)].map((match) => match[1]),
        // CISA ICS tables: "CVSS Version / Base Score / Base Severity / Vector String / 3.1 / 9.8 / …".
        ...[...text.matchAll(/CVSS Version\s+Base Score\s+Base Severity\s+Vector String\s+[\d.]+\s+(\d{1,2}\.\d)\b/gi)].map((match) => match[1]),
    ]
        .map(Number)
        .filter((score) => score > 0 && score <= 10);

    const byScore = scores.length > 0 ? fromScore(Math.max(...scores)) : "unknown";
    const byLabel = fromWord(label?.[1] === "Moderate" ? "medium" : label?.[1]);

    const rank: Severity[] = ["unknown", "low", "medium", "high", "critical"];

    return rank.indexOf(byScore) >= rank.indexOf(byLabel) ? byScore : byLabel;
}

/* ------------------------------ Exploitation ----------------------------- */

const DENIED = [
    /\bno known public exploitation\b/i,
    /\bnot aware of any (?:public announcements or )?(?:malicious use|exploitation|active exploitation)\b/i,
    /\bnot (?:been |currently )?(?:known to (?:be|have been) )?(?:actively |publicly )?exploited\b/i,
    /\bno (?:evidence|indication|reports?) of (?:active |in-the-wild )?exploitation\b/i,
];

const REPORTED = [
    /\bexploited in the wild\b/i,
    /\bknown to be exploited\b/i,
    /\b(?:is|are|has been|have been) (?:actively )?exploited\b/i,
    /\bactive(?:ly)? exploit(?:ed|ation)\b/i,
    /\baware of (?:\w+ ){0,3}(?:exploitation|attacks?|malicious use)\b/i,
    /\bexploitation (?:has been|was) (?:observed|detected|reported)\b/i,
    /\blimited,? targeted (?:attacks?|exploitation)\b/i,
];

/**
 * What the source's own text claims. A denial wins: CISA ICS advisories carry
 * a standard "no known public exploitation" sentence, and "an attacker could
 * exploit" describes capability, not an attack.
 */
export function exploitationClaimIn(text: string): "reported" | "denied" | null {
    if (DENIED.some((pattern) => pattern.test(text))) {
        return "denied";
    }

    return REPORTED.some((pattern) => pattern.test(text)) ? "reported" : null;
}

/* -------------------------------- Helpers -------------------------------- */

function item(
    source: FeedSourceId,
    itemKey: string,
    fields: Partial<RawItem> & Pick<RawItem, "title" | "url">,
): RawItem {
    const text = (fields.text ?? "").slice(0, TEXT_LIMIT);
    const all = `${fields.title}\n${text}`;

    return {
        source,
        itemKey,
        publishedAt: null,
        cves: cvesIn(all),
        severity: severityIn(all),
        exploitationClaim: exploitationClaimIn(text),
        products: [],
        platforms: [],
        sectors: [],
        iocs: [],
        kevListed: false,
        ...fields,
        text,
    };
}

/** Drops tracking parameters and fragments that make one page look like many. */
export function canonicalUrl(url: string): string {
    try {
        const parsed = new URL(url.trim());

        parsed.hash = parsed.hash.startsWith("#gcp-") ? parsed.hash : "";

        for (const key of [...parsed.searchParams.keys()]) {
            if (/^(utm_|vs_)/i.test(key)) {
                parsed.searchParams.delete(key);
            }
        }

        return parsed.toString();
    } catch {
        return url.trim();
    }
}

function lastPathSegment(url: string): string {
    return new URL(url).pathname.replace(/\/+$/, "").split("/").pop() ?? url;
}

/* -------------------------------- Adapters ------------------------------- */

export function parseKev(catalog: CisaKevCatalog, since: Date): RawItem[] {
    return (catalog.vulnerabilities ?? [])
        .filter((entry) => entry.cveID && entry.dateAdded && new Date(`${entry.dateAdded}T00:00:00Z`) >= since)
        .map((entry) => {
            const cve = entry.cveID!.toUpperCase();
            // The catalog's notes usually start with the vendor's advisory link.
            const vendorLink = entry.notes?.match(/https?:\/\/[^\s;]+/)?.[0];
            const product = [entry.vendorProject, entry.product].filter(Boolean).join(" ");

            return item("cisa-kev", `kev:${cve}`, {
                title: `${cve} ${entry.vulnerabilityName ?? ""}`.trim(),
                url: vendorLink ?? `https://nvd.nist.gov/vuln/detail/${cve}`,
                publishedAt: new Date(`${entry.dateAdded}T00:00:00Z`).toISOString(),
                text: [
                    entry.shortDescription,
                    entry.knownRansomwareCampaignUse === "Known" ? "Known to be used in ransomware campaigns." : "",
                ].join(" "),
                cves: [cve],
                severity: "unknown",
                products: product ? [product] : [],
                kevListed: true,
                exploitationClaim: null,
            });
        });
}

function parseCisa(source: "cisa-advisories" | "cisa-ics", entries: FeedEntry[]): RawItem[] {
    return entries
        // KEV additions are covered by the catalog itself.
        .filter((entry) => !/\bAdds? .*Known Exploited Vulnerabilit/i.test(entry.title))
        .map((entry) => {
            const html = entry.html.slice(0, HTML_LIMIT);
            const text = htmlToText(html);
            const sectors = text.match(/critical infrastructure sectors?\s*:?\s*([^\n]+?)(?:\s+Countries\/Areas Deployed|\n|$)/i)?.[1];
            const ics = /\/ics-(?:advisories|medical-advisories)\//.test(entry.link);

            return item(source, `cisa:${lastPathSegment(entry.link)}`, {
                title: entry.title,
                url: canonicalUrl(entry.link),
                publishedAt: entry.published ?? entry.updated,
                text,
                products: ics ? [entry.title] : [],
                sectors: sectors ? sectors.split(/\s*,\s*/).map((sector) => sector.trim()).filter(Boolean) : [],
                iocs: extractIocs(html, canonicalUrl(entry.link)),
            });
        });
}

function parseMsrc(entries: FeedEntry[]): RawItem[] {
    return entries
        // Only first publications; later revisions are mostly informational edits.
        .filter((entry) => /^1\.0+$/.test(entry.attributes.Revision ?? ""))
        .map((entry) =>
            item("msrc", `msrc:${entry.id}`, {
                title: entry.title,
                url: canonicalUrl(entry.link),
                publishedAt: entry.published,
                text: htmlToText(entry.html),
                products: [entry.title.replace(CVE, "").trim()].filter(Boolean),
                platforms: ["Microsoft"],
            }),
        );
}

const VENDOR_NAMES: Record<"paloalto" | "fortinet" | "cisco" | "aws" | "gcp", string> = {
    paloalto: "Palo Alto Networks",
    fortinet: "Fortinet",
    cisco: "Cisco",
    aws: "AWS",
    gcp: "Google Cloud",
};

function parseVendor(
    source: "paloalto" | "fortinet" | "cisco" | "aws" | "gcp",
    entries: FeedEntry[],
): RawItem[] {
    return entries.map((entry) => {
        let url = canonicalUrl(entry.link);
        const text = htmlToText(entry.html);

        if (source === "aws") {
            // The feed links to an RSS redirect; the bulletin itself is linked in the body.
            url = canonicalUrl(entry.html.match(/https:\/\/aws\.amazon\.com\/security\/security-bulletins\/[^"'<\s]+/)?.[0] ?? url);
        }

        if (source === "cisco") {
            url = canonicalUrl(entry.id.startsWith("http") ? entry.id : url);
        }

        const key = source === "gcp" ? entry.title : lastPathSegment(url);

        // Palo Alto titles are "CVE-… PAN-OS: Title (Severity: X)".
        const product = source === "paloalto"
            ? entry.title.replace(CVE, "").match(/^\s*([^:]+):/)?.[1]?.trim()
            : undefined;

        // Google Cloud gives severity in a table cell of its own.
        const tableSeverity = source === "gcp"
            ? fromWord(entry.html.match(/<td[^>]*>\s*(?:<p>)?\s*(Critical|High|Medium|Low)\s*(?:<\/p>)?\s*<\/td>/i)?.[1])
            : "unknown";

        return item(source, `${source}:${key}`, {
            title: entry.title,
            url,
            publishedAt: entry.published ?? entry.updated,
            text,
            ...(tableSeverity !== "unknown" ? { severity: tableSeverity } : {}),
            // Only Palo Alto states the product in a fixed place. For the others the
            // vendor is what the feed establishes; the title, shown as the heading,
            // carries the detail, and in-scope products are added when matched.
            products: [product ?? VENDOR_NAMES[source]],
            platforms: source === "aws" ? ["AWS"] : source === "gcp" ? ["Google Cloud"] : [],
        });
    });
}

/* ------------------------------- Registry -------------------------------- */

export const FEED_URLS: Record<Exclude<FeedSourceId, "cisa-kev">, string> = {
    "cisa-advisories": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    "cisa-ics": "https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml",
    msrc: "https://api.msrc.microsoft.com/update-guide/rss",
    paloalto: "https://security.paloaltonetworks.com/rss.xml",
    fortinet: "https://filestore.fortinet.com/fortiguard/rss/ir.xml",
    cisco: "https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml",
    aws: "https://aws.amazon.com/security/security-bulletins/rss/feed/",
    gcp: "https://cloud.google.com/feeds/google-cloud-security-bulletins.xml",
};

/** Parses one source's feed document. Exported for tests with recorded feeds. */
export function parseSource(source: Exclude<FeedSourceId, "cisa-kev">, xml: string): RawItem[] {
    const entries = parseFeed(xml);

    switch (source) {
        case "cisa-advisories":
        case "cisa-ics":
            return parseCisa(source, entries);
        case "msrc":
            return parseMsrc(entries);
        default:
            return parseVendor(source, entries);
    }
}

/** Items published within the window. Undated items are kept, since their age is unknown. */
export function withinWindow(items: RawItem[], since: Date): RawItem[] {
    return items.filter((item) => !item.publishedAt || new Date(item.publishedAt) >= since);
}

export type SourceFetcher = (source: FeedSourceId) => Promise<RawItem[]>;

export function createSourceFetcher(options: {
    timeoutMs: number;
    retry?: RetryPolicy;
    since: () => Date;
    kevCatalog: () => Promise<{ catalog: CisaKevCatalog }>;
}): SourceFetcher {
    return async (source) => {
        if (source === "cisa-kev") {
            return parseKev((await options.kevCatalog()).catalog, options.since());
        }

        const response = await fetchWithRetry(
            FEED_URLS[source],
            {
                method: "GET",
                headers: {
                    Accept: "application/rss+xml, application/atom+xml, application/xml, text/xml",
                    "User-Agent": "ThreatIntel-AI feed reader",
                },
            },
            { timeoutMs: options.timeoutMs, retry: options.retry ?? MONITOR_RETRY },
        );

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const body = await response.text();

        if (!/<(rss|feed)[\s>]/i.test(body.slice(0, 2000))) {
            // A bot-check or error page answered with 200.
            throw new Error("the source did not return a feed");
        }

        // Some feeds hold years of history (MSRC lists every CVE); only recent items matter.
        return withinWindow(parseSource(source, body), options.since());
    };
}
