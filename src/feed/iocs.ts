import { decodeEntities } from "./rss.js";
import type { Ioc, IocType } from "./types.js";

/*
 * Indicators are taken only from a source's own "Indicators of Compromise"
 * section, or from an indicator file the source links to. Nothing elsewhere on
 * a page counts: articles also mention example domains, reference links, and
 * version numbers that look like indicators. Values are kept exactly as
 * published, including defanging such as hxxp and [.], so a hunter can search
 * for what the source wrote.
 */

/** Most indicators kept per item; sources occasionally publish thousands. */
export const MAX_IOCS = 500;

const HEADING = /<(h[1-6])[^>]*>([\s\S]*?)<\/\1>|<(p|strong|b)[^>]*>\s*(?:<(?:strong|b)[^>]*>)?([^<]{0,80})(?:<\/(?:strong|b)>)?\s*<\/\3>/gi;

// "Indicators" alone is how The DFIR Report titles its section; it must be the whole heading.
const IOC_TITLE = /\b(indicators? of compromise|iocs?)\b|^\s*indicators\s*:?\s*$/i;

/* Page furniture that follows an article: a section never extends into it. */
const CHROME_HEADING = /^(share this|related (posts?|articles?|content)|leave a (reply|comment)|comments?|subscribe|newsletter|tags?|about the author|recent posts)\b/i;
const CHROME_TAG = /<(?:footer|main)\b|<[a-z]+[^>]+(?:id|class)\s*=\s*["'][^"']*\b(?:comments?|related-posts?|share-buttons?|sidebar)\b/i;

/* Sites that host references and analysis, never the threat itself. */
const REFERENCE_HOSTS = /(^|\.)(github\.com|githubusercontent\.com|virustotal\.com|any\.run|hybrid-analysis\.com|urlscan\.io|attack\.mitre\.org|twitter\.com|x\.com|linkedin\.com|youtube\.com|cisa\.gov|nist\.gov|mitre\.org|w3\.org|wikipedia\.org)$/i;

/* What a source says when its indicators need care before blocking. */
const CAUTION = /[^.\n]*\b(?:shared (?:saas |hosting )?infrastructure|legitimate (?:services?|infrastructure)|may not want to (?:apply|block)|do not block|false positives?|sinkhole[ds]?|benign)\b[^.\n]*\.?/i;

function headingLevel(tag: string): number {
    return /^h[1-6]$/i.test(tag) ? Number(tag[1]) : 7;
}

function withoutScripts(html: string): string {
    return html.replace(/<(script|style|noscript)\b[\s\S]*?<\/\1>/gi, " ");
}

/** The HTML of each indicator section, from its heading to the next heading of the same or higher level. */
export function iocSections(rawHtml: string): string[] {
    const html = withoutScripts(rawHtml);

    const headings = [...html.matchAll(HEADING)].map((match) => ({
        index: match.index ?? 0,
        end: (match.index ?? 0) + match[0].length,
        level: headingLevel(match[1] ?? match[3] ?? "p"),
        text: decodeEntities((match[2] ?? match[4] ?? "").replace(/<[^>]+>/g, " ")).trim(),
    }));

    const sections: string[] = [];

    for (const [position, heading] of headings.entries()) {
        if (!IOC_TITLE.test(heading.text) || heading.text.length > 80) {
            continue;
        }

        const next = headings
            .slice(position + 1)
            .find((other) => (other.level <= heading.level && other.level < 7) || CHROME_HEADING.test(other.text));

        let section = html.slice(heading.end, next ? next.index : html.length);
        const chrome = section.search(CHROME_TAG);

        if (chrome >= 0) {
            section = section.slice(0, chrome);
        }

        sections.push(section);
    }

    return sections;
}

const PATTERNS: Array<{ type: IocType; pattern: RegExp }> = [
    // Defanged parts ("[.]", "[:]") are part of the URL; other brackets end it.
    { type: "url", pattern: /\b(?:hxxps?|https?|fxp|ftp)(?:\[:\]|:)\/\/(?:[^\s<>"'()[\]]|\[\.\]|\[:\])+/gi },
    { type: "sha256", pattern: /\b[a-f0-9]{64}\b/gi },
    { type: "sha1", pattern: /\b[a-f0-9]{40}\b/gi },
    { type: "md5", pattern: /\b[a-f0-9]{32}\b/gi },
    {
        type: "ipv4",
        pattern: /\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:(?:\[\.\]|\.)(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b/g,
    },
    // Only defanged domains: an undefanged name in an indicator section may be a reference.
    { type: "domain", pattern: /\b(?:[a-z0-9-]+(?:\[\.\]|\.))*[a-z0-9-]+\[\.\][a-z]{2,24}\b/gi },
];

const FILE_NAME = /^[\w.-]{1,120}\.(?:exe|dll|ps1|psm1|bat|cmd|vbs|vbe|js|jse|jar|msi|lnk|hta|scr|iso|img|zip|rar|7z|sh|elf|so|py|docm|xlsm|pptm|wsf|sys)$/i;

/* The most directly huntable types first, so a shortened post keeps them. */
const TYPE_ORDER: IocType[] = ["ipv4", "domain", "url", "sha256", "filename", "sha1", "md5"];

function hostOf(url: string): string {
    try {
        return new URL(url.replace(/^hxxp/i, "http").replace(/\[:\]/g, ":").replace(/\[\.\]/g, ".")).hostname.toLowerCase();
    } catch {
        return "";
    }
}

function cells(sectionHtml: string): string[] {
    return [...sectionHtml.matchAll(/<(td|li|code)[^>]*>([\s\S]*?)<\/\1>/gi)].map((match) =>
        decodeEntities(match[2].replace(/<[^>]+>/g, " ")).replace(/\s+/g, " ").trim(),
    );
}

class Collector {
    private readonly found = new Map<string, Ioc>();

    constructor(private readonly sourceUrl: string) {}

    add(type: IocType, value: string, note?: string): void {
        const key = `${type}:${value.toLowerCase()}`;

        if (!this.found.has(key)) {
            this.found.set(key, { type, value, source: this.sourceUrl, ...(note ? { note } : {}) });
        }
    }

    list(): Ioc[] {
        return [...this.found.values()];
    }
}

/** Orders by usefulness and caps the list, noting the cap so the count is never silently wrong. */
export function finalizeIocs(iocs: Ioc[]): Ioc[] {
    const ordered = [...iocs].sort((a, b) => TYPE_ORDER.indexOf(a.type) - TYPE_ORDER.indexOf(b.type));

    if (ordered.length <= MAX_IOCS) {
        return ordered;
    }

    const note = `The source lists ${ordered.length} indicators; the first ${MAX_IOCS} are kept here.`;

    return ordered.slice(0, MAX_IOCS).map((ioc) => ({ ...ioc, note: ioc.note ?? note }));
}

/** Indicators from the given HTML's indicator sections, deduplicated. */
export function extractIocs(html: string, sourceUrl: string): Ioc[] {
    const collector = new Collector(sourceUrl);
    const ownHost = hostOf(sourceUrl);

    for (const section of iocSections(html)) {
        let text = decodeEntities(section.replace(/<[^>]+>/g, " "));

        // The source's own warning about these indicators travels with them.
        const caution = text.match(CAUTION)?.[0].replace(/\s+/g, " ").trim().slice(0, 240);

        for (const { type, pattern } of PATTERNS) {
            for (const match of text.matchAll(pattern)) {
                // Sentence punctuation after a URL is not part of it.
                const value = type === "url" ? match[0].replace(/[.,;:!?]+$/, "") : match[0];

                if (type === "url") {
                    const host = hostOf(value);

                    // Links to the article's own site or to reference sites are not indicators.
                    if (!host || host === ownHost || host.endsWith(`.${ownHost}`) || REFERENCE_HOSTS.test(host)) {
                        continue;
                    }
                }

                collector.add(type, value, caution);
            }

            // A URL's host must not be counted again as a domain or address.
            if (type === "url") {
                text = text.replace(pattern, " ");
            }
        }

        for (const cell of cells(section)) {
            if (FILE_NAME.test(cell)) {
                collector.add("filename", cell, caution);
            }
        }
    }

    return finalizeIocs(collector.list());
}

/* ----------------------------- Indicator files ---------------------------- */

/** Repositories whose files are indicator datasets published by the source itself. */
const INDICATOR_REPOS = [/^https:\/\/github\.com\/The-DFIR-Report\/DFIR-Report-Indicators\/blob\/([\w.-]+)\/([\w./%-]+\.(?:md|txt|csv))$/i];

/** Raw-file URLs of trusted indicator files linked from an article's indicator sections. */
export function indicatorFileLinks(html: string): string[] {
    const links = new Set<string>();

    for (const section of iocSections(html)) {
        for (const match of section.matchAll(/https:\/\/github\.com\/[^\s"'<>)]+/gi)) {
            for (const repo of INDICATOR_REPOS) {
                const parts = match[0].match(repo);

                if (parts) {
                    links.add(`https://raw.githubusercontent.com/The-DFIR-Report/DFIR-Report-Indicators/${parts[1]}/${parts[2]}`);
                }
            }
        }
    }

    return [...links];
}

const PLAIN_DOMAIN = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$/i;
const PLAIN_IPV4 = /^(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;

/**
 * Indicators from a dedicated indicator file: one value per line inside code
 * fences. The whole file is an indicator list, so plain domains and links to
 * hosting sites count here, unlike in an article.
 */
export function extractIocsFromIndicatorFile(text: string, sourceUrl: string): Ioc[] {
    const collector = new Collector(sourceUrl);
    let fenced = false;

    for (const raw of text.split(/\r?\n/)) {
        const line = raw.trim();

        if (line.startsWith("```")) {
            fenced = !fenced;
            continue;
        }

        if (!fenced || !line || /\s/.test(line)) {
            continue;
        }

        if (/^[a-f0-9]{64}$/i.test(line)) collector.add("sha256", line);
        else if (/^[a-f0-9]{40}$/i.test(line)) collector.add("sha1", line);
        else if (/^[a-f0-9]{32}$/i.test(line)) collector.add("md5", line);
        else if (PLAIN_IPV4.test(line) || /^\d{1,3}(?:\[\.\]\d{1,3}){3}$/.test(line)) collector.add("ipv4", line);
        else if (/^(?:hxxps?|https?)(?:\[:\]|:)\/\//i.test(line)) collector.add("url", line);
        else if (PLAIN_DOMAIN.test(line) || /\[\.\]/.test(line)) collector.add("domain", line);
    }

    return finalizeIocs(collector.list());
}
