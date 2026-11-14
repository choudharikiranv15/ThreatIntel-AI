import { decodeEntities } from "./rss.js";
import type { Ioc, IocType } from "./types.js";

/*
 * Indicators are taken only from a source's own "Indicators of Compromise"
 * section. Nothing elsewhere on a page counts: articles also mention example
 * domains, reference links, and version numbers that look like indicators.
 * Values are kept exactly as published, including defanging such as hxxp and
 * [.], so a hunter can search for what the source wrote.
 */

const HEADING = /<(h[1-6])[^>]*>([\s\S]*?)<\/\1>|<(p|strong|b)[^>]*>\s*(?:<(?:strong|b)[^>]*>)?([^<]{0,80})(?:<\/(?:strong|b)>)?\s*<\/\3>/gi;

const IOC_TITLE = /\b(indicators? of compromise|iocs?)\b/i;

function headingLevel(tag: string): number {
    return /^h[1-6]$/i.test(tag) ? Number(tag[1]) : 7;
}

/** The HTML of each indicator section, from its heading to the next heading of the same or higher level. */
export function iocSections(html: string): string[] {
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
            .find((other) => other.level <= heading.level && other.level < 7);

        sections.push(html.slice(heading.end, next ? next.index : html.length));
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

function cells(sectionHtml: string): string[] {
    return [...sectionHtml.matchAll(/<(td|li|code)[^>]*>([\s\S]*?)<\/\1>/gi)].map((match) =>
        decodeEntities(match[2].replace(/<[^>]+>/g, " ")).replace(/\s+/g, " ").trim(),
    );
}

/** Indicators from the given HTML's indicator sections, deduplicated, in order of appearance. */
export function extractIocs(html: string, sourceUrl: string): Ioc[] {
    const found = new Map<string, Ioc>();

    const add = (type: IocType, value: string) => {
        const key = `${type}:${value.toLowerCase()}`;

        if (!found.has(key)) {
            found.set(key, { type, value, source: sourceUrl });
        }
    };

    for (const section of iocSections(html)) {
        let text = decodeEntities(section.replace(/<[^>]+>/g, " "));

        for (const { type, pattern } of PATTERNS) {
            for (const match of text.matchAll(pattern)) {
                // Sentence punctuation after a URL is not part of it.
                add(type, type === "url" ? match[0].replace(/[.,;:!?]+$/, "") : match[0]);
            }

            // A URL's host must not be counted again as a domain or address.
            if (type === "url") {
                text = text.replace(pattern, " ");
            }
        }

        for (const cell of cells(section)) {
            if (FILE_NAME.test(cell)) {
                add("filename", cell);
            }
        }
    }

    // A hash is not also a shorter hash: drop md5/sha1 matches inside longer ones.
    const values = [...found.values()];

    return values.filter(
        (ioc) =>
            !(ioc.type === "md5" || ioc.type === "sha1") ||
            !values.some(
                (other) =>
                    other !== ioc &&
                    (other.type === "sha256" || other.type === "sha1") &&
                    other.value.length > ioc.value.length &&
                    other.value.toLowerCase().includes(ioc.value.toLowerCase()),
            ),
    );
}
