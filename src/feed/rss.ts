/*
 * A small RSS 2.0 and Atom reader for the advisory feeds this plugin uses. It
 * reads only item-level title, link, id, dates, description, and attributes,
 * which is all the feeds provide, and never evaluates markup.
 */

export type FeedEntry = {
    title: string;
    link: string;
    id: string;
    /** ISO time, or null when the feed gives none or an unreadable one. */
    published: string | null;
    updated: string | null;
    /** The entry body as published: usually HTML. */
    html: string;
    attributes: Record<string, string>;
};

const NAMED_ENTITIES: Record<string, string> = {
    amp: "&",
    lt: "<",
    gt: ">",
    quot: '"',
    apos: "'",
    nbsp: " ",
};

export function decodeEntities(text: string): string {
    return text.replace(/&(#x[0-9a-f]+|#[0-9]+|[a-z]+);/gi, (whole, code: string) => {
        if (code[0] === "#") {
            const value = code[1] === "x" || code[1] === "X"
                ? Number.parseInt(code.slice(2), 16)
                : Number.parseInt(code.slice(1), 10);

            return Number.isFinite(value) && value > 0 && value <= 0x10ffff
                ? String.fromCodePoint(value)
                : whole;
        }

        return NAMED_ENTITIES[code.toLowerCase()] ?? whole;
    });
}

/** Text of an element's content: CDATA kept verbatim, entities decoded otherwise. */
function contentOf(raw: string): string {
    const cdata = raw.match(/^\s*<!\[CDATA\[([\s\S]*?)\]\]>\s*$/);

    return cdata ? cdata[1] : decodeEntities(raw);
}

function element(block: string, name: string): { content: string; attributes: string } | null {
    const pattern = new RegExp(`<${name}(\\s[^>]*)?(?:/>|>([\\s\\S]*?)</${name}>)`, "i");
    const match = block.match(pattern);

    return match ? { content: match[2] ?? "", attributes: match[1] ?? "" } : null;
}

function attributesOf(text: string): Record<string, string> {
    const attributes: Record<string, string> = {};

    for (const match of text.matchAll(/([\w:-]+)\s*=\s*"([^"]*)"/g)) {
        attributes[match[1]] = decodeEntities(match[2]);
    }

    return attributes;
}

function isoTime(text: string | undefined): string | null {
    if (!text) {
        return null;
    }

    let value = text.trim();

    // CISA writes two-digit years ("Thu, 12 Nov 26 12:00:00 +0000").
    value = value.replace(/^(\w{3},\s+\d{1,2}\s+\w{3}\s+)(\d{2})(\s)/, "$120$2$3");
    // MSRC writes "Z" as an RFC 822 zone ("22:46:06 Z").
    value = value.replace(/\s+Z$/, " +0000");
    // Cisco writes "2026-11-13 20:41:37.0" with no zone; it is UTC.
    value = value.replace(/^(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})(\.\d+)?$/, "$1T$2Z");

    const time = Date.parse(value);

    return Number.isNaN(time) ? null : new Date(time).toISOString();
}

export function parseFeed(xml: string): FeedEntry[] {
    const blocks = [
        ...xml.matchAll(/<item(\s[^>]*)?>([\s\S]*?)<\/item>/gi),
        ...xml.matchAll(/<entry(\s[^>]*)?>([\s\S]*?)<\/entry>/gi),
    ];

    return blocks.map((match) => {
        const block = match[2];
        const title = contentOf(element(block, "title")?.content ?? "").replace(/\s+/g, " ").trim();

        // RSS: <link>url</link>. Atom: <link rel="alternate" href="url"/>.
        const linkElement = element(block, "link");
        let link = contentOf(linkElement?.content ?? "").trim();

        if (!link && linkElement) {
            link = attributesOf(linkElement.attributes).href ?? "";
        }

        const id = contentOf(element(block, "guid")?.content ?? element(block, "id")?.content ?? "").trim() || link;
        const body = element(block, "description") ?? element(block, "content") ?? element(block, "summary");

        return {
            title,
            link,
            id,
            published: isoTime(
                contentOf(element(block, "pubDate")?.content ?? element(block, "published")?.content ?? ""),
            ),
            updated: isoTime(contentOf(element(block, "updated")?.content ?? "")),
            html: contentOf(body?.content ?? ""),
            attributes: attributesOf(match[1] ?? ""),
        };
    });
}

/** Plain text from HTML: tags removed, entities decoded, whitespace collapsed. */
export function htmlToText(html: string): string {
    return decodeEntities(
        html
            .replace(/<(script|style)[\s\S]*?<\/\1>/gi, " ")
            .replace(/<br\s*\/?>|<\/(p|div|li|tr|td|th|h[1-6])>/gi, "\n")
            .replace(/<[^>]+>/g, " "),
    )
        .replace(/[ \t ]+/g, " ")
        .replace(/\s*\n\s*/g, "\n")
        .trim();
}
