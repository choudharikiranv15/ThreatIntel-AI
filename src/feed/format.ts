import { sanitize } from "../watch/notify.js";
import type { EvaluatedItem, Ioc } from "./types.js";

/*
 * The post format the SOC asked for, and nothing else. Every value comes from
 * an external source, so text is escaped against mentions and markdown, and
 * indicators are put in code spans so Discord never turns them into links.
 */

const DISCORD_LIMIT = 1950;
export const NO_IOCS = "No IOCs published in the source.";
const NOT_SPECIFIED = "Not specified in the source.";

const IOC_LABELS: Record<Ioc["type"], string> = {
    ipv4: "IP",
    domain: "Domain",
    url: "URL",
    sha256: "SHA256",
    sha1: "SHA1",
    md5: "MD5",
    filename: "File",
};

function list(values: string[], limit = 8): string {
    const unique = [...new Set(values.map((value) => value.trim()).filter(Boolean))];

    if (unique.length === 0) {
        return NOT_SPECIFIED;
    }

    const shown = unique.slice(0, limit).map((value) => sanitize(value, 120)).join(", ");

    return unique.length > limit ? `${shown}, and ${unique.length - limit} more` : shown;
}

/** A code span that a backtick inside the value cannot break. */
function code(value: string): string {
    return `\`${value.replace(/`/g, "'")}\``;
}

/** The heading: the threat or vulnerability name, never a generic label. */
export function threatName(item: Pick<EvaluatedItem, "title" | "cves">): string {
    const title = item.title.replace(/\s*\(Severity: \w+\)\s*$/i, "").trim();

    if (title) {
        // A bare bulletin id ("GCP-2026-079") says little; name its CVEs when there are few.
        if (!/\bCVE-\d{4}-\d+/i.test(title) && item.cves.length > 0 && item.cves.length <= 3) {
            return `${title}: ${item.cves.join(", ")}`;
        }

        return title;
    }

    return item.cves[0] ?? "Unnamed advisory";
}

/*
 * Discord groups consecutive messages from one sender under a single name, so
 * separate posts can read as one. The divider marks where each post starts.
 */
export const POST_DIVIDER = "━━━━━━━━━━━━━━━━━━━━━━━━━━━━";

export function formatFeedPost(item: EvaluatedItem, options: { updated?: boolean } = {}): string {
    const head = [
        POST_DIVIDER,
        "**Threat Name:**",
        `${sanitize(threatName(item), 180)}${options.updated ? " (updated)" : ""}`,
        "",
        "**Affected Tools / Products:**",
        list(item.products),
        "",
        "**Affected Platforms:**",
        list(item.platforms),
        "",
        "**Article:**",
        // Angle brackets stop a link preview card; the link stays clickable.
        /^https?:\/\/[^\s<>]+$/i.test(item.url) ? `<${item.url}>` : NOT_SPECIFIED,
        "",
        "**IOCs to Hunt:**",
    ].join("\n");

    if (item.iocs.length === 0) {
        return `${head}\n${NO_IOCS}`;
    }

    const lines: string[] = [];
    let length = head.length;

    for (const [index, ioc] of item.iocs.entries()) {
        const line = `- ${IOC_LABELS[ioc.type]}: ${code(ioc.value)}`;
        const remaining = item.iocs.length - index;
        const tail = `\n- …and ${remaining} more in the article.`;

        if (length + line.length + 1 + tail.length > DISCORD_LIMIT) {
            lines.push(`- …and ${remaining} more in the article.`);
            break;
        }

        lines.push(line);
        length += line.length + 1;
    }

    return `${head}\n${lines.join("\n")}`;
}
