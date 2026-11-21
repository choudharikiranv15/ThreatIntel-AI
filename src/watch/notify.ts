import type { WatchEvent } from "./store.js";

/*
 * Formats one Discord message per check. Values come from external sources, so
 * they are escaped: a vendor record must not be able to ping the server or
 * break the formatting.
 */

const DISCORD_LIMIT = 1900;
const MAX_LISTED_CHANGES = 5;

const SOURCE_LINKS: Record<string, (target: string) => string> = {
    NVD: (target) => `https://nvd.nist.gov/vuln/detail/${target}`,
    CISA_KEV: () => "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    REDHAT: (target) => `https://access.redhat.com/security/cve/${target.toLowerCase()}`,
    OSV: (target) => `https://osv.dev/vulnerability/${target}`,
};

const SOURCE_NAMES: Record<string, string> = {
    NVD: "NVD",
    CISA_KEV: "CISA KEV",
    REDHAT: "Red Hat",
    OSV: "OSV",
    EPSS: "FIRST EPSS",
};

/** Neutralises mentions, markdown, and links in untrusted text. */
export function sanitize(text: string, limit = 200): string {
    const clipped = text.length > limit ? `${text.slice(0, limit)}…` : text;

    return clipped
        .replace(/[\r\n]+/g, " ")
        // A zero-width space after @ stops @everyone, @here, and user mentions.
        .replace(/@/g, "@​")
        .replace(/<(?=[@#&!:a])/g, "<​")
        .replace(/([\\*_~`|>[\]()])/g, "\\$1");
}

function describeValue(value: unknown): string {
    if (value === null || value === undefined) {
        return "none";
    }

    if (Array.isArray(value)) {
        return value.length === 0 ? "none" : value.map(String).join(", ");
    }

    if (typeof value === "object") {
        const record = value as Record<string, unknown>;

        // Version-list changes are stored as added/removed summaries.
        if ("added" in record || "removed" in record) {
            const parts: string[] = [];

            if (Array.isArray(record.added) && record.added.length > 0) {
                parts.push(`added ${record.addedTotal ?? record.added.length}: ${record.added.slice(0, 3).join(", ")}`);
            }

            if (Array.isArray(record.removed) && record.removed.length > 0) {
                parts.push(`removed ${record.removedTotal ?? record.removed.length}: ${record.removed.slice(0, 3).join(", ")}`);
            }

            return parts.join("; ") || "changed";
        }

        return JSON.stringify(value);
    }

    return String(value);
}

const KIND_TITLES: Record<WatchEvent["kind"], string> = {
    intelligence_change: "Intelligence change",
    integrity_warning: "Integrity warning",
    baseline_reset: "Baseline reset",
    monitor_failure: "Monitoring failure",
    monitor_recovered: "Monitoring recovered",
    // Feed posts carry their own rendered text and never come through here.
    threat_feed: "Threat feed",
};

export function formatNotification(events: WatchEvent[]): string {
    const [first] = events;
    const target = sanitize(first.target, 40);
    const changes = events.filter((event) => event.kind === "intelligence_change");
    const headline = changes.length > 0
        ? `${changes.length} intelligence change${changes.length === 1 ? "" : "s"}`
        : KIND_TITLES[first.kind];

    const lines: string[] = [`**ThreatIntel watch: ${target}** (${headline})`];

    if (events.some((event) => event.possibleDuplicate)) {
        lines.push("_This alert may repeat an earlier delivery that was interrupted._");
    }

    for (const event of events.slice(0, MAX_LISTED_CHANGES)) {
        const label = sanitize([event.field, event.scope].filter(Boolean).join(" "), 80);

        const values = event.kind === "intelligence_change"
            ? `: ${sanitize(describeValue(event.before), 120)} → **${sanitize(describeValue(event.after), 120)}**`
            : "";

        lines.push(`• ${KIND_TITLES[event.kind]}${label ? `, ${label}` : ""}${values}`);
        lines.push(`  ${sanitize(event.explanation, 300)}`);
    }

    if (events.length > MAX_LISTED_CHANGES) {
        lines.push(`…and ${events.length - MAX_LISTED_CHANGES} more. Ask the bot to compare investigations of ${target}.`);
    }

    const sources = [...new Set(events.flatMap((event) => event.sources))]
        .filter((source) => SOURCE_LINKS[source]);

    if (sources.length > 0) {
        // Angle brackets stop Discord from embedding a preview for each link.
        lines.push(
            `Sources: ${sources.map((source) => `${SOURCE_NAMES[source]} <${SOURCE_LINKS[source](first.target)}>`).join(" · ")}`,
        );
    }

    const investigation = first.investigationId ?? first.baselineInvestigationId;

    lines.push(
        `Observed ${first.observedAt}${investigation ? ` · investigation ${investigation}` : ""}`,
    );

    const message = lines.join("\n");

    return message.length <= DISCORD_LIMIT
        ? message
        : `${message.slice(0, DISCORD_LIMIT - 1)}…`;
}
