import { PRIORITY_RANK } from "./classify.js";
import type { EvaluatedItem, Exploitation, Priority, Severity } from "./types.js";

/*
 * Decides what one cycle posts. Pure, so every rule is tested without a
 * database. A cycle's schedule is not a posting quota: when nothing
 * qualifies, nothing is posted.
 */

export type SelectionConfig = {
    minPriority: Exclude<Priority, "ignore">;
    maxPostsPerCycle: number;
    /** No repeat post of one item within this window, unless urgent. */
    cooldownHours: number;
    /** A CVE posted within this window is not posted again through another advisory. */
    dedupeDays: number;
    /** Items published longer ago than this are not posted for the first time. */
    maxAgeDays: number;
    /** New or newly confirmed P1 exploitation may exceed the per-cycle limit. */
    urgentBypass: boolean;
    urgentMaxPerCycle: number;
};

export const DEFAULT_SELECTION: SelectionConfig = {
    minPriority: "P3",
    maxPostsPerCycle: 3,
    cooldownHours: 24,
    dedupeDays: 14,
    maxAgeDays: 3,
    urgentBypass: true,
    urgentMaxPerCycle: 2,
};

/** What was posted before for this item. */
export type PublishedState = {
    lastPublishedAt: string;
    exploitation: Exploitation;
    iocCount: number;
};

export type Candidate = {
    item: EvaluatedItem;
    published: PublishedState | null;
};

/** A CVE's most recent post, from any item. */
export type RecentCve = {
    itemKey: string;
    publishedAt: string;
    exploitation: Exploitation;
    iocCount: number;
};

/** A recent post, for recognising the same threat arriving through another article. */
export type RecentPost = {
    itemKey: string;
    title: string;
    publishedAt: string;
    iocValues: ReadonlySet<string>;
};

const TITLE_STOPWORDS = new Set([
    "the", "and", "for", "with", "from", "into", "that", "this", "new", "how", "what", "why", "are", "was",
    "via", "using", "use", "uses", "inside", "attack", "attacks", "threat", "threats", "campaign", "analysis",
    "report", "alert", "flash", "security", "vulnerability", "vulnerabilities", "malware",
]);

function titleWords(title: string): Set<string> {
    return new Set(
        (title.toLowerCase().match(/[a-z0-9]+/g) ?? []).filter((word) => word.length >= 3 && !TITLE_STOPWORDS.has(word)),
    );
}

/** Shared distinctive words over all distinctive words, 0 to 1. */
export function titleSimilarity(a: string, b: string): number {
    const first = titleWords(a);
    const second = titleWords(b);

    if (first.size === 0 || second.size === 0) {
        return 0;
    }

    const shared = [...first].filter((word) => second.has(word)).length;

    return shared / (first.size + second.size - shared);
}

const IOC_OVERLAP = 0.8;
const TITLE_MATCH = 0.7;

/**
 * The recent post that already covers this threat, if any. An item whose
 * indicators were nearly all posted adds nothing to hunt; an item with no CVE
 * and no indicators is the same threat when its title is nearly the same.
 * CVE overlap is handled separately.
 */
export function sameThreat(
    item: EvaluatedItem,
    posts: readonly RecentPost[],
    now: Date,
    config: SelectionConfig,
): RecentPost | null {
    for (const post of posts) {
        if (post.itemKey === item.itemKey || hoursBetween(post.publishedAt, now) > config.dedupeDays * 24) {
            continue;
        }

        if (item.iocs.length > 0) {
            const known = item.iocs.filter((ioc) => post.iocValues.has(ioc.value.toLowerCase())).length;

            if (known / item.iocs.length >= IOC_OVERLAP) {
                return post;
            }
        } else if (item.cves.length === 0 && titleSimilarity(item.title, post.title) >= TITLE_MATCH) {
            return post;
        }
    }

    return null;
}

export type Decision =
    | { kind: "publish"; updated: boolean; urgent: boolean }
    | { kind: "defer"; reason: string }
    | { kind: "suppress"; reason: string }
    | { kind: "ignore"; reason: string }
    | { kind: "expire"; reason: string }
    | { kind: "keep"; reason: string };

const EXPLOITATION_RANK: Record<Exploitation, number> = { confirmed: 3, reported: 2, none: 1 };
const SEVERITY_RANK: Record<Severity, number> = { critical: 5, high: 4, medium: 3, low: 2, unknown: 1 };

function hoursBetween(from: string, to: Date): number {
    return (to.getTime() - new Date(from).getTime()) / 3_600_000;
}

/** Why a published item is worth posting again, or null if it is not. */
export function materialUpdate(item: EvaluatedItem, published: PublishedState): string | null {
    if (EXPLOITATION_RANK[item.exploitation] > EXPLOITATION_RANK[published.exploitation]) {
        return `exploitation is now ${item.exploitation}`;
    }

    if (item.iocs.length > published.iocCount) {
        return `${item.iocs.length - published.iocCount} new indicators`;
    }

    return null;
}

/** True when another recent post already covers every CVE here and this adds nothing. */
function coveredBy(
    item: EvaluatedItem,
    recent: ReadonlyMap<string, RecentCve>,
    now: Date,
    config: SelectionConfig,
): RecentCve | null {
    if (item.cves.length === 0) {
        return null;
    }

    const covering = item.cves.map((cve) => recent.get(cve));

    if (covering.some((entry) => !entry || entry.itemKey === item.itemKey || hoursBetween(entry.publishedAt, now) > config.dedupeDays * 24)) {
        return null;
    }

    const entries = covering as RecentCve[];
    const addsExploitation = entries.every((entry) => EXPLOITATION_RANK[item.exploitation] > EXPLOITATION_RANK[entry.exploitation]);
    const addsIndicators = item.iocs.length > 0 && entries.every((entry) => entry.iocCount === 0);

    return addsExploitation || addsIndicators ? null : entries[0];
}

function rank(a: Candidate, b: Candidate): number {
    return (
        PRIORITY_RANK[a.item.priority] - PRIORITY_RANK[b.item.priority] ||
        EXPLOITATION_RANK[b.item.exploitation] - EXPLOITATION_RANK[a.item.exploitation] ||
        SEVERITY_RANK[b.item.severity] - SEVERITY_RANK[a.item.severity] ||
        (b.item.publishedAt ?? "").localeCompare(a.item.publishedAt ?? "") ||
        a.item.itemKey.localeCompare(b.item.itemKey)
    );
}

export function selectForPublication(
    candidates: Candidate[],
    recentCves: ReadonlyMap<string, RecentCve>,
    config: SelectionConfig,
    now: Date,
    recentPosts: readonly RecentPost[] = [],
): Map<string, Decision> {
    const decisions = new Map<string, Decision>();
    const posts = [...recentPosts];
    const eligible: Array<Candidate & { updated: boolean; urgent: boolean }> = [];

    for (const candidate of candidates) {
        const { item, published } = candidate;

        if (item.priority === "ignore" || PRIORITY_RANK[item.priority] > PRIORITY_RANK[config.minPriority]) {
            decisions.set(item.itemKey, {
                kind: "ignore",
                reason: item.priority === "ignore" ? "below every priority threshold" : `${item.priority} is below the minimum ${config.minPriority}`,
            });
            continue;
        }

        let updated = false;
        let urgent = item.priority === "P1" && item.exploitation === "confirmed";

        if (published) {
            const why = materialUpdate(item, published);

            if (!why) {
                decisions.set(item.itemKey, { kind: "keep", reason: "already posted, no material change" });
                continue;
            }

            updated = true;
            urgent = urgent && published.exploitation !== "confirmed";

            if (!urgent && hoursBetween(published.lastPublishedAt, now) < config.cooldownHours) {
                decisions.set(item.itemKey, { kind: "defer", reason: `updated (${why}) but in cooldown` });
                continue;
            }
        } else if (item.publishedAt && hoursBetween(item.publishedAt, now) > config.maxAgeDays * 24) {
            decisions.set(item.itemKey, { kind: "expire", reason: `published more than ${config.maxAgeDays} days ago` });
            continue;
        }

        eligible.push({ ...candidate, updated, urgent });
    }

    eligible.sort(rank);

    /* CVEs posted in this cycle also count as covered. */
    const covered = new Map(recentCves);
    let posted = 0;
    let urgentPosted = 0;

    for (const candidate of eligible) {
        const { item } = candidate;
        const duplicate = candidate.updated ? null : coveredBy(item, covered, now, config);

        if (duplicate) {
            decisions.set(item.itemKey, { kind: "suppress", reason: `already covered by ${duplicate.itemKey}` });
            continue;
        }

        const repeat = candidate.updated ? null : sameThreat(item, posts, now, config);

        if (repeat) {
            decisions.set(item.itemKey, { kind: "suppress", reason: `same threat as ${repeat.itemKey}, with nothing new to hunt` });
            continue;
        }

        const withinLimit = posted < config.maxPostsPerCycle;
        const urgentException = !withinLimit && candidate.urgent && config.urgentBypass && urgentPosted < config.urgentMaxPerCycle;

        if (!withinLimit && !urgentException) {
            decisions.set(item.itemKey, { kind: "defer", reason: "per-cycle limit reached; kept for a later cycle" });
            continue;
        }

        if (urgentException) {
            urgentPosted += 1;
        } else {
            posted += 1;
        }

        decisions.set(item.itemKey, { kind: "publish", updated: candidate.updated, urgent: urgentException });

        posts.push({
            itemKey: item.itemKey,
            title: item.title,
            publishedAt: now.toISOString(),
            iocValues: new Set(item.iocs.map((ioc) => ioc.value.toLowerCase())),
        });

        for (const cve of item.cves) {
            covered.set(cve, {
                itemKey: item.itemKey,
                publishedAt: now.toISOString(),
                exploitation: item.exploitation,
                iocCount: item.iocs.length,
            });
        }
    }

    return decisions;
}
