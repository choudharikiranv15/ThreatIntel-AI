import { SOURCE_LABELS, type FeedSourceId } from "../feed/types.js";
import { parseIndicator, type Indicator } from "../lookup/indicator.js";
import { db } from "../persistence/db.js";

/*
 * Team memory: what the team and the feed already know about an indicator.
 * Built only from records this deployment keeps (earlier lookups and the
 * indicators feed articles published), stated as counts and dates. Who looked
 * something up is never shown.
 */

export type FeedMention = {
    title: string;
    source: string;
    url: string;
    /** When the article was published, or first seen. */
    date: string | null;
    /** Whether the feed posted it. */
    posted: boolean;
};

export type TeamHistory = {
    previousLookups: number;
    analysts: number;
    firstAt: string | null;
    lastAt: string | null;
    feed: FeedMention[];
    statement: string;
};

/* Feed articles publish indicators defanged ("evil[.]com"); lookups store them plain. */
const NORMALISED_IOC = String.raw`regexp_replace(regexp_replace(regexp_replace(lower(trim(i->>'value')), '\[\.\]|\(\.\)|\{\.\}|\[dot\]', '.', 'g'), '^hxxp', 'http'), '\[:\]', ':', 'g')`;

const day = (iso: string | null) => (iso ? iso.slice(0, 10) : "an unknown date");

export function historyStatement(history: Omit<TeamHistory, "statement">): string {
    const parts: string[] = [];

    if (history.previousLookups > 0) {
        const times = history.previousLookups === 1 ? "once" : `${history.previousLookups} times`;
        const people = history.analysts === 1 ? "1 analyst" : `${history.analysts} analysts`;

        parts.push(
            history.previousLookups === 1
                ? `Looked up ${times} before by the team (${day(history.lastAt)}).`
                : `Looked up ${times} before by ${people} (first ${day(history.firstAt)}, last ${day(history.lastAt)}).`,
        );
    } else {
        parts.push("Not looked up by the team before.");
    }

    for (const mention of history.feed) {
        parts.push(`Listed as an indicator in "${mention.title}" (${mention.source}, ${day(mention.date)})${mention.posted ? ", posted to the threat feed" : ""}.`);
    }

    return parts.join(" ");
}

export async function teamHistory(indicator: Indicator, currentLookupId: string): Promise<TeamHistory> {
    const [lookups, mentions] = await Promise.all([
        db.query<{ n: number; people: number; first: Date | null; last: Date | null }>(
            `SELECT count(DISTINCT lookup_id)::int AS n, count(DISTINCT requested_by)::int AS people,
                    min(checked_at) AS first, max(checked_at) AS last
             FROM public.indicator_lookups
             WHERE indicator = $1 AND lookup_id <> $2::uuid`,
            [indicator.value, currentLookupId],
        ),
        db.query<{ title: string; source: string; url: string; d: Date | null; posted: boolean }>(
            `SELECT f.title, f.source, f.url, coalesce(f.published_at, f.first_seen_at) AS d,
                    bool_or(f.last_published_at IS NOT NULL) AS posted
             FROM public.feed_items f, jsonb_array_elements(f.iocs) i
             WHERE ${NORMALISED_IOC} IN ($1, $2)
             GROUP BY f.item_key, f.title, f.source, f.url, d
             ORDER BY d DESC NULLS LAST
             LIMIT 3`,
            // A URL may be stored with or without its trailing slash.
            [indicator.value, indicator.value.replace(/\/$/, "")],
        ),
    ]);

    const row = lookups.rows[0];
    const history = {
        previousLookups: row?.n ?? 0,
        analysts: row?.people ?? 0,
        firstAt: row?.first ? row.first.toISOString() : null,
        lastAt: row?.last ? row.last.toISOString() : null,
        feed: mentions.rows.map((m) => ({
            title: m.title.slice(0, 160),
            source: SOURCE_LABELS[m.source as FeedSourceId] ?? m.source,
            url: m.url,
            date: m.d ? m.d.toISOString() : null,
            posted: m.posted,
        })),
    };

    return { ...history, statement: historyStatement(history) };
}

/* --------------------------------- Retro-hunt -------------------------------- */

export type RetroMatch = {
    itemKey: string;
    /** The indicator as the article published it (often defanged). */
    published: string;
    indicator: string;
    lookups: number;
    lastAt: string;
};

export const RETRO_DAYS = 90;
export const RETRO_MAX_PER_CYCLE = 5;

/**
 * Indicators in newly collected articles that the team looked up in the last
 * RETRO_DAYS days: something checked before now has context.
 */
export async function retroHuntMatches(
    items: Array<{ itemKey: string; iocs: Array<{ value: string; type?: string }> }>,
    query: (values: string[], days: number) => Promise<Array<{ indicator: string; n: number; last: Date }>> = recentLookups,
): Promise<RetroMatch[]> {
    const byValue = new Map<string, { itemKey: string; published: string }>();

    for (const item of items) {
        for (const ioc of item.iocs) {
            // The article's own label wins: "svchost.exe" would otherwise parse as a domain.
            if (ioc.type === "filename") continue;

            const parsed = parseIndicator(ioc.value);

            if (!("error" in parsed) && !byValue.has(parsed.value)) {
                byValue.set(parsed.value, { itemKey: item.itemKey, published: ioc.value });
            }
        }
    }

    if (byValue.size === 0) {
        return [];
    }

    const rows = await query([...byValue.keys()], RETRO_DAYS);

    return rows
        .map((row) => ({ ...byValue.get(row.indicator)!, indicator: row.indicator, lookups: row.n, lastAt: row.last.toISOString() }))
        .sort((a, b) => b.lastAt.localeCompare(a.lastAt))
        .slice(0, RETRO_MAX_PER_CYCLE);
}

async function recentLookups(values: string[], days: number) {
    const { rows } = await db.query<{ indicator: string; n: number; last: Date }>(
        `SELECT indicator, count(DISTINCT lookup_id)::int AS n, max(checked_at) AS last
         FROM public.indicator_lookups
         WHERE indicator = ANY($1::text[]) AND checked_at > now() - make_interval(days => $2::int)
         GROUP BY indicator`,
        [values, days],
    );

    return rows;
}
