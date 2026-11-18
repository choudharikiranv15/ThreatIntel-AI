import { db } from "../persistence/db.js";
import type { Indicator } from "./indicator.js";
import type { LookupSourceId, SourceResult } from "./sources.js";

/*
 * Lookup persistence: cache, daily budgets, per-person limits, and the record
 * of what was sent to which service.
 */

/** Answers worth reusing. Failures are always retried. */
const CACHEABLE = ["success", "observed_absence"];

export async function cachedResult(
    indicator: Indicator,
    source: LookupSourceId,
    maxAgeHours: number,
): Promise<SourceResult | null> {
    const { rows } = await db.query(
        `SELECT source, status, facts, error, reference, checked_at
         FROM public.indicator_lookups
         WHERE indicator = $1 AND source = $2 AND status = ANY($3::text[])
           AND checked_at > now() - make_interval(hours => $4::int)
         ORDER BY checked_at DESC LIMIT 1`,
        [indicator.value, source, CACHEABLE, maxAgeHours],
    );

    const row = rows[0];

    return row
        ? {
            source: row.source,
            status: row.status,
            facts: row.facts,
            error: row.error,
            reference: row.reference,
            checkedAt: row.checked_at.toISOString(),
            cached: true,
        }
        : null;
}

/** Calls made to a service today (UTC), not counting answers served from the cache. */
export async function callsToday(source: LookupSourceId): Promise<number> {
    const { rows } = await db.query<{ n: string }>(
        `SELECT count(*) AS n FROM public.indicator_lookups
         WHERE source = $1 AND NOT cached
           AND status NOT IN ('not_configured', 'not_applicable', 'budget_exhausted')
           AND checked_at >= date_trunc('day', now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'`,
        [source],
    );

    return Number(rows[0].n);
}

/** Lookups one person started in the last hour. */
export async function lookupsLastHour(requestedBy: string): Promise<number> {
    const { rows } = await db.query<{ n: string }>(
        `SELECT count(DISTINCT lookup_id) AS n FROM public.indicator_lookups
         WHERE requested_by = $1 AND checked_at > now() - interval '1 hour'`,
        [requestedBy],
    );

    return Number(rows[0].n);
}

export async function recordLookup(
    lookupId: string,
    indicator: Indicator,
    requestedBy: string,
    results: SourceResult[],
): Promise<void> {
    if (results.length === 0) {
        return;
    }

    await db.query(
        `INSERT INTO public.indicator_lookups
             (lookup_id, indicator, indicator_type, source, status, facts, error, reference, cached, requested_by, checked_at)
         SELECT $1, $2, $3, r.source, r.status, r.facts, r.error, r.reference, r.cached, $4, r.checked_at
         FROM jsonb_to_recordset($5::jsonb) AS r(
             source text, status text, facts jsonb, error text, reference text, cached boolean, checked_at timestamptz
         )`,
        [
            lookupId,
            indicator.value,
            indicator.type,
            requestedBy.slice(0, 120),
            JSON.stringify(results.map((result) => ({
                source: result.source,
                status: result.status,
                facts: result.facts,
                error: result.error,
                reference: result.reference,
                cached: result.cached === true,
                checked_at: result.checkedAt,
            }))),
        ],
    );
}

/** Lookup history is kept for 90 days. */
export async function pruneLookups(): Promise<void> {
    await db.query("DELETE FROM public.indicator_lookups WHERE checked_at < now() - interval '90 days'");
}
