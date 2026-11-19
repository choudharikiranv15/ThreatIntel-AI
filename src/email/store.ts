import { db } from "../persistence/db.js";
import type { MailCheck, MailCheckCommand } from "./mxtoolbox.js";

/*
 * MXToolbox check persistence: the cache, the daily budget, the per-person
 * limit, and the record of which domain was sent. Headers are never stored.
 */

export async function cachedMailCheck(command: MailCheckCommand, argument: string, maxAgeHours: number): Promise<MailCheck | null> {
    const { rows } = await db.query(
        `SELECT command, argument, status, facts, error, reference, checked_at
         FROM public.mail_checks
         WHERE command = $1 AND argument = $2 AND status = 'success'
           AND checked_at > now() - make_interval(hours => $3::int)
         ORDER BY checked_at DESC LIMIT 1`,
        [command, argument, maxAgeHours],
    );

    const row = rows[0];

    return row
        ? {
            command: row.command,
            argument: row.argument,
            status: row.status,
            facts: row.facts,
            error: row.error,
            reference: row.reference,
            checkedAt: row.checked_at.toISOString(),
            cached: true,
        }
        : null;
}

/** MXToolbox calls made today (UTC); cached answers and checks never sent do not count. */
export async function mailCallsToday(): Promise<number> {
    const { rows } = await db.query<{ n: string }>(
        `SELECT count(*) AS n FROM public.mail_checks
         WHERE NOT cached AND status NOT IN ('not_configured', 'budget_exhausted')
           AND checked_at >= date_trunc('day', now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'`,
    );

    return Number(rows[0].n);
}

/** Header analyses with DNS checks one person started in the last hour. */
export async function analysesLastHour(requestedBy: string): Promise<number> {
    const { rows } = await db.query<{ n: string }>(
        `SELECT count(DISTINCT analysis_id) AS n FROM public.mail_checks
         WHERE requested_by = $1 AND checked_at > now() - interval '1 hour'`,
        [requestedBy],
    );

    return Number(rows[0].n);
}

export async function recordMailChecks(analysisId: string, requestedBy: string, checks: MailCheck[]): Promise<void> {
    if (checks.length === 0) {
        return;
    }

    await db.query(
        `INSERT INTO public.mail_checks
             (analysis_id, command, argument, status, facts, error, reference, cached, requested_by, checked_at)
         SELECT $1, r.command, r.argument, r.status, r.facts, r.error, r.reference, r.cached, $2, r.checked_at
         FROM jsonb_to_recordset($3::jsonb) AS r(
             command text, argument text, status text, facts jsonb, error text, reference text, cached boolean, checked_at timestamptz
         )`,
        [
            analysisId,
            requestedBy.slice(0, 120),
            JSON.stringify(checks.map((check) => ({
                command: check.command,
                argument: check.argument,
                status: check.status,
                facts: check.facts,
                error: check.error,
                reference: check.reference,
                cached: check.cached === true,
                checked_at: check.checkedAt,
            }))),
        ],
    );
}

/** Check history is kept for 90 days. */
export async function pruneMailChecks(): Promise<void> {
    await db.query("DELETE FROM public.mail_checks WHERE checked_at < now() - interval '90 days'");
}
