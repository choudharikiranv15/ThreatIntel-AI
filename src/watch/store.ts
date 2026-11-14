import { db } from "../persistence/db.js";

/*
 * PostgreSQL is the source of truth for the watchlist, the schedule, the locks,
 * and the notification outbox. Nothing here depends on process memory, so a
 * restart or a new host picks up exactly where the last one stopped.
 */

export const MIN_INTERVAL_HOURS = 6;
export const MAX_INTERVAL_HOURS = 168;
export const DEFAULT_INTERVAL_HOURS = 24;

export type WatchEntry = {
    target: string;
    enabled: boolean;
    intervalHours: number;
    createdAt: string;
    createdBy: string | null;
    baselineInvestigationId: string | null;
    lastCheckedAt: string | null;
    lastSuccessAt: string | null;
    nextCheckAt: string;
    consecutiveFailures: number;
    lastOutcome: string | null;
    lastError: string | null;
    failureAlerted: boolean;
    leaseOwner: string | null;
    leaseExpiresAt: string | null;
};

type WatchRow = {
    target: string;
    enabled: boolean;
    interval_hours: number;
    created_at: Date;
    created_by: string | null;
    baseline_investigation_id: string | null;
    last_checked_at: Date | null;
    last_success_at: Date | null;
    next_check_at: Date;
    consecutive_failures: number;
    last_outcome: string | null;
    last_error: string | null;
    failure_alerted: boolean;
    lease_owner: string | null;
    lease_expires_at: Date | null;
};

const WATCH_COLUMNS = `
    target, enabled, interval_hours, created_at, created_by,
    baseline_investigation_id, last_checked_at, last_success_at, next_check_at,
    consecutive_failures, last_outcome, last_error, failure_alerted,
    lease_owner, lease_expires_at`;

const iso = (value: Date | null): string | null =>
    value ? value.toISOString() : null;

function toEntry(row: WatchRow): WatchEntry {
    return {
        target: row.target,
        enabled: row.enabled,
        intervalHours: row.interval_hours,
        createdAt: row.created_at.toISOString(),
        createdBy: row.created_by,
        baselineInvestigationId: row.baseline_investigation_id,
        lastCheckedAt: iso(row.last_checked_at),
        lastSuccessAt: iso(row.last_success_at),
        nextCheckAt: row.next_check_at.toISOString(),
        consecutiveFailures: row.consecutive_failures,
        lastOutcome: row.last_outcome,
        lastError: row.last_error,
        failureAlerted: row.failure_alerted,
        leaseOwner: row.lease_owner,
        leaseExpiresAt: iso(row.lease_expires_at),
    };
}

export function normalizeTarget(target: string): string | null {
    const normalized = String(target ?? "").trim().toUpperCase();

    return /^CVE-\d{4}-\d{4,}$/.test(normalized) ? normalized : null;
}

export function validInterval(hours: number): boolean {
    return (
        Number.isInteger(hours) &&
        hours >= MIN_INTERVAL_HOURS &&
        hours <= MAX_INTERVAL_HOURS
    );
}

/* -------------------------------- Watchlist -------------------------------- */

export async function addWatch(
    target: string,
    options: { intervalHours: number; createdBy: string | null; maxEntries: number },
): Promise<{ status: "added" | "exists" | "limit"; entry: WatchEntry | null }> {
    // The count check and insert are one statement, so concurrent adds cannot
    // both slip under the limit. The primary key prevents duplicates.
    const { rows } = await db.query<WatchRow>(
        `INSERT INTO public.watchlist (target, interval_hours, created_by)
         SELECT $1, $2, $3
         WHERE (SELECT count(*) FROM public.watchlist) < $4
         ON CONFLICT (target) DO NOTHING
         RETURNING ${WATCH_COLUMNS}`,
        [target, options.intervalHours, options.createdBy, options.maxEntries],
    );

    if (rows[0]) {
        return { status: "added", entry: toEntry(rows[0]) };
    }

    const existing = await getWatch(target);

    return existing
        ? { status: "exists", entry: existing }
        : { status: "limit", entry: null };
}

export async function removeWatch(target: string): Promise<boolean> {
    // Events are kept: they are the history of what was observed and sent.
    const { rowCount } = await db.query(
        "DELETE FROM public.watchlist WHERE target = $1",
        [target],
    );

    return (rowCount ?? 0) > 0;
}

export async function getWatch(target: string): Promise<WatchEntry | null> {
    const { rows } = await db.query<WatchRow>(
        `SELECT ${WATCH_COLUMNS} FROM public.watchlist WHERE target = $1`,
        [target],
    );

    return rows[0] ? toEntry(rows[0]) : null;
}

export async function listWatches(): Promise<WatchEntry[]> {
    const { rows } = await db.query<WatchRow>(
        `SELECT ${WATCH_COLUMNS} FROM public.watchlist ORDER BY target`,
    );

    return rows.map(toEntry);
}

export async function updateWatch(
    target: string,
    changes: { enabled?: boolean; intervalHours?: number },
): Promise<WatchEntry | null> {
    // Re-enabling schedules a check now; a new interval counts from the last check.
    const { rows } = await db.query<WatchRow>(
        `UPDATE public.watchlist
         SET enabled = COALESCE($2, enabled),
             interval_hours = COALESCE($3, interval_hours),
             next_check_at = CASE
                 WHEN $2 IS TRUE AND NOT enabled THEN now()
                 WHEN $3 IS NOT NULL THEN
                     COALESCE(last_checked_at, now()) + make_interval(hours => $3::int)
                 ELSE next_check_at
             END
         WHERE target = $1
         RETURNING ${WATCH_COLUMNS}`,
        [target, changes.enabled ?? null, changes.intervalHours ?? null],
    );

    return rows[0] ? toEntry(rows[0]) : null;
}

/* --------------------------------- Leases ---------------------------------- */

/**
 * Claims due checks. A lease is taken in one statement using the database's
 * clock, so two workers cannot claim the same CVE, and a crashed worker's lease
 * simply expires.
 */
export async function claimDueWatches(
    owner: string,
    leaseSeconds: number,
    limit: number,
): Promise<WatchEntry[]> {
    const { rows } = await db.query<WatchRow>(
        `UPDATE public.watchlist
         SET lease_owner = $1,
             lease_expires_at = now() + make_interval(secs => $2::int)
         WHERE target IN (
             SELECT target FROM public.watchlist
             WHERE enabled
               AND next_check_at <= now()
               AND (lease_expires_at IS NULL OR lease_expires_at < now())
             ORDER BY next_check_at
             LIMIT $3
             FOR UPDATE SKIP LOCKED
         )
         RETURNING ${WATCH_COLUMNS}`,
        [owner, leaseSeconds, limit],
    );

    return rows.map(toEntry);
}

/** Claims one CVE now, for example right after it is added. */
export async function claimWatch(
    target: string,
    owner: string,
    leaseSeconds: number,
): Promise<WatchEntry | null> {
    const { rows } = await db.query<WatchRow>(
        `UPDATE public.watchlist
         SET lease_owner = $2,
             lease_expires_at = now() + make_interval(secs => $3::int)
         WHERE target = $1
           AND (lease_expires_at IS NULL OR lease_expires_at < now())
         RETURNING ${WATCH_COLUMNS}`,
        [target, owner, leaseSeconds],
    );

    return rows[0] ? toEntry(rows[0]) : null;
}

/**
 * Extends a lease this worker still holds, right before its check starts. A
 * cycle claims several CVEs at once, so a slow cycle could otherwise reach a
 * CVE after its lease expired and another worker took it. Returns null when
 * the lease is no longer this worker's, and the check must then be skipped.
 */
export async function renewLease(
    target: string,
    owner: string,
    leaseSeconds: number,
): Promise<WatchEntry | null> {
    const { rows } = await db.query<WatchRow>(
        `UPDATE public.watchlist
         SET lease_expires_at = now() + make_interval(secs => $3::int)
         WHERE target = $1 AND lease_owner = $2
         RETURNING ${WATCH_COLUMNS}`,
        [target, owner, leaseSeconds],
    );

    return rows[0] ? toEntry(rows[0]) : null;
}

/**
 * Records a check's outcome and releases the lease. Only the lease holder can
 * do this, so a worker whose lease expired cannot overwrite a newer result.
 * Returns null when the lease was lost.
 */
export async function completeCheck(
    target: string,
    owner: string,
    outcome:
        | { success: true; outcome: string; baselineInvestigationId: string | null }
        | { success: false; outcome: string; error: string },
): Promise<WatchEntry | null> {
    const { rows } = outcome.success
        ? await db.query<WatchRow>(
            `UPDATE public.watchlist
             SET last_checked_at = now(),
                 last_success_at = now(),
                 consecutive_failures = 0,
                 last_outcome = $3,
                 last_error = NULL,
                 baseline_investigation_id = COALESCE($4, baseline_investigation_id),
                 next_check_at = now() + make_interval(hours => interval_hours),
                 lease_owner = NULL,
                 lease_expires_at = NULL
             WHERE target = $1 AND lease_owner = $2
             RETURNING ${WATCH_COLUMNS}`,
            [target, owner, outcome.outcome, outcome.baselineInvestigationId],
        )
        // A failed check retries sooner than the interval, backing off: 30 minutes,
        // then doubling, but never later than the normal interval.
        : await db.query<WatchRow>(
            `UPDATE public.watchlist
             SET last_checked_at = now(),
                 consecutive_failures = consecutive_failures + 1,
                 last_outcome = $3,
                 last_error = $4,
                 next_check_at = now() + LEAST(
                     make_interval(hours => interval_hours),
                     make_interval(mins => (30 * power(2, LEAST(consecutive_failures, 8)))::int)
                 ),
                 lease_owner = NULL,
                 lease_expires_at = NULL
             WHERE target = $1 AND lease_owner = $2
             RETURNING ${WATCH_COLUMNS}`,
            [target, owner, outcome.outcome, outcome.error.slice(0, 500)],
        );

    return rows[0] ? toEntry(rows[0]) : null;
}

export async function setFailureAlerted(
    target: string,
    alerted: boolean,
): Promise<void> {
    await db.query(
        "UPDATE public.watchlist SET failure_alerted = $2 WHERE target = $1",
        [target, alerted],
    );
}

/* ---------------------------------- Events --------------------------------- */

export type NewWatchEvent = {
    target: string;
    checkId: string;
    kind:
    | "intelligence_change"
    | "integrity_warning"
    | "baseline_reset"
    | "monitor_failure"
    | "monitor_recovered";
    fingerprint: string;
    field: string | null;
    scope: string | null;
    before: unknown;
    after: unknown;
    explanation: string;
    sources: string[];
    baselineInvestigationId: string | null;
    investigationId: string | null;
    deliverable: boolean;
};

export type WatchEvent = NewWatchEvent & {
    id: string;
    observedAt: string;
    deliveryStatus: string;
    attempts: number;
    nextAttemptAt: string | null;
    lastError: string | null;
    sentAt: string | null;
    messageIds: string[];
    possibleDuplicate: boolean;
};

type EventRow = {
    id: string;
    target: string;
    check_id: string;
    kind: NewWatchEvent["kind"];
    fingerprint: string;
    field: string | null;
    scope: string | null;
    before_value: unknown;
    after_value: unknown;
    explanation: string;
    sources: string[];
    baseline_investigation_id: string | null;
    investigation_id: string | null;
    observed_at: Date;
    deliverable: boolean;
    delivery_status: string;
    attempts: number;
    next_attempt_at: Date | null;
    last_error: string | null;
    sent_at: Date | null;
    message_ids: string[];
    possible_duplicate: boolean;
};

function toEvent(row: EventRow): WatchEvent {
    return {
        id: row.id,
        target: row.target,
        checkId: row.check_id,
        kind: row.kind,
        fingerprint: row.fingerprint,
        field: row.field,
        scope: row.scope,
        before: row.before_value,
        after: row.after_value,
        explanation: row.explanation,
        sources: row.sources,
        baselineInvestigationId: row.baseline_investigation_id,
        investigationId: row.investigation_id,
        observedAt: row.observed_at.toISOString(),
        deliverable: row.deliverable,
        deliveryStatus: row.delivery_status,
        attempts: row.attempts,
        nextAttemptAt: iso(row.next_attempt_at),
        lastError: row.last_error,
        sentAt: iso(row.sent_at),
        messageIds: row.message_ids,
        possibleDuplicate: row.possible_duplicate,
    };
}

/**
 * Saves events before any delivery is attempted. An event already seen, with
 * the same fingerprint, is ignored, so repeated checks store a change once.
 * Returns the events actually inserted.
 */
export async function insertEvents(events: NewWatchEvent[]): Promise<WatchEvent[]> {
    const inserted: WatchEvent[] = [];

    for (const event of events) {
        const { rows } = await db.query<EventRow>(
            `INSERT INTO public.watch_events (
                 target, check_id, kind, fingerprint, field, scope,
                 before_value, after_value, explanation, sources,
                 baseline_investigation_id, investigation_id,
                 deliverable, delivery_status, next_attempt_at
             )
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14,
                     CASE WHEN $13 THEN now() ELSE NULL END)
             ON CONFLICT (fingerprint) DO NOTHING
             RETURNING *`,
            [
                event.target,
                event.checkId,
                event.kind,
                event.fingerprint,
                event.field,
                event.scope,
                JSON.stringify(event.before ?? null),
                JSON.stringify(event.after ?? null),
                event.explanation,
                JSON.stringify(event.sources),
                event.baselineInvestigationId,
                event.investigationId,
                event.deliverable,
                event.deliverable ? "pending" : "not_deliverable",
            ],
        );

        if (rows[0]) {
            inserted.push(toEvent(rows[0]));
        }
    }

    return inserted;
}

export type ClaimedEvent = WatchEvent & {
    /** The previous attempt's lease expired mid-send, so it may have arrived. */
    resumedAfterCrash: boolean;
};

/**
 * Claims deliverable events that are due, including any whose earlier send was
 * interrupted. An interrupted send may already have reached Discord, so it is
 * marked as a possible duplicate rather than resent silently.
 */
export async function claimDeliveries(
    owner: string,
    leaseSeconds: number,
    limit: number,
): Promise<ClaimedEvent[]> {
    const { rows } = await db.query<EventRow & { previous_status: string }>(
        `WITH due AS (
             SELECT id, delivery_status AS previous_status
             FROM public.watch_events
             WHERE deliverable
               AND (
                   (delivery_status = 'pending'
                    AND (next_attempt_at IS NULL OR next_attempt_at <= now()))
                   OR (delivery_status = 'sending' AND lease_expires_at < now())
               )
             ORDER BY observed_at
             LIMIT $3
             FOR UPDATE SKIP LOCKED
         )
         UPDATE public.watch_events AS e
         SET delivery_status = 'sending',
             attempts = e.attempts + 1,
             lease_owner = $1,
             lease_expires_at = now() + make_interval(secs => $2::int),
             possible_duplicate = e.possible_duplicate OR due.previous_status = 'sending'
         FROM due
         WHERE e.id = due.id
         RETURNING e.*, due.previous_status`,
        [owner, leaseSeconds, limit],
    );

    return rows.map((row) => ({
        ...toEvent(row),
        resumedAfterCrash: row.previous_status === "sending",
    }));
}

export async function markSent(
    ids: string[],
    owner: string,
    messageIds: string[],
): Promise<number> {
    const { rowCount } = await db.query(
        `UPDATE public.watch_events
         SET delivery_status = 'sent', sent_at = now(), message_ids = $3,
             last_error = NULL, lease_owner = NULL, lease_expires_at = NULL
         WHERE id = ANY($1::uuid[]) AND lease_owner = $2`,
        [ids, owner, JSON.stringify(messageIds)],
    );

    return rowCount ?? 0;
}

/**
 * Records a failed send. Retries back off from 1 minute, doubling to at most
 * 6 hours; after the last attempt the event stays 'failed' until it is
 * requeued, and is never lost.
 */
export async function markFailed(
    ids: string[],
    owner: string,
    error: string,
    options: { maxAttempts: number; possibleDuplicate: boolean },
): Promise<number> {
    const { rowCount } = await db.query(
        `UPDATE public.watch_events
         SET delivery_status = CASE WHEN attempts >= $4 THEN 'failed' ELSE 'pending' END,
             next_attempt_at = CASE
                 WHEN attempts >= $4 THEN NULL
                 ELSE now() + LEAST(
                     make_interval(hours => 6),
                     make_interval(mins => power(2, LEAST(attempts - 1, 9))::int)
                 )
             END,
             last_error = $3,
             possible_duplicate = possible_duplicate OR $5,
             lease_owner = NULL,
             lease_expires_at = NULL
         WHERE id = ANY($1::uuid[]) AND lease_owner = $2`,
        [ids, owner, error.slice(0, 500), options.maxAttempts, options.possibleDuplicate],
    );

    return rowCount ?? 0;
}

/**
 * OpenClaw's own queue now holds this alert and owns its retries, so ours must
 * never send it again.
 */
export async function markHandedOff(
    ids: string[],
    owner: string,
    note: string,
): Promise<number> {
    const { rowCount } = await db.query(
        `UPDATE public.watch_events
         SET delivery_status = 'handed_off', last_error = $3, next_attempt_at = NULL,
             lease_owner = NULL, lease_expires_at = NULL
         WHERE id = ANY($1::uuid[]) AND lease_owner = $2`,
        [ids, owner, note.slice(0, 500)],
    );

    return rowCount ?? 0;
}

/** Requeues failed deliveries, for example after fixing the channel config. */
export async function requeueFailed(target: string | null): Promise<number> {
    const { rowCount } = await db.query(
        `UPDATE public.watch_events
         SET delivery_status = 'pending', next_attempt_at = now(), attempts = 0
         WHERE delivery_status = 'failed' AND ($1::text IS NULL OR target = $1)`,
        [target],
    );

    return rowCount ?? 0;
}

export async function recentEvents(
    target: string,
    limit: number,
): Promise<WatchEvent[]> {
    const { rows } = await db.query<EventRow>(
        `SELECT * FROM public.watch_events
         WHERE target = $1 ORDER BY observed_at DESC LIMIT $2`,
        [target, limit],
    );

    return rows.map(toEvent);
}

export async function deliveryCounts(): Promise<Record<string, number>> {
    const { rows } = await db.query<{ delivery_status: string; count: string }>(
        `SELECT delivery_status, count(*) FROM public.watch_events GROUP BY delivery_status`,
    );

    return Object.fromEntries(rows.map((row) => [row.delivery_status, Number(row.count)]));
}
