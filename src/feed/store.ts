import { createHash, randomUUID } from "node:crypto";

import { db } from "../persistence/db.js";
import type { Decision, PublishedState, RecentCve } from "./select.js";
import type { EvaluatedItem, Exploitation, Ioc, Priority, ProviderOutcome, Severity } from "./types.js";

/*
 * Feed persistence. The feed_state row is the schedule and the lock, leased the
 * same way as watchlist rows. Selected posts go into the watch_events outbox
 * (channel 'feed'), so delivery, retries, and duplicate labelling are shared
 * with watch alerts.
 */

export type FeedState = {
    nextRunAt: string;
    lastRunAt: string | null;
    lastSuccessAt: string | null;
    lastPublishedAt: string | null;
    consecutiveFailures: number;
    lastError: string | null;
    leaseOwner: string | null;
    leaseExpiresAt: string | null;
};

type StateRow = {
    next_run_at: Date;
    last_run_at: Date | null;
    last_success_at: Date | null;
    last_published_at: Date | null;
    consecutive_failures: number;
    last_error: string | null;
    lease_owner: string | null;
    lease_expires_at: Date | null;
};

const iso = (value: Date | null): string | null => (value ? value.toISOString() : null);

function toState(row: StateRow): FeedState {
    return {
        nextRunAt: row.next_run_at.toISOString(),
        lastRunAt: iso(row.last_run_at),
        lastSuccessAt: iso(row.last_success_at),
        lastPublishedAt: iso(row.last_published_at),
        consecutiveFailures: row.consecutive_failures,
        lastError: row.last_error,
        leaseOwner: row.lease_owner,
        leaseExpiresAt: iso(row.lease_expires_at),
    };
}

/** Takes the feed lease when a run is due and no live lease is held. One atomic update. */
export async function claimFeedRun(owner: string, leaseSeconds: number): Promise<FeedState | null> {
    const { rows } = await db.query<StateRow>(
        `UPDATE public.feed_state
         SET lease_owner = $1,
             lease_expires_at = now() + make_interval(secs => $2::int),
             last_run_at = now()
         WHERE id = 1
           AND next_run_at <= now()
           AND (lease_expires_at IS NULL OR lease_expires_at < now())
         RETURNING *`,
        [owner, leaseSeconds],
    );

    return rows[0] ? toState(rows[0]) : null;
}

export async function getFeedState(): Promise<FeedState | null> {
    const { rows } = await db.query<StateRow>("SELECT * FROM public.feed_state WHERE id = 1");

    return rows[0] ? toState(rows[0]) : null;
}

/** Makes the next cycle due now. The running scheduler picks it up. */
export async function requestRunNow(): Promise<void> {
    await db.query("UPDATE public.feed_state SET next_run_at = now() WHERE id = 1");
}

export async function startRun(): Promise<string> {
    const { rows } = await db.query<{ id: string }>("INSERT INTO public.feed_runs DEFAULT VALUES RETURNING id");

    return rows[0].id;
}

export type RunCounts = {
    discovered: number;
    newItems: number;
    updatedItems: number;
    filtered: number;
    duplicatesSuppressed: number;
    selected: number;
    deferred: number;
};

export const EMPTY_COUNTS: RunCounts = {
    discovered: 0,
    newItems: 0,
    updatedItems: 0,
    filtered: 0,
    duplicatesSuppressed: 0,
    selected: 0,
    deferred: 0,
};

/**
 * Records the run and releases the lease. A failed run retries sooner, backing
 * off from 30 minutes, never later than the normal interval. Only the lease
 * holder can record, so a worker that lost its lease cannot reschedule.
 */
export async function finishRun(
    runId: string,
    owner: string,
    result: {
        status: "success" | "partial" | "failed";
        counts: RunCounts;
        providers: ProviderOutcome[];
        error: string | null;
        durationMs: number;
        published: boolean;
    },
    intervalHours: number,
): Promise<boolean> {
    const client = await db.connect();

    try {
        await client.query("BEGIN");

        await client.query(
            `UPDATE public.feed_runs
             SET finished_at = now(), status = $2, duration_ms = $3,
                 discovered = $4, new_items = $5, updated_items = $6, filtered = $7,
                 duplicates_suppressed = $8, selected = $9, deferred = $10,
                 providers = $11, error = $12
             WHERE id = $1`,
            [
                runId,
                result.status,
                result.durationMs,
                result.counts.discovered,
                result.counts.newItems,
                result.counts.updatedItems,
                result.counts.filtered,
                result.counts.duplicatesSuppressed,
                result.counts.selected,
                result.counts.deferred,
                JSON.stringify(result.providers),
                result.error?.slice(0, 500) ?? null,
            ],
        );

        const failed = result.status === "failed";

        const { rowCount } = await client.query(
            `UPDATE public.feed_state
             SET last_success_at = CASE WHEN $3 THEN last_success_at ELSE now() END,
                 last_published_at = CASE WHEN $5 THEN now() ELSE last_published_at END,
                 consecutive_failures = CASE WHEN $3 THEN consecutive_failures + 1 ELSE 0 END,
                 last_error = $4,
                 next_run_at = now() + CASE
                     WHEN $3 THEN LEAST(
                         make_interval(hours => $2::int),
                         make_interval(mins => (30 * power(2, LEAST(consecutive_failures, 8)))::int)
                     )
                     ELSE make_interval(hours => $2::int)
                 END,
                 lease_owner = NULL,
                 lease_expires_at = NULL
             WHERE id = 1 AND lease_owner = $1`,
            [owner, intervalHours, failed, result.error?.slice(0, 500) ?? null, result.published],
        );

        await client.query("COMMIT");

        return (rowCount ?? 0) > 0;
    } catch (error) {
        await client.query("ROLLBACK").catch(() => undefined);
        throw error;
    } finally {
        client.release();
    }
}

/* --------------------------------- Items --------------------------------- */

export type StoredItem = {
    itemKey: string;
    state: "queued" | "published" | "ignored" | "suppressed" | "expired";
    contentHash: string;
    published: PublishedState | null;
    item: EvaluatedItem;
};

type ItemRow = {
    item_key: string;
    source: string;
    title: string;
    url: string;
    published_at: Date | null;
    cves: string[];
    products: string[];
    platforms: string[];
    iocs: Ioc[];
    severity: Severity;
    exploitation: Exploitation;
    priority: Priority;
    confidence: EvaluatedItem["confidence"];
    reasons: string[];
    content_hash: string;
    state: StoredItem["state"];
    last_published_at: Date | null;
    published_exploitation: Exploitation | null;
    published_ioc_count: number | null;
};

function toStored(row: ItemRow): StoredItem {
    return {
        itemKey: row.item_key,
        state: row.state,
        contentHash: row.content_hash,
        published: row.last_published_at
            ? {
                lastPublishedAt: row.last_published_at.toISOString(),
                exploitation: row.published_exploitation ?? "none",
                iocCount: row.published_ioc_count ?? 0,
            }
            : null,
        // Enough to rank and format a queued item again; matching text is not kept.
        item: {
            source: row.source as EvaluatedItem["source"],
            itemKey: row.item_key,
            title: row.title,
            url: row.url,
            publishedAt: iso(row.published_at),
            text: "",
            cves: row.cves,
            severity: row.severity,
            exploitationClaim: null,
            products: row.products,
            platforms: row.platforms,
            sectors: [],
            iocs: row.iocs,
            kevListed: false,
            priority: row.priority,
            confidence: row.confidence,
            exploitation: row.exploitation,
            reasons: row.reasons,
            matchedBioPharma: [],
            matchedSecurityProducts: [],
            matchedLogSources: [],
        },
    };
}

/** The fields whose change makes an item worth deciding again. */
export function contentHash(item: EvaluatedItem): string {
    return createHash("sha256")
        .update(
            JSON.stringify([
                item.title,
                item.url,
                [...item.cves].sort(),
                item.severity,
                item.exploitation,
                item.priority,
                item.iocs.map((ioc) => `${ioc.type}:${ioc.value}`).sort(),
                [...item.products].sort(),
                [...item.platforms].sort(),
            ]),
        )
        .digest("hex");
}

export async function loadItems(keys: string[]): Promise<Map<string, StoredItem>> {
    if (keys.length === 0) {
        return new Map();
    }

    const { rows } = await db.query<ItemRow>("SELECT * FROM public.feed_items WHERE item_key = ANY($1::text[])", [keys]);

    return new Map(rows.map((row) => [row.item_key, toStored(row)]));
}

/** Items waiting from earlier cycles. */
export async function loadQueued(): Promise<StoredItem[]> {
    const { rows } = await db.query<ItemRow>("SELECT * FROM public.feed_items WHERE state = 'queued'");

    return rows.map(toStored);
}

/** Saves what was seen this cycle. New items start queued; existing items keep their state. */
export async function upsertItems(items: Array<EvaluatedItem & { contentHash: string }>, maxAgeDays: number): Promise<void> {
    if (items.length === 0) {
        return;
    }

    await db.query(
        `INSERT INTO public.feed_items AS f (
             item_key, source, title, url, published_at, cves, products, platforms, iocs,
             severity, exploitation, priority, confidence, reasons, content_hash, state, expires_at
         )
         SELECT r.item_key, r.source, r.title, r.url, r.published_at, r.cves, r.products, r.platforms, r.iocs,
                r.severity, r.exploitation, r.priority, r.confidence, r.reasons, r.content_hash, 'queued',
                COALESCE(r.published_at, now()) + make_interval(days => $2::int)
         FROM jsonb_to_recordset($1::jsonb) AS r(
             item_key text, source text, title text, url text, published_at timestamptz,
             cves text[], products text[], platforms text[], iocs jsonb,
             severity text, exploitation text, priority text, confidence text, reasons jsonb, content_hash text
         )
         ON CONFLICT (item_key) DO UPDATE SET
             title = EXCLUDED.title,
             url = EXCLUDED.url,
             published_at = COALESCE(EXCLUDED.published_at, f.published_at),
             cves = EXCLUDED.cves,
             products = EXCLUDED.products,
             platforms = EXCLUDED.platforms,
             iocs = EXCLUDED.iocs,
             severity = EXCLUDED.severity,
             exploitation = EXCLUDED.exploitation,
             priority = EXCLUDED.priority,
             confidence = EXCLUDED.confidence,
             reasons = EXCLUDED.reasons,
             content_hash = EXCLUDED.content_hash,
             last_seen_at = now(),
             retrieved_at = now()`,
        [
            JSON.stringify(
                items.map((item) => ({
                    item_key: item.itemKey,
                    source: item.source,
                    title: item.title,
                    url: item.url,
                    published_at: item.publishedAt,
                    cves: item.cves,
                    products: item.products,
                    platforms: item.platforms,
                    iocs: item.iocs,
                    severity: item.severity,
                    exploitation: item.exploitation,
                    priority: item.priority,
                    confidence: item.confidence,
                    reasons: item.reasons,
                    content_hash: item.contentHash,
                })),
            ),
            maxAgeDays,
        ],
    );
}

/** The latest post of each CVE within the window, from any feed item. */
export async function recentCves(days: number): Promise<Map<string, RecentCve>> {
    const { rows } = await db.query<{
        cve: string;
        item_key: string;
        last_published_at: Date;
        published_exploitation: Exploitation | null;
        published_ioc_count: number | null;
    }>(
        `SELECT DISTINCT ON (cve) cve, item_key, last_published_at, published_exploitation, published_ioc_count
         FROM public.feed_items, unnest(cves) AS cve
         WHERE last_published_at > now() - make_interval(days => $1::int)
         ORDER BY cve, last_published_at DESC`,
        [days],
    );

    return new Map(
        rows.map((row) => [
            row.cve,
            {
                itemKey: row.item_key,
                publishedAt: row.last_published_at.toISOString(),
                exploitation: row.published_exploitation ?? "none",
                iocCount: row.published_ioc_count ?? 0,
            },
        ]),
    );
}

const STATE_FOR: Record<Exclude<Decision["kind"], "publish" | "keep">, StoredItem["state"]> = {
    defer: "queued",
    suppress: "suppressed",
    ignore: "ignored",
    expire: "expired",
};

/**
 * Applies a cycle's decisions in one transaction. A published item's post is
 * inserted into the outbox in the same transaction that marks it published,
 * so a crash can neither lose a post nor post an item twice.
 */
export async function applyDecisions(
    decisions: Map<string, Decision>,
    items: Map<string, EvaluatedItem & { contentHash: string }>,
    messages: Map<string, string>,
): Promise<void> {
    const client = await db.connect();

    try {
        await client.query("BEGIN");

        for (const [itemKey, decision] of decisions) {
            const item = items.get(itemKey);

            if (!item) {
                continue;
            }

            if (decision.kind === "keep") {
                await client.query(
                    "UPDATE public.feed_items SET state = 'published', state_reason = $2 WHERE item_key = $1",
                    [itemKey, decision.reason],
                );
                continue;
            }

            if (decision.kind !== "publish") {
                await client.query(
                    "UPDATE public.feed_items SET state = $2, state_reason = $3 WHERE item_key = $1",
                    [itemKey, STATE_FOR[decision.kind], decision.reason],
                );
                continue;
            }

            const message = messages.get(itemKey);

            if (!message) {
                continue;
            }

            await client.query(
                `INSERT INTO public.watch_events (
                     target, check_id, kind, fingerprint, field, scope, before_value, after_value,
                     explanation, sources, deliverable, delivery_status, next_attempt_at, channel, message
                 )
                 VALUES ($1, $2, 'threat_feed', $3, 'feed', $4, NULL, $5, $6, $7, true, 'pending', now(), 'feed', $8)
                 ON CONFLICT (fingerprint) DO NOTHING`,
                [
                    itemKey,
                    randomUUID(),
                    `feed:${itemKey}:${item.contentHash}`,
                    item.priority,
                    JSON.stringify({ priority: item.priority, exploitation: item.exploitation, updated: decision.updated }),
                    `${item.priority} ${decision.updated ? "update" : "post"}: ${item.reasons.join("; ")}`.slice(0, 1000),
                    JSON.stringify([item.url]),
                    message,
                ],
            );

            await client.query(
                `UPDATE public.feed_items
                 SET state = 'published', state_reason = $2, last_published_at = now(),
                     published_hash = content_hash, published_exploitation = exploitation,
                     published_ioc_count = jsonb_array_length(iocs)
                 WHERE item_key = $1`,
                [itemKey, decision.urgent ? "posted as urgent, above the per-cycle limit" : decision.updated ? "posted as an update" : "posted"],
            );
        }

        await client.query("COMMIT");
    } catch (error) {
        await client.query("ROLLBACK").catch(() => undefined);
        throw error;
    } finally {
        client.release();
    }
}

/** Keeps the table small: items never posted are dropped after 30 days. Posted ones stay as history. */
export async function pruneItems(): Promise<void> {
    await db.query(
        `DELETE FROM public.feed_items
         WHERE last_published_at IS NULL AND state IN ('ignored', 'expired', 'suppressed')
           AND last_seen_at < now() - interval '30 days'`,
    );
}

/* -------------------------------- Status --------------------------------- */

export async function recentRuns(limit: number) {
    const { rows } = await db.query(
        `SELECT id, started_at, finished_at, status, duration_ms, discovered, new_items, updated_items,
                filtered, duplicates_suppressed, selected, deferred, providers, error
         FROM public.feed_runs ORDER BY started_at DESC LIMIT $1`,
        [limit],
    );

    return rows.map((row) => ({
        id: row.id,
        startedAt: iso(row.started_at),
        finishedAt: iso(row.finished_at),
        status: row.status,
        durationMs: row.duration_ms,
        discovered: row.discovered,
        newItems: row.new_items,
        updatedItems: row.updated_items,
        filtered: row.filtered,
        duplicatesSuppressed: row.duplicates_suppressed,
        selected: row.selected,
        deferred: row.deferred,
        providers: row.providers,
        error: row.error,
    }));
}

export async function itemCounts(): Promise<Record<string, number>> {
    const { rows } = await db.query<{ state: string; priority: string; count: string }>(
        "SELECT state, priority, count(*) FROM public.feed_items GROUP BY state, priority",
    );

    return Object.fromEntries(rows.map((row) => [`${row.state}:${row.priority}`, Number(row.count)]));
}

export async function feedDeliveryCounts(): Promise<Record<string, number>> {
    const { rows } = await db.query<{ delivery_status: string; count: string }>(
        "SELECT delivery_status, count(*) FROM public.watch_events WHERE channel = 'feed' GROUP BY delivery_status",
    );

    return Object.fromEntries(rows.map((row) => [row.delivery_status, Number(row.count)]));
}

export async function recentPosts(limit: number) {
    const { rows } = await db.query(
        `SELECT e.target, e.scope, e.observed_at, e.delivery_status, e.attempts, e.last_error, e.message_ids,
                e.possible_duplicate, i.title
         FROM public.watch_events e
         LEFT JOIN public.feed_items i ON i.item_key = e.target
         WHERE e.channel = 'feed' ORDER BY e.observed_at DESC LIMIT $1`,
        [limit],
    );

    return rows.map((row) => ({
        title: row.title ?? row.target,
        item: row.target,
        priority: row.scope,
        selectedAt: iso(row.observed_at),
        deliveryStatus: row.delivery_status,
        attempts: row.attempts,
        lastError: row.last_error,
        messageIds: row.message_ids,
        possibleDuplicate: row.possible_duplicate,
    }));
}
