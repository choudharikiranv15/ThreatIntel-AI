import { hostname } from "node:os";
import { randomUUID } from "node:crypto";

import { investigateCve } from "../engine.js";
import { persistInvestigation } from "../persistence/persist-investigation.js";
import { createKevCatalogCache, fetchKevCatalog } from "../sources/cisa-kev.js";
import { MONITOR_RETRY } from "../sources/request-signal.js";
import type { InvestigationResult } from "../types.js";
import type { Deliverer } from "./delivery.js";
import {
    defaultCheckDependencies,
    healthEvents,
    runWatchCheck,
    type CheckDependencies,
    type CheckOutcome,
} from "./monitor.js";
import { formatNotification } from "./notify.js";
import * as store from "./store.js";

/*
 * The background loop. All schedule and delivery state lives in PostgreSQL, so
 * starting this on any host, after any restart, resumes from the database. The
 * loop itself only decides when to look.
 */

export type WatchSettings = {
    enabled: boolean;
    notifyTarget: string | null;
    tickMinutes: number;
    nvdApiKey?: string;
    requestTimeoutMs: number;
};

export const CHECK_LEASE_SECONDS = 15 * 60;
export const DELIVERY_LEASE_SECONDS = 2 * 60;
export const MAX_DELIVERY_ATTEMPTS = 6;
const CHECKS_PER_TICK = 10;
const DELIVERIES_PER_TICK = 50;
const PAUSE_BETWEEN_CHECKS_MS = 2_000;
const KEV_CACHE_MS = 60 * 60 * 1000;

export function workerId(): string {
    return `${hostname()}:${process.pid}:${randomUUID().slice(0, 8)}`;
}

/** Live investigation for monitoring: patient retries and one KEV download. */
export function createMonitorInvestigator(
    settings: Pick<WatchSettings, "nvdApiKey" | "requestTimeoutMs">,
): (target: string) => Promise<InvestigationResult> {
    const kevCatalog = createKevCatalogCache(
        () => fetchKevCatalog(settings.requestTimeoutMs, undefined, MONITOR_RETRY),
        KEV_CACHE_MS,
    );

    return (target) =>
        investigateCve(target, {
            nvdApiKey: settings.nvdApiKey,
            requestTimeoutMs: settings.requestTimeoutMs,
            retry: MONITOR_RETRY,
            kevCatalog,
        });
}

export type WatchRuntime = {
    owner: string;
    check: CheckDependencies;
    deliverer: Deliverer | null;
    /** Sends threat feed posts to the feed channel. */
    feedDeliverer?: Deliverer | null;
    pauseMs?: number;
    log?: (message: string) => void;
};

/** The threat feed's part of the shared service loop. */
export type FeedHooks = {
    enabled: boolean;
    buildDeliverer: () => Deliverer | null;
    /** Runs a collection cycle if one is due; leases make this safe on every tick. */
    runIfDue: (owner: string, log: (message: string) => void) => Promise<unknown>;
};

const POSSIBLE_REPEAT_NOTE = "\n-# This post may repeat an earlier one: the previous send was interrupted.";

/** Runs a claimed check and records it, including monitoring's own health. */
export async function checkAndRecord(
    entry: store.WatchEntry,
    runtime: WatchRuntime,
): Promise<{ outcome: CheckOutcome; entry: store.WatchEntry | null }> {
    const outcome = await runWatchCheck(entry, runtime.check);

    const updated = await store.completeCheck(
        entry.target,
        runtime.owner,
        outcome.success
            ? {
                success: true,
                outcome: outcome.outcome,
                baselineInvestigationId: outcome.baselineInvestigationId,
            }
            : { success: false, outcome: outcome.outcome, error: outcome.error },
    );

    if (!updated) {
        runtime.log?.(`watch ${entry.target}: lease was lost before the result was recorded`);

        return { outcome, entry: null };
    }

    const health = healthEvents(entry, updated, randomUUID());

    if (health.events.length > 0) {
        await runtime.check.insertEvents(health.events);
    }

    if (health.failureAlerted !== null) {
        await store.setFailureAlerted(updated.target, health.failureAlerted);
    }

    return { outcome, entry: updated };
}

export async function runDueChecks(runtime: WatchRuntime): Promise<number> {
    const claimed = await store.claimDueWatches(
        runtime.owner,
        CHECK_LEASE_SECONDS,
        CHECKS_PER_TICK,
    );

    for (const [index, entry] of claimed.entries()) {
        if (index > 0) {
            // Pacing keeps well inside provider rate limits.
            await new Promise((done) => setTimeout(done, runtime.pauseMs ?? PAUSE_BETWEEN_CHECKS_MS));
        }

        try {
            // Earlier checks in this cycle may have outlasted the claim.
            const renewed = await store.renewLease(entry.target, runtime.owner, CHECK_LEASE_SECONDS);

            if (!renewed) {
                runtime.log?.(`watch ${entry.target}: skipped, another worker holds the lease`);
                continue;
            }

            const { outcome } = await checkAndRecord(renewed, runtime);

            runtime.log?.(`watch ${entry.target}: ${outcome.outcome}`);
        } catch (error) {
            // The lease expires on its own, so the check is retried later.
            runtime.log?.(`watch ${entry.target}: check aborted: ${String(error)}`);
        }
    }

    return claimed.length;
}

/**
 * Sends due notifications, one message per check. Each event is already saved;
 * this only moves it between delivery states.
 */
export async function deliverPending(runtime: WatchRuntime): Promise<{ sent: number; failed: number; handedOff: number }> {
    const counts = { sent: 0, failed: 0, handedOff: 0 };

    const deliverers: Record<store.DeliveryChannel, Deliverer | null> = {
        watch: runtime.deliverer,
        feed: runtime.feedDeliverer ?? null,
    };

    // Only claim what can be sent now, so nothing sits leased without a sender.
    const channels = (Object.keys(deliverers) as store.DeliveryChannel[]).filter((channel) => deliverers[channel]);

    if (channels.length === 0) {
        return counts;
    }

    const claimed = await store.claimDeliveries(
        runtime.owner,
        DELIVERY_LEASE_SECONDS,
        DELIVERIES_PER_TICK,
        channels,
    );

    const groups = new Map<string, store.ClaimedEvent[]>();

    for (const event of claimed) {
        groups.set(event.checkId, [...(groups.get(event.checkId) ?? []), event]);
    }

    for (const events of groups.values()) {
        const ids = events.map((event) => event.id);
        const first = events[0];
        const deliver = deliverers[first.channel];

        if (!deliver) {
            continue;
        }

        const text = first.channel === "feed"
            ? `${first.message ?? ""}${events.some((event) => event.possibleDuplicate) ? POSSIBLE_REPEAT_NOTE : ""}`
            : formatNotification(events);

        const result = await deliver(text);

        if (result.status === "sent") {
            await store.markSent(ids, runtime.owner, result.messageIds);
            counts.sent += events.length;
        } else if (result.status === "handed_off") {
            await store.markHandedOff(ids, runtime.owner, result.note);
            counts.handedOff += events.length;
        } else {
            await store.markFailed(ids, runtime.owner, result.error, {
                maxAttempts: MAX_DELIVERY_ATTEMPTS,
                possibleDuplicate: result.sentBeforeError,
            });
            counts.failed += events.length;
        }
    }

    return counts;
}

export type WatchService = {
    id: string;
    start: (ctx: { logger?: { info: (message: string) => void; warn: (message: string) => void } }) => Promise<void>;
    stop: () => Promise<void>;
    /** Runs one cycle now. Used by tests and by startup recovery. */
    tick: () => Promise<void>;
};

export function createWatchService(
    settings: WatchSettings,
    buildDeliverer: () => Deliverer | null,
    overrides: Partial<Pick<WatchRuntime, "check" | "owner">> = {},
    feed: FeedHooks | null = null,
): WatchService {
    let timer: ReturnType<typeof setInterval> | null = null;
    let firstRun: ReturnType<typeof setTimeout> | null = null;
    let running: Promise<void> | null = null;
    let log: (message: string) => void = () => undefined;

    const owner = overrides.owner ?? workerId();

    const runtime = (): WatchRuntime => ({
        owner,
        check: overrides.check ?? defaultCheckDependencies(
            createMonitorInvestigator(settings),
            persistInvestigation,
            store.insertEvents,
        ),
        deliverer: settings.enabled && settings.notifyTarget ? buildDeliverer() : null,
        feedDeliverer: feed?.enabled ? feed.buildDeliverer() : null,
        log,
    });

    const tick = async (): Promise<void> => {
        // One cycle at a time in this process; leases cover other processes.
        if (running) {
            return running;
        }

        running = (async () => {
            const current = runtime();

            if (settings.enabled) {
                try {
                    await runDueChecks(current);
                } catch (error) {
                    log(`watch: check cycle failed: ${String(error)}`);
                }
            }

            if (feed?.enabled) {
                try {
                    await feed.runIfDue(owner, log);
                } catch (error) {
                    log(`threat feed: cycle failed: ${String(error)}`);
                }
            }

            try {
                await deliverPending(current);
            } catch (error) {
                log(`watch: delivery cycle failed: ${String(error)}`);
            }
        })().finally(() => {
            running = null;
        });

        return running;
    };

    return {
        id: "threatintel-watch",

        async start(ctx) {
            log = (message) => ctx.logger?.info(message);

            if (!settings.enabled && !feed?.enabled) {
                ctx.logger?.info("threatintel watch: monitoring and threat feed disabled by config");
                return;
            }

            if (!settings.enabled) {
                ctx.logger?.info("threatintel watch: monitoring disabled by config; threat feed enabled");
            } else if (!settings.notifyTarget) {
                ctx.logger?.warn("threatintel watch: no watchNotifyTarget set; changes are saved but not sent");
            }

            // A short delay keeps startup work out of the channel-connect window.
            // Anything missed while down is simply overdue, so this catches up.
            firstRun = setTimeout(() => void tick(), 30_000);
            timer = setInterval(() => void tick(), settings.tickMinutes * 60_000);

            firstRun.unref?.();
            timer.unref?.();
        },

        async stop() {
            if (firstRun) clearTimeout(firstRun);
            if (timer) clearInterval(timer);
            firstRun = null;
            timer = null;

            // Let an in-flight cycle finish so its leases are released cleanly.
            await running;
        },

        tick,
    };
}
