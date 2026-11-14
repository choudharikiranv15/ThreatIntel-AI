import { Type } from "typebox";

import { safeDatabaseError } from "../persistence/db.js";
import { toToolText } from "../tool-result.js";
import type { CheckOutcome } from "./monitor.js";
import * as store from "./store.js";

/*
 * Watchlist tools. Every one, reads included, requires the runtime's trusted
 * owner flag. That flag comes from OpenClaw (commands.ownerAllowFrom), never
 * from the model's arguments, so a prompt cannot grant itself access.
 */

export type WatchToolContext = {
    senderIsOwner?: boolean;
    requesterSenderId?: string;
};

export type WatchToolDeps = {
    maxEntries: number;
    defaultIntervalHours: number;
    monitoringEnabled: boolean;
    notifyConfigured: boolean;
    /** Establishes a baseline now, under the same lease as scheduled checks. */
    checkNow: (target: string) => Promise<CheckOutcome | null>;
};

type ToolResult = {
    content: { type: "text"; text: string }[];
    details: unknown;
};

function result(payload: unknown): ToolResult {
    const text = toToolText(payload);

    return { content: [{ type: "text", text }], details: text };
}

const OWNER_ONLY = {
    error: "owner_only",
    message:
        "Watchlist access is limited to the bot owner. Ask the owner, or have them add you to commands.ownerAllowFrom.",
};

function denied(context: WatchToolContext): ToolResult | null {
    return context.senderIsOwner === true ? null : result(OWNER_ONLY);
}

function entryView(entry: store.WatchEntry) {
    return {
        target: entry.target,
        enabled: entry.enabled,
        intervalHours: entry.intervalHours,
        lastCheckedAt: entry.lastCheckedAt,
        lastSuccessAt: entry.lastSuccessAt,
        nextCheckAt: entry.nextCheckAt,
        lastOutcome: entry.lastOutcome,
        consecutiveFailures: entry.consecutiveFailures,
        lastError: entry.lastError,
        hasBaseline: entry.baselineInvestigationId !== null,
        baselineInvestigationId: entry.baselineInvestigationId,
    };
}

/* Models tend to relabel bare timestamps with the reader's timezone. */
const TIMES_NOTE = "All timestamps are UTC (ISO 8601). Convert them before stating a local time.";

async function guarded(
    context: WatchToolContext,
    action: string,
    run: () => Promise<unknown>,
): Promise<ToolResult> {
    const refusal = denied(context);

    if (refusal) {
        return refusal;
    }

    try {
        return result(await run());
    } catch (error) {
        throw new Error(safeDatabaseError(action, error));
    }
}

const targetParam = Type.String({
    description: "CVE identifier, for example CVE-2024-3094.",
});

const intervalParam = Type.Optional(
    Type.Integer({
        description: `Hours between checks, ${store.MIN_INTERVAL_HOURS} to ${store.MAX_INTERVAL_HOURS}.`,
        minimum: store.MIN_INTERVAL_HOURS,
        maximum: store.MAX_INTERVAL_HOURS,
    }),
);

function invalidTarget(target: unknown) {
    return {
        error: "invalid_target",
        message: `Not a CVE identifier: ${String(target).slice(0, 40)}`,
    };
}

export const WATCH_TOOL_DEFINITIONS = {
    add: {
        name: "threatintel_watch_add",
        label: "ThreatIntel Watch Add",
        description: [
            "Add a CVE to the persistent watchlist, owner only.",
            "An immediate investigation becomes the baseline; later checks report only verified intelligence changes.",
            "If the result says owner_only, tell the user only the bot owner can manage the watchlist.",
            "Report the baseline outcome exactly; a failed baseline is retried on schedule.",
        ].join(" "),
        parameters: Type.Object({
            target: targetParam,
            intervalHours: intervalParam,
        }),
    },
    remove: {
        name: "threatintel_watch_remove",
        label: "ThreatIntel Watch Remove",
        description:
            "Remove a CVE from the watchlist, owner only. Past alerts are kept as history.",
        parameters: Type.Object({ target: targetParam }),
    },
    list: {
        name: "threatintel_watch_list",
        label: "ThreatIntel Watch List",
        description:
            "List watched CVEs with their schedule and last result, owner only. Report total when the list is capped.",
        parameters: Type.Object({}),
    },
    set: {
        name: "threatintel_watch_set",
        label: "ThreatIntel Watch Set",
        description:
            "Enable or disable monitoring of a watched CVE, or change its interval, owner only.",
        parameters: Type.Object({
            target: targetParam,
            enabled: Type.Optional(Type.Boolean()),
            intervalHours: intervalParam,
        }),
    },
    status: {
        name: "threatintel_watch_status",
        label: "ThreatIntel Watch Status",
        description: [
            "Show monitoring status, owner only: whether monitoring is running, a CVE's last and next check, recent events, and delivery state.",
            "Set retryFailedDeliveries=true to requeue alerts whose delivery failed.",
            "Describe not_deliverable events as recorded without alerting, and failed deliveries as kept for retry.",
        ].join(" "),
        parameters: Type.Object({
            target: Type.Optional(targetParam),
            retryFailedDeliveries: Type.Optional(Type.Boolean()),
        }),
    },
} as const;

export function buildWatchTools(context: WatchToolContext, deps: WatchToolDeps) {
    const { add, remove, list, set, status } = WATCH_TOOL_DEFINITIONS;

    return {
        add: {
            ...add,
            execute: async (_id: string, params: { target: string; intervalHours?: number }) =>
                guarded(context, "Adding to the watchlist", async () => {
                    const target = store.normalizeTarget(params.target);

                    if (!target) {
                        return invalidTarget(params.target);
                    }

                    const intervalHours = params.intervalHours ?? deps.defaultIntervalHours;

                    if (!store.validInterval(intervalHours)) {
                        return { error: "invalid_interval", message: `Interval must be ${store.MIN_INTERVAL_HOURS} to ${store.MAX_INTERVAL_HOURS} hours.` };
                    }

                    const added = await store.addWatch(target, {
                        intervalHours,
                        createdBy: context.requesterSenderId ?? null,
                        maxEntries: deps.maxEntries,
                    });

                    if (added.status === "limit") {
                        return { error: "watchlist_full", message: `The watchlist already holds ${deps.maxEntries} CVEs.` };
                    }

                    if (added.status === "exists") {
                        return { status: "already_watched", entry: entryView(added.entry as store.WatchEntry) };
                    }

                    const outcome = await deps.checkNow(target);
                    const entry = await store.getWatch(target);

                    return {
                        status: "added",
                        baseline: outcome
                            ? outcome.success
                                ? outcome.outcome
                                : `not established yet: ${outcome.error}`
                            : "another check is running; the baseline follows on schedule",
                        monitoring: deps.monitoringEnabled ? "running" : "disabled in config",
                        notifications: deps.notifyConfigured ? "configured" : "no channel configured",
                        entry: entry ? entryView(entry) : null,
                    };
                }),
        },

        remove: {
            ...remove,
            execute: async (_id: string, params: { target: string }) =>
                guarded(context, "Removing from the watchlist", async () => {
                    const target = store.normalizeTarget(params.target);

                    return target
                        ? { target, removed: await store.removeWatch(target) }
                        : invalidTarget(params.target);
                }),
        },

        list: {
            ...list,
            execute: async () =>
                guarded(context, "Listing the watchlist", async () => {
                    const entries = await store.listWatches();

                    return {
                        monitoring: deps.monitoringEnabled ? "running" : "disabled in config",
                        notifications: deps.notifyConfigured ? "configured" : "no channel configured",
                        times: TIMES_NOTE,
                        total: entries.length,
                        omitted: Math.max(0, entries.length - 50),
                        entries: entries.slice(0, 50).map((entry) => ({
                            target: entry.target,
                            enabled: entry.enabled,
                            intervalHours: entry.intervalHours,
                            lastSuccessAt: entry.lastSuccessAt,
                            nextCheckAt: entry.nextCheckAt,
                            lastOutcome: entry.lastOutcome,
                            consecutiveFailures: entry.consecutiveFailures,
                            lastError: entry.lastError,
                        })),
                    };
                }),
        },

        set: {
            ...set,
            execute: async (
                _id: string,
                params: { target: string; enabled?: boolean; intervalHours?: number },
            ) =>
                guarded(context, "Updating the watchlist", async () => {
                    const target = store.normalizeTarget(params.target);

                    if (!target) {
                        return invalidTarget(params.target);
                    }

                    if (params.intervalHours !== undefined && !store.validInterval(params.intervalHours)) {
                        return { error: "invalid_interval", message: `Interval must be ${store.MIN_INTERVAL_HOURS} to ${store.MAX_INTERVAL_HOURS} hours.` };
                    }

                    const entry = await store.updateWatch(target, {
                        enabled: params.enabled,
                        intervalHours: params.intervalHours,
                    });

                    return entry
                        ? { status: "updated", entry: entryView(entry) }
                        : { error: "not_watched", message: `${target} is not on the watchlist.` };
                }),
        },

        status: {
            ...status,
            execute: async (
                _id: string,
                params: { target?: string; retryFailedDeliveries?: boolean },
            ) =>
                guarded(context, "Reading watch status", async () => {
                    const target = params.target ? store.normalizeTarget(params.target) : null;

                    if (params.target && !target) {
                        return invalidTarget(params.target);
                    }

                    const requeued = params.retryFailedDeliveries
                        ? await store.requeueFailed(target)
                        : 0;

                    const entry = target ? await store.getWatch(target) : null;

                    return {
                        monitoring: deps.monitoringEnabled ? "running" : "disabled in config",
                        notifications: deps.notifyConfigured ? "configured" : "no channel configured",
                        times: TIMES_NOTE,
                        deliveries: await store.deliveryCounts(),
                        requeuedFailedDeliveries: requeued,
                        ...(target
                            ? {
                                entry: entry ? entryView(entry) : null,
                                recentEvents: (await store.recentEvents(target, 10)).map((event) => ({
                                    kind: event.kind,
                                    field: event.field,
                                    scope: event.scope,
                                    before: event.before,
                                    after: event.after,
                                    // What the alert means; before and after alone are easy to misread.
                                    explanation: event.explanation,
                                    comparedWithInvestigationId: event.baselineInvestigationId,
                                    investigationId: event.investigationId,
                                    observedAt: event.observedAt,
                                    deliveryStatus: event.deliveryStatus,
                                    attempts: event.attempts,
                                    lastError: event.lastError,
                                    messageIds: event.messageIds,
                                    possibleDuplicate: event.possibleDuplicate,
                                })),
                            }
                            : {}),
                    };
                }),
        },
    };
}
