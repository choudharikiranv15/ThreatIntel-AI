import { Type } from "typebox";

import * as watchStore from "../watch/store.js";
import { guarded, type WatchToolContext } from "../watch/tools.js";
import type { FeedSettings } from "./runtime.js";
import * as store from "./store.js";

/*
 * Feed tools, owner only like the watchlist tools: the same trusted runtime
 * flag decides, never the model's arguments.
 */

const TIMES_NOTE = "All timestamps are UTC (ISO 8601). Convert them before stating a local time.";

export const FEED_TOOL_DEFINITIONS = {
    status: {
        name: "threatintel_feed_status",
        label: "ThreatIntel Feed Status",
        description: [
            "Show the threat intelligence feed's status, owner only: last and next collection, per-run counts (discovered, filtered, duplicates suppressed, selected, deferred), each source's outcome and duration, configured scope, and recent posts with delivery state and message ids.",
            "Set retryFailedDeliveries=true to requeue feed posts whose delivery failed.",
            "A run with status failed collected nothing; never describe it as an empty successful collection.",
        ].join(" "),
        parameters: Type.Object({
            retryFailedDeliveries: Type.Optional(Type.Boolean()),
        }),
    },
    runNow: {
        name: "threatintel_feed_run_now",
        label: "ThreatIntel Feed Run Now",
        description:
            "Schedule a threat feed collection now, owner only. The running gateway performs it within one tick; report that it was scheduled, not its results.",
        parameters: Type.Object({}),
    },
} as const;

export function buildFeedTools(context: WatchToolContext, settings: FeedSettings) {
    const { status, runNow } = FEED_TOOL_DEFINITIONS;

    return {
        status: {
            ...status,
            execute: async (_id: string, params: { retryFailedDeliveries?: boolean }) =>
                guarded(context, "Reading feed status", async () => {
                    const requeued = params.retryFailedDeliveries
                        ? await watchStore.requeueFailed(null, "feed")
                        : 0;

                    return {
                        feed: settings.enabled ? "enabled" : "disabled in config",
                        notifications: settings.notifyTarget ? "configured" : "no channel configured",
                        times: TIMES_NOTE,
                        intervalHours: settings.intervalHours,
                        sources: settings.sources,
                        unknownSources: settings.unknownSources,
                        scope: {
                            bioPharmaTerms: settings.scope.bioPharmaTerms.length > 0 ? settings.scope.bioPharmaTerms.length : "built-in defaults",
                            bioPharmaProducts: settings.scope.bioPharmaProducts.length,
                            securityProducts: settings.scope.securityProducts.length,
                            logSources: settings.scope.logSources.length,
                        },
                        selection: settings.selection,
                        state: await store.getFeedState(),
                        recentRuns: await store.recentRuns(5),
                        items: await store.itemCounts(),
                        deliveries: await store.feedDeliveryCounts(),
                        recentPosts: await store.recentPosts(10),
                        requeuedFailedDeliveries: requeued,
                    };
                }),
        },
        runNow: {
            ...runNow,
            execute: async () =>
                guarded(context, "Scheduling a feed run", async () => {
                    if (!settings.enabled) {
                        return { status: "not_scheduled", reason: "The feed is disabled in config (feedEnabled)." };
                    }

                    await store.requestRunNow();

                    return { status: "scheduled", note: "The gateway runs it on its next tick." };
                }),
        },
    };
}
