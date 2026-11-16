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

/* The rules a model most often gets wrong when reading feed status. */
export const HOW_TO_READ = [
    "A post with deliveryStatus 'sent' is already in the feed channel. It is never posted again unless its exploitation status rises or it gains new indicators.",
    "'discovered' counts every item the sources currently list, including items already posted or filtered in earlier cycles; 'newItems' counts the ones seen for the first time.",
    "A successful run with 'selected' 0 means nothing new qualified. That is normal when sources publish nothing new, and is not a failure or a delay.",
    "Items are never held back for a later cycle except when 'deferred' is above 0, which means the per-cycle post limit was reached.",
    "The feed and the watchlist are separate: feed posts are not watchlist entries.",
    "quietNotices are the 'no latest feed' messages posted after a cycle with nothing to post; they are not threat posts and are counted separately.",
];

type RunSummary = {
    startedAt: string | null;
    status: string;
    discovered: number;
    newItems: number;
    selected: number;
    deferred: number;
    error: string | null;
};

type PostSummary = { title: string; selectedAt: string | null; deliveryStatus: string };

/** One plain-language paragraph, so the answer starts from facts rather than raw counts. */
export function summarizeFeed(input: {
    enabled: boolean;
    nextRunAt: string | null;
    lastRun: RunSummary | null;
    posts: PostSummary[];
    sentTotal: number;
}): string {
    if (!input.enabled) {
        return "The threat feed is disabled in config, so no cycles run.";
    }

    const parts: string[] = [];
    const run = input.lastRun;

    if (!run) {
        parts.push("No cycle has run yet.");
    } else if (run.status === "failed") {
        parts.push(`The last cycle, at ${run.startedAt}, failed and collected nothing: ${run.error ?? "unknown error"}.`);
    } else {
        parts.push(
            `The last cycle ran at ${run.startedAt} (${run.status}): the sources list ${run.discovered} items, ${run.newItems} of them new, and ${run.selected} were posted.`,
        );

        if (run.selected === 0 && run.deferred === 0) {
            parts.push("Nothing new qualified, so nothing was posted; this is normal when the sources publish nothing new.");
        } else if (run.deferred > 0) {
            parts.push(`${run.deferred} qualifying items wait for a later cycle because the per-cycle limit was reached.`);
        }
    }

    if (input.nextRunAt) {
        parts.push(`The next cycle is due at ${input.nextRunAt}.`);
    }

    const latest = input.posts[0];

    if (latest) {
        const batch = input.posts
            .filter((post) => post.selectedAt?.slice(0, 16) === latest.selectedAt?.slice(0, 16))
            .map((post) => post.title);

        parts.push(
            `${input.sentTotal} posts have been delivered in total. The most recent, at ${latest.selectedAt}: ${batch.join("; ")}. Delivered posts are already in the feed channel.`,
        );
    } else {
        parts.push("Nothing has been posted yet.");
    }

    return parts.join(" ");
}

export const FEED_TOOL_DEFINITIONS = {
    status: {
        name: "threatintel_feed_status",
        label: "ThreatIntel Feed Status",
        description: [
            "Show the threat intelligence feed's status, owner only: last and next collection, per-run counts (discovered, filtered, duplicates suppressed, selected, deferred), each source's outcome and duration, configured scope, and recent posts with delivery state and message ids.",
            "Set retryFailedDeliveries=true to requeue feed posts whose delivery failed.",
            "A run with status failed collected nothing; never describe it as an empty successful collection.",
            "Start your answer from the result's summary and follow its howToRead rules: delivered posts are already in the channel and are never reposted.",
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

                    const state = await store.getFeedState();
                    const recentRuns = await store.recentRuns(5);
                    const deliveries = await store.feedDeliveryCounts();
                    const recentPosts = await store.recentPosts(10);

                    return {
                        // Read first: the plain answer, then the rules for the raw data below.
                        summary: summarizeFeed({
                            enabled: settings.enabled,
                            nextRunAt: state?.nextRunAt ?? null,
                            lastRun: recentRuns[0] ?? null,
                            posts: recentPosts,
                            sentTotal: deliveries.sent ?? 0,
                        }),
                        howToRead: HOW_TO_READ,
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
                        state,
                        recentRuns,
                        items: await store.itemCounts(),
                        deliveries,
                        recentPosts,
                        quietNotices: { enabled: settings.quietNotice, ...(await store.quietNoticeCounts()) },
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
