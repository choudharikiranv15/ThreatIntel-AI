import type { OpenClawPluginApi } from "openclaw/plugin-sdk/plugin-entry";

import { createKevCatalogCache, fetchKevCatalog } from "../sources/cisa-kev.js";
import { MONITOR_RETRY } from "../sources/request-signal.js";
import {
    createDirectDeliverer,
    createQueueDeliverer,
    type Deliverer,
    type DeliveryMode,
} from "../watch/delivery.js";
import type { FeedHooks } from "../watch/service.js";
import type { ScopeConfig } from "./classify.js";
import { runFeedCycleIfDue } from "./cycle.js";
import { DEFAULT_SELECTION, type SelectionConfig } from "./select.js";
import { createSourceFetcher } from "./sources.js";
import { ALL_FEED_SOURCES, type FeedSourceId } from "./types.js";

/*
 * Plugin config to feed settings. Lists are config, so scope is maintained
 * without code changes. No credentials are needed: every source is public.
 */

export type FeedPluginConfig = {
    requestTimeoutMs?: number;
    watchDeliveryMode?: DeliveryMode;
    feedEnabled?: boolean;
    feedNotifyTarget?: string;
    feedIntervalHours?: number;
    feedSources?: string[];
    feedBioPharmaTerms?: string[];
    feedBioPharmaProducts?: string[];
    feedSecurityProducts?: string[];
    feedLogSources?: string[];
    feedMinPriority?: "P1" | "P2" | "P3";
    feedMaxPostsPerCycle?: number;
    feedCooldownHours?: number;
    feedDedupeDays?: number;
    feedMaxAgeDays?: number;
    feedUrgentBypass?: boolean;
    feedUrgentMaxPerCycle?: number;
    feedQuietNotice?: boolean;
};

export type FeedSettings = {
    enabled: boolean;
    notifyTarget: string | null;
    intervalHours: number;
    sources: FeedSourceId[];
    unknownSources: string[];
    scope: ScopeConfig;
    selection: SelectionConfig;
    requestTimeoutMs: number;
    deliveryMode: DeliveryMode;
    quietNotice: boolean;
};

const clean = (values: string[] | undefined): string[] =>
    [...new Set((values ?? []).map((value) => value.trim()).filter(Boolean))];

export function feedSettings(config: FeedPluginConfig): FeedSettings {
    const requested = config.feedSources ? clean(config.feedSources) : ALL_FEED_SOURCES;

    return {
        enabled: config.feedEnabled === true,
        notifyTarget: config.feedNotifyTarget?.trim() || null,
        intervalHours: config.feedIntervalHours ?? 3,
        sources: requested.filter((source): source is FeedSourceId => (ALL_FEED_SOURCES as string[]).includes(source)),
        unknownSources: requested.filter((source) => !(ALL_FEED_SOURCES as string[]).includes(source)),
        scope: {
            bioPharmaTerms: clean(config.feedBioPharmaTerms),
            bioPharmaProducts: clean(config.feedBioPharmaProducts),
            securityProducts: clean(config.feedSecurityProducts),
            logSources: clean(config.feedLogSources),
        },
        selection: {
            minPriority: config.feedMinPriority ?? DEFAULT_SELECTION.minPriority,
            maxPostsPerCycle: config.feedMaxPostsPerCycle ?? DEFAULT_SELECTION.maxPostsPerCycle,
            cooldownHours: config.feedCooldownHours ?? DEFAULT_SELECTION.cooldownHours,
            dedupeDays: config.feedDedupeDays ?? DEFAULT_SELECTION.dedupeDays,
            maxAgeDays: config.feedMaxAgeDays ?? DEFAULT_SELECTION.maxAgeDays,
            urgentBypass: config.feedUrgentBypass ?? DEFAULT_SELECTION.urgentBypass,
            urgentMaxPerCycle: config.feedUrgentMaxPerCycle ?? DEFAULT_SELECTION.urgentMaxPerCycle,
        },
        requestTimeoutMs: config.requestTimeoutMs ?? 15000,
        deliveryMode: config.watchDeliveryMode ?? "direct",
        quietNotice: config.feedQuietNotice ?? true,
    };
}

const KEV_CACHE_MS = 60 * 60 * 1000;

/* Deliverer override for tests, as for the watchlist. */
let testFeedDeliverer: Deliverer | null | undefined;

export function setFeedDelivererForTesting(deliverer: Deliverer | null | undefined): void {
    testFeedDeliverer = deliverer;
}

export function createFeedHooks(
    api: Pick<OpenClawPluginApi, "config">,
    config: FeedPluginConfig,
): FeedHooks {
    const settings = feedSettings(config);

    // One catalog download serves both the KEV source and the KEV cross-check.
    const kevCatalog = createKevCatalogCache(
        () => fetchKevCatalog(settings.requestTimeoutMs, undefined, MONITOR_RETRY),
        KEV_CACHE_MS,
    );

    const fetchSource = createSourceFetcher({
        timeoutMs: settings.requestTimeoutMs,
        retry: MONITOR_RETRY,
        since: () => new Date(Date.now() - settings.selection.maxAgeDays * 86_400_000),
        kevCatalog,
    });

    return {
        enabled: settings.enabled,
        buildDeliverer: () => {
            if (testFeedDeliverer !== undefined) {
                return testFeedDeliverer;
            }

            if (!settings.notifyTarget) {
                return null;
            }

            const getConfig = () => api.config;

            return settings.deliveryMode === "openclaw_queue"
                ? createQueueDeliverer(getConfig, settings.notifyTarget)
                : createDirectDeliverer(getConfig, settings.notifyTarget);
        },
        runIfDue: (owner, log) =>
            runFeedCycleIfDue({
                owner,
                sources: settings.sources,
                fetchSource,
                kevCves: async () => {
                    const { catalog } = await kevCatalog();

                    return new Set((catalog.vulnerabilities ?? []).map((entry) => entry.cveID?.toUpperCase() ?? "").filter(Boolean));
                },
                scope: settings.scope,
                selection: settings.selection,
                intervalHours: settings.intervalHours,
                quietNotice: settings.quietNotice,
                log,
            }),
    };
}
