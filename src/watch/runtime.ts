import type { OpenClawPluginApi } from "openclaw/plugin-sdk/plugin-entry";

import { createFeedHooks, type FeedPluginConfig } from "../feed/runtime.js";
import { persistInvestigation } from "../persistence/persist-investigation.js";
import {
    createDirectDeliverer,
    createQueueDeliverer,
    type Deliverer,
    type DeliveryMode,
} from "./delivery.js";
import { defaultCheckDependencies, type CheckOutcome } from "./monitor.js";
import {
    CHECK_LEASE_SECONDS,
    checkAndRecord,
    createMonitorInvestigator,
    createWatchService,
    workerId,
    type WatchSettings,
} from "./service.js";
import * as store from "./store.js";
import type { WatchToolDeps } from "./tools.js";

/*
 * Turns plugin config into the watch service and the tools' dependencies. One
 * worker id per process, shared by the scheduler and by immediate checks, so a
 * lease taken by either is recognised as this process's own.
 */

export type WatchPluginConfig = {
    nvdApiKey?: string;
    requestTimeoutMs?: number;
    watchEnabled?: boolean;
    watchNotifyTarget?: string;
    watchTickMinutes?: number;
    watchDefaultIntervalHours?: number;
    watchMaxEntries?: number;
    watchDeliveryMode?: DeliveryMode;
};

const OWNER = workerId();

/* Deliverer override for tests: the only stub on the plugin path. */
let testDeliverer: Deliverer | null | undefined;

export function setWatchDelivererForTesting(deliverer: Deliverer | null | undefined): void {
    testDeliverer = deliverer;
}

export function watchSettings(config: WatchPluginConfig): WatchSettings & {
    defaultIntervalHours: number;
    maxEntries: number;
    deliveryMode: DeliveryMode;
} {
    return {
        enabled: config.watchEnabled === true,
        notifyTarget: config.watchNotifyTarget?.trim() || null,
        tickMinutes: config.watchTickMinutes ?? 5,
        nvdApiKey: config.nvdApiKey,
        requestTimeoutMs: config.requestTimeoutMs ?? 15000,
        defaultIntervalHours: config.watchDefaultIntervalHours ?? store.DEFAULT_INTERVAL_HOURS,
        maxEntries: config.watchMaxEntries ?? 100,
        deliveryMode: config.watchDeliveryMode ?? "direct",
    };
}

export function buildDeliverer(
    api: Pick<OpenClawPluginApi, "config">,
    config: WatchPluginConfig,
): Deliverer | null {
    if (testDeliverer !== undefined) {
        return testDeliverer;
    }

    const settings = watchSettings(config);

    if (!settings.notifyTarget) {
        return null;
    }

    const getConfig = () => api.config;

    return settings.deliveryMode === "openclaw_queue"
        ? createQueueDeliverer(getConfig, settings.notifyTarget)
        : createDirectDeliverer(getConfig, settings.notifyTarget);
}

/** One service for watch checks, the threat feed, and delivery of both: no second scheduler. */
export function createPluginWatchService(
    api: Pick<OpenClawPluginApi, "config">,
    config: WatchPluginConfig & FeedPluginConfig,
) {
    return createWatchService(
        watchSettings(config),
        () => buildDeliverer(api, config),
        { owner: OWNER },
        createFeedHooks(api, config),
    );
}

export function watchToolDeps(config: WatchPluginConfig): WatchToolDeps {
    const settings = watchSettings(config);

    return {
        maxEntries: settings.maxEntries,
        defaultIntervalHours: settings.defaultIntervalHours,
        monitoringEnabled: settings.enabled,
        notifyConfigured: settings.notifyTarget !== null,
        checkNow: async (target): Promise<CheckOutcome | null> => {
            const entry = await store.claimWatch(target, OWNER, CHECK_LEASE_SECONDS);

            if (!entry) {
                return null;
            }

            const { outcome } = await checkAndRecord(entry, {
                owner: OWNER,
                check: defaultCheckDependencies(
                    createMonitorInvestigator(settings),
                    persistInvestigation,
                    store.insertEvents,
                ),
                deliverer: null,
            });

            return outcome;
        },
    };
}
