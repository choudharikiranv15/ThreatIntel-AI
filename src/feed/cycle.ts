import { evaluate, type ScopeConfig } from "./classify.js";
import { formatFeedPost } from "./format.js";
import { selectForPublication, type Candidate, type SelectionConfig } from "./select.js";
import type { SourceFetcher } from "./sources.js";
import * as store from "./store.js";
import type { EvaluatedItem, FeedSourceId, ProviderOutcome, RawItem } from "./types.js";

/*
 * One collection cycle: collect, evaluate, deduplicate, select, and hand the
 * selected posts to the outbox. Sending happens in the shared delivery step.
 */

export const FEED_LEASE_SECONDS = 30 * 60;

export type FeedCycleDeps = {
    owner: string;
    sources: FeedSourceId[];
    fetchSource: SourceFetcher;
    /** CVEs in the CISA KEV catalog, or null when the catalog could not be read. */
    kevCves: () => Promise<ReadonlySet<string> | null>;
    scope: ScopeConfig;
    selection: SelectionConfig;
    intervalHours: number;
    log?: (message: string) => void;
};

export type FeedCycleResult = {
    runId: string;
    status: "success" | "partial" | "failed";
    counts: store.RunCounts;
    providers: ProviderOutcome[];
};

/** Runs a cycle if one is due and no other worker holds the feed lease. */
export async function runFeedCycleIfDue(deps: FeedCycleDeps): Promise<FeedCycleResult | null> {
    const claimed = await store.claimFeedRun(deps.owner, FEED_LEASE_SECONDS);

    if (!claimed) {
        return null;
    }

    const started = Date.now();
    const runId = await store.startRun();
    let providers: ProviderOutcome[] = [];

    try {
        /* 1. Collect: every source on its own, so one failure blocks nothing. */
        const settled = await Promise.all(
            deps.sources.map(async (source): Promise<{ outcome: ProviderOutcome; items: RawItem[] }> => {
                const sourceStarted = Date.now();

                try {
                    const items = await deps.fetchSource(source);

                    return {
                        outcome: { source, status: "success", items: items.length, error: null, durationMs: Date.now() - sourceStarted },
                        items,
                    };
                } catch (error) {
                    return {
                        outcome: {
                            source,
                            status: "failed",
                            items: 0,
                            error: (error instanceof Error ? error.message : String(error)).slice(0, 300),
                            durationMs: Date.now() - sourceStarted,
                        },
                        items: [],
                    };
                }
            }),
        );

        providers = settled.map((entry) => entry.outcome);

        const failed = providers.filter((outcome) => outcome.status === "failed");

        for (const outcome of failed) {
            deps.log?.(`threat feed: ${outcome.source} failed: ${outcome.error}`);
        }

        if (deps.sources.length === 0 || failed.length === deps.sources.length) {
            // Nothing was collected: a failure, never an empty success.
            const error = deps.sources.length === 0 ? "no sources enabled" : "every source failed";

            await store.finishRun(
                runId,
                deps.owner,
                { status: "failed", counts: store.EMPTY_COUNTS, providers, error, durationMs: Date.now() - started, published: false },
                deps.intervalHours,
            );

            return { runId, status: "failed", counts: store.EMPTY_COUNTS, providers };
        }

        /* 2. Evaluate. One advisory can arrive through two feeds; keep it once. */
        const raw = new Map<string, RawItem>();

        for (const item of settled.flatMap((entry) => entry.items)) {
            if (!raw.has(item.itemKey)) {
                raw.set(item.itemKey, item);
            }
        }

        const kev = (await deps.kevCves().catch(() => null)) ?? new Set<string>();

        const evaluated = new Map<string, EvaluatedItem & { contentHash: string }>();

        for (const item of raw.values()) {
            const result = { ...item, ...evaluate(item, deps.scope, kev) };

            evaluated.set(item.itemKey, { ...result, contentHash: store.contentHash(result) });
        }

        /* 3. Compare with what is stored. */
        const existing = await store.loadItems([...evaluated.keys()]);
        const counts: store.RunCounts = { ...store.EMPTY_COUNTS, discovered: raw.size };
        const candidates: Candidate[] = [];

        for (const item of evaluated.values()) {
            const previous = existing.get(item.itemKey);

            if (!previous) {
                counts.newItems += 1;
                candidates.push({ item, published: null });
                continue;
            }

            if (previous.contentHash !== item.contentHash) {
                counts.updatedItems += 1;
                candidates.push({ item, published: previous.published });
                continue;
            }

            // Unchanged: only items still waiting for a slot are decided again.
            if (previous.state === "queued") {
                candidates.push({ item, published: previous.published });
            }
        }

        await store.upsertItems([...evaluated.values()], deps.selection.maxAgeDays);

        /* Items deferred earlier that the feeds no longer list still compete. */
        for (const queued of await store.loadQueued()) {
            if (!evaluated.has(queued.itemKey)) {
                candidates.push({ item: queued.item, published: queued.published });
                evaluated.set(queued.itemKey, { ...queued.item, contentHash: queued.contentHash });
            }
        }

        /* 4. Select and hand over to the outbox. */
        const decisions = selectForPublication(
            candidates,
            await store.recentCves(deps.selection.dedupeDays),
            deps.selection,
            new Date(),
        );

        const messages = new Map<string, string>();

        for (const [itemKey, decision] of decisions) {
            const item = evaluated.get(itemKey);

            if (item && decision.kind === "publish") {
                messages.set(itemKey, formatFeedPost(item, { updated: decision.updated }));
                counts.selected += 1;
            } else if (decision.kind === "ignore" || decision.kind === "expire") {
                counts.filtered += 1;
            } else if (decision.kind === "suppress") {
                counts.duplicatesSuppressed += 1;
            } else if (decision.kind === "defer") {
                counts.deferred += 1;
            }
        }

        await store.applyDecisions(decisions, evaluated, messages);
        await store.pruneItems();

        const status = failed.length > 0 ? "partial" : "success";

        await store.finishRun(
            runId,
            deps.owner,
            {
                status,
                counts,
                providers,
                error: failed.length > 0 ? `${failed.length} of ${deps.sources.length} sources failed` : null,
                durationMs: Date.now() - started,
                published: counts.selected > 0,
            },
            deps.intervalHours,
        );

        deps.log?.(
            `threat feed: ${status}; ${counts.discovered} found, ${counts.selected} selected, ${counts.duplicatesSuppressed} duplicates, ${counts.deferred} deferred, ${counts.filtered} filtered`,
        );

        return { runId, status, counts, providers };
    } catch (error) {
        const message = error instanceof Error ? error.message : String(error);

        await store
            .finishRun(
                runId,
                deps.owner,
                { status: "failed", counts: store.EMPTY_COUNTS, providers, error: message, durationMs: Date.now() - started, published: false },
                deps.intervalHours,
            )
            .catch(() => undefined);

        throw error;
    }
}
