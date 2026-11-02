
import type { InvestigationResult } from "../types.js";
import { investigateCve } from "../engine.js";
import { safeDatabaseError } from "./db.js";
import {
    persistInvestigationResult,
    type PersistenceResult,
} from "./index.js";
import {
    getPriorInvestigation,
    type PriorInvestigationResult,
} from "./investigation-prior.js";

export type InvestigationExecutionResult = {
    mode: "reused" | "refreshed";
    prior: PriorInvestigationResult;
    freshResult: InvestigationResult | null;
    persistence: PersistenceResult | null;
};

type ServiceDependencies = {
    getPrior: typeof getPriorInvestigation;
    investigate: typeof investigateCve;
    persist: typeof persistInvestigationResult;
};

const defaultDependencies: ServiceDependencies = {
    getPrior: getPriorInvestigation,
    investigate: investigateCve,
    persist: persistInvestigationResult,
};

export async function investigateWithPriorPolicy(
    target: string,
    options: {
        nvdApiKey?: string;
        requestTimeoutMs?: number;
        forceRefresh?: boolean;
        signal?: AbortSignal;
    } = {},
    dependencies: ServiceDependencies = defaultDependencies,
): Promise<InvestigationExecutionResult> {
    const normalizedTarget = target.trim().toUpperCase();

    if (!normalizedTarget) {
        throw new Error("Investigation target must not be empty.");
    }

    let prior: PriorInvestigationResult;

    /*
     * Threat intelligence does not depend on our database, so an outage must
     * not block an investigation. lookupError keeps it distinct from "no prior
     * investigation exists".
     */
    try {
        prior = await dependencies.getPrior(normalizedTarget);
    } catch (error) {
        prior = {
            target: normalizedTarget,
            found: false,
            latestInvestigation: null,
            decision: {
                decision: "refresh",
                reason:
                    "Investigation history could not be read, so a fresh investigation was performed.",
                ageHours: null,
            },
            context: null,
            lookupError: safeDatabaseError(
                "Reading investigation history",
                error,
            ),
        };
    }

    if (
        !options.forceRefresh &&
        prior.found &&
        prior.decision?.decision === "reuse" &&
        prior.context
    ) {
        return {
            mode: "reused",
            prior,
            freshResult: null,
            persistence: null,
        };
    }

    const freshResult = await dependencies.investigate(
        normalizedTarget,
        {
            nvdApiKey: options.nvdApiKey,
            requestTimeoutMs: options.requestTimeoutMs ?? 15000,
            signal: options.signal,
        },
    );

    // Provider errors from an aborted call are not a result worth recording.
    options.signal?.throwIfAborted();

    const persistence =
        await dependencies.persist(freshResult);

    return {
        mode: "refreshed",
        prior,
        freshResult,
        persistence,
    };
}
