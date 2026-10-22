
import type { InvestigationResult } from "../types.js";
import { investigateCve } from "../engine.js";
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
    } = {},
    dependencies: ServiceDependencies = defaultDependencies,
): Promise<InvestigationExecutionResult> {
    const normalizedTarget = target.trim().toUpperCase();

    if (!normalizedTarget) {
        throw new Error("Investigation target must not be empty.");
    }

    const prior = await dependencies.getPrior(normalizedTarget);

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
        },
    );

    const persistence =
        await dependencies.persist(freshResult);

    return {
        mode: "refreshed",
        prior,
        freshResult,
        persistence,
    };
}
