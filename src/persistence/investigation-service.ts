import type { InvestigationResult } from "../types.js";

import {
    investigateCve,
} from "../engine.js";

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

export async function investigateWithPriorPolicy(
    target: string,
    options: {
        nvdApiKey?: string;
        requestTimeoutMs?: number;
    } = {},
): Promise<InvestigationExecutionResult> {
    const prior =
        await getPriorInvestigation(target);

    if (
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

    const freshResult =
        await investigateCve(
            target,
            {
                nvdApiKey:
                    options.nvdApiKey,

                requestTimeoutMs:
                    options.requestTimeoutMs ??
                    15000,
            },
        );

    const persistence =
        await persistInvestigationResult(
            freshResult,
        );

    return {
        mode: "refreshed",
        prior,
        freshResult,
        persistence,
    };
}