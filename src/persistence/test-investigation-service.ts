
import {
    investigateWithPriorPolicy,
} from "./investigation-service.js";

import type {
    PriorInvestigationResult,
} from "./investigation-prior.js";

import type {
    InvestigationResult,
} from "../types.js";

import type {
    PersistenceResult,
} from "./index.js";

function assert(
    condition: boolean,
    message: string,
): asserts condition {
    if (!condition) {
        throw new Error(`Assertion failed: ${message}`);
    }
}

function makePrior(
    overrides: Partial<PriorInvestigationResult> = {},
): PriorInvestigationResult {
    return {
        target: "CVE-2024-3094",
        found: true,
        latestInvestigation: {
            id: "prior-investigation-id",
            status: "confirmed",
            createdAt: "2026-09-22T08:00:00.000Z",
        },
        decision: {
            decision: "reuse",
            reason: "Fresh, complete prior investigation.",
            ageHours: 4,
        },
        context: {
            investigation: {
                status: "confirmed",
            },
            evidence: [{}],
            facts: [{}],
            inferences: [{}],
        } as unknown as NonNullable<
            PriorInvestigationResult["context"]
        >,
        ...overrides,
    };
}

function makeInvestigation(): InvestigationResult {
    return {
        target: "CVE-2024-3094",
    } as InvestigationResult;
}

function makePersistence(
    overrides: Partial<PersistenceResult> = {},
): PersistenceResult {
    return {
        persisted: true,
        investigationId: "new-investigation-id",
        error: null,
        ...overrides,
    };
}

async function runTests(): Promise<void> {
    console.log("Testing investigation service orchestration...");

    /*
     * 1. A reusable prior investigation skips fresh work.
     */
    {
        let investigateCalls = 0;
        let persistCalls = 0;
        let receivedTarget = "";

        const result = await investigateWithPriorPolicy(
            " cve-2024-3094 ",
            {},
            {
                getPrior: async (target) => {
                    receivedTarget = target;
                    return makePrior();
                },
                investigate: async () => {
                    investigateCalls++;
                    return makeInvestigation();
                },
                persist: async () => {
                    persistCalls++;
                    return makePersistence();
                },
            },
        );

        assert(result.mode === "reused", "should reuse prior result");
        assert(result.freshResult === null, "fresh result should be null");
        assert(result.persistence === null, "persistence should be null");
        assert(investigateCalls === 0, "reuse must not investigate");
        assert(persistCalls === 0, "reuse must not persist again");
        assert(
            receivedTarget === "CVE-2024-3094",
            "target should be normalized before lookup",
        );

        console.log("✓ Reuse skips investigation and persistence");
    }

    /*
     * 2. forceRefresh bypasses a reusable prior result.
     */
    {
        let investigateCalls = 0;
        let persistCalls = 0;

        const result = await investigateWithPriorPolicy(
            "CVE-2024-3094",
            { forceRefresh: true },
            {
                getPrior: async () => makePrior(),
                investigate: async (target, options) => {
                    investigateCalls++;

                    assert(
                        target === "CVE-2024-3094",
                        "normalized target should reach the engine",
                    );
                    assert(
                        options.requestTimeoutMs === 15000,
                        "default request timeout should be passed",
                    );

                    return makeInvestigation();
                },
                persist: async () => {
                    persistCalls++;
                    return makePersistence();
                },
            },
        );

        assert(result.mode === "refreshed", "forceRefresh should refresh");
        assert(investigateCalls === 1, "should investigate exactly once");
        assert(persistCalls === 1, "should persist exactly once");
        assert(
            result.persistence?.persisted === true,
            "persistence should succeed",
        );

        console.log("✓ forceRefresh forces fresh investigation");
    }

    /*
     * 3. No prior investigation triggers fresh work.
     */
    {
        let investigateCalls = 0;
        let persistCalls = 0;

        const result = await investigateWithPriorPolicy(
            "CVE-2024-3094",
            {},
            {
                getPrior: async () =>
                    makePrior({
                        found: false,
                        latestInvestigation: null,
                        decision: {
                            decision: "refresh",
                            reason: "No prior investigation exists.",
                            ageHours: null,
                        },
                        context: null,
                    }),
                investigate: async () => {
                    investigateCalls++;
                    return makeInvestigation();
                },
                persist: async () => {
                    persistCalls++;
                    return makePersistence();
                },
            },
        );

        assert(result.mode === "refreshed", "missing prior should refresh");
        assert(investigateCalls === 1, "should investigate once");
        assert(persistCalls === 1, "should persist once");

        console.log("✓ Missing prior triggers fresh investigation");
    }

    /*
     * 4. A stale or incomplete prior result triggers fresh work.
     */
    {
        let investigateCalls = 0;
        let persistCalls = 0;

        const result = await investigateWithPriorPolicy(
            "CVE-2024-3094",
            {},
            {
                getPrior: async () =>
                    makePrior({
                        decision: {
                            decision: "refresh",
                            reason: "Prior investigation is stale.",
                            ageHours: 52,
                        },
                    }),
                investigate: async () => {
                    investigateCalls++;
                    return makeInvestigation();
                },
                persist: async () => {
                    persistCalls++;
                    return makePersistence();
                },
            },
        );

        assert(result.mode === "refreshed", "stale prior should refresh");
        assert(investigateCalls === 1, "should investigate once");
        assert(persistCalls === 1, "should persist once");

        console.log("✓ Stale prior triggers fresh investigation");
    }

    /*
     * 5. Persistence failures remain visible to the caller.
     */
    {
        const result = await investigateWithPriorPolicy(
            "CVE-2024-3094",
            {},
            {
                getPrior: async () =>
                    makePrior({
                        found: false,
                        latestInvestigation: null,
                        decision: {
                            decision: "refresh",
                            reason: "No prior investigation exists.",
                            ageHours: null,
                        },
                        context: null,
                    }),
                investigate: async () => makeInvestigation(),
                persist: async () =>
                    makePersistence({
                        persisted: false,
                        investigationId: null,
                        error: "Database unavailable",
                    }),
            },
        );

        assert(result.mode === "refreshed", "investigation should complete");
        assert(result.freshResult !== null, "fresh result should be returned");
        assert(
            result.persistence?.persisted === false,
            "persistence failure must be visible",
        );
        assert(
            result.persistence?.error === "Database unavailable",
            "persistence error should be preserved",
        );

        console.log("✓ Persistence failure is surfaced");
    }

    /*
     * 6. Empty targets are rejected before dependencies run.
     */
    {
        let dependencyCalls = 0;
        let threw = false;

        try {
            await investigateWithPriorPolicy(
                "   ",
                {},
                {
                    getPrior: async () => {
                        dependencyCalls++;
                        return makePrior();
                    },
                    investigate: async () => {
                        dependencyCalls++;
                        return makeInvestigation();
                    },
                    persist: async () => {
                        dependencyCalls++;
                        return makePersistence();
                    },
                },
            );
        } catch (error) {
            threw =
                error instanceof Error &&
                error.message.includes("must not be empty");
        }

        assert(threw, "empty target should be rejected");
        assert(
            dependencyCalls === 0,
            "no dependency should run for an empty target",
        );

        console.log("✓ Empty target is rejected");
    }

    /*
     * 7. A prior-lookup failure must stop execution.
     * Never treat a database error as an absent prior investigation.
     */
    {
        let investigateCalls = 0;
        let persistCalls = 0;
        let receivedExpectedError = false;

        try {
            await investigateWithPriorPolicy(
                "CVE-2024-3094",
                {},
                {
                    getPrior: async () => {
                        throw new Error("Database connection unavailable");
                    },
                    investigate: async () => {
                        investigateCalls++;
                        return makeInvestigation();
                    },
                    persist: async () => {
                        persistCalls++;
                        return makePersistence();
                    },
                },
            );
        } catch (error) {
            receivedExpectedError =
                error instanceof Error &&
                error.message === "Database connection unavailable";
        }

        assert(
            receivedExpectedError,
            "prior-lookup error should propagate to the caller",
        );
        assert(
            investigateCalls === 0,
            "investigation must not run after a prior-lookup failure",
        );
        assert(
            persistCalls === 0,
            "persistence must not run after a prior-lookup failure",
        );

        console.log("✓ Prior-lookup failure stops execution safely");
    }

    console.log("All investigation service tests PASSED.");
}

runTests().catch((error: unknown) => {
    console.error("Investigation service tests FAILED");
    console.error(error);
    process.exitCode = 1;
});
