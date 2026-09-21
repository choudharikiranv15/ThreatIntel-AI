import {
    evaluatePriorInvestigation,
} from "./investigation-policy.js";

const NOW =
    new Date(
        "2026-09-22T12:00:00.000Z",
    );

function completedProviders() {
    return [
        {
            provider: "NVD",
            status: "success",
        },
        {
            provider: "CISA_KEV",
            status: "observed_absence",
        },
    ];
}

function assert(
    condition: boolean,
    message: string,
) {
    if (!condition) {
        throw new Error(
            `Assertion failed: ${message}`,
        );
    }
}

/*
 * Fresh confirmed investigation
 */
{
    const result =
        evaluatePriorInvestigation(
            {
                status: "confirmed",

                createdAt:
                    "2026-09-22T08:00:00.000Z",

                providerResults:
                    completedProviders(),

                limitations: [],

                evidenceCount: 1,
            },
            {
                now: NOW,
            },
        );

    assert(
        result.decision ===
        "reuse",
        "fresh confirmed investigation should be reusable",
    );
}

/*
 * Stale investigation
 */
{
    const result =
        evaluatePriorInvestigation(
            {
                status: "confirmed",

                createdAt:
                    "2026-09-20T08:00:00.000Z",

                providerResults:
                    completedProviders(),

                limitations: [],

                evidenceCount: 1,
            },
            {
                now: NOW,
            },
        );

    assert(
        result.decision ===
        "refresh",
        "stale investigation should be refreshed",
    );
}

/*
 * Partial investigation
 */
{
    const result =
        evaluatePriorInvestigation(
            {
                status: "partial",

                createdAt:
                    "2026-09-22T08:00:00.000Z",

                providerResults:
                    completedProviders(),

                limitations: [],

                evidenceCount: 1,
            },
            {
                now: NOW,
            },
        );

    assert(
        result.decision ===
        "refresh",
        "partial investigation should be refreshed",
    );
}

/*
 * Provider failure
 */
{
    const result =
        evaluatePriorInvestigation(
            {
                status: "confirmed",

                createdAt:
                    "2026-09-22T08:00:00.000Z",

                providerResults: [
                    {
                        provider: "NVD",
                        status: "success",
                    },
                    {
                        provider: "CISA_KEV",
                        status: "timeout",
                    },
                ],

                limitations: [],

                evidenceCount: 1,
            },
            {
                now: NOW,
            },
        );

    assert(
        result.decision ===
        "refresh",
        "provider failure should force refresh",
    );
}

/*
 * Limitations present
 */
{
    const result =
        evaluatePriorInvestigation(
            {
                status: "confirmed",

                createdAt:
                    "2026-09-22T08:00:00.000Z",

                providerResults:
                    completedProviders(),

                limitations: [
                    "CISA lookup failed",
                ],

                evidenceCount: 1,
            },
            {
                now: NOW,
            },
        );

    assert(
        result.decision ===
        "refresh",
        "limitations should force refresh",
    );
}

/*
 * No evidence
 */
{
    const result =
        evaluatePriorInvestigation(
            {
                status: "confirmed",

                createdAt:
                    "2026-09-22T08:00:00.000Z",

                providerResults:
                    completedProviders(),

                limitations: [],

                evidenceCount: 0,
            },
            {
                now: NOW,
            },
        );

    assert(
        result.decision ===
        "refresh",
        "missing evidence should force refresh",
    );
}

/*
 * Unknown provider state
 */
{
    const result =
        evaluatePriorInvestigation(
            {
                status: "confirmed",

                createdAt:
                    "2026-09-22T08:00:00.000Z",

                providerResults: [
                    {
                        provider: "NVD",
                        status: "success",
                    },
                ],

                limitations: [],

                evidenceCount: 1,
            },
            {
                now: NOW,
            },
        );

    assert(
        result.decision ===
        "refresh",
        "missing CISA result should force refresh",
    );
}

console.log(
    "Testing prior investigation policy...",
);

console.log(
    "✓ Fresh confirmed investigation → reuse",
);

console.log(
    "✓ Stale investigation → refresh",
);

console.log(
    "✓ Partial investigation → refresh",
);

console.log(
    "✓ Provider failure → refresh",
);

console.log(
    "✓ Limitations → refresh",
);

console.log(
    "✓ Missing evidence → refresh",
);

console.log(
    "✓ Missing provider result → refresh",
);

console.log(
    "✅ Investigation policy tests PASSED",
);