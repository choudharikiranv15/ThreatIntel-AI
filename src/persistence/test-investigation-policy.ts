
import {
    evaluatePriorInvestigation,
} from "./investigation-policy.js";

const NOW = new Date("2026-09-22T12:00:00.000Z");

const FRESH_EVIDENCE = [
    "2026-09-22T08:00:00.000Z",
];

type PolicyInput = {
    status: "confirmed" | "partial" | "not-found" | "failed";
    createdAt: string;
    providerResults: unknown[];
    limitations: string[];
    evidenceCount: number;
    evidenceRetrievedAt: string[];
};

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
): asserts condition {
    if (!condition) {
        throw new Error(`Assertion failed: ${message}`);
    }
}

function evaluate(
    input: PolicyInput,
    options: {
        maxAgeHours?: number;
    } = {},
) {
    return evaluatePriorInvestigation(input, {
        now: NOW,
        ...options,
    });
}

function validInput(
    overrides: Partial<PolicyInput> = {},
): PolicyInput {
    return {
        status: "confirmed",
        createdAt: "2026-09-22T08:00:00.000Z",
        providerResults: completedProviders(),
        limitations: [],
        evidenceCount: 1,
        evidenceRetrievedAt: FRESH_EVIDENCE,
        ...overrides,
    };
}

/*
 * 1. Fresh confirmed investigation
 */
{
    const result = evaluate(validInput());

    assert(
        result.decision === "reuse",
        "fresh confirmed investigation with fresh evidence should be reusable",
    );

    console.log("✓ Fresh confirmed investigation → reuse");
}

/*
 * 2. Stale investigation
 */
{
    const result = evaluate(
        validInput({
            createdAt: "2026-09-20T08:00:00.000Z",
        }),
    );

    assert(
        result.decision === "refresh",
        "stale investigation should be refreshed",
    );

    console.log("✓ Stale investigation → refresh");
}

/*
 * 3. Partial investigation
 */
{
    const result = evaluate(
        validInput({
            status: "partial",
        }),
    );

    assert(
        result.decision === "refresh",
        "partial investigation should be refreshed",
    );

    console.log("✓ Partial investigation → refresh");
}

/*
 * 4. Provider failure
 */
{
    const result = evaluate(
        validInput({
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
        }),
    );

    assert(
        result.decision === "refresh",
        "provider failure should force refresh",
    );

    console.log("✓ Provider failure → refresh");
}

/*
 * 5. Limitations present
 */
{
    const result = evaluate(
        validInput({
            limitations: ["CISA lookup failed"],
        }),
    );

    assert(
        result.decision === "refresh",
        "unresolved limitations should force refresh",
    );

    console.log("✓ Limitations → refresh");
}

/*
 * 6. No evidence
 */
{
    const result = evaluate(
        validInput({
            evidenceCount: 0,
            evidenceRetrievedAt: [],
        }),
    );

    assert(
        result.decision === "refresh",
        "missing evidence should force refresh",
    );

    console.log("✓ Missing evidence → refresh");
}

/*
 * 7. Missing provider result
 */
{
    const result = evaluate(
        validInput({
            providerResults: [
                {
                    provider: "NVD",
                    status: "success",
                },
            ],
        }),
    );

    assert(
        result.decision === "refresh",
        "missing CISA result should force refresh",
    );

    console.log("✓ Missing provider result → refresh");
}

/*
 * 8. Stale evidence inside a recent investigation
 */
{
    const result = evaluate(
        validInput({
            createdAt: "2026-09-22T11:30:00.000Z",
            evidenceRetrievedAt: [
                "2026-09-20T08:00:00.000Z",
            ],
        }),
    );

    assert(
        result.decision === "refresh",
        "stale evidence should force refresh even when the investigation is recent",
    );

    assert(
        result.reason.toLowerCase().includes("evidence"),
        "refresh reason should identify stale evidence",
    );

    console.log("✓ Stale evidence → refresh");
}

/*
 * 9. Missing evidence timestamp
 */
{
    const result = evaluate(
        validInput({
            evidenceRetrievedAt: [],
        }),
    );

    assert(
        result.decision === "refresh",
        "missing evidence timestamp should force refresh",
    );

    console.log("✓ Missing evidence timestamp → refresh");
}

/*
 * 10. Invalid evidence timestamp
 */
{
    const result = evaluate(
        validInput({
            evidenceRetrievedAt: ["not-a-valid-date"],
        }),
    );

    assert(
        result.decision === "refresh",
        "invalid evidence timestamp should force refresh",
    );

    assert(
        result.reason.toLowerCase().includes("invalid"),
        "reason should identify the invalid timestamp",
    );

    console.log("✓ Invalid evidence timestamp → refresh");
}

/*
 * 11. Mixed-age evidence: one fresh, one stale
 */
{
    const result = evaluate(
        validInput({
            evidenceCount: 2,
            evidenceRetrievedAt: [
                "2026-09-22T11:00:00.000Z",
                "2026-09-20T08:00:00.000Z",
            ],
        }),
    );

    assert(
        result.decision === "refresh",
        "one stale evidence record should force refresh",
    );

    console.log("✓ Mixed-age evidence → refresh");
}

/*
 * 12. Future-dated evidence timestamp
 */
{
    const result = evaluate(
        validInput({
            evidenceRetrievedAt: [
                "2026-09-22T12:01:00.000Z",
            ],
        }),
    );

    assert(
        result.decision === "refresh",
        "future-dated evidence must never be reused",
    );

    assert(
        result.reason.toLowerCase().includes("future"),
        "reason should identify the future evidence timestamp",
    );

    console.log("✓ Future evidence timestamp → refresh");
}

/*
 * 13. Future-dated investigation creation timestamp
 */
{
    const result = evaluate(
        validInput({
            createdAt: "2026-09-22T12:01:00.000Z",
        }),
    );

    assert(
        result.decision === "refresh",
        "future-dated investigation must never be reused",
    );

    assert(
        result.reason.toLowerCase().includes("future"),
        "reason should identify the future investigation timestamp",
    );

    assert(
        result.ageHours === null,
        "invalid chronological ordering should not produce an age",
    );

    console.log("✓ Future investigation timestamp → refresh");
}

/*
 * 14. Invalid freshness configuration
 */
{
    let threw = false;

    try {
        evaluate(validInput(), {
            maxAgeHours: -1,
        });
    } catch (error) {
        threw =
            error instanceof RangeError &&
            error.message.includes("maxAgeHours");
    }

    assert(
        threw,
        "negative maxAgeHours must throw a RangeError",
    );

    console.log("✓ Invalid maxAgeHours → RangeError");
}

console.log("All 14 investigation policy tests PASSED.");
