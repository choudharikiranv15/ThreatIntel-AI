import {
    investigateCve,
} from "./engine.js";

import type {
    ProviderResult,
} from "./types.js";

const CVE =
    "CVE-2024-3094";

const failures: string[] = [];

function assert(
    condition: boolean,
    message: string,
): void {
    if (!condition) {
        failures.push(message);
    }
}

function fakeProvider(
    result: ProviderResult,
): () => Promise<ProviderResult> {
    return async () => result;
}

function successEvidence(
    source:
        | "NVD"
        | "CISA_KEV",
): ProviderResult {
    return {
        provider: source,
        status: "success",
        error: null,
        checkedAt:
            "2026-01-01T00:00:00.000Z",
        evidence: {
            source,
            sourceType: "primary",
            retrievedAt:
                "2026-01-01T00:00:00.000Z",
            url:
                source === "NVD"
                    ? "https://nvd.nist.gov/"
                    : "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            title:
                source === "NVD"
                    ? "NVD"
                    : "CISA Known Exploited Vulnerabilities",
            confidence: "high",
            facts: {},
            extractedFacts: [],
            references: [],
        },
    };
}

function absenceProvider(
    source:
        | "NVD"
        | "CISA_KEV",
): ProviderResult {
    return {
        provider: source,
        status: "observed_absence",
        error: null,
        checkedAt:
            "2026-01-01T00:00:00.000Z",
        evidence: null,
    };
}

function failureProvider(
    source:
        | "NVD"
        | "CISA_KEV",
): ProviderResult {
    return {
        provider: source,
        status: "error",
        error:
            `${source} simulated failure`,
        checkedAt:
            "2026-01-01T00:00:00.000Z",
        evidence: null,
    };
}

function timeoutProvider(
    source:
        | "NVD"
        | "CISA_KEV",
): ProviderResult {
    return {
        provider: source,
        status: "timeout",
        error:
            `${source} simulated timeout`,
        checkedAt:
            "2026-01-01T00:00:00.000Z",
        evidence: null,
    };
}

/* -------------------------------------------------------------------------- */
/* Test 1                                                                     */
/* NVD success + CISA absence                                                 */
/* -------------------------------------------------------------------------- */

{
    const result =
        await investigateCve(
            CVE,
            {
                requestTimeoutMs: 1000,

                providers: {
                    nvd: fakeProvider(
                        successEvidence("NVD"),
                    ),

                    cisaKev: fakeProvider(
                        absenceProvider(
                            "CISA_KEV",
                        ),
                    ),
                },
            },
        );

    const nvd =
        result.providerResults.find(
            (provider) =>
                provider.provider === "NVD",
        );

    const cisa =
        result.providerResults.find(
            (provider) =>
                provider.provider ===
                "CISA_KEV",
        );

    assert(
        nvd?.status === "success",
        "Test 1: NVD should be success.",
    );

    assert(
        cisa?.status ===
        "observed_absence",
        "Test 1: CISA should be observed_absence.",
    );

    assert(
        result.summary.kevStatus ===
        "not-listed",
        "Test 1: expected not-listed KEV status.",
    );

    assert(
        result.status === "confirmed",
        `Test 1: expected confirmed, got ${result.status}.`,
    );
}

/* -------------------------------------------------------------------------- */
/* Test 2                                                                     */
/* NVD timeout + CISA success                                                 */
/* -------------------------------------------------------------------------- */

{
    const result =
        await investigateCve(
            CVE,
            {
                requestTimeoutMs: 1000,

                providers: {
                    nvd: fakeProvider(
                        timeoutProvider("NVD"),
                    ),

                    cisaKev: fakeProvider(
                        successEvidence(
                            "CISA_KEV",
                        ),
                    ),
                },
            },
        );

    assert(
        result.status === "partial",
        `Test 2: expected partial, got ${result.status}.`,
    );

    assert(
        result.limitations.length >
        0,
        "Test 2: expected NVD timeout limitation.",
    );

    assert(
        result.summary.kevStatus ===
        "listed",
        "Test 2: successful CISA should produce listed.",
    );
}

/* -------------------------------------------------------------------------- */
/* Test 3                                                                     */
/* NVD success + CISA timeout                                                 */
/* -------------------------------------------------------------------------- */

{
    const result =
        await investigateCve(
            CVE,
            {
                requestTimeoutMs: 1000,

                providers: {
                    nvd: fakeProvider(
                        successEvidence("NVD"),
                    ),

                    cisaKev: fakeProvider(
                        timeoutProvider(
                            "CISA_KEV",
                        ),
                    ),
                },
            },
        );

    const cisa =
        result.providerResults.find(
            (provider) =>
                provider.provider ===
                "CISA_KEV",
        );

    assert(
        cisa?.status === "timeout",
        "Test 3: CISA should be timeout.",
    );

    assert(
        result.status === "partial",
        `Test 3: expected partial, got ${result.status}.`,
    );

    assert(
        result.summary.kevStatus ===
        "unknown",
        `Test 3: expected unknown KEV status, got ${result.summary.kevStatus}.`,
    );

    assert(
        result.limitations.length >
        0,
        "Test 3: expected CISA timeout limitation.",
    );
}

/* -------------------------------------------------------------------------- */
/* Test 4                                                                     */
/* Both providers fail                                                       */
/* -------------------------------------------------------------------------- */

{
    const result =
        await investigateCve(
            CVE,
            {
                requestTimeoutMs: 1000,

                providers: {
                    nvd: fakeProvider(
                        failureProvider("NVD"),
                    ),

                    cisaKev: fakeProvider(
                        failureProvider(
                            "CISA_KEV",
                        ),
                    ),
                },
            },
        );

    assert(
        result.status === "failed",
        `Test 4: expected failed, got ${result.status}.`,
    );

    assert(
        result.evidence.length ===
        0,
        "Test 4: failed providers must produce no evidence.",
    );

    assert(
        result.limitations.length >=
        2,
        "Test 4: expected both provider failures to produce limitations.",
    );

    assert(
        result.summary.kevStatus ===
        "unknown",
        "Test 4: failed CISA provider must produce unknown KEV status.",
    );
}

/* -------------------------------------------------------------------------- */
/* Test 5                                                                     */
/* NVD absence + CISA absence                                                 */
/* -------------------------------------------------------------------------- */

{
    const result =
        await investigateCve(
            CVE,
            {
                requestTimeoutMs: 1000,

                providers: {
                    nvd: fakeProvider(
                        absenceProvider("NVD"),
                    ),

                    cisaKev: fakeProvider(
                        absenceProvider(
                            "CISA_KEV",
                        ),
                    ),
                },
            },
        );

    assert(
        result.evidence.length ===
        0,
        "Test 5: observed absence must not become positive evidence.",
    );

    assert(
        result.summary.kevStatus ===
        "not-listed",
        "Test 5: expected not-listed KEV status.",
    );
}

/* -------------------------------------------------------------------------- */
/* Test 6                                                                     */
/* Timeout never becomes evidence                                             */
/* -------------------------------------------------------------------------- */

{
    const result =
        await investigateCve(
            CVE,
            {
                requestTimeoutMs: 1000,

                providers: {
                    nvd: fakeProvider(
                        timeoutProvider("NVD"),
                    ),

                    cisaKev: fakeProvider(
                        timeoutProvider(
                            "CISA_KEV",
                        ),
                    ),
                },
            },
        );

    assert(
        result.evidence.length ===
        0,
        "Test 6: timeout providers must never generate evidence.",
    );

    for (
        const provider of result.providerResults
    ) {
        if (
            provider.status === "timeout"
        ) {
            assert(
                provider.evidence === null,
                `Test 6: ${provider.provider} timeout contains evidence.`,
            );
        }
    }
}

/* -------------------------------------------------------------------------- */
/* Final                                                                      */
/* -------------------------------------------------------------------------- */

if (failures.length > 0) {
    console.error(
        "\n❌ Fault tests FAILED\n",
    );

    for (
        const failure of failures
    ) {
        console.error(
            `  - ${failure}`,
        );
    }

    process.exitCode = 1;
} else {
    console.log(
        "\n✅ All fault tests PASSED",
    );

    console.log(
        "  ✓ NVD success + CISA absence",
    );

    console.log(
        "  ✓ NVD timeout + CISA success",
    );

    console.log(
        "  ✓ NVD success + CISA timeout",
    );

    console.log(
        "  ✓ Both providers fail",
    );

    console.log(
        "  ✓ NVD absence + CISA absence",
    );

    console.log(
        "  ✓ Timeout never becomes evidence",
    );
}