import {
    investigateCve,
} from "./engine.js";

import type {
    Evidence,
    InvestigationResult,
    ProviderResult,
} from "./types.js";

function assert(
    condition: unknown,
    message: string,
): asserts condition {
    if (!condition) {
        throw new Error(
            `Assertion failed: ${message}`,
        );
    }
}

function makeEvidence(
    source: "NVD" | "CISA_KEV",
): Evidence {
    return {
        id: `${source}:test`,
        source,
        sourceType: "primary",
        retrievedAt:
            new Date().toISOString(),
        url:
            source === "NVD"
                ? "https://nvd.nist.gov/"
                : "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        title: source,
        confidence: "high",
        facts: {},
        extractedFacts: [],
        references: [],
    };
}

function validNvdResult(): ProviderResult {
    return {
        provider: "NVD",
        status: "success",
        evidence: makeEvidence("NVD"),
        error: null,
        checkedAt:
            new Date().toISOString(),
    };
}

function validCisaResult(): ProviderResult {
    return {
        provider: "CISA_KEV",
        status: "success",
        evidence:
            makeEvidence("CISA_KEV"),
        error: null,
        checkedAt:
            new Date().toISOString(),
    };
}

function fakeResult(
    result: unknown,
): (
    cveId: string,
) => Promise<ProviderResult> {
    return async () =>
        result as ProviderResult;
}

async function testSuccessWithoutEvidence() {
    const result =
        await investigateCve(
            "CVE-2024-3094",
            {
                requestTimeoutMs: 15000,
                providers: {
                    nvd: fakeResult({
                        provider: "NVD",
                        status: "success",
                        evidence: null,
                        error: null,
                        checkedAt:
                            new Date().toISOString(),
                    }),
                    cisaKev:
                        async () =>
                        ({
                            provider: "CISA_KEV",
                            status:
                                "observed_absence",
                            evidence: null,
                            error: null,
                            checkedAt:
                                new Date().toISOString(),
                        }),
                },
            },
        );

    const nvd =
        result.providerResults.find(
            (provider) =>
                provider.provider === "NVD",
        );

    assert(
        nvd?.status === "error",
        "invalid NVD success result should become error",
    );

    assert(
        nvd?.evidence === null,
        "invalid provider result must not retain evidence",
    );
}

async function testErrorWithEvidence() {
    const result =
        await investigateCve(
            "CVE-2024-3094",
            {
                requestTimeoutMs: 15000,
                providers: {
                    nvd: fakeResult({
                        provider: "NVD",
                        status: "error",
                        evidence:
                            makeEvidence("NVD"),
                        error:
                            "Simulated provider failure",
                        checkedAt:
                            new Date().toISOString(),
                    }),
                    cisaKev:
                        async () =>
                        ({
                            provider: "CISA_KEV",
                            status:
                                "observed_absence",
                            evidence: null,
                            error: null,
                            checkedAt:
                                new Date().toISOString(),
                        }),
                },
            },
        );

    const nvd =
        result.providerResults.find(
            (provider) =>
                provider.provider === "NVD",
        );

    assert(
        nvd?.status === "error",
        "error-with-evidence should remain error",
    );

    assert(
        nvd?.evidence === null,
        "error provider must never expose evidence",
    );
}

async function testObservedAbsenceWithEvidence() {
    const result =
        await investigateCve(
            "CVE-2024-3094",
            {
                requestTimeoutMs: 15000,
                providers: {
                    nvd: fakeResult({
                        provider: "NVD",
                        status:
                            "observed_absence",
                        evidence:
                            makeEvidence("NVD"),
                        error: null,
                        checkedAt:
                            new Date().toISOString(),
                    }),
                    cisaKev:
                        async () =>
                        ({
                            provider: "CISA_KEV",
                            status:
                                "observed_absence",
                            evidence: null,
                            error: null,
                            checkedAt:
                                new Date().toISOString(),
                        }),
                },
            },
        );

    const nvd =
        result.providerResults.find(
            (provider) =>
                provider.provider === "NVD",
        );

    assert(
        nvd?.status === "error",
        "absence-with-evidence should become error",
    );

    assert(
        nvd?.evidence === null,
        "absence result must not retain evidence",
    );
}

async function testWrongProviderEvidence() {
    const result =
        await investigateCve(
            "CVE-2024-3094",
            {
                requestTimeoutMs: 15000,
                providers: {
                    nvd: fakeResult({
                        provider: "NVD",
                        status: "success",
                        evidence:
                            makeEvidence("CISA_KEV"),
                        error: null,
                        checkedAt:
                            new Date().toISOString(),
                    }),
                    cisaKev:
                        async () =>
                        ({
                            provider: "CISA_KEV",
                            status:
                                "observed_absence",
                            evidence: null,
                            error: null,
                            checkedAt:
                                new Date().toISOString(),
                        }),
                },
            },
        );

    const nvd =
        result.providerResults.find(
            (provider) =>
                provider.provider === "NVD",
        );

    assert(
        nvd?.status === "error",
        "wrong-source evidence should become error",
    );

    assert(
        nvd?.evidence === null,
        "wrong-source evidence must never enter investigation evidence",
    );
}

async function testMalformedEvidence() {
    const result =
        await investigateCve(
            "CVE-2024-3094",
            {
                requestTimeoutMs: 15000,
                providers: {
                    nvd: fakeResult({
                        provider: "NVD",
                        status: "success",
                        evidence: {
                            source: "NVD",
                            sourceType: "primary",
                        },
                        error: null,
                        checkedAt:
                            new Date().toISOString(),
                    }),
                    cisaKev:
                        async () =>
                        ({
                            provider: "CISA_KEV",
                            status:
                                "observed_absence",
                            evidence: null,
                            error: null,
                            checkedAt:
                                new Date().toISOString(),
                        }),
                },
            },
        );

    const nvd =
        result.providerResults.find(
            (provider) =>
                provider.provider === "NVD",
        );

    assert(
        nvd?.status === "error",
        "malformed evidence should become error",
    );

    assert(
        nvd?.evidence === null,
        "malformed evidence must not enter evidence collection",
    );
}

async function run() {
    await testSuccessWithoutEvidence();
    console.log(
        "  ✓ success without evidence",
    );

    await testErrorWithEvidence();
    console.log(
        "  ✓ error with evidence",
    );

    await testObservedAbsenceWithEvidence();
    console.log(
        "  ✓ absence with evidence",
    );

    await testWrongProviderEvidence();
    console.log(
        "  ✓ wrong provider evidence",
    );

    await testMalformedEvidence();
    console.log(
        "  ✓ malformed evidence",
    );

    console.log(
        "\n✅ All validation tests PASSED",
    );
}

run().catch((error) => {
    console.error(
        "\n❌ Validation tests FAILED",
    );
    console.error(error);
    process.exit(1);
});