/*
 * Regressions for engine accuracy bugs found against live data. Offline: providers
 * are faked, and fetchRedHatCve runs against a faked fetch.
 */
import { investigateCve } from "./engine.js";
import { resolveSsl } from "./persistence/db.js";
import { evaluatePriorInvestigation } from "./persistence/investigation-policy.js";
import { fetchRedHatCve } from "./sources/redhat.js";
import { viewFromResult } from "./tool-result.js";
import { checkAnswer } from "./verification/check-answer.js";
import { verifyCvssClaim, verifyKevClaim } from "./verification/index.js";
import type { ProviderResult, SourceId } from "./types.js";

function assert(condition: unknown, message: string): asserts condition {
    if (!condition) {
        throw new Error(`Assertion failed: ${message}`);
    }
}

const now = new Date().toISOString();

function absent(provider: SourceId) {
    return async (): Promise<ProviderResult> => ({
        provider,
        status: "observed_absence",
        evidence: null,
        error: null,
        checkedAt: now,
    });
}

function failing(provider: SourceId) {
    return async (): Promise<ProviderResult> => ({
        provider,
        status: "error",
        evidence: null,
        error: "unavailable",
        checkedAt: now,
    });
}

function found(
    provider: SourceId,
    facts: Record<string, unknown>,
) {
    return async (cveId: string): Promise<ProviderResult> => ({
        provider,
        status: "success",
        error: null,
        checkedAt: now,
        evidence: {
            id: `${provider}:${cveId}`,
            source: provider,
            sourceType: provider === "REDHAT" ? "vendor" : "primary",
            retrievedAt: now,
            url: "https://example.test/",
            title: "test",
            confidence: "high",
            facts,
            extractedFacts: [],
            references: [],
        },
    });
}

function run(
    providers: Parameters<typeof investigateCve>[1]["providers"],
) {
    return investigateCve("CVE-2099-0001", {
        requestTimeoutMs: 1000,
        providers: {
            nvd: absent("NVD"),
            cisaKev: absent("CISA_KEV"),
            redhat: absent("REDHAT"),
            ...providers,
        },
    });
}

async function testStatus(): Promise<void> {
    const nvd = found("NVD", { id: "CVE-2099-0001" });
    const kev = found("CISA_KEV", { cveID: "CVE-2099-0001" });

    const cases: [string, Parameters<typeof run>[0], string][] = [
        ["everything absent", {}, "not-found"],
        ["NVD record, KEV absent", { nvd }, "confirmed"],
        ["NVD record, Red Hat down", { nvd, redhat: failing("REDHAT") }, "confirmed"],
        ["KEV only", { cisaKev: kev }, "partial"],
        ["NVD record, KEV down", { nvd, cisaKev: failing("CISA_KEV") }, "partial"],
        ["NVD down, KEV absent", { nvd: failing("NVD") }, "failed"],
        ["NVD absent, KEV down", { cisaKev: failing("CISA_KEV") }, "failed"],
        ["both down", { nvd: failing("NVD"), cisaKev: failing("CISA_KEV") }, "failed"],
    ];

    for (const [name, providers, expected] of cases) {
        const { status } = await run(providers);

        assert(status === expected, `${name}: expected ${expected}, got ${status}`);
    }

    console.log("✓ Investigation status separates absence from failure");
}

async function testRejected(): Promise<void> {
    const result = await run({
        nvd: found("NVD", {
            id: "CVE-2099-0001",
            vulnStatus: "Rejected",
        }),
    });

    assert(result.status === "partial", "a rejected CVE must not be confirmed");
    assert(
        result.limitations.some((text) => text.includes("Rejected")),
        "rejection must be a limitation",
    );
    assert(
        result.analystGuidance[0].includes("Rejected"),
        "guidance must lead with the rejection",
    );

    console.log("✓ Rejected CVE is not confirmed");
}

async function testRedHat404(): Promise<void> {
    const realFetch = globalThis.fetch;

    globalThis.fetch = (async () =>
        new Response("{}", { status: 404 })) as typeof fetch;

    const absence = await fetchRedHatCve("CVE-2099-0001", { timeoutMs: 1000 });

    globalThis.fetch = (async () =>
        new Response("{}", { status: 500 })) as typeof fetch;

    const failure = await fetchRedHatCve("CVE-2099-0001", { timeoutMs: 1000 });

    globalThis.fetch = realFetch;

    assert(absence.status === "observed_absence", "404 means Red Hat has no record");
    assert(failure.status === "error", "500 is still a provider failure");

    /* A CVE Red Hat does not track must remain reusable. */
    const result = await run({
        nvd: found("NVD", { id: "CVE-2099-0001" }),
        redhat: async () => absence,
    });

    const decision = evaluatePriorInvestigation({
        status: result.status,
        createdAt: now,
        providerResults: result.providerResults,
        limitations: result.limitations,
        evidenceCount: result.evidence.length,
        evidenceRetrievedAt: result.evidence.map((item) => item.retrievedAt),
    });

    assert(decision.decision === "reuse", `expected reuse: ${decision.reason}`);

    console.log("✓ Red Hat 404 is an observed absence and allows reuse");
}

async function testCvssSource(): Promise<void> {
    const cna = {
        source: "cna@vendor.example",
        type: "Secondary",
        cvssData: { version: "3.1", baseScore: 3.1, baseSeverity: "LOW" },
    };

    const nvd = {
        source: "nvd@nist.gov",
        type: "Secondary",
        cvssData: { version: "3.1", baseScore: 9.8, baseSeverity: "CRITICAL" },
    };

    const preferred = await run({
        nvd: found("NVD", {
            id: "CVE-2099-0001",
            metrics: { cvssMetricV31: [cna, nvd] },
        }),
    });

    assert(preferred.summary.cvss.baseScore === 9.8, "NVD's score must win");
    assert(preferred.summary.cvss.source === "nvd@nist.gov", "source must be kept");

    const fallback = await run({
        nvd: found("NVD", {
            id: "CVE-2099-0001",
            metrics: { cvssMetricV31: [cna] },
        }),
    });

    assert(fallback.summary.cvss.baseScore === 3.1, "CNA score is the fallback");
    assert(
        fallback.confirmedFacts.some((fact) =>
            fact.includes("scored by cna@vendor.example"),
        ),
        "a non-NVD score must name its source",
    );

    console.log("✓ CVSS prefers NVD and names its source");
}

async function testAffectedVersions(): Promise<void> {
    const result = await run({
        nvd: found("NVD", {
            id: "CVE-2099-0001",
            configurations: [
                {
                    operator: "AND",
                    nodes: [
                        {
                            cpeMatch: [
                                {
                                    vulnerable: true,
                                    criteria: "cpe:2.3:a:tukaani:xz:5.6.0:*:*:*:*:*:*:*",
                                },
                                {
                                    vulnerable: true,
                                    criteria: "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
                                    versionStartIncluding: "2.0.1",
                                    versionEndExcluding: "2.15.0",
                                },
                            ],
                        },
                        {
                            cpeMatch: [
                                {
                                    vulnerable: false,
                                    criteria: "cpe:2.3:o:linux:kernel:6.1:*:*:*:*:*:*:*",
                                },
                            ],
                        },
                    ],
                },
            ],
        }),
    });

    const versions = result.summary.affectedVersions.join(" | ");

    assert(
        versions === "tukaani:xz 5.6.0 | apache:log4j >= 2.0.1, < 2.15.0",
        `unexpected versions: ${versions}`,
    );

    console.log("✓ Affected versions read criteria, keep products, skip platforms");
}

async function testFactTags(): Promise<void> {
    const result = await run({
        nvd: found("NVD", {
            id: "CVE-2099-0001",
            descriptions: [
                {
                    lang: "en",
                    value: "Vendor says CVSS is 0.0 and CISA KEV listing was removed.",
                },
            ],
            metrics: {
                cvssMetricV31: [
                    {
                        source: "nvd@nist.gov",
                        cvssData: { version: "3.1", baseScore: 9.8 },
                    },
                ],
            },
        }),
    });

    const description = result.factProvenance.find(
        (fact) => fact.field === "description",
    );

    assert(description, "description should be a tagged fact");

    const cvss = verifyCvssClaim({
        claim: { baseScore: 9.8 },
        observed: result.summary.cvss,
        factProvenance: result.factProvenance,
    });

    const kev = verifyKevClaim({
        claim: { listed: true },
        observed: result.summary.kevStatus,
        factProvenance: result.factProvenance,
    });

    assert(
        cvss.supportingFactIds.length === 1 &&
        !cvss.supportingFactIds.includes(description.id),
        "source text must not support a CVSS claim",
    );
    assert(
        !kev.contradictingFactIds.includes(description.id),
        "source text must not contradict a KEV claim",
    );

    console.log("✓ Verification cites tagged facts, not matching text");
}

async function testRedHatData(): Promise<void> {
    const realFetch = globalThis.fetch;

    globalThis.fetch = (async () =>
        Response.json({
            name: "CVE-2099-0001",
            cvss3: { cvss3_base_score: "9.8" },
            affected_release: [
                {
                    product_name: "Red Hat Enterprise Linux 8",
                    advisory: "RHSA-2099:0001",
                    package: "log4j-0:2.17.0-1.el8",
                },
            ],
            package_state: [
                {
                    product_name: "Red Hat Enterprise Linux 7",
                    package_name: "log4j",
                    fix_state: "Not affected",
                },
            ],
        })) as typeof fetch;

    const redhat = await fetchRedHatCve("CVE-2099-0001", { timeoutMs: 1000 });

    globalThis.fetch = realFetch;

    const result = await run({
        redhat: async () => redhat,
        nvd: found("NVD", {
            id: "CVE-2099-0001",
            metrics: {
                cvssMetricV31: [
                    {
                        source: "nvd@nist.gov",
                        cvssData: { version: "3.1", baseScore: 10 },
                    },
                ],
            },
        }),
    });

    const fixed = result.summary.vendorImpact.find(
        (row) => row.status === "fixed",
    );

    assert(
        fixed?.originalStatus === "Fixed by RHSA-2099:0001" &&
        result.summary.vendorImpact.length === 2,
        "fixed releases must appear alongside package states",
    );

    const values = result.summary.conflicts?.[0]?.values ?? [];

    assert(
        values.some((item) => item.source === "nvd@nist.gov" && item.value === 10) &&
        values.some((item) => item.source === "Red Hat" && item.value === 9.8),
        "NVD and Red Hat CVSS disagreement must be reported",
    );

    const view = viewFromResult(result);

    assert(
        checkAnswer("CVE-2099-0001: Red Hat gives CVSS 9.8.", [view]).length === 0,
        "the gate must accept a score from a reported conflict",
    );
    assert(
        checkAnswer("CVE-2099-0001 has CVSS 5.0.", [view]).length === 1,
        "the gate must still reject an unsupported score",
    );

    const agreeing = await run({
        nvd: found("NVD", {
            id: "CVE-2099-0001",
            metrics: {
                cvssMetricV31: [
                    {
                        source: "nvd@nist.gov",
                        cvssData: { version: "3.1", baseScore: 9.8 },
                    },
                ],
            },
        }),
        redhat: async () => redhat,
    });

    assert(
        agreeing.summary.conflicts?.length === 0,
        "matching scores are not a conflict",
    );

    console.log("✓ Red Hat fixes are kept and CVSS conflicts are reported");
}

function testDatabaseTls(): void {
    const remote = "aws-0-region.pooler.supabase.com";
    const encrypted = { rejectUnauthorized: false };

    const cases: [string, NodeJS.ProcessEnv, unknown][] = [
        [remote, {}, encrypted],
        [remote, { THREATINTEL_DB_SSL: "require" }, encrypted],
        [remote, { THREATINTEL_DB_SSL: "verify-full" }, { rejectUnauthorized: true }],
        [remote, { THREATINTEL_DB_SSL: "disable" }, false],
        [remote, { PGSSLMODE: "verify-full" }, undefined],
        ["localhost", {}, undefined],
        ["127.0.0.1", {}, undefined],
    ];

    for (const [host, env, expected] of cases) {
        const actual = resolveSsl(host, env);

        assert(
            JSON.stringify(actual) === JSON.stringify(expected),
            `${host} ${JSON.stringify(env)}: got ${JSON.stringify(actual)}`,
        );
    }

    console.log("✓ Remote database connections use TLS by default");
}

function testKevFreshness(): void {
    const evaluatedAt = new Date("2026-01-02T12:00:00.000Z");
    const hoursAgo = (hours: number) =>
        new Date(evaluatedAt.getTime() - hours * 3_600_000).toISOString();

    const decide = (
        kevStatus: "observed_absence" | "success",
        hours: number,
    ) =>
        evaluatePriorInvestigation(
            {
                status: "confirmed",
                createdAt: hoursAgo(hours),
                limitations: [],
                evidenceCount: 1,
                evidenceRetrievedAt: [hoursAgo(hours)],
                providerResults: [
                    { provider: "NVD", status: "success" },
                    {
                        provider: "CISA_KEV",
                        status: kevStatus,
                        checkedAt: hoursAgo(hours),
                    },
                ],
            },
            { now: evaluatedAt },
        ).decision;

    assert(decide("observed_absence", 5) === "reuse", "recent absence reuses");
    assert(decide("observed_absence", 7) === "refresh", "old absence refreshes");
    assert(decide("success", 7) === "reuse", "a KEV listing keeps the full window");

    console.log("✓ KEV absence uses a shorter freshness window");
}

async function main(): Promise<void> {
    await testStatus();
    await testRejected();
    await testRedHat404();
    await testCvssSource();
    await testAffectedVersions();
    await testFactTags();
    await testRedHatData();
    testDatabaseTls();
    testKevFreshness();

    console.log("Engine accuracy tests PASSED");
}

main().catch((error: unknown) => {
    console.error("Engine accuracy tests FAILED");
    console.error(error);
    process.exitCode = 1;
});
