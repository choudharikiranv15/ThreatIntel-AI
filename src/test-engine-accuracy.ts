/*
 * Regressions for engine accuracy bugs found against live data. Offline: providers
 * are faked, and fetchRedHatCve runs against a faked fetch.
 */
import { investigateCve } from "./engine.js";
import { evaluatePriorInvestigation } from "./persistence/investigation-policy.js";
import { fetchRedHatCve } from "./sources/redhat.js";
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

async function main(): Promise<void> {
    await testStatus();
    await testRejected();
    await testRedHat404();

    console.log("Engine accuracy tests PASSED");
}

main().catch((error: unknown) => {
    console.error("Engine accuracy tests FAILED");
    console.error(error);
    process.exitCode = 1;
});
