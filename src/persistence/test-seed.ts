import { investigateCve } from "../engine.js";
import type { ProviderResult } from "../types.js";
import { db } from "./db.js";
import { persistInvestigation } from "./persist-investigation.js";

/**
 * Persists a complete investigation, so database tests need no pre-existing rows.
 */
export async function seedInvestigation(target: string): Promise<string> {
    const checkedAt = new Date().toISOString();

    const absent: ProviderResult = {
        provider: "CISA_KEV",
        status: "observed_absence",
        evidence: null,
        error: null,
        checkedAt,
    };

    const result = await investigateCve(target, {
        requestTimeoutMs: 1000,
        providers: {
            cisaKev: async () => absent,
            redhat: async () => ({ ...absent, provider: "REDHAT" }),
            nvd: async () => ({
                provider: "NVD",
                status: "success",
                error: null,
                checkedAt,
                evidence: {
                    id: `NVD:${target}`,
                    source: "NVD",
                    sourceType: "primary",
                    retrievedAt: checkedAt,
                    url: "https://example.test/",
                    title: "Seeded record",
                    confidence: "high",
                    extractedFacts: [],
                    references: [],
                    facts: {
                        id: target,
                        metrics: {
                            cvssMetricV31: [
                                {
                                    source: "nvd@nist.gov",
                                    cvssData: {
                                        version: "3.1",
                                        baseScore: 9.8,
                                        vectorString:
                                            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                    },
                                },
                            ],
                        },
                    },
                },
            }),
        },
    });

    return persistInvestigation(result);
}

export async function deleteSeededInvestigation(
    target: string,
): Promise<void> {
    await db.query(
        "DELETE FROM public.investigations WHERE target = $1",
        [target],
    );
}
