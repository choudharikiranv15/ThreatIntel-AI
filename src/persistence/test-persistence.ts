import { db, closeDatabase } from "./db.js";
import { persistInvestigation } from "./persist-investigation.js";
import type { InvestigationResult } from "../types.js";

async function main(): Promise<void> {
    let investigationId: string | undefined;

    try {
        const testId = `TEST-${Date.now()}`;

        const result: InvestigationResult = {
            target: testId,
            targetType: "cve",
            investigationType: "vulnerability",
            status: "confirmed",

            summary: {
                severity: "HIGH",
                cvss: {
                    version: "3.1",
                    baseScore: 8.8,
                    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
                    severity: "HIGH",
                },
                kevStatus: "not-listed",
                cwe: ["CWE-79"],
                affectedVersions: ["1.0.0", "1.1.0"],
            },

            confirmedFacts: [
                `${testId} has a test vulnerability record.`,
                `${testId} has a CVSS v3.1 score of 8.8.`,
            ],

            factProvenance: [
                {
                    id: crypto.randomUUID(),
                    claim: `${testId} has a test vulnerability record.`,
                    evidenceId: "NVD:test-evidence",
                    field: "id",
                },
                {
                    id: crypto.randomUUID(),
                    claim: `${testId} has a CVSS v3.1 score of 8.8.`,
                    evidenceId: "NVD:test-evidence",
                    field: "metrics.cvssMetricV31",
                },
            ],

            inferences: [
                "The vulnerability should receive elevated review priority.",
            ],

            inferenceProvenance: [
                {
                    id: crypto.randomUUID(),
                    claim: "The vulnerability should receive elevated review priority.",
                    supportingFactIds: [],
                },
            ],

            evidence: [
                {
                    id: "NVD:test-evidence",
                    source: "NVD",
                    sourceType: "primary",
                    retrievedAt: new Date().toISOString(),
                    url: "https://example.com/test-evidence",
                    title: "Test NVD Evidence",
                    confidence: "high",

                    facts: {
                        id: testId,
                        cvss: {
                            version: "3.1",
                            baseScore: 8.8,
                        },
                    },

                    extractedFacts: [
                        {
                            claim: `${testId} has a test vulnerability record.`,
                            field: "id",
                        },
                        {
                            claim: `${testId} has a CVSS v3.1 score of 8.8.`,
                            field: "metrics.cvssMetricV31",
                        },
                    ],

                    references: [
                        {
                            title: "Test reference",
                            url: "https://example.com/reference",
                            retrieved: false,
                        },
                    ],
                },
            ],

            providerResults: [
                {
                    provider: "NVD",
                    status: "success",
                    evidence: null,
                    error: null,
                    checkedAt: new Date().toISOString(),
                },
                {
                    provider: "CISA_KEV",
                    status: "observed_absence",
                    evidence: null,
                    error: null,
                    checkedAt: new Date().toISOString(),
                },
            ],

            limitations: [],

            analystGuidance: [
                "Validate affected assets before remediation decisions.",
            ],
        };

        console.log("Persisting test investigation...");

        investigationId = await persistInvestigation(result);

        console.log(`✅ Investigation persisted: ${investigationId}`);

        const investigation = await db.query(
            `
      SELECT id, target, status
      FROM investigations
      WHERE id = $1
      `,
            [investigationId],
        );

        const evidence = await db.query(
            `
      SELECT id, source, title
      FROM evidence
      WHERE investigation_id = $1
      `,
            [investigationId],
        );

        const facts = await db.query(
            `
      SELECT id, claim, evidence_id
      FROM facts
      WHERE investigation_id = $1
      ORDER BY id
      `,
            [investigationId],
        );

        const inferences = await db.query(
            `
      SELECT id, claim, supporting_fact_ids
      FROM inferences
      WHERE investigation_id = $1
      `,
            [investigationId],
        );

        if (investigation.rows.length !== 1) {
            throw new Error("Investigation verification failed");
        }

        if (evidence.rows.length !== 1) {
            throw new Error("Evidence verification failed");
        }

        if (facts.rows.length !== 2) {
            throw new Error(
                `Fact verification failed: expected 2, got ${facts.rows.length}`,
            );
        }

        if (inferences.rows.length !== 1) {
            throw new Error("Inference verification failed");
        }

        console.log("✅ Investigation row verified");
        console.log("✅ Evidence row verified");
        console.log("✅ Fact rows verified");
        console.log("✅ Inference row verified");

        console.log("");
        console.log("Persistence integration test PASSED");
    } catch (error) {
        console.error("");
        console.error("❌ Persistence integration test FAILED");

        if (error instanceof Error) {
            console.error(error.message);
        } else {
            console.error(error);
        }

        process.exitCode = 1;
    } finally {
        if (investigationId) {
            await db.query(
                `
        DELETE FROM investigations
        WHERE id = $1
        `,
                [investigationId],
            );

            console.log(`🧹 Test data removed: ${investigationId}`);
        }

        await closeDatabase();
    }
}

void main();