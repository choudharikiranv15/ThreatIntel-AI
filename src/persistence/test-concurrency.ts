
import { randomUUID } from "node:crypto";
import { db, closeDatabase } from "./db.js";
import { persistInvestigation } from "./persist-investigation.js";
import type { InvestigationResult } from "../types.js";

function createResult(
    target: string,
    runId: string,
): InvestigationResult {
    const evidenceId = `NVD:${runId}:evidence`;
    const factId = `fact:${runId}`;
    const inferenceId = `inference:${runId}`;
    const claim = `${target} test fact for ${runId}`;

    return {
        target,
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
            affectedVersions: ["1.0.0"],
            vendorImpact: [],
        },

        confirmedFacts: [claim],
        factProvenance: [
            {
                id: factId,
                claim,
                evidenceId,
                field: "id",
            },
        ],

        inferences: [`Review ${target} for ${runId}`],
        inferenceProvenance: [
            {
                id: inferenceId,
                claim: `Review ${target} for ${runId}`,
                supportingFactIds: [factId],
            },
        ],

        evidence: [
            {
                id: evidenceId,
                source: "NVD",
                sourceType: "primary",
                retrievedAt: new Date().toISOString(),
                url: "https://nvd.nist.gov/",
                title: `Concurrency test evidence ${runId}`,
                confidence: "high",
                facts: {
                    target,
                    runId,
                },
                extractedFacts: [
                    {
                        claim,
                        field: "id",
                    },
                ],
                references: [
                    {
                        title: "NVD",
                        url: "https://nvd.nist.gov/",
                        retrieved: false,
                    },
                ],
            },
        ],

        providerResults: [],
        limitations: [],
        analystGuidance: [],
        verifications: [],
    };
}

async function main(): Promise<void> {
    const token = randomUUID();
    const uniqueTargets = Array.from(
        { length: 8 },
        (_, index) => `TEST-CONCURRENCY-${token}-${index}`,
    );
    const duplicateTarget = `TEST-DUPLICATE-${token}`;
    const allTargets = [...uniqueTargets, duplicateTarget];

    try {
        console.log("Testing concurrent persistence...");

        const jobs = [
            ...uniqueTargets.map((target, index) =>
                createResult(target, `${token}-unique-${index}`),
            ),
            ...Array.from({ length: 3 }, (_, index) =>
                createResult(duplicateTarget, `${token}-duplicate-${index}`),
            ),
        ];

        const results = await Promise.allSettled(
            jobs.map((result) => persistInvestigation(result)),
        );

        const failures = results.filter(
            (result) => result.status === "rejected",
        );

        if (failures.length > 0) {
            for (const failure of failures) {
                if (failure.status === "rejected") {
                    console.error("Persistence failure:", failure.reason);
                }
            }

            throw new Error(
                `${failures.length} of ${jobs.length} concurrent writes failed`,
            );
        }

        const investigationIds = results.map((result) => {
            if (result.status !== "fulfilled") {
                throw new Error("Unexpected rejected persistence result");
            }

            return result.value;
        });

        if (new Set(investigationIds).size !== jobs.length) {
            throw new Error(
                "Expected a distinct investigation ID for every write",
            );
        }

        console.log(`✓ All ${jobs.length} concurrent writes succeeded`);
        console.log("✓ Every write received a distinct investigation ID");

        const persisted = await db.query<{
            id: string;
            target: string;
            evidence_count: number;
            fact_count: number;
            inference_count: number;
        }>(
            `
            SELECT
                i.id,
                i.target,
                COUNT(DISTINCT e.id)::int AS evidence_count,
                COUNT(DISTINCT f.id)::int AS fact_count,
                COUNT(DISTINCT inf.id)::int AS inference_count
            FROM public.investigations i
            LEFT JOIN public.evidence e
                ON e.investigation_id = i.id
            LEFT JOIN public.facts f
                ON f.investigation_id = i.id
            LEFT JOIN public.inferences inf
                ON inf.investigation_id = i.id
            WHERE i.id = ANY($1::uuid[])
            GROUP BY i.id, i.target
            `,
            [investigationIds],
        );

        if (persisted.rows.length !== jobs.length) {
            throw new Error(
                `Expected ${jobs.length} investigations, found ${persisted.rows.length}`,
            );
        }

        for (const row of persisted.rows) {
            if (
                row.evidence_count !== 1 ||
                row.fact_count !== 1 ||
                row.inference_count !== 1
            ) {
                throw new Error(
                    `Data isolation failure for ${row.target}: ` +
                    `evidence=${row.evidence_count}, ` +
                    `facts=${row.fact_count}, ` +
                    `inferences=${row.inference_count}`,
                );
            }
        }

        console.log("✓ Evidence, facts and inferences remain isolated");

        const duplicateRows = persisted.rows.filter(
            (row) => row.target === duplicateTarget,
        );

        if (duplicateRows.length !== 3) {
            throw new Error(
                `Expected 3 history entries for repeated target; found ${duplicateRows.length}`,
            );
        }

        console.log(
            "✓ Repeated target produced 3 independent investigation history entries",
        );
        console.log("");
        console.log("Concurrency integration test PASSED");
    } catch (error: unknown) {
        console.error("");
        console.error("Concurrency integration test FAILED:");
        console.error(error);
        process.exitCode = 1;
    } finally {
        try {
            await db.query(
                `DELETE FROM public.investigations
                 WHERE target = ANY($1::text[])`,
                [allTargets],
            );
            console.log("✓ Test records cleaned up");
        } catch (cleanupError) {
            console.error("⚠ Test-data cleanup failed:", cleanupError);
            process.exitCode = 1;
        }

        await closeDatabase();
    }
}

void main();
