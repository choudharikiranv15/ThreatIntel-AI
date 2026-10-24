
import { db, closeDatabase } from "./db.js";
import { persistInvestigation } from "./persist-investigation.js";
import type {
    Evidence,
    InvestigationResult,
} from "../types.js";

function assert(
    condition: boolean,
    message: string,
): asserts condition {
    if (!condition) {
        throw new Error(`Assertion failed: ${message}`);
    }
}

function makeEvidence(
    id: string,
    confidence: Evidence["confidence"],
): Evidence {
    return {
        id,
        source: "NVD",
        sourceType: "primary",
        retrievedAt: new Date().toISOString(),
        url: `https://example.com/${encodeURIComponent(id)}`,
        title: `Rollback test evidence ${id}`,
        confidence,
        facts: { test: true },
        extractedFacts: [],
        references: [],
    };
}

function makeInvestigation(
    target: string,
): InvestigationResult {
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

        confirmedFacts: [],
        factProvenance: [],
        inferences: [],
        inferenceProvenance: [],

        evidence: [
            // This record should insert successfully inside the transaction.
            makeEvidence("rollback-valid-evidence", "high"),

            // The database CHECK constraint must reject this record.
            makeEvidence(
                "rollback-invalid-evidence",
                "invalid" as Evidence["confidence"],
            ),
        ],

        providerResults: [
            {
                provider: "NVD",
                status: "success",
                evidence: null,
                error: null,
                checkedAt: new Date().toISOString(),
            },
        ],

        limitations: [],
        analystGuidance: [],
        verifications: [],
    };
}

async function main(): Promise<void> {
    const target =
        `TEST-ROLLBACK-${Date.now()}-${crypto.randomUUID()}`;

    let persistenceFailed = false;

    try {
        console.log("Testing transaction rollback...");
        console.log(`Test target: ${target}`);

        const result = makeInvestigation(target);

        try {
            await persistInvestigation(result);
        } catch (error) {
            persistenceFailed = true;

            const message =
                error instanceof Error
                    ? error.message
                    : String(error);

            console.log("✓ Invalid evidence insert was rejected");
            console.log(`Database error: ${message}`);

            assert(
                message.includes("evidence_confidence_check"),
                "failure should come from the expected confidence constraint",
            );
        }

        assert(
            persistenceFailed,
            "persistence should fail for invalid evidence confidence",
        );

        const verification = await db.query<{
            investigations: string;
            evidence: string;
            facts: string;
            inferences: string;
        }>(
            `
            SELECT
                (
                    SELECT COUNT(*)::text
                    FROM investigations
                    WHERE target = $1
                ) AS investigations,
                (
                    SELECT COUNT(*)::text
                    FROM evidence e
                    JOIN investigations i
                      ON i.id = e.investigation_id
                    WHERE i.target = $1
                ) AS evidence,
                (
                    SELECT COUNT(*)::text
                    FROM facts f
                    JOIN investigations i
                      ON i.id = f.investigation_id
                    WHERE i.target = $1
                ) AS facts,
                (
                    SELECT COUNT(*)::text
                    FROM inferences inf
                    JOIN investigations i
                      ON i.id = inf.investigation_id
                    WHERE i.target = $1
                ) AS inferences
            `,
            [target],
        );

        const counts = verification.rows[0];

        assert(counts !== undefined, "rollback verification query returned no row");

        console.log("Remaining records after failed transaction:");
        console.log(`  Investigations: ${counts.investigations}`);
        console.log(`  Evidence:       ${counts.evidence}`);
        console.log(`  Facts:          ${counts.facts}`);
        console.log(`  Inferences:     ${counts.inferences}`);

        assert(
            Number(counts.investigations) === 0,
            "failed transaction must not leave an investigation",
        );
        assert(
            Number(counts.evidence) === 0,
            "failed transaction must not leave evidence",
        );
        assert(
            Number(counts.facts) === 0,
            "failed transaction must not leave facts",
        );
        assert(
            Number(counts.inferences) === 0,
            "failed transaction must not leave inferences",
        );

        console.log("");
        console.log("✓ Transaction rollback verified");
        console.log("Rollback integration test PASSED");
    } catch (error) {
        console.error("");
        console.error("Rollback integration test FAILED");
        console.error(error);
        process.exitCode = 1;
    } finally {
        try {
            // Defensive cleanup in case the test itself or rollback failed.
            // This target is unique to this test invocation.
            await db.query(
                "DELETE FROM investigations WHERE target = $1",
                [target],
            );
        } catch (cleanupError) {
            console.error("Test cleanup failed:", cleanupError);
            process.exitCode = 1;
        }

        try {
            await closeDatabase();
        } catch (closeError) {
            console.error("Database pool shutdown failed:", closeError);
            process.exitCode = 1;
        }
    }
}

void main();
