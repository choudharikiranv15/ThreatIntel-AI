
import { randomUUID } from "node:crypto";
import { db } from "./db.js";

async function main(): Promise<void> {
    const client = await db.connect();
    const token = randomUUID();
    const targetA = `TEST-INTEGRITY-A-${token}`;
    const targetB = `TEST-INTEGRITY-B-${token}`;
    let transactionStarted = false;

    try {
        console.log("Testing cross-investigation evidence integrity...");

        await client.query("BEGIN");
        transactionStarted = true;

        const investigationA = await client.query(
            `INSERT INTO public.investigations
         (target, target_type, investigation_type, status)
       VALUES ($1, 'cve', 'vulnerability', 'confirmed')
       RETURNING id`,
            [targetA],
        );

        const investigationB = await client.query(
            `INSERT INTO public.investigations
         (target, target_type, investigation_type, status)
       VALUES ($1, 'cve', 'vulnerability', 'confirmed')
       RETURNING id`,
            [targetB],
        );

        const investigationAId = investigationA.rows[0]?.id;
        const investigationBId = investigationB.rows[0]?.id;

        if (!investigationAId || !investigationBId) {
            throw new Error("Failed to create test investigations");
        }

        const evidence = await client.query(
            `INSERT INTO public.evidence
         (investigation_id, source, source_type, title, url,
          confidence, retrieved_at, raw_payload)
       VALUES ($1, 'NVD', 'primary', 'Integrity test evidence',
               'https://nvd.nist.gov/', 'high', NOW(), '{}'::jsonb)
       RETURNING id`,
            [investigationBId],
        );

        const evidenceId = evidence.rows[0]?.id;

        if (!evidenceId) {
            throw new Error("Failed to create test evidence");
        }

        await client.query("SAVEPOINT cross_investigation_test");

        let rejected = false;

        try {
            await client.query(
                `INSERT INTO public.facts
           (investigation_id, evidence_id, claim)
         VALUES ($1, $2, $3)`,
                [
                    investigationAId,
                    evidenceId,
                    "This cross-investigation link must be rejected",
                ],
            );
        } catch (error: unknown) {
            await client.query("ROLLBACK TO SAVEPOINT cross_investigation_test");

            const dbError = error as { code?: string; constraint?: string };

            if (dbError.code !== "23503") {
                throw error;
            }

            rejected = true;

            console.log(
                `✓ Invalid link rejected by PostgreSQL (${dbError.constraint ?? "foreign key"})`,
            );
        }

        if (!rejected) {
            await client.query("ROLLBACK TO SAVEPOINT cross_investigation_test");
            throw new Error(
                "INTEGRITY FAILURE: PostgreSQL accepted evidence from another investigation",
            );
        }

        await client.query(
            `DELETE FROM public.investigations
       WHERE target = ANY($1::text[])`,
            [[targetA, targetB]],
        );

        await client.query("COMMIT");
        transactionStarted = false;

        console.log("✓ Test records cleaned up");
        console.log("Cross-investigation integrity test PASSED");
    } catch (error: unknown) {
        if (transactionStarted) {
            try {
                await client.query("ROLLBACK");
            } catch (rollbackError) {
                console.error("Rollback failed:", rollbackError);
            }
        }

        console.error("Cross-investigation integrity test FAILED:", error);
        process.exitCode = 1;
    } finally {
        client.release();
        await db.end();
    }
}

void main();
