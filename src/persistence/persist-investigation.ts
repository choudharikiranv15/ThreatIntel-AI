
import { db } from "./db.js";
import type { InvestigationResult } from "../types.js";

export async function persistInvestigation(
    result: InvestigationResult,
): Promise<string> {
    const client = await db.connect();
    let transactionStarted = false;

    try {
        await client.query("BEGIN");
        transactionStarted = true;

        const investigationQuery = `
            INSERT INTO investigations (
                target,
                target_type,
                investigation_type,
                status,
                summary,
                provider_results,
                limitations,
                analyst_guidance
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING id
        `;

        const investigationResult = await client.query<{ id: string }>(
            investigationQuery,
            [
                result.target,
                result.targetType,
                result.investigationType,
                result.status,
                JSON.stringify(result.summary),
                JSON.stringify(result.providerResults),
                JSON.stringify(result.limitations),
                JSON.stringify(result.analystGuidance),
            ],
        );

        const investigationId = investigationResult.rows[0]?.id;

        if (!investigationId) {
            throw new Error("Failed to create investigation");
        }

        const evidenceQuery = `
            INSERT INTO evidence (
                investigation_id,
                source_evidence_id,
                source,
                source_type,
                title,
                url,
                confidence,
                retrieved_at,
                raw_payload,
                source_references
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            RETURNING id
        `;

        const evidenceIdMap = new Map<string, string>();

        for (const evidence of result.evidence) {
            const evidenceResult = await client.query<{ id: string }>(
                evidenceQuery,
                [
                    investigationId,
                    evidence.id,
                    evidence.source,
                    evidence.sourceType,
                    evidence.title,
                    evidence.url,
                    evidence.confidence,
                    evidence.retrievedAt,
                    JSON.stringify(evidence.facts),
                    JSON.stringify(evidence.references),
                ],
            );

            const databaseEvidenceId = evidenceResult.rows[0]?.id;

            if (!databaseEvidenceId) {
                throw new Error(
                    `Failed to create evidence: ${evidence.id}`,
                );
            }

            evidenceIdMap.set(evidence.id, databaseEvidenceId);
        }

        const factQuery = `
            INSERT INTO facts (
                investigation_id,
                evidence_id,
                claim,
                field,
                source_fact_id
            )
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id
        `;

        for (const fact of result.factProvenance) {
            const databaseEvidenceId = evidenceIdMap.get(
                fact.evidenceId,
            );

            if (!databaseEvidenceId) {
                throw new Error(
                    `No persisted evidence found for fact ${fact.id}: ${fact.evidenceId}`,
                );
            }

            const factResult = await client.query<{ id: string }>(
                factQuery,
                [
                    investigationId,
                    databaseEvidenceId,
                    fact.claim,
                    fact.field ?? null,
                    fact.id,
                ],
            );

            if (!factResult.rows[0]?.id) {
                throw new Error(`Failed to create fact: ${fact.id}`);
            }
        }

        const inferenceQuery = `
            INSERT INTO inferences (
                investigation_id,
                claim,
                supporting_fact_ids,
                source_inference_id
            )
            VALUES ($1, $2, $3, $4)
            RETURNING id
        `;

        for (const inference of result.inferenceProvenance) {
            const inferenceResult = await client.query<{ id: string }>(
                inferenceQuery,
                [
                    investigationId,
                    inference.claim,
                    JSON.stringify(inference.supportingFactIds),
                    inference.id,
                ],
            );

            if (!inferenceResult.rows[0]?.id) {
                throw new Error(
                    `Failed to create inference: ${inference.id}`,
                );
            }
        }

        await client.query("COMMIT");
        transactionStarted = false;

        return investigationId;
    } catch (error) {
        if (transactionStarted) {
            try {
                await client.query("ROLLBACK");
            } catch (rollbackError) {
                // Preserve the original persistence error. Attach rollback
                // information where possible for troubleshooting.
                if (error instanceof Error) {
                    const rollbackMessage =
                        rollbackError instanceof Error
                            ? rollbackError.message
                            : String(rollbackError);

                    error.message +=
                        ` (ROLLBACK also failed: ${rollbackMessage})`;
                }
            }
        }

        throw error;
    } finally {
        client.release();
    }
}
