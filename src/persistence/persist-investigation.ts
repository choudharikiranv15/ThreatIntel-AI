import { db } from "./db.js";
import type { InvestigationResult } from "../types.js";

export async function persistInvestigation(
    result: InvestigationResult,
): Promise<string> {
    const client = await db.connect();

    try {
        await client.query("BEGIN");

        // ---------------------------------------------------------
        // 1. Investigation
        // ---------------------------------------------------------

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

        if (investigationResult.rows.length === 0) {
            throw new Error("Failed to create investigation");
        }

        const investigationId = investigationResult.rows[0].id;

        // ---------------------------------------------------------
        // 2. Evidence
        // ---------------------------------------------------------

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
      VALUES (
        $1,
        $2,
        $3,
        $4,
        $5,
        $6,
        $7,
        $8,
        $9,
        $10
      )
      RETURNING id
    `;

        // Maps the engine's logical evidence ID to the database UUID.
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

            if (evidenceResult.rows.length === 0) {
                throw new Error(
                    `Failed to create evidence: ${evidence.id}`,
                );
            }

            evidenceIdMap.set(
                evidence.id,
                evidenceResult.rows[0].id,
            );
        }

        // ---------------------------------------------------------
        // 3. Facts
        // ---------------------------------------------------------

        const factQuery = `
      INSERT INTO facts (
        id,
        investigation_id,
        evidence_id,
        claim,
        field
      )
      VALUES ($1, $2, $3, $4, $5)
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

            await client.query(factQuery, [
                fact.id,
                investigationId,
                databaseEvidenceId,
                fact.claim,
                fact.field ?? null,
            ]);
        }

        // ---------------------------------------------------------
        // 4. Inferences
        // ---------------------------------------------------------

        const inferenceQuery = `
      INSERT INTO inferences (
        id,
        investigation_id,
        claim,
        supporting_fact_ids
      )
      VALUES ($1, $2, $3, $4)
    `;

        for (const inference of result.inferenceProvenance) {
            await client.query(inferenceQuery, [
                inference.id,
                investigationId,
                inference.claim,
                JSON.stringify(inference.supportingFactIds),
            ]);
        }

        // ---------------------------------------------------------
        // 5. Commit
        // ---------------------------------------------------------

        await client.query("COMMIT");

        return investigationId;
    } catch (error) {
        // Any failure rolls back the complete investigation.
        await client.query("ROLLBACK");
        throw error;
    } finally {
        client.release();
    }
}