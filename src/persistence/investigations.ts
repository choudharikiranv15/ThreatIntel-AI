import { db } from "./db.js";
import type { InvestigationResult } from "../types.js";

export async function insertInvestigation(
    result: InvestigationResult,
): Promise<string> {
    const query = `
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

    const values = [
        result.target,
        result.targetType,
        result.investigationType,
        result.status,
        JSON.stringify(result.summary),
        JSON.stringify(result.providerResults),
        JSON.stringify(result.limitations),
        JSON.stringify(result.analystGuidance),
    ];

    const { rows } = await db.query<{ id: string }>(query, values);

    if (rows.length === 0) {
        throw new Error("Failed to insert investigation");
    }

    return rows[0].id;
}