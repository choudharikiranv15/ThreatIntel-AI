import { db } from "./db.js";

export type PersistedInference = {
    id: string;
    claim: string;
    supportingFactIds: string[];
};

export async function insertInference(
    investigationId: string,
    inference: PersistedInference,
): Promise<void> {
    const query = `
    INSERT INTO inferences (
      id,
      investigation_id,
      claim,
      supporting_fact_ids
    )
    VALUES ($1, $2, $3, $4)
  `;

    const values = [
        inference.id,
        investigationId,
        inference.claim,
        JSON.stringify(inference.supportingFactIds),
    ];

    await db.query(query, values);
}