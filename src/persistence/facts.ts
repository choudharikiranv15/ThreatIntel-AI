import { db } from "./db.js";

export type PersistedFact = {
    id: string;
    claim: string;
    evidenceId: string;
    field?: string;
};

export async function insertFact(
    investigationId: string,
    fact: PersistedFact,
): Promise<void> {
    const query = `
    INSERT INTO facts (
      id,
      investigation_id,
      evidence_id,
      claim,
      field
    )
    VALUES ($1, $2, $3, $4, $5)
  `;

    const values = [
        fact.id,
        investigationId,
        fact.evidenceId,
        fact.claim,
        fact.field ?? null,
    ];

    await db.query(query, values);
}