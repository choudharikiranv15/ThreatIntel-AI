import { db } from "./db.js";
import type { Evidence } from "../types.js";

export async function insertEvidence(
    investigationId: string,
    evidence: Evidence,
): Promise<void> {
    const query = `
    INSERT INTO evidence (
      id,
      investigation_id,
      source,
      source_type,
      retrieved_at,
      url,
      title,
      confidence,
      facts,
      extracted_facts,
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
      $10,
      $11
    )
  `;

    const values = [
        evidence.id,
        investigationId,
        evidence.source,
        evidence.sourceType,
        evidence.retrievedAt,
        evidence.url,
        evidence.title,
        evidence.confidence,
        JSON.stringify(evidence.facts),
        JSON.stringify(evidence.extractedFacts),
        JSON.stringify(evidence.references),
    ];

    await db.query(query, values);
}