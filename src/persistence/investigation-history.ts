import { db } from "./db.js";
import type { InvestigationStatus } from "../types.js";

export type InvestigationHistoryItem = {
  id: string;
  target: string;
  targetType: string;
  investigationType: string;
  status: InvestigationStatus;
  createdAt: string;
};

export async function findInvestigationHistory(
  target: string,
): Promise<InvestigationHistoryItem[]> {
  const query = `
    SELECT
      id,
      target,
      target_type,
      investigation_type,
      status,
      created_at
    FROM investigations
    WHERE target = $1
    ORDER BY created_at DESC
  `;

  const { rows } = await db.query<{
    id: string;
    target: string;
    target_type: string;
    investigation_type: string;
    status: InvestigationStatus;
    created_at: Date;
  }>(query, [target]);

  return rows.map((row) => ({
    id: row.id,
    target: row.target,
    targetType: row.target_type,
    investigationType: row.investigation_type,
    status: row.status,
    createdAt: row.created_at.toISOString(),
  }));
}
