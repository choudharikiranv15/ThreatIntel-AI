import type { InvestigationResult } from "../types.js";
import { persistInvestigation } from "./persist-investigation.js";

export type PersistenceResult = {
    persisted: boolean;
    investigationId: string | null;
    error: string | null;
};

export async function persistInvestigationResult(
    result: InvestigationResult,
): Promise<PersistenceResult> {
    try {
        const investigationId =
            await persistInvestigation(result);

        return {
            persisted: true,
            investigationId,
            error: null,
        };
    } catch (error) {
        return {
            persisted: false,
            investigationId: null,
            error:
                error instanceof Error
                    ? error.message
                    : String(error),
        };
    }
}