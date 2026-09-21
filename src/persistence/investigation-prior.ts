import { findInvestigationHistory } from "./investigation-history.js";
import {
    getInvestigationContext,
    type InvestigationContext,
} from "./investigation-context.js";

export type PriorInvestigationResult = {
    target: string;
    found: boolean;
    latestInvestigation: {
        id: string;
        status: string;
        createdAt: string;
    } | null;
    context: InvestigationContext | null;
};

export async function getPriorInvestigation(
    target: string,
): Promise<PriorInvestigationResult> {
    const history =
        await findInvestigationHistory(target);

    if (history.length === 0) {
        return {
            target,
            found: false,
            latestInvestigation: null,
            context: null,
        };
    }

    const latest = history[0];

    const context =
        await getInvestigationContext(latest.id);

    return {
        target,
        found: true,
        latestInvestigation: {
            id: latest.id,
            status: latest.status,
            createdAt: latest.createdAt,
        },
        context,
    };
}