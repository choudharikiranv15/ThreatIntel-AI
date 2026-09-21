import { findInvestigationHistory } from "./investigation-history.js";

import {
    getInvestigationContext,
    type InvestigationContext,
} from "./investigation-context.js";

import {
    evaluatePriorInvestigation,
    type PriorDecision,
} from "./investigation-policy.js";

export type PriorInvestigationResult = {
    target: string;

    found: boolean;

    latestInvestigation: {
        id: string;
        status: string;
        createdAt: string;
    } | null;

    decision: PriorDecision | null;

    context: InvestigationContext | null;
};

export async function getPriorInvestigation(
    target: string,
): Promise<PriorInvestigationResult> {
    const history =
        await findInvestigationHistory(
            target,
        );

    if (
        history.length === 0
    ) {
        return {
            target,
            found: false,
            latestInvestigation: null,
            decision: {
                decision: "refresh",
                reason:
                    "No prior investigation exists for this target.",
                ageHours: null,
            },
            context: null,
        };
    }

    const latest =
        history[0];

    const context =
        await getInvestigationContext(
            latest.id,
        );

    if (!context) {
        return {
            target,
            found: true,
            latestInvestigation: {
                id: latest.id,
                status: latest.status,
                createdAt:
                    latest.createdAt,
            },
            decision: {
                decision: "refresh",
                reason:
                    "Prior investigation metadata exists, but its persisted context could not be retrieved.",
                ageHours: null,
            },
            context: null,
        };
    }

    const decision =
        evaluatePriorInvestigation({
            status:
                context.investigation.status,

            createdAt:
                context.investigation.createdAt,

            providerResults:
                context.investigation
                    .providerResults,

            limitations:
                context.investigation
                    .limitations,

            evidenceCount:
                context.evidence.length,
        });

    return {
        target,
        found: true,

        latestInvestigation: {
            id: latest.id,
            status: latest.status,
            createdAt:
                latest.createdAt,
        },

        decision,

        context,
    };
}