import { investigateCve } from "../engine.js";
import type {
    Evidence,
    InvestigationResult,
    ProviderResult,
    SourceId,
} from "../types.js";
import { ENGINE_VERSION } from "../version.js";
import { hashPayload } from "./evidence-hash.js";
import {
    getInvestigationContext,
    type InvestigationContext,
} from "./investigation-context.js";

export type ReplayReport = {
    investigationId: string;
    recordedEngineVersion: string | null;
    currentEngineVersion: string;
    evidence: {
        id: string;
        integrity: "verified" | "tampered" | "not_hashed";
    }[];
    differences: string[];
    reproduced: boolean;
};

function storedProvider(
    context: InvestigationContext,
    provider: SourceId,
): () => Promise<ProviderResult> {
    const stored = context.investigation.providerResults.find(
        (result) => (result as ProviderResult).provider === provider,
    ) as ProviderResult | undefined;

    return async () => {
        if (!stored) {
            throw new Error(`${provider} result was not recorded.`);
        }

        if (!stored.evidence) {
            return stored;
        }

        // Replay the evidence row, so a change to it cannot go unnoticed.
        const row = context.evidence.find(
            (item) => item.source === provider,
        );

        const evidence: Evidence = {
            ...stored.evidence,
            facts: row?.rawPayload ?? stored.evidence.facts,
        };

        return { ...stored, evidence };
    };
}

function compare(
    label: string,
    recorded: unknown,
    replayed: unknown,
    differences: string[],
): void {
    if (hashPayload(recorded ?? null) !== hashPayload(replayed ?? null)) {
        differences.push(
            `${label}: recorded ${JSON.stringify(recorded)}, replay produced ${JSON.stringify(replayed)}`,
        );
    }
}

/**
 * Re-derives an investigation from its stored provider results, with no network
 * access, and checks the stored evidence against its hashes. A difference means
 * either the extraction logic or the stored data changed since it was recorded;
 * the engine versions and evidence integrity show which.
 */
export async function replayContext(
    context: InvestigationContext,
): Promise<ReplayReport> {
    const replayed: InvestigationResult = await investigateCve(
        context.investigation.target,
        {
            requestTimeoutMs: 1000,
            providers: {
                nvd: storedProvider(context, "NVD"),
                cisaKev: storedProvider(context, "CISA_KEV"),
                redhat: storedProvider(context, "REDHAT"),
            },
        },
    );

    const evidence = context.evidence.map((item) => ({
        id: item.sourceEvidenceId ?? item.id,
        integrity: !item.contentSha256
            ? ("not_hashed" as const)
            : hashPayload(item.rawPayload) === item.contentSha256
                ? ("verified" as const)
                : ("tampered" as const),
    }));

    const differences: string[] = [];

    compare(
        "status",
        context.investigation.status,
        replayed.status,
        differences,
    );

    compare(
        "summary",
        context.investigation.summary,
        replayed.summary,
        differences,
    );

    const byId = (a: { id: string }, b: { id: string }) =>
        a.id.localeCompare(b.id);

    compare(
        "facts",
        context.facts
            .map((fact) => ({
                id: fact.sourceFactId ?? fact.id,
                claim: fact.claim,
                field: fact.field ?? undefined,
            }))
            .sort(byId),
        replayed.factProvenance
            .map((fact) => ({
                id: fact.id,
                claim: fact.claim,
                field: fact.field,
            }))
            .sort(byId),
        differences,
    );

    compare(
        "inferences",
        context.inferences
            .map((inference) => ({
                id: inference.sourceInferenceId ?? inference.id,
                claim: inference.claim,
            }))
            .sort(byId),
        replayed.inferenceProvenance
            .map((inference) => ({
                id: inference.id,
                claim: inference.claim,
            }))
            .sort(byId),
        differences,
    );

    return {
        investigationId: context.investigation.id,
        recordedEngineVersion: context.investigation.engineVersion,
        currentEngineVersion: ENGINE_VERSION,
        evidence,
        differences,
        reproduced:
            differences.length === 0 &&
            evidence.every((item) => item.integrity !== "tampered"),
    };
}

export async function replayInvestigation(
    investigationId: string,
): Promise<ReplayReport | null> {
    const context = await getInvestigationContext(investigationId);

    return context ? replayContext(context) : null;
}
