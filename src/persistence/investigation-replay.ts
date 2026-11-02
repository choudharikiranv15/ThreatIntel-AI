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

/**
 * Hashes cover evidence payloads only. A clean hash check therefore says nothing
 * about provider statuses, summaries, or facts, which is why they are reported
 * separately and "fully verified" requires both.
 */
export type InvestigationIntegrity = {
    /** Hash and presence checks on evidence rows. */
    evidenceRows:
    | "verified"
    | "tampered"
    | "missing"
    | "inconsistent"
    | "not_hashed"
    | "none";

    /**
     * Whether the record matches what its own evidence re-derives. Only meaningful
     * on the same engine version; across versions it cannot be determined.
     */
    recordConsistency: "consistent" | "inconsistent" | "unverifiable";

    fullyVerified: boolean;
};

export type ReplayReport = {
    investigationId: string;
    recordedEngineVersion: string | null;
    currentEngineVersion: string;
    evidence: {
        id: string;
        integrity:
        | "verified"
        | "tampered"
        | "not_hashed"
        | "missing"
        | "inconsistent";
    }[];
    integrity: InvestigationIntegrity;
    differences: string[];
    reproduced: boolean;
};

function storedResult(
    context: InvestigationContext,
    provider: SourceId,
): ProviderResult | undefined {
    return context.investigation.providerResults.find(
        (result) => (result as ProviderResult).provider === provider,
    ) as ProviderResult | undefined;
}

function storedProvider(
    context: InvestigationContext,
    provider: SourceId,
): () => Promise<ProviderResult> {
    const stored = storedResult(context, provider);

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

/**
 * Runs stored provider results through the current engine, with no network access.
 */
export function rederiveContext(
    context: InvestigationContext,
): Promise<InvestigationResult> {
    return investigateCve(
        context.investigation.target,
        {
            requestTimeoutMs: 1000,
            providers: {
                nvd: storedProvider(context, "NVD"),
                cisaKev: storedProvider(context, "CISA_KEV"),
                redhat: storedProvider(context, "REDHAT"),
                // Older investigations did not check OSV; that is not a failure.
                osv: storedResult(context, "OSV")
                    ? storedProvider(context, "OSV")
                    : null,
            },
        },
    );
}

export function verifyEvidence(
    context: InvestigationContext,
): ReplayReport["evidence"] {
    const rows: ReplayReport["evidence"] = context.evidence.map((item) => {
        const stored = storedResult(context, item.source);

        return {
            id: item.sourceEvidenceId ?? item.id,
            integrity:
                stored && stored.status !== "success"
                    // A provider recorded as having no evidence, yet a row exists.
                    ? ("inconsistent" as const)
                    : !item.contentSha256
                        ? ("not_hashed" as const)
                        : hashPayload(item.rawPayload) === item.contentSha256
                            ? ("verified" as const)
                            : ("tampered" as const),
        };
    });

    // Triggers block updates but allow deletes, so an absent row must be noticed.
    const missing: ReplayReport["evidence"] =
        (context.investigation.providerResults as ProviderResult[])
            .filter(
                (result) =>
                    result.status === "success" &&
                    !context.evidence.some(
                        (item) => item.source === result.provider,
                    ),
            )
            .map((result) => ({
                id: result.evidence?.id ?? `${result.provider}:unknown`,
                integrity: "missing" as const,
            }));

    return [...rows, ...missing];
}

/**
 * Whether a stored investigation can be fully vouched for. No evidence, missing
 * evidence, or a record its evidence does not reproduce is never "verified".
 */
export function assessIntegrity(
    context: InvestigationContext,
    rederived: InvestigationResult,
): InvestigationIntegrity {
    const states = new Set(
        verifyEvidence(context).map((item) => item.integrity),
    );

    const evidenceRows: InvestigationIntegrity["evidenceRows"] =
        states.has("tampered")
            ? "tampered"
            : states.has("missing")
                ? "missing"
                : states.has("inconsistent")
                    ? "inconsistent"
                    : states.has("not_hashed")
                        ? "not_hashed"
                        : states.size === 0
                            ? "none"
                            : "verified";

    const recordConsistency: InvestigationIntegrity["recordConsistency"] =
        context.investigation.engineVersion !== ENGINE_VERSION
            ? "unverifiable"
            : recordDifferences(context, rederived).length === 0
                ? "consistent"
                : "inconsistent";

    return {
        evidenceRows,
        recordConsistency,
        fullyVerified:
            evidenceRows === "verified" &&
            recordConsistency === "consistent",
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
    const replayed = await rederiveContext(context);

    const evidence = verifyEvidence(context);

    const differences = recordDifferences(context, replayed);

    return {
        investigationId: context.investigation.id,
        recordedEngineVersion: context.investigation.engineVersion,
        currentEngineVersion: ENGINE_VERSION,
        evidence,
        integrity: assessIntegrity(context, replayed),
        differences,
        reproduced:
            differences.length === 0 &&
            evidence.every(
                (item) =>
                    item.integrity !== "tampered" &&
                    item.integrity !== "missing" &&
                    item.integrity !== "inconsistent",
            ),
    };
}

function recordDifferences(
    context: InvestigationContext,
    replayed: InvestigationResult,
): string[] {
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

    return differences;
}

export async function replayInvestigation(
    investigationId: string,
): Promise<ReplayReport | null> {
    const context = await getInvestigationContext(investigationId);

    return context ? replayContext(context) : null;
}
