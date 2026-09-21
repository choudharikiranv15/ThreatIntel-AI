import { db } from "./db.js";
import type {
    EvidenceConfidence,
    InvestigationStatus,
    SourceId,
    SourceType,
} from "../types.js";

export type InvestigationContext = {
    investigation: {
        id: string;
        target: string;
        targetType: string;
        investigationType: string;
        status: InvestigationStatus;
        summary: Record<string, unknown>;
        providerResults: unknown[];
        limitations: string[];
        analystGuidance: string[];
        createdAt: string;
    };

    evidence: EvidenceContext[];

    facts: FactContext[];

    inferences: InferenceContext[];
};

export type EvidenceContext = {
    id: string;
    sourceEvidenceId: string | null;
    source: SourceId;
    sourceType: SourceType;
    title: string;
    url: string;
    confidence: EvidenceConfidence;
    retrievedAt: string;
    rawPayload: Record<string, unknown>;
    sourceReferences: unknown[];
};

export type FactContext = {
    id: string;
    sourceFactId: string | null;
    evidenceId: string;
    claim: string;
    field: string | null;
    createdAt: string;
};

export type InferenceContext = {
    id: string;
    sourceInferenceId: string | null;
    claim: string;
    supportingFactIds: string[];
    supportingFacts: FactContext[];
    createdAt: string;
};

type InvestigationRow = {
    id: string;
    target: string;
    target_type: string;
    investigation_type: string;
    status: InvestigationStatus;
    summary: Record<string, unknown>;
    provider_results: unknown[];
    limitations: string[];
    analyst_guidance: string[];
    created_at: Date;
};

type EvidenceRow = {
    id: string;
    source_evidence_id: string | null;
    source: SourceId;
    source_type: SourceType;
    title: string;
    url: string;
    confidence: EvidenceConfidence;
    retrieved_at: Date;
    raw_payload: Record<string, unknown>;
    source_references: unknown[];
};

type FactRow = {
    id: string;
    source_fact_id: string | null;
    evidence_id: string;
    claim: string;
    field: string | null;
    created_at: Date;
};

type InferenceRow = {
    id: string;
    source_inference_id: string | null;
    claim: string;
    supporting_fact_ids: unknown;
    created_at: Date;
};

function parseStringArray(value: unknown): string[] {
    if (!Array.isArray(value)) {
        return [];
    }

    return value.filter(
        (item): item is string => typeof item === "string",
    );
}

export async function getInvestigationContext(
    investigationId: string,
): Promise<InvestigationContext | null> {
    const investigationResult =
        await db.query<InvestigationRow>(
            `
        SELECT
          id,
          target,
          target_type,
          investigation_type,
          status,
          summary,
          provider_results,
          limitations,
          analyst_guidance,
          created_at
        FROM investigations
        WHERE id = $1
      `,
            [investigationId],
        );

    if (investigationResult.rows.length === 0) {
        return null;
    }

    const investigation = investigationResult.rows[0];

    const [
        evidenceResult,
        factsResult,
        inferencesResult,
    ] = await Promise.all([
        db.query<EvidenceRow>(
            `
        SELECT
          id,
          source_evidence_id,
          source,
          source_type,
          title,
          url,
          confidence,
          retrieved_at,
          raw_payload,
          source_references
        FROM evidence
        WHERE investigation_id = $1
        ORDER BY retrieved_at ASC
      `,
            [investigationId],
        ),

        db.query<FactRow>(
            `
        SELECT
          id,
          source_fact_id,
          evidence_id,
          claim,
          field,
          created_at
        FROM facts
        WHERE investigation_id = $1
        ORDER BY created_at ASC
      `,
            [investigationId],
        ),

        db.query<InferenceRow>(
            `
        SELECT
          id,
          source_inference_id,
          claim,
          supporting_fact_ids,
          created_at
        FROM inferences
        WHERE investigation_id = $1
        ORDER BY created_at ASC
      `,
            [investigationId],
        ),
    ]);

    const evidence = evidenceResult.rows.map(
        (row): EvidenceContext => ({
            id: row.id,
            sourceEvidenceId: row.source_evidence_id,
            source: row.source,
            sourceType: row.source_type,
            title: row.title,
            url: row.url,
            confidence: row.confidence,
            retrievedAt: row.retrieved_at.toISOString(),
            rawPayload: row.raw_payload,
            sourceReferences: row.source_references,
        }),
    );

    const facts = factsResult.rows.map(
        (row): FactContext => ({
            id: row.id,
            sourceFactId: row.source_fact_id,
            evidenceId: row.evidence_id,
            claim: row.claim,
            field: row.field,
            createdAt: row.created_at.toISOString(),
        }),
    );

    const factBySourceId = new Map<string, FactContext>();

    for (const fact of facts) {
        if (fact.sourceFactId) {
            factBySourceId.set(
                fact.sourceFactId,
                fact,
            );
        }
    }

    const inferences = inferencesResult.rows.map(
        (row): InferenceContext => {
            const supportingFactIds =
                parseStringArray(row.supporting_fact_ids);

            const supportingFacts =
                supportingFactIds
                    .map((factId) =>
                        factBySourceId.get(factId),
                    )
                    .filter(
                        (fact): fact is FactContext =>
                            fact !== undefined,
                    );

            return {
                id: row.id,
                sourceInferenceId:
                    row.source_inference_id,
                claim: row.claim,
                supportingFactIds,
                supportingFacts,
                createdAt:
                    row.created_at.toISOString(),
            };
        },
    );

    return {
        investigation: {
            id: investigation.id,
            target: investigation.target,
            targetType: investigation.target_type,
            investigationType:
                investigation.investigation_type,
            status: investigation.status,
            summary: investigation.summary,
            providerResults:
                investigation.provider_results,
            limitations:
                investigation.limitations,
            analystGuidance:
                investigation.analyst_guidance,
            createdAt:
                investigation.created_at.toISOString(),
        },

        evidence,
        facts,
        inferences,
    };
}