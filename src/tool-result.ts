import type { InvestigationContext } from "./persistence/investigation-context.js";
import { classifyEvidenceReferences } from "./reference-provenance.js";
import type {
    CvssDetails,
    EvidenceConflict,
    EvidenceReference,
    InvestigationResult,
    KevStatus,
    VendorImpactAssessment,
} from "./types.js";

/*
 * What the LLM actually receives.
 *
 * OpenClaw truncates oversized tool results (16K/32K/64K chars depending on the
 * model's context window), which silently removed provider results and produced
 * invalid JSON. This view is bounded below the lowest default cap, and is the
 * same for fresh and reused investigations. Raw source payloads stay in the
 * database and never enter the tool result.
 */
export const MAX_TOOL_RESULT_CHARS = 16000;

// Leaves room for the fields wrapped around the view (decision, persistence).
const VIEW_BUDGET_CHARS = MAX_TOOL_RESULT_CHARS - 1500;

const TIERS = [
    { items: 25, references: 8, text: 800 },
    { items: 12, references: 3, text: 400 },
    { items: 5, references: 0, text: 200 },
];

type Tier = (typeof TIERS)[number];

export type Capped<T> = {
    items: T[];
    total: number;
    omitted: number;
};

export type ViewFact = {
    id: string;
    claim: string;
    evidenceId: string;
    field?: string;

    /** The claim quotes text written by an external source. */
    untrusted?: true;
};

export type InvestigationView = {
    target: string;
    status: string;
    summary: {
        severity: string | null;
        cvss: CvssDetails;
        kevStatus: KevStatus;
        conflicts: EvidenceConflict[];
        cwe: string[];
        affectedVersions: Capped<string>;
        vendorImpact: Capped<{
            product: string;
            package: string;
            status: string;
            originalStatus: string;
        }>;
    };
    providerResults: {
        provider: string;
        status: string;
        checkedAt: string | null;
        error: string | null;
        catalogVersion?: string;
    }[];
    facts: ViewFact[];
    inferences: {
        id: string;
        claim: string;
        supportingFactIds: string[];
    }[];
    evidence: {
        id: string;
        source: string;
        sourceType: string;
        title: string;
        url: string;
        confidence: string;
        retrievedAt: string;
        references: Capped<
            ReturnType<typeof classifyEvidenceReferences>[number]
        >;
    }[];
    limitations: string[];
    analystGuidance: string[];
};

type ViewSource = {
    target: string;
    status: string;
    summary: Partial<InvestigationResult["summary"]>;
    providerResults: unknown[];
    facts: ViewFact[];
    inferences: InvestigationView["inferences"];
    evidence: (Omit<InvestigationView["evidence"][number], "references"> & {
        references: EvidenceReference[];
    })[];
    limitations: string[];
    analystGuidance: string[];
};

function capped<T>(list: T[], limit: number): Capped<T> {
    const items = list.slice(0, limit);

    return {
        items,
        total: list.length,
        omitted: list.length - items.length,
    };
}

function clip(text: string, limit: number): string {
    return text.length <= limit
        ? text
        : `${text.slice(0, limit)}... [truncated]`;
}

/* Free text that vendors and CNAs write, which can carry prompt injection. */
const UNTRUSTED_FIELDS = new Set(["description", "statement"]);

const IMPACT_ORDER: Record<string, number> = {
    affected: 0,
    unknown: 1,
    fixed: 2,
    not_affected: 3,
};

function vendorImpactRows(
    impact: VendorImpactAssessment[],
): InvestigationView["summary"]["vendorImpact"]["items"] {
    return [...impact]
        .sort(
            (a, b) =>
                (IMPACT_ORDER[a.status] ?? 1) -
                (IMPACT_ORDER[b.status] ?? 1),
        )
        .map((row) => ({
            product: row.productName,
            package: row.packageName,
            status: row.status,
            originalStatus: row.originalStatus,
        }));
}

/*
 * A CVE can list hundreds of downstream products. When the list is capped, the
 * product the CVE is actually about must survive, so products named in its
 * description come first.
 */
function primaryProductsFirst(
    versions: string[],
    facts: ViewFact[],
): string[] {
    const description =
        facts
            .find((fact) => fact.field === "description")
            ?.claim.toLowerCase() ?? "";

    const isNamed = (entry: string): boolean => {
        const product = entry
            .split(" ")[0]
            .split(":")[1]
            ?.replaceAll("_", " ")
            .toLowerCase();

        return Boolean(product) && description.includes(product);
    };

    return [
        ...versions.filter(isNamed),
        ...versions.filter((entry) => !isNamed(entry)),
    ];
}

function providerRows(
    providerResults: unknown[],
    tier: Tier,
): InvestigationView["providerResults"] {
    return providerResults.map((value) => {
        const row = (value ?? {}) as Record<string, unknown>;

        return {
            provider: String(row.provider ?? "unknown"),
            status: String(row.status ?? "unknown"),
            checkedAt:
                typeof row.checkedAt === "string" ? row.checkedAt : null,
            error:
                typeof row.error === "string"
                    ? clip(row.error, tier.text)
                    : null,
            ...(typeof row.catalogVersion === "string"
                ? { catalogVersion: row.catalogVersion }
                : {}),
        };
    });
}

function render(source: ViewSource, tier: Tier): InvestigationView {
    const { summary } = source;

    return {
        target: source.target,
        status: source.status,
        summary: {
            severity: summary.severity ?? null,
            cvss: summary.cvss ?? {
                version: null,
                baseScore: null,
                vector: null,
                severity: null,
            },
            kevStatus: summary.kevStatus ?? "unknown",
            conflicts: summary.conflicts ?? [],
            cwe: summary.cwe ?? [],
            affectedVersions: capped(
                primaryProductsFirst(
                    summary.affectedVersions ?? [],
                    source.facts,
                ),
                tier.items,
            ),
            vendorImpact: capped(
                vendorImpactRows(summary.vendorImpact ?? []),
                tier.items,
            ),
        },
        providerResults: providerRows(source.providerResults, tier),
        facts: source.facts.map((fact) => ({
            ...fact,
            claim: clip(fact.claim, tier.text),
            ...(fact.field && UNTRUSTED_FIELDS.has(fact.field)
                ? { untrusted: true as const }
                : {}),
        })),
        inferences: source.inferences,
        evidence: source.evidence.map((item) => ({
            ...item,
            references: capped(
                classifyEvidenceReferences(item.references),
                tier.references,
            ),
        })),
        limitations: source.limitations.map((limitation) =>
            clip(limitation, tier.text),
        ),
        analystGuidance: source.analystGuidance,
    };
}

function bounded(source: ViewSource): InvestigationView {
    let view = render(source, TIERS[0]);

    for (const tier of TIERS) {
        view = render(source, tier);

        if (JSON.stringify(view, null, 2).length <= VIEW_BUDGET_CHARS) {
            break;
        }
    }

    return view;
}

export function viewFromResult(
    result: InvestigationResult,
): InvestigationView {
    return bounded({
        target: result.target,
        status: result.status,
        summary: result.summary,
        providerResults: result.providerResults,
        facts: result.factProvenance.map((fact) => ({
            id: fact.id,
            claim: fact.claim,
            evidenceId: fact.evidenceId,
            ...(fact.field ? { field: fact.field } : {}),
        })),
        inferences: result.inferenceProvenance,
        evidence: result.evidence.map((item) => ({
            id: item.id,
            source: item.source,
            sourceType: item.sourceType,
            title: item.title,
            url: item.url,
            confidence: item.confidence,
            retrievedAt: item.retrievedAt,
            references: item.references,
        })),
        limitations: result.limitations,
        analystGuidance: result.analystGuidance,
    });
}

export function viewFromContext(
    context: InvestigationContext,
): InvestigationView {
    const { investigation } = context;

    // Persisted facts reference database ids; report source ids, as fresh runs do.
    const sourceEvidenceIds = new Map(
        context.evidence.map((item) => [
            item.id,
            item.sourceEvidenceId ?? item.id,
        ]),
    );

    return bounded({
        target: investigation.target,
        status: investigation.status,
        summary:
            investigation.summary as Partial<InvestigationResult["summary"]>,
        providerResults: investigation.providerResults,
        facts: context.facts.map((fact) => ({
            id: fact.sourceFactId ?? fact.id,
            claim: fact.claim,
            evidenceId:
                sourceEvidenceIds.get(fact.evidenceId) ?? fact.evidenceId,
            ...(fact.field ? { field: fact.field } : {}),
        })),
        inferences: context.inferences.map((inference) => ({
            id: inference.sourceInferenceId ?? inference.id,
            claim: inference.claim,
            supportingFactIds: inference.supportingFactIds,
        })),
        evidence: context.evidence.map((item) => ({
            id: item.sourceEvidenceId ?? item.id,
            source: item.source,
            sourceType: item.sourceType,
            title: item.title,
            url: item.url,
            confidence: item.confidence,
            retrievedAt: item.retrievedAt,
            references: item.sourceReferences as EvidenceReference[],
        })),
        limitations: investigation.limitations,
        analystGuidance: investigation.analystGuidance,
    });
}
