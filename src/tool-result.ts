import type { InvestigationContext } from "./persistence/investigation-context.js";
import { classifyEvidenceReferences } from "./reference-provenance.js";
import type {
    AssessmentStatement,
    Correlation,
    CvssDetails,
    EvidenceReference,
    InvestigationResult,
    KevStatus,
    PackageFix,
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
export const VIEW_BUDGET_CHARS = MAX_TOOL_RESULT_CHARS - 3500;

/** The largest comparison attached to a fresh result, within the room left above. */
export const COMPARISON_BUDGET_CHARS = 2800;

const TIERS = [
    { items: 25, references: 8, text: 800 },
    { items: 12, references: 3, text: 400 },
    { items: 5, references: 0, text: 200 },
    { items: 3, references: 0, text: 100 },
];

type Tier = (typeof TIERS)[number];

/* Disputes and inferences come last in no order that a cap may silently cut. */
const MIN_ASSESSMENT_ITEMS = 16;

const MAX_CORRELATION_VALUES = 8;

/* Identifiers and machine-readable values: shortening these would corrupt them. */
const PRESERVED_KEYS = new Set([
  "id",
  "target",
  "status",
  "mode",
  "evidenceId",
  "provider",
  "vector",
  "checkedAt",
  "retrievedAt",
  "total",
  "omitted",
]);

function shrink(value: unknown, maxItems: number, maxChars: number): unknown {
  if (typeof value === "string") {
    return clip(value, maxChars);
  }

  if (Array.isArray(value)) {
    return value
      .slice(0, maxItems)
      .map((item) => shrink(item, maxItems, maxChars));
  }

  if (typeof value === "object" && value !== null) {
    const shrunk = Object.fromEntries(
      Object.entries(value).map(([key, item]) => [
        key,
        PRESERVED_KEYS.has(key)
          ? item
          : shrink(item, maxItems, maxChars),
      ]),
    ) as Record<string, unknown>;

    // A capped list must keep telling the truth about what is missing.
    if (Array.isArray(shrunk.items) && typeof shrunk.total === "number") {
      shrunk.omitted = shrunk.total - shrunk.items.length;
    }

    return shrunk;
  }

  return value;
}

/**
 * Serializes a complete tool response, guaranteed to fit the limit. Tool results
 * are read by a model, so formatting whitespace (about 30%) would only displace
 * intelligence; OpenClaw passes a string through unchanged, while it pretty-prints
 * objects. The caps above keep normal results well inside the limit, so reduction
 * here is only a last defence against abnormal data, and it announces itself.
 */
export function toToolText(payload: unknown): string {
  const text = JSON.stringify(payload);

  if (text.length <= MAX_TOOL_RESULT_CHARS) {
    return text;
  }

  for (const [maxItems, maxChars] of [
    [20, 200],
    [10, 120],
    [5, 80],
    [3, 60],
  ]) {
    const reduced = JSON.stringify({
      _reducedToFit:
        "This result was too large, so lists and text were shortened. It is incomplete.",
      ...(shrink(payload, maxItems, maxChars) as object),
    });

    if (reduced.length <= MAX_TOOL_RESULT_CHARS) {
      return reduced;
    }
  }

  const record = (payload ?? {}) as Record<string, unknown>;

  return JSON.stringify({
    _reducedToFit:
      "This result was too large to return. Only its identity is shown, so no finding may be drawn from it.",
    target: clip(String(record.target ?? "unknown"), 100),
    status: clip(String(record.status ?? "unknown"), 40),
    mode: clip(String(record.mode ?? "unknown"), 20),
  });
}

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

export type ViewCorrelation = Omit<Correlation, "explanation"> & {
    explanation?: string;
};

/* Cites only what a statement rests on, so empty lists cost nothing. */
export type ViewStatement =
    Pick<AssessmentStatement, "topic" | "kind" | "statement"> &
    Partial<Pick<AssessmentStatement, "factIds" | "providerChecks" | "evidenceIds">>;

/*
 * The budget should hold intelligence, not repetition. An agreement's reason says
 * it all, and its identical vectors add nothing. Other explanations already appear
 * as assessment statements, except for records saved before assessments existed
 * and aligned severity levels, which the assessment leaves out.
 */
function compactCorrelation(
    correlation: Correlation,
    hasAssessment: boolean,
): ViewCorrelation {
    const capped: ViewCorrelation =
        correlation.values.length > MAX_CORRELATION_VALUES
            ? {
                ...correlation,
                values: correlation.values.slice(0, MAX_CORRELATION_VALUES),
                valuesOmitted:
                    correlation.values.length - MAX_CORRELATION_VALUES,
            }
            : correlation;

    const { explanation: _explanation, ...withoutExplanation } = capped;

    if (correlation.classification === "agreement") {
        return {
            ...withoutExplanation,
            values: capped.values.map(({ vector: _vector, ...value }) => value),
        };
    }

    return hasAssessment && correlation.interpretation?.aligned !== true
        ? withoutExplanation
        : capped;
}

function compactStatement(item: AssessmentStatement): ViewStatement {
    return {
        topic: item.topic,
        kind: item.kind,
        statement: item.statement,
        ...(item.factIds.length > 0 ? { factIds: item.factIds } : {}),
        ...(item.providerChecks.length > 0
            ? { providerChecks: item.providerChecks }
            : {}),
        ...(item.evidenceIds.length > 0 ? { evidenceIds: item.evidenceIds } : {}),
    };
}

export type InvestigationView = {
    target: string;
    status: string;
    summary: {
        severity: string | null;
        cvss: CvssDetails;
        kevStatus: KevStatus;
        correlations: Capped<ViewCorrelation>;
        cwe: Capped<string>;
        affectedVersions: Capped<string>;
        vendorImpact: Capped<{
            product: string;
            package: string;
            status: string;
            originalStatus: string;
        }> & {
            /** Exact counts across every row, including any omitted from items. */
            statusCounts: Record<string, number>;
        };
        packageFixes: Capped<PackageFix>;
    };
    assessment: Capped<ViewStatement>;
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

function statusCounts(
    impact: VendorImpactAssessment[],
): Record<string, number> {
    const counts: Record<string, number> = {};

    for (const row of impact) {
        counts[row.status] = (counts[row.status] ?? 0) + 1;
    }

    return counts;
}

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

/* v0.3 recorded only CVSS disagreements, with nothing to classify them by. */
function correlationsOf(
    summary: ViewSource["summary"],
): Correlation[] {
    return summary.correlations ?? (summary.conflicts ?? []).map((conflict) => ({
        id: "cvss",
        topic: "cvss" as const,
        scope: null,
        classification: "conflict" as const,
        reason: "recorded_before_classification",
        explanation:
            "This investigation predates conflict classification, so the cause of the difference is unknown.",
        values: conflict.values.map((item) => ({
            ...item,
            evidenceId: null,
        })),
    }));
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
            correlations: capped(
                correlationsOf(summary).map((correlation) =>
                    compactCorrelation(correlation, Boolean(summary.assessment)),
                ),
                tier.items,
            ),
            cwe: capped(summary.cwe ?? [], tier.items),
            affectedVersions: capped(
                primaryProductsFirst(
                    summary.affectedVersions ?? [],
                    source.facts,
                ),
                tier.items,
            ),
            vendorImpact: {
                ...capped(
                    vendorImpactRows(summary.vendorImpact ?? []),
                    tier.items,
                ),
                statusCounts: statusCounts(summary.vendorImpact ?? []),
            },
            packageFixes: capped(summary.packageFixes ?? [], tier.items),
        },
        assessment: capped(
            (summary.assessment ?? []).map((item) => ({
                ...compactStatement(item),
                statement: clip(item.statement, tier.text),
            })),
            Math.max(tier.items, MIN_ASSESSMENT_ITEMS),
        ),
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

export function clipAllStrings<T>(value: T, limit: number): T {
    if (typeof value === "string") {
        return clip(value, limit) as T;
    }

    if (Array.isArray(value) && value.every((item) => typeof item === "string")) {
        return value.map((item) => clip(item, limit)) as T;
    }

    if (Array.isArray(value)) {
        return value.map((item) => clipAllStrings(item, limit)) as T;
    }

    if (typeof value === "object" && value !== null) {
        return Object.fromEntries(
            Object.entries(value).map(([key, item]) => [
                key,
                PRESERVED_KEYS.has(key) ? item : clipAllStrings(item, limit),
            ]),
        ) as T;
    }

    return value;
}

function bounded(source: ViewSource): InvestigationView {
    for (const tier of TIERS) {
        const view = render(source, tier);

        // Measured raw: toToolText would shrink an oversized view and hide it.
        if (JSON.stringify(view).length <= VIEW_BUDGET_CHARS) {
            return view;
        }
    }

    // Only abnormally long text gets here, and identifiers are never shortened.
    // toToolText still enforces the actual limit on the complete response.
    const last = render(source, TIERS[TIERS.length - 1]);

    let view = last;

    for (const limit of [100, 80, 60, 45]) {
        view = clipAllStrings(last, limit);

        if (JSON.stringify(view).length <= VIEW_BUDGET_CHARS) {
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
        limitations: [
            ...result.limitations,
            ...(result.summary.enrichmentLimitations ?? []),
        ],
        analystGuidance: result.analystGuidance,
    });
}

export function viewFromContext(
    context: InvestigationContext,
): InvestigationView {
    const { investigation } = context;

    const summary =
        investigation.summary as Partial<InvestigationResult["summary"]>;

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
        summary,
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
        limitations: [
            ...investigation.limitations,
            ...(summary.enrichmentLimitations ?? []),
        ],
        analystGuidance: investigation.analystGuidance,
    });
}
