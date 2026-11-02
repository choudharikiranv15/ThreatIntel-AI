export type SourceId =
  | "NVD"
  | "CISA_KEV"
  | "REDHAT"
  | "OSV";

export type SourceType =
  | "primary"
  | "vendor"
  | "community";

export type EvidenceConfidence =
  | "high"
  | "medium"
  | "low";

export type ProviderStatus =
  | "success"
  | "observed_absence"
  | "error"
  | "timeout";

export type KevStatus =
  | "listed"
  | "not-listed"
  | "unknown";

export type InvestigationStatus =
  | "confirmed"
  | "partial"
  | "not-found"
  | "failed";

export type KnowledgeState =
  | "confirmed"
  | "contradicted"
  | "unsupported"
  | "unknown";

export type ClaimVerification = {
  id: string;
  claim: string;
  state: KnowledgeState;
  supportingFactIds: string[];
  contradictingFactIds: string[];
};

export type CvssDetails = {
  version: string | null;
  baseScore: number | null;
  vector: string | null;
  severity: string | null;

  /**
   * Who assigned this score. An NVD record can carry CNA or CISA scores.
   */
  source?: string | null;
};

export type EvidenceFact = {
  claim: string;
  field?: string;
};

export type EvidenceFactRecord = {
  id: string;
  claim: string;
  evidenceId: string;
  field?: string;
};

export type InferenceRecord = {
  id: string;
  claim: string;
  supportingFactIds: string[];
};

export type EvidenceReference = {
  title: string;
  url: string;
  retrieved: boolean;
};

export type Evidence = {
  id: string;

  source: SourceId;

  sourceType: SourceType;

  retrievedAt: string;

  url: string;

  title: string;

  confidence: EvidenceConfidence;

  /**
   * Facts directly extracted from this retrieved source.
   */
  facts: Record<string, unknown>;

  /**
   * Human-readable claims derived directly from facts.
   *
   * These are NOT LLM-generated.
   */
  extractedFacts: EvidenceFact[];

  /**
   * URLs/references discovered inside the source.
   *
   * retrieved=false means ThreatIntel AI has NOT independently
   * retrieved or verified that source.
   */
  references: EvidenceReference[];
};

export type ProviderResult = {
  provider: SourceId;

  status: ProviderStatus;

  /**
   * Evidence returned when status === "success".
   */
  evidence: Evidence | null;

  /**
   * Error information when status === "error" or "timeout".
   */
  error: string | null;

  /**
   * Timestamp of the provider operation.
   */
  checkedAt: string;

  /**
   * The KEV catalog release that was checked. An absence has no evidence
   * record, so this is what ties "not listed" to a point in time.
   */
  catalogVersion?: string;
};

export type VendorImpactStatus =
  | "affected"
  | "fixed"
  | "not_affected"
  | "unknown";

export type VendorImpactAssessment = {
  vendor: string;

  productName: string;

  packageName: string;

  cpe: string | null;

  status: VendorImpactStatus;

  originalStatus: string;

  sourceUrl: string;

  retrievedAt: string;

  evidenceId: string;

  reason: string;
};

/**
 * Investigations saved by v0.3 recorded CVSS disagreements in this shape.
 */
export type LegacyEvidenceConflict = {
  field: "cvss.baseScore";

  values: {
    source: string;
    value: number;
  }[];
};

export type CorrelationValue = {
  source: string;
  value: string | number;
  vector?: string | null;
  evidenceId: string | null;
};

/**
 * What independent sources say about one thing. Sources are never reduced to a
 * single value: every source's answer stays attached.
 */
export type Correlation = {
  id: string;

  topic:
  | "cvss"
  | "severity"
  | "exploitation"
  | "vendor_assessment"
  | "fixed_version";

  scope: string | null;

  /**
   * conflict: sources disagree about the same thing.
   * explained_difference: sources are answering different questions.
   * incomplete: a comparison could not be completed.
   */
  classification:
  | "agreement"
  | "conflict"
  | "explained_difference"
  | "incomplete";

  reason: string;

  explanation: string;

  values: CorrelationValue[];

  /** Set when an output cap removed values from this comparison. */
  valuesOmitted?: number;

  /**
   * A reading this engine applies, not something any source states. Red Hat's
   * scale and CVSS severity are separate, so an alignment here is never agreement.
   */
  interpretation?: {
    kind: "approximate_name_alignment";
    aligned: boolean;
  };
};

export type PackageFix = {
  ecosystem: string;
  package: string;
  fixedVersions: string[];
  lastAffectedVersions: string[];
  advisoryId: string;
};

/**
 * One assessment statement, with what it rests on. Every statement except a gap
 * must cite a fact, a provider check, or evidence.
 */
export type AssessmentStatement = {
  topic: string;
  kind: "fact" | "inference" | "conflict" | "difference" | "gap";
  statement: string;
  factIds: string[];
  providerChecks: SourceId[];
  evidenceIds: string[];
};

export type InvestigationSummary = {
  severity: string | null;

  cvss: CvssDetails;

  kevStatus: KevStatus;

  cwe: string[];

  affectedVersions: string[];

  vendorImpact: VendorImpactAssessment[];

  correlations?: Correlation[];

  packageFixes?: PackageFix[];

  assessment?: AssessmentStatement[];

  /**
   * Missing OSV enrichment. Kept apart from the investigation's limitations
   * because it should not, alone, block reuse of complete core evidence.
   */
  enrichmentLimitations?: string[];

  /** Read only from investigations saved by v0.3. */
  conflicts?: LegacyEvidenceConflict[];
};

export type InvestigationResult = {
  target: string;

  targetType: "cve";

  investigationType: "vulnerability";

  status: InvestigationStatus;

  summary: InvestigationSummary;

  /**
   * Facts directly supported by retrieved evidence.
   *
   * The LLM MUST NOT add facts here.
   */
  confirmedFacts: string[];

  factProvenance: EvidenceFactRecord[];

  /**
   * Conservative analytical conclusions derived from confirmed facts.
   *
   * These are not source facts.
   */
  inferences: string[];

  inferenceProvenance: InferenceRecord[];

  /**
   * Directly retrieved evidence.
   */
  evidence: Evidence[];

  /**
   * Complete provider execution state.
   *
   * This prevents "not found", "not listed", and
   * "provider failed" from being conflated.
   */
  providerResults: ProviderResult[];

  /**
   * Problems or scope limitations encountered.
   */
  limitations: string[];

  /**
   * Conservative SOC recommendations.
   */
  analystGuidance: string[];
};