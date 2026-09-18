export type SourceId =
  | "NVD"
  | "CISA_KEV";

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

export type CvssDetails = {
  version: string | null;
  baseScore: number | null;
  vector: string | null;
  severity: string | null;
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
};

export type InvestigationSummary = {
  severity: string | null;

  cvss: CvssDetails;

  kevStatus: KevStatus;

  cwe: string[];

  affectedVersions: string[];
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