export type SourceId = "NVD" | "CISA_KEV";

export type Evidence = {
  source: SourceId;
  retrievedAt: string;
  url: string;
  title: string;
  facts: Record<string, unknown>;
};

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
   * Facts directly extracted from authoritative evidence.
   *
   * These are NOT LLM-generated claims.
   */
  confirmedFacts: string[];

  /**
   * Conservative analytical conclusions derived from confirmed facts.
   *
   * These must never be presented as directly sourced facts.
   */
  inferences: string[];

  evidence: Evidence[];

  /**
   * Problems encountered while collecting evidence.
   */
  limitations: string[];

  /**
   * Conservative SOC recommendations.
   */
  analystGuidance: string[];
};