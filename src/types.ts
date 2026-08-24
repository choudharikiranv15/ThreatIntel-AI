export type SourceId = "NVD" | "CISA_KEV";

export type Evidence = {
  source: SourceId;
  retrievedAt: string;
  url: string;
  title: string;
  facts: Record<string, unknown>;
};

export type InvestigationResult = {
  target: string;
  targetType: "cve";
  investigationType: "vulnerability";
  status: "complete" | "partial" | "not_found" | "error";
  verdict: {
    severity: string | null;
    knownExploited: boolean | null;
    confidence: number;
  };
  evidence: Evidence[];
  limitations: string[];
  analystGuidance: string[];
};