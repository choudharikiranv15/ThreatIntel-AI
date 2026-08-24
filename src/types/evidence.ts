export type EvidenceSource =
    | "NVD"
    | "CISA KEV";

export interface EvidenceItem {
    source: EvidenceSource;
    retrievedAt: string;
    url: string;
    title: string;
    facts: Record<string, unknown>;
}

export interface InvestigationResult {
    target: string;

    status:
    | "confirmed"
    | "not-found"
    | "partial"
    | "failed";

    evidence: EvidenceItem[];

    findings: string[];

    limitations: string[];

    analystGuidance: string[];
}