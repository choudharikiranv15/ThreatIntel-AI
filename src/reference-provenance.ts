
import type { EvidenceReference } from "./types.js";

export type ClassifiedEvidenceReference =
    EvidenceReference & {
        provenance:
        | "independently_retrieved"
        | "listed_not_independently_retrieved";
    };

export function classifyEvidenceReferences(
    references: EvidenceReference[],
): ClassifiedEvidenceReference[] {
    return references.map((reference) => ({
        ...reference,
        provenance: reference.retrieved
            ? "independently_retrieved"
            : "listed_not_independently_retrieved",
    }));
}
