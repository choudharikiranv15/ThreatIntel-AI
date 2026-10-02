import type {
    ClaimVerification,
    CvssDetails,
    EvidenceFactRecord,
    KnowledgeState,
} from "../types.js";

export type CvssClaim = {
    baseScore?: number;
    version?: string;
    vector?: string;
    severity?: string;
};

export type CvssVerificationInput = {
    claim: CvssClaim;
    observed: CvssDetails | null;
    factProvenance: EvidenceFactRecord[];
};

function matchesClaim(
    claim: CvssClaim,
    observed: CvssDetails,
): boolean {
    if (
        claim.baseScore !== undefined &&
        claim.baseScore !== observed.baseScore
    ) {
        return false;
    }

    if (
        claim.version !== undefined &&
        claim.version !== observed.version
    ) {
        return false;
    }

    if (
        claim.vector !== undefined &&
        claim.vector !== observed.vector
    ) {
        return false;
    }

    if (
        claim.severity !== undefined &&
        claim.severity.toUpperCase() !==
        (observed.severity ?? "").toUpperCase()
    ) {
        return false;
    }

    return true;
}

function hasClaimFields(claim: CvssClaim): boolean {
    return Object.keys(claim).length > 0;
}

export function verifyCvssClaim(
    input: CvssVerificationInput,
): ClaimVerification {
    const { claim, observed, factProvenance } = input;

    const claimText = [
        claim.version !== undefined ? `version=${claim.version}` : null,
        claim.baseScore !== undefined ? `baseScore=${claim.baseScore}` : null,
        claim.vector !== undefined ? `vector=${claim.vector}` : null,
        claim.severity !== undefined ? `severity=${claim.severity}` : null,
    ]
        .filter(Boolean)
        .join(", ");

    const id = `cvss:${claimText || "empty"}`;

    if (!hasClaimFields(claim)) {
        return {
            id,
            claim: claimText,
            state: "unknown",
            supportingFactIds: [],
            contradictingFactIds: [],
        };
    }

    if (!observed) {
        return {
            id,
            claim: claimText,
            state: "unknown",
            supportingFactIds: [],
            contradictingFactIds: [],
        };
    }

    const matching = matchesClaim(claim, observed);

    const cvssFacts = factProvenance.filter((fact) => {
        const field = fact.field?.toLowerCase() ?? "";

        return (
            field.startsWith("cvss") ||
            fact.claim.toLowerCase().includes("cvss")
        );
    });

    if (matching) {
        return {
            id,
            claim: claimText,
            state: "confirmed",
            supportingFactIds: cvssFacts.map((fact) => fact.id),
            contradictingFactIds: [],
        };
    }

    return {
        id,
        claim: claimText,
        state: "contradicted",
        supportingFactIds: [],
        contradictingFactIds: cvssFacts.map((fact) => fact.id),
    };
}