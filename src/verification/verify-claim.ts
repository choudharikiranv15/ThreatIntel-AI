import type {
    ClaimVerification,
    CvssDetails,
    EvidenceFactRecord,
    KevStatus,
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

export type KevClaim = {
    listed: boolean;
};

export type KevVerificationInput = {
    claim: KevClaim;
    observed: KevStatus;
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

function hasClaimFields(
    claim: CvssClaim,
): boolean {
    return Object.keys(claim).length > 0;
}

function hasObservedCvss(
    observed: CvssDetails,
): boolean {
    return (
        observed.baseScore !== null ||
        observed.version !== null ||
        observed.vector !== null ||
        observed.severity !== null
    );
}

function getCvssFacts(
    factProvenance: EvidenceFactRecord[],
): EvidenceFactRecord[] {
    return factProvenance.filter((fact) => {
        const field = fact.field?.toLowerCase() ?? "";

        return (
            field.startsWith("cvss") ||
            fact.claim.toLowerCase().includes("cvss")
        );
    });
}

function getKevFacts(
    factProvenance: EvidenceFactRecord[],
): EvidenceFactRecord[] {
    return factProvenance.filter((fact) => {
        const field = fact.field?.toLowerCase() ?? "";

        return (
            field.startsWith("kev") ||
            fact.claim.toLowerCase().includes("cisa kev")
        );
    });
}

export function verifyCvssClaim(
    input: CvssVerificationInput,
): ClaimVerification {
    const {
        claim,
        observed,
        factProvenance,
    } = input;

    const claimText = [
        claim.version !== undefined
            ? `version=${claim.version}`
            : null,

        claim.baseScore !== undefined
            ? `baseScore=${claim.baseScore}`
            : null,

        claim.vector !== undefined
            ? `vector=${claim.vector}`
            : null,

        claim.severity !== undefined
            ? `severity=${claim.severity}`
            : null,
    ]
        .filter(Boolean)
        .join(", ");

    const id = `cvss:${claimText || "empty"}`;

    /*
     * No actual claim was supplied.
     */
    if (!hasClaimFields(claim)) {
        return {
            id,
            claim: claimText,
            state: "unknown",
            supportingFactIds: [],
            contradictingFactIds: [],
        };
    }

    /*
     * No CVSS object was observed at all.
     */
    if (!observed) {
        return {
            id,
            claim: claimText,
            state: "unknown",
            supportingFactIds: [],
            contradictingFactIds: [],
        };
    }

    /*
     * A CVSS object exists, but every field is null.
     *
     * This means the evidence does not provide
     * enough information to verify or contradict
     * the claim.
     */
    if (!hasObservedCvss(observed)) {
        return {
            id,
            claim: claimText,
            state: "unknown",
            supportingFactIds: [],
            contradictingFactIds: [],
        };
    }

    const cvssFacts = getCvssFacts(
        factProvenance,
    );

    /*
     * We have actual CVSS evidence.
     * Now we can distinguish between
     * confirmed and contradicted.
     */
    if (matchesClaim(claim, observed)) {
        return {
            id,
            claim: claimText,
            state: "confirmed",
            supportingFactIds: cvssFacts.map(
                (fact) => fact.id,
            ),
            contradictingFactIds: [],
        };
    }

    return {
        id,
        claim: claimText,
        state: "contradicted",
        supportingFactIds: [],
        contradictingFactIds: cvssFacts.map(
            (fact) => fact.id,
        ),
    };
}

export function verifyKevClaim(
    input: KevVerificationInput,
): ClaimVerification {
    const {
        claim,
        observed,
        factProvenance,
    } = input;

    const claimText =
        `CISA KEV listed=${claim.listed}`;

    const id =
        `kev:${claim.listed}`;

    /*
     * CISA KEV provider could not determine
     * the status.
     *
     * This is UNKNOWN, not contradicted.
     */
    if (observed === "unknown") {
        return {
            id,
            claim: claimText,
            state: "unknown",
            supportingFactIds: [],
            contradictingFactIds: [],
        };
    }

    const kevFacts =
        getKevFacts(factProvenance);

    const observedListed =
        observed === "listed";

    /*
     * The observed KEV state matches
     * the claim.
     */
    if (claim.listed === observedListed) {
        return {
            id,
            claim: claimText,
            state: "confirmed",
            supportingFactIds:
                kevFacts.map((fact) => fact.id),
            contradictingFactIds: [],
        };
    }

    /*
     * The observed KEV state contradicts
     * the claim.
     */
    return {
        id,
        claim: claimText,
        state: "contradicted",
        supportingFactIds: [],
        contradictingFactIds:
            kevFacts.map((fact) => fact.id),
    };
}