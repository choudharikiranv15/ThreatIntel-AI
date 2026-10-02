import {
    verifyInvestigationCvssClaim,
} from "../engine.js";

import type {
    InvestigationResult,
} from "../types.js";

const investigationWithCvss: InvestigationResult = {
    verifications: [],
    target: "CVE-TEST-0001",
    targetType: "cve",
    investigationType: "vulnerability",
    status: "confirmed",

    summary: {
        severity: "CRITICAL",
        cvss: {
            version: "3.1",
            baseScore: 10,
            vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            severity: "CRITICAL",
        },
        kevStatus: "not-listed",
        cwe: [],
        affectedVersions: [],
    },

    confirmedFacts: [
        "CVE-TEST-0001 NVD CVSS: CVSS v3.1, base score 10, vector CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H.",
    ],

    factProvenance: [
        {
            id: "fact-cvss-1",
            claim:
                "CVE-TEST-0001 NVD CVSS: CVSS v3.1, base score 10, vector CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H.",
            evidenceId: "evidence-nvd-1",
            field: "cvss",
        },
    ],

    inferences: [],
    inferenceProvenance: [],

    evidence: [],

    providerResults: [],

    limitations: [],

    analystGuidance: [],
};

const investigationWithoutCvss: InvestigationResult = {
    ...investigationWithCvss,

    summary: {
        ...investigationWithCvss.summary,

        cvss: {
            version: null,
            baseScore: null,
            vector: null,
            severity: null,
        },
    },

    confirmedFacts: [],
    factProvenance: [],
};

const confirmed = verifyInvestigationCvssClaim(
    investigationWithCvss,
    {
        baseScore: 10,
    },
);

if (confirmed.state !== "confirmed") {
    throw new Error(
        `Expected confirmed, got ${confirmed.state}`,
    );
}

if (
    !confirmed.supportingFactIds.includes(
        "fact-cvss-1",
    )
) {
    throw new Error(
        "Expected the CVSS fact to support the confirmed claim",
    );
}

const contradicted = verifyInvestigationCvssClaim(
    investigationWithCvss,
    {
        baseScore: 7.5,
    },
);

if (contradicted.state !== "contradicted") {
    throw new Error(
        `Expected contradicted, got ${contradicted.state}`,
    );
}

if (
    !contradicted.contradictingFactIds.includes(
        "fact-cvss-1",
    )
) {
    throw new Error(
        "Expected the CVSS fact to contradict the claim",
    );
}

const unknown = verifyInvestigationCvssClaim(
    investigationWithoutCvss,
    {
        baseScore: 10,
    },
);

if (unknown.state !== "unknown") {
    throw new Error(
        `Expected unknown, got ${unknown.state}`,
    );
}

if (unknown.supportingFactIds.length !== 0) {
    throw new Error(
        "Expected no supporting facts for an unknown claim",
    );
}

if (unknown.contradictingFactIds.length !== 0) {
    throw new Error(
        "Expected no contradicting facts for an unknown claim",
    );
}

console.log(
    "Engine integration verification tests PASSED",
);
