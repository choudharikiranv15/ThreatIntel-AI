import assert from "node:assert/strict";

import { verifyCvssClaim } from "./verify-claim.js";
import type {
    CvssDetails,
    EvidenceFactRecord,
} from "../types.js";

const observed: CvssDetails = {
    version: "3.1",
    baseScore: 10,
    vector:
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    severity: "CRITICAL",
};

const provenance: EvidenceFactRecord[] = [
    {
        id: "fact:nvd:cvss",
        claim: "NVD CVSS v3.1 base score is 10.0 (CRITICAL).",
        evidenceId: "NVD:CVE-2024-3094",
        field: "cvss",
    },
];

{
    const result = verifyCvssClaim({
        claim: {
            baseScore: 10,
        },
        observed,
        factProvenance: provenance,
    });

    assert.equal(result.state, "confirmed");
    assert.deepEqual(result.supportingFactIds, [
        "fact:nvd:cvss",
    ]);
    assert.deepEqual(result.contradictingFactIds, []);
}

{
    const result = verifyCvssClaim({
        claim: {
            baseScore: 9.8,
        },
        observed,
        factProvenance: provenance,
    });

    assert.equal(result.state, "contradicted");
    assert.deepEqual(result.supportingFactIds, []);
    assert.deepEqual(result.contradictingFactIds, [
        "fact:nvd:cvss",
    ]);
}

{
    const result = verifyCvssClaim({
        claim: {
            version: "3.1",
            baseScore: 10,
            vector:
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            severity: "CRITICAL",
        },
        observed,
        factProvenance: provenance,
    });

    assert.equal(result.state, "confirmed");
}

{
    const result = verifyCvssClaim({
        claim: {
            baseScore: 10,
        },
        observed: null,
        factProvenance: [],
    });

    assert.equal(result.state, "unknown");
}

{
    const result = verifyCvssClaim({
        claim: {},
        observed,
        factProvenance: provenance,
    });

    assert.equal(result.state, "unknown");
}

console.log("CVSS claim verification tests PASSED");