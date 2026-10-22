
import assert from "node:assert/strict";
import {
    classifyEvidenceReferences,
} from "./reference-provenance.js";

const references = classifyEvidenceReferences([
    {
        title: "Vendor advisory",
        url: "https://example.com/advisory",
        retrieved: false,
    },
    {
        title: "Independently retrieved source",
        url: "https://example.com/checked",
        retrieved: true,
    },
]);

assert.equal(references.length, 2);

assert.equal(
    references[0].provenance,
    "listed_not_independently_retrieved",
);

assert.equal(references[0].retrieved, false);
assert.equal(
    references[0].url,
    "https://example.com/advisory",
);

assert.equal(
    references[1].provenance,
    "independently_retrieved",
);

assert.equal(references[1].retrieved, true);

console.log("Reference provenance tests PASSED");
