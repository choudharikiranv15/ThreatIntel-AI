import {
  investigateCve,
} from "./engine.js";

import type {
  ProviderResult,
} from "./types.js";

const cveId =
  "CVE-2024-3094";

const nvdProvider = async (
  target: string,
): Promise<ProviderResult> => ({
  provider: "NVD",
  status: "success",
  checkedAt: new Date().toISOString(),
  error: null,
  evidence: {
    id: "",
    source: "NVD",
    sourceType: "primary",
    retrievedAt: new Date().toISOString(),
    url:
      `https://nvd.nist.gov/vuln/detail/${target}`,
    title: `NVD ${target}`,
    confidence: "high",
    facts: {
      descriptions: [
        {
          lang: "en",
          value: "Test vulnerability.",
        },
      ],
      metrics: {
        cvssMetricV31: [
          {
            cvssData: {
              version: "3.1",
              baseScore: 10,
              vectorString:
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
              baseSeverity: "CRITICAL",
            },
          },
        ],
      },
      weaknesses: [],
      configurations: [],
    },
    extractedFacts: [],
    references: [],
  },
});

const cisaProvider = async (
  _target: string,
): Promise<ProviderResult> => ({
  provider: "CISA_KEV",
  status: "observed_absence",
  checkedAt: new Date().toISOString(),
  error: null,
  evidence: null,
});

const result =
  await investigateCve(
    cveId,
    {
      requestTimeoutMs: 5000,
      providers: {
        nvd: nvdProvider,
        cisaKev: cisaProvider,
      },
    },
  );

if (
  result.factProvenance.length !==
  result.confirmedFacts.length
) {
  throw new Error(
    "Every confirmed fact must have a provenance record.",
  );
}

const evidenceIds =
  new Set(
    result.evidence.map(
      (item) => item.id,
    ),
  );

for (
  const fact of result.factProvenance
) {
  if (
    !evidenceIds.has(
      fact.evidenceId,
    )
  ) {
    throw new Error(
      `Fact ${fact.id} references missing evidence ${fact.evidenceId}`,
    );
  }
}

const factIds =
  new Set(
    result.factProvenance.map(
      (fact) => fact.id,
    ),
  );

for (
  const inference
  of result.inferenceProvenance
) {
  for (
    const factId
    of inference.supportingFactIds
  ) {
    if (!factIds.has(factId)) {
      throw new Error(
        `Inference ${inference.id} references unknown fact ${factId}`,
      );
    }
  }
}

console.log(
  "✅ Provenance tests PASSED",
);

console.log(
  `Evidence records: ${result.evidence.length}`,
);

console.log(
  `Confirmed facts: ${result.confirmedFacts.length}`,
);

console.log(
  `Fact provenance records: ${result.factProvenance.length}`,
);

console.log(
  `Inference provenance records: ${result.inferenceProvenance.length}`,
);
