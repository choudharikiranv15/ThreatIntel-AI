import {
  investigateCve,
} from "./engine.js";

const CVE =
  "CVE-2024-3094";

const result =
  await investigateCve(
    CVE,
    {
      requestTimeoutMs: 15000,
    },
  );

console.log(
  JSON.stringify(
    result,
    null,
    2,
  ),
);

const failures: string[] = [];

function assert(
  condition: boolean,
  message: string,
): void {
  if (!condition) {
    failures.push(message);
  }
}

/* -------------------------------------------------------------------------- */
/* Basic result checks                                                        */
/* -------------------------------------------------------------------------- */

assert(
  result.target === CVE,
  `Expected target ${CVE}, got ${result.target}`,
);

assert(
  result.targetType === "cve",
  `Expected targetType=cve, got ${result.targetType}`,
);

assert(
  result.investigationType ===
  "vulnerability",
  "Expected investigationType=vulnerability",
);

/* -------------------------------------------------------------------------- */
/* Investigation status                                                       */
/* -------------------------------------------------------------------------- */

const validStatuses =
  new Set([
    "confirmed",
    "partial",
    "not-found",
    "failed",
  ]);

assert(
  validStatuses.has(
    result.status,
  ),
  `Invalid investigation status: ${String(
    result.status,
  )}`,
);

/* -------------------------------------------------------------------------- */
/* Provider results                                                           */
/* -------------------------------------------------------------------------- */

const nvdProvider =
  result.providerResults.find(
    (provider) =>
      provider.provider === "NVD",
  );

const cisaProvider =
  result.providerResults.find(
    (provider) =>
      provider.provider ===
      "CISA_KEV",
  );

assert(
  Boolean(nvdProvider),
  "NVD provider result was not returned.",
);

assert(
  Boolean(cisaProvider),
  "CISA KEV provider result was not returned.",
);

assert(
  result.providerResults.length === 2,
  `Expected 2 provider results, got ${result.providerResults.length}`,
);

/* -------------------------------------------------------------------------- */
/* Provider status validation                                                 */
/* -------------------------------------------------------------------------- */

const validProviderStatuses =
  new Set([
    "success",
    "observed_absence",
    "error",
    "timeout",
  ]);

for (
  const provider of result.providerResults
) {
  assert(
    validProviderStatuses.has(
      provider.status,
    ),
    `Invalid provider status for ${provider.provider}: ${String(
      provider.status,
    )}`,
  );

  assert(
    Boolean(provider.checkedAt),
    `${provider.provider} is missing checkedAt.`,
  );

  if (
    provider.status === "error" ||
    provider.status === "timeout"
  ) {
    assert(
      provider.evidence === null,
      `${provider.provider} has evidence despite status=${provider.status}.`,
    );
  }

  if (
    provider.status === "success"
  ) {
    assert(
      provider.evidence !== null,
      `${provider.provider} succeeded but returned no evidence.`,
    );
  }
}

/* -------------------------------------------------------------------------- */
/* NVD                                                                         */
/* -------------------------------------------------------------------------- */

const nvdEvidence =
  result.evidence.find(
    (evidence) =>
      evidence.source === "NVD",
  );

assert(
  Boolean(nvdEvidence),
  "NVD evidence was not returned.",
);

if (nvdEvidence) {
  assert(
    nvdEvidence.sourceType ===
    "primary",
    `NVD evidence should be primary, got ${nvdEvidence.sourceType}`,
  );

  assert(
    nvdEvidence.confidence ===
    "high",
    `NVD evidence should have high confidence, got ${nvdEvidence.confidence}`,
  );

  assert(
    Boolean(nvdEvidence.retrievedAt),
    "NVD evidence is missing retrievedAt.",
  );

  assert(
    Boolean(nvdEvidence.url),
    "NVD evidence is missing URL.",
  );

  assert(
    Boolean(nvdEvidence.facts),
    "NVD evidence is missing facts.",
  );

  assert(
    Array.isArray(
      nvdEvidence.extractedFacts,
    ),
    "NVD extractedFacts must be an array.",
  );

  assert(
    Array.isArray(
      nvdEvidence.references,
    ),
    "NVD references must be an array.",
  );
}

/* -------------------------------------------------------------------------- */
/* NVD provider/evidence consistency                                          */
/* -------------------------------------------------------------------------- */

if (nvdProvider) {
  if (
    nvdProvider.status ===
    "success"
  ) {
    assert(
      nvdProvider.evidence !== null,
      "NVD provider says success but evidence is null.",
    );
  }

  if (
    nvdProvider.evidence !== null
  ) {
    assert(
      nvdProvider.evidence.source ===
      "NVD",
      "NVD provider returned evidence with incorrect source.",
    );
  }
}

/* -------------------------------------------------------------------------- */
/* CVSS                                                                        */
/* -------------------------------------------------------------------------- */

assert(
  result.summary.cvss.baseScore ===
  10.0,
  `Expected CVSS base score 10.0, got ${String(
    result.summary.cvss.baseScore,
  )}`,
);

assert(
  result.summary.cvss.version ===
  "3.1",
  `Expected CVSS version 3.1, got ${String(
    result.summary.cvss.version,
  )}`,
);

assert(
  result.summary.cvss.severity ===
  "CRITICAL",
  `Expected severity CRITICAL, got ${String(
    result.summary.cvss.severity,
  )}`,
);

assert(
  result.summary.cvss.vector ===
  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
  `Unexpected CVSS vector: ${String(
    result.summary.cvss.vector,
  )}`,
);

/* -------------------------------------------------------------------------- */
/* CWE                                                                         */
/* -------------------------------------------------------------------------- */

assert(
  result.summary.cwe.includes(
    "CWE-506",
  ),
  "Expected CWE-506 in extracted weaknesses.",
);

/* -------------------------------------------------------------------------- */
/* CISA KEV                                                                    */
/* -------------------------------------------------------------------------- */

const validKevStatuses =
  new Set([
    "listed",
    "not-listed",
    "unknown",
  ]);

assert(
  validKevStatuses.has(
    result.summary.kevStatus,
  ),
  `Invalid KEV status: ${String(
    result.summary.kevStatus,
  )}`,
);

if (cisaProvider) {
  if (
    cisaProvider.status ===
    "observed_absence"
  ) {
    assert(
      result.summary.kevStatus ===
      "not-listed",
      `CISA observed_absence must map to not-listed, got ${result.summary.kevStatus}`,
    );
  }

  if (
    cisaProvider.status ===
    "error" ||
    cisaProvider.status ===
    "timeout"
  ) {
    assert(
      result.summary.kevStatus ===
      "unknown",
      `CISA ${cisaProvider.status} must map to unknown, got ${result.summary.kevStatus}`,
    );
  }

  if (
    cisaProvider.status ===
    "success"
  ) {
    assert(
      cisaProvider.evidence !==
      null,
      "CISA success requires evidence.",
    );
  }
}

/* -------------------------------------------------------------------------- */
/* Evidence integrity                                                         */
/* -------------------------------------------------------------------------- */

for (
  const evidence of result.evidence
) {
  assert(
    Boolean(evidence.source),
    "Evidence item is missing source.",
  );

  assert(
    Boolean(evidence.sourceType),
    `Evidence item ${evidence.source} is missing sourceType.`,
  );

  assert(
    Boolean(evidence.retrievedAt),
    `Evidence item ${evidence.source} is missing retrievedAt.`,
  );

  assert(
    Boolean(evidence.url),
    `Evidence item ${evidence.source} is missing URL.`,
  );

  assert(
    Boolean(evidence.title),
    `Evidence item ${evidence.source} is missing title.`,
  );

  assert(
    Boolean(evidence.facts),
    `Evidence item ${evidence.source} is missing facts.`,
  );

  assert(
    Array.isArray(
      evidence.extractedFacts,
    ),
    `Evidence item ${evidence.source} has invalid extractedFacts.`,
  );

  assert(
    Array.isArray(
      evidence.references,
    ),
    `Evidence item ${evidence.source} has invalid references.`,
  );

  assert(
    Boolean(evidence.confidence),
    `Evidence item ${evidence.source} is missing confidence.`,
  );
}

/* -------------------------------------------------------------------------- */
/* Confirmed facts vs inference                                               */
/* -------------------------------------------------------------------------- */

assert(
  result.confirmedFacts.length >
  0,
  "No confirmed facts were produced.",
);

assert(
  result.inferences.length >
  0,
  "No explicit inference section was produced.",
);

for (
  const fact of result.confirmedFacts
) {
  assert(
    fact.trim().length > 0,
    "Empty confirmed fact was produced.",
  );
}

for (
  const inference of result.inferences
) {
  assert(
    inference.trim().length > 0,
    "Empty inference was produced.",
  );
}

/* -------------------------------------------------------------------------- */
/* Safety / hallucination checks                                              */
/* -------------------------------------------------------------------------- */

const combinedText =
  [
    ...result.confirmedFacts,
    ...result.inferences,
    ...result.analystGuidance,
  ]
    .join("\n")
    .toLowerCase();

assert(
  !combinedText.includes(
    "presence of a vulnerable version confirms compromise",
  ),
  "Engine incorrectly treats vulnerable-version presence as proof of compromise.",
);

assert(
  !combinedText.includes(
    "not listed in kev means the vulnerability is not exploited",
  ),
  "Engine incorrectly treats KEV absence as proof that the vulnerability is not exploited.",
);

assert(
  !combinedText.includes(
    "not-listed means the vulnerability is not exploited",
  ),
  "Engine incorrectly treats not-listed KEV status as proof of no exploitation.",
);

/* -------------------------------------------------------------------------- */
/* Limitation consistency                                                     */
/* -------------------------------------------------------------------------- */

for (
  const provider of result.providerResults
) {
  if (
    provider.status === "error" ||
    provider.status === "timeout"
  ) {
    const providerName =
      provider.provider ===
        "CISA_KEV"
        ? "CISA KEV"
        : provider.provider;

    const hasLimitation =
      result.limitations.some(
        (limitation) =>
          limitation
            .toLowerCase()
            .includes(
              providerName.toLowerCase(),
            ),
      );

    assert(
      hasLimitation,
      `${provider.provider} failed but no corresponding limitation was reported.`,
    );
  }
}

if (
  cisaProvider &&
  (
    cisaProvider.status ===
    "error" ||
    cisaProvider.status ===
    "timeout"
  )
) {
  assert(
    result.summary.kevStatus !==
    "not-listed",
    "CISA lookup failure was incorrectly converted to not-listed.",
  );
}

/* -------------------------------------------------------------------------- */
/* Final                                                                      */
/* -------------------------------------------------------------------------- */

if (failures.length > 0) {
  console.error(
    "\n❌ Golden test FAILED\n",
  );

  for (
    const failure of failures
  ) {
    console.error(
      `  - ${failure}`,
    );
  }

  process.exitCode = 1;
} else {
  console.log(
    "\n✅ Golden test PASSED",
  );

  console.log(
    `CVE: ${result.target}`,
  );

  console.log(
    `Status: ${result.status}`,
  );

  console.log(
    `Severity: ${result.summary.severity}`,
  );

  console.log(
    `CVSS: ${result.summary.cvss.baseScore}`,
  );

  console.log(
    `KEV: ${result.summary.kevStatus}`,
  );

  console.log(
    "Provider results:",
  );

  for (
    const provider of result.providerResults
  ) {
    console.log(
      `  ${provider.provider}: ${provider.status}`,
    );
  }

  console.log(
    `Evidence sources: ${result.evidence
      .map(
        (evidence) =>
          evidence.source,
      )
      .join(", ")}`,
  );
}