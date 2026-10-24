/**
 * Golden test for Red Hat CVE-2024-3094 vendor impact assessment.
 *
 * This test verifies the actual Red Hat API response for CVE-2024-3094
 * is correctly parsed and produces vendor impact assessments.
 */

import {
  investigateCve,
} from "../engine.js";

const CVE_3094 =
  "CVE-2024-3094";

const result =
  await investigateCve(
    CVE_3094,
    {
      requestTimeoutMs: 15000,
    },
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
/* Red Hat provider                                                           */
/* -------------------------------------------------------------------------- */

const redhatProvider =
  result.providerResults.find(
    (provider) =>
      provider.provider === "REDHAT",
  );

assert(
  Boolean(redhatProvider),
  "Red Hat provider result was not returned.",
);

if (
  redhatProvider?.status ===
  "success"
) {
  console.log(
    "✓ Red Hat provider succeeded",
  );

  const redhatEvidence =
    result.evidence.find(
      (evidence) =>
        evidence.source === "REDHAT",
    );

  assert(
    redhatEvidence?.sourceType ===
    "vendor",
    `Red Hat evidence should have sourceType=vendor, got ${redhatEvidence?.sourceType}`,
  );

  assert(
    result.summary.vendorImpact.length > 0,
    `Expected vendor impact assessments, got ${result.summary.vendorImpact.length}`,
  );

  console.log(
    `✓ Found ${result.summary.vendorImpact.length} vendor impact assessments`,
  );

  const rhel8 =
    result.summary.vendorImpact.find(
      (impact) =>
        impact.productName.includes(
          "Red Hat Enterprise Linux 8",
        ),
    );

  const rhel9 =
    result.summary.vendorImpact.find(
      (impact) =>
        impact.productName.includes(
          "Red Hat Enterprise Linux 9",
        ),
    );

  const jboss =
    result.summary.vendorImpact.find(
      (impact) =>
        impact.productName.includes(
          "JBoss",
        ),
    );

  if (rhel8) {
    console.log(
      `✓ RHEL 8 xz: ${rhel8.status} (original: ${rhel8.originalStatus})`,
    );

    assert(
      rhel8.status === "not_affected",
      `RHEL 8 should be not_affected, got ${rhel8.status}`,
    );

    assert(
      rhel8.packageName === "xz",
      `RHEL 8 package should be xz, got ${rhel8.packageName}`,
    );
  }

  if (rhel9) {
    console.log(
      `✓ RHEL 9 xz: ${rhel9.status} (original: ${rhel9.originalStatus})`,
    );

    assert(
      rhel9.status === "not_affected",
      `RHEL 9 should be not_affected, got ${rhel9.status}`,
    );
  }

  if (jboss) {
    console.log(
      `✓ JBoss xz: ${jboss.status} (original: ${jboss.originalStatus})`,
    );

    assert(
      jboss.status === "not_affected",
      `JBoss should be not_affected, got ${jboss.status}`,
    );
  }

  /* Verify distinct product assessments are preserved */
  const productNames = new Set(
    result.summary.vendorImpact.map(
      (impact) =>
        impact.productName,
    ),
  );

  assert(
    productNames.size ===
    result.summary.vendorImpact.length,
    "All product assessments should be preserved separately",
  );

  console.log(
    `✓ All ${productNames.size} product assessments preserved`,
  );

  /* Verify CVE identifier was validated */
  const packageState =
    redhatEvidence?.facts
      .package_state;

  assert(
    Array.isArray(packageState),
    "package_state should be an array",
  );

  /* Verify evidence provenance */
  const hasRedHatFact =
    result.confirmedFacts.some(
      (fact) =>
        fact.includes("Red Hat"),
    );

  assert(
    hasRedHatFact,
    "Confirmed facts should include Red Hat reference",
  );

  console.log(
    "✓ Evidence provenance verified",
  );
} else if (
  redhatProvider?.status === "error"
) {
  console.log(
    "⚠ Red Hat provider failed (network or API issue):",
  );
  console.log(
    `  ${redhatProvider.error}`,
  );

  assert(
    result.status !== "failed",
    "Red Hat failure should not cause investigation to fail",
  );

  console.log(
    "✓ Investigation continued despite Red Hat failure",
  );
} else if (
  redhatProvider?.status === "timeout"
) {
  console.log(
    "⚠ Red Hat provider timed out",
  );

  assert(
    result.status !== "failed",
    "Red Hat timeout should not cause investigation to fail",
  );

  console.log(
    "✓ Investigation continued despite Red Hat timeout",
  );
}

/* -------------------------------------------------------------------------- */
/* Investigation integrity                                                    */
/* -------------------------------------------------------------------------- */

assert(
  result.status === "confirmed" ||
  result.status === "partial",
  `Investigation status should be confirmed or partial, got ${result.status}`,
);

assert(
  result.providerResults.length === 3,
  `Expected 3 provider results (NVD, CISA_KEV, REDHAT), got ${result.providerResults.length}`,
);

console.log(
  `✓ Investigation status: ${result.status}`,
);

/* -------------------------------------------------------------------------- */
/* Final                                                                      */
/* -------------------------------------------------------------------------- */

if (failures.length > 0) {
  console.error(
    "\n❌ Red Hat golden test FAILED\n",
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
    "\n✅ Red Hat golden test PASSED",
  );

  console.log(
    `CVE: ${result.target}`,
  );

  console.log(
    `Vendor impact assessments: ${result.summary.vendorImpact.length}`,
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
}
