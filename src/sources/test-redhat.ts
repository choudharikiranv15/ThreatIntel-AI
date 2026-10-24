import {
  investigateCve,
} from "../engine.js";

import type {
  ProviderResult,
  VendorImpactAssessment,
} from "../types.js";

const CVE_3094 =
  "CVE-2024-3094";

const failures: string[] = [];

function assert(
  condition: boolean,
  message: string,
): void {
  if (!condition) {
    failures.push(message);
  }
}

function fakeProvider(
  result: ProviderResult,
): () => Promise<ProviderResult> {
  return async () => result;
}

function successEvidence(
  source:
    | "NVD"
    | "CISA_KEV",
): ProviderResult {
  return {
    provider: source,
    status: "success",
    error: null,
    checkedAt:
      "2026-01-01T00:00:00.000Z",
    evidence: {
      id: `${source}:${CVE_3094}`,
      source,
      sourceType: "primary",
      retrievedAt:
        "2026-01-01T00:00:00.000Z",
      url:
        source === "NVD"
          ? "https://nvd.nist.gov/"
          : "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
      title:
        source === "NVD"
          ? "NVD"
          : "CISA KEV",
      confidence: "high",
      facts: {},
      extractedFacts: [],
      references: [],
    },
  };
}

function absenceProvider(
  source:
    | "NVD"
    | "CISA_KEV",
): ProviderResult {
  return {
    provider: source,
    status: "observed_absence",
    error: null,
    checkedAt:
      "2026-01-01T00:00:00.000Z",
    evidence: null,
  };
}

function redhatSuccess(
  packageState: unknown[],
): ProviderResult {
  return {
    provider: "REDHAT",
    status: "success",
    error: null,
    checkedAt:
      "2026-01-01T00:00:00.000Z",
    evidence: {
      id: `REDHAT:${CVE_3094}`,
      source: "REDHAT",
      sourceType: "vendor",
      retrievedAt:
        "2026-01-01T00:00:00.000Z",
      url:
        "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2024-3094.json",
      title:
        `Red Hat CVE Record - ${CVE_3094}`,
      confidence: "high",
      facts: {
        name: CVE_3094,
        threat_severity: "Critical",
        statement:
          "Test statement",
        package_state: packageState,
      },
      extractedFacts: [],
      references: [],
    },
  };
}

function redhatFailure(): ProviderResult {
  return {
    provider: "REDHAT",
    status: "error",
    error: "Red Hat API simulated failure",
    checkedAt:
      "2026-01-01T00:00:00.000Z",
    evidence: null,
  };
}

function redhatTimeout(): ProviderResult {
  return {
    provider: "REDHAT",
    status: "timeout",
    error: "Red Hat API simulated timeout",
    checkedAt:
      "2026-01-01T00:00:00.000Z",
    evidence: null,
  };
}

/* -------------------------------------------------------------------------- */
/* Test 1: Explicit "Not affected" status                                    */
/* -------------------------------------------------------------------------- */

{
  const result =
    await investigateCve(
      CVE_3094,
      {
        requestTimeoutMs: 1000,

        providers: {
          nvd: fakeProvider(
            successEvidence("NVD"),
          ),

          cisaKev: fakeProvider(
            absenceProvider(
              "CISA_KEV",
            ),
          ),

          redhat: fakeProvider(
            redhatSuccess([
              {
                product_name:
                  "Red Hat Enterprise Linux 8",
                package_name: "xz",
                fix_state: "Not affected",
                cpe:
                  "cpe:/o:redhat:enterprise_linux:8",
              },
            ]),
          ),
        },
      },
    );

  const redhatProvider =
    result.providerResults.find(
      (provider) =>
        provider.provider === "REDHAT",
    );

  assert(
    redhatProvider?.status === "success",
    "Test 1: Red Hat provider should be success.",
  );

  assert(
    result.summary.vendorImpact.length === 1,
    `Test 1: Expected 1 vendor impact, got ${result.summary.vendorImpact.length}.`,
  );

  const assessment =
    result.summary.vendorImpact[0];

  assert(
    assessment?.status === "not_affected",
    `Test 1: Expected not_affected, got ${assessment?.status}.`,
  );

  assert(
    assessment?.vendor === "Red Hat",
    `Test 1: Expected vendor Red Hat, got ${assessment?.vendor}.`,
  );

  assert(
    assessment?.productName ===
    "Red Hat Enterprise Linux 8",
    `Test 1: Expected product name Red Hat Enterprise Linux 8, got ${assessment?.productName}.`,
  );

  assert(
    assessment?.packageName === "xz",
    `Test 1: Expected package name xz, got ${assessment?.packageName}.`,
  );

  assert(
    assessment?.originalStatus ===
    "Not affected",
    `Test 1: Expected original status Not affected, got ${assessment?.originalStatus}.`,
  );

  assert(
    assessment?.evidenceId ===
    `REDHAT:${CVE_3094}`,
    "Test 1: Expected evidenceId to match.",
  );

  const redhatEvidence =
    result.evidence.find(
      (evidence) =>
        evidence.source === "REDHAT",
    );

  assert(
    redhatEvidence?.sourceType ===
    "vendor",
    `Test 1: Red Hat evidence should have sourceType=vendor, got ${redhatEvidence?.sourceType}.`,
  );

  assert(
    result.status === "confirmed",
    `Test 1: Investigation should be confirmed, got ${result.status}.`,
  );
}

/* -------------------------------------------------------------------------- */
/* Test 2: Explicit "Affected" status                                        */
/* -------------------------------------------------------------------------- */

{
  const result =
    await investigateCve(
      CVE_3094,
      {
        requestTimeoutMs: 1000,

        providers: {
          nvd: fakeProvider(
            successEvidence("NVD"),
          ),

          cisaKev: fakeProvider(
            absenceProvider(
              "CISA_KEV",
            ),
          ),

          redhat: fakeProvider(
            redhatSuccess([
              {
                product_name:
                  "Red Hat Enterprise Linux 6",
                package_name: "xz",
                fix_state: "Affected",
                cpe:
                  "cpe:/o:redhat:enterprise_linux:6",
              },
            ]),
          ),
        },
      },
    );

  const assessment =
    result.summary.vendorImpact[0];

  assert(
    assessment?.status === "affected",
    `Test 2: Expected affected, got ${assessment?.status}.`,
  );

  assert(
    assessment?.originalStatus ===
    "Affected",
    `Test 2: Expected original status Affected, got ${assessment?.originalStatus}.`,
  );
}

/* -------------------------------------------------------------------------- */
/* Test 3: Unknown status                                                     */
/* -------------------------------------------------------------------------- */

{
  const result =
    await investigateCve(
      CVE_3094,
      {
        requestTimeoutMs: 1000,

        providers: {
          nvd: fakeProvider(
            successEvidence("NVD"),
          ),

          cisaKev: fakeProvider(
            absenceProvider(
              "CISA_KEV",
            ),
          ),

          redhat: fakeProvider(
            redhatSuccess([
              {
                product_name:
                  "Red Hat Enterprise Linux 9",
                package_name: "xz",
                fix_state:
                  "Under investigation",
                cpe:
                  "cpe:/o:redhat:enterprise_linux:9",
              },
            ]),
          ),
        },
      },
    );

  const assessment =
    result.summary.vendorImpact[0];

  assert(
    assessment?.status === "unknown",
    `Test 3: Expected unknown status for 'Under investigation', got ${assessment?.status}.`,
  );

  assert(
    assessment?.reason ===
    "Under investigation",
    `Test 3: Reason should be original status, got ${assessment?.reason}.`,
  );
}

/* -------------------------------------------------------------------------- */
/* Test 4: Missing package_state                                              */
/* -------------------------------------------------------------------------- */

{
  const result =
    await investigateCve(
      CVE_3094,
      {
        requestTimeoutMs: 1000,

        providers: {
          nvd: fakeProvider(
            successEvidence("NVD"),
          ),

          cisaKev: fakeProvider(
            absenceProvider(
              "CISA_KEV",
            ),
          ),

          redhat: fakeProvider(
            redhatSuccess([]),
          ),
        },
      },
    );

  assert(
    result.summary.vendorImpact.length === 0,
    `Test 4: Expected 0 vendor impact when package_state is empty, got ${result.summary.vendorImpact.length}.`,
  );

  assert(
    result.status === "confirmed",
    `Test 4: Investigation should still be confirmed, got ${result.status}.`,
  );
}

/* -------------------------------------------------------------------------- */
/* Test 5: Multiple products and packages                                     */
/* -------------------------------------------------------------------------- */

{
  const result =
    await investigateCve(
      CVE_3094,
      {
        requestTimeoutMs: 1000,

        providers: {
          nvd: fakeProvider(
            successEvidence("NVD"),
          ),

          cisaKev: fakeProvider(
            absenceProvider(
              "CISA_KEV",
            ),
          ),

          redhat: fakeProvider(
            redhatSuccess([
              {
                product_name:
                  "Red Hat Enterprise Linux 8",
                package_name: "xz",
                fix_state: "Not affected",
                cpe:
                  "cpe:/o:redhat:enterprise_linux:8",
              },
              {
                product_name:
                  "Red Hat Enterprise Linux 9",
                package_name: "xz",
                fix_state: "Not affected",
                cpe:
                  "cpe:/o:redhat:enterprise_linux:9",
              },
              {
                product_name:
                  "Red Hat JBoss Enterprise Application Platform 8",
                package_name: "xz",
                fix_state: "Not affected",
                cpe: null,
              },
            ]),
          ),
        },
      },
    );

  assert(
    result.summary.vendorImpact.length === 3,
    `Test 5: Expected 3 vendor impacts, got ${result.summary.vendorImpact.length}.`,
  );

  const rhel8 =
    result.summary.vendorImpact.find(
      (impact) =>
        impact.productName ===
        "Red Hat Enterprise Linux 8",
    );

  const rhel9 =
    result.summary.vendorImpact.find(
      (impact) =>
        impact.productName ===
        "Red Hat Enterprise Linux 9",
    );

  const jboss =
    result.summary.vendorImpact.find(
      (impact) =>
        impact.productName.includes(
          "JBoss",
        ),
    );

  assert(
    rhel8?.status === "not_affected",
    `Test 5: RHEL 8 should be not_affected, got ${rhel8?.status}.`,
  );

  assert(
    rhel9?.status === "not_affected",
    `Test 5: RHEL 9 should be not_affected, got ${rhel9?.status}.`,
  );

  assert(
    jboss?.status === "not_affected",
    `Test 5: JBoss should be not_affected, got ${jboss?.status}.`,
  );

  assert(
    jboss?.cpe === null,
    `Test 5: JBoss CPE should be null, got ${jboss?.cpe}.`,
  );
}

/* -------------------------------------------------------------------------- */
/* Test 6: Red Hat failure doesn't break investigation                        */
/* -------------------------------------------------------------------------- */

{
  const result =
    await investigateCve(
      CVE_3094,
      {
        requestTimeoutMs: 1000,

        providers: {
          nvd: fakeProvider(
            successEvidence("NVD"),
          ),

          cisaKev: fakeProvider(
            absenceProvider(
              "CISA_KEV",
            ),
          ),

          redhat: fakeProvider(
            redhatFailure(),
          ),
        },
      },
    );

  const redhatProvider =
    result.providerResults.find(
      (provider) =>
        provider.provider === "REDHAT",
    );

  assert(
    redhatProvider?.status === "error",
    `Test 6: Red Hat provider should be error, got ${redhatProvider?.status}.`,
  );

  assert(
    result.summary.vendorImpact.length === 0,
    `Test 6: Failed Red Hat should produce no vendor impact, got ${result.summary.vendorImpact.length}.`,
  );

  assert(
    result.status === "confirmed",
    `Test 6: Investigation should still be confirmed when Red Hat fails, got ${result.status}.`,
  );

  const hasLimitation =
    result.limitations.some(
      (limitation) =>
        limitation
          .toLowerCase()
          .includes("red hat"),
    );

  assert(
    hasLimitation,
    "Test 6: Red Hat failure should produce a limitation.",
  );
}

/* -------------------------------------------------------------------------- */
/* Test 7: Red Hat timeout                                                    */
/* -------------------------------------------------------------------------- */

{
  const result =
    await investigateCve(
      CVE_3094,
      {
        requestTimeoutMs: 1000,

        providers: {
          nvd: fakeProvider(
            successEvidence("NVD"),
          ),

          cisaKev: fakeProvider(
            absenceProvider(
              "CISA_KEV",
            ),
          ),

          redhat: fakeProvider(
            redhatTimeout(),
          ),
        },
      },
    );

  const redhatProvider =
    result.providerResults.find(
      (provider) =>
        provider.provider === "REDHAT",
    );

  assert(
    redhatProvider?.status === "timeout",
    `Test 7: Red Hat provider should be timeout, got ${redhatProvider?.status}.`,
  );

  assert(
    result.summary.vendorImpact.length === 0,
    `Test 7: Timeout Red Hat should produce no vendor impact, got ${result.summary.vendorImpact.length}.`,
  );

  assert(
    result.status === "confirmed",
    `Test 7: Investigation should still be confirmed when Red Hat times out, got ${result.status}.`,
  );
}

/* -------------------------------------------------------------------------- */
/* Test 8: Evidence provenance                                                */
/* -------------------------------------------------------------------------- */

{
  const result =
    await investigateCve(
      CVE_3094,
      {
        requestTimeoutMs: 1000,

        providers: {
          nvd: fakeProvider(
            successEvidence("NVD"),
          ),

          cisaKev: fakeProvider(
            absenceProvider(
              "CISA_KEV",
            ),
          ),

          redhat: fakeProvider(
            redhatSuccess([
              {
                product_name:
                  "Red Hat Enterprise Linux 8",
                package_name: "xz",
                fix_state: "Not affected",
              },
            ]),
          ),
        },
      },
    );

  const redhatEvidence =
    result.evidence.find(
      (evidence) =>
        evidence.source === "REDHAT",
    );

  assert(
    redhatEvidence !== undefined,
    "Test 8: Red Hat evidence should exist.",
  );

  assert(
    redhatEvidence?.sourceType ===
    "vendor",
    `Test 8: Red Hat evidence should have sourceType=vendor, got ${redhatEvidence?.sourceType}.`,
  );

  assert(
    redhatEvidence?.confidence ===
    "high",
    `Test 8: Red Hat evidence should have high confidence, got ${redhatEvidence?.confidence}.`,
  );

  const hasRedHatFact =
    result.confirmedFacts.some(
      (fact) =>
        fact.includes("Red Hat"),
    );

  assert(
    hasRedHatFact,
    "Test 8: Confirmed facts should include Red Hat reference.",
  );
}

/* -------------------------------------------------------------------------- */
/* Test 9: Conflicting statuses for same package                             */
/* -------------------------------------------------------------------------- */

{
  const result =
    await investigateCve(
      CVE_3094,
      {
        requestTimeoutMs: 1000,

        providers: {
          nvd: fakeProvider(
            successEvidence("NVD"),
          ),

          cisaKev: fakeProvider(
            absenceProvider(
              "CISA_KEV",
            ),
          ),

          redhat: fakeProvider(
            redhatSuccess([
              {
                product_name:
                  "Red Hat Enterprise Linux 8",
                package_name: "xz",
                fix_state: "Not affected",
              },
              {
                product_name:
                  "Red Hat Enterprise Linux 7",
                package_name: "xz",
                fix_state: "Affected",
              },
            ]),
          ),
        },
      },
    );

  assert(
    result.summary.vendorImpact.length === 2,
    `Test 9: Expected 2 separate vendor impacts, got ${result.summary.vendorImpact.length}.`,
  );

  const rhel8 =
    result.summary.vendorImpact.find(
      (impact) =>
        impact.productName.includes("8"),
    );

  const rhel7 =
    result.summary.vendorImpact.find(
      (impact) =>
        impact.productName.includes("7"),
    );

  assert(
    rhel8?.status === "not_affected",
    `Test 9: RHEL 8 should be not_affected, got ${rhel8?.status}.`,
  );

  assert(
    rhel7?.status === "affected",
    `Test 9: RHEL 7 should be affected, got ${rhel7?.status}.`,
  );
}

/* -------------------------------------------------------------------------- */
/* Test 10: All providers succeed                                             */
/* -------------------------------------------------------------------------- */

{
  const result =
    await investigateCve(
      CVE_3094,
      {
        requestTimeoutMs: 1000,

        providers: {
          nvd: fakeProvider(
            successEvidence("NVD"),
          ),

          cisaKev: fakeProvider(
            successEvidence(
              "CISA_KEV",
            ),
          ),

          redhat: fakeProvider(
            redhatSuccess([
              {
                product_name:
                  "Red Hat Enterprise Linux 9",
                package_name: "xz",
                fix_state: "Not affected",
              },
            ]),
          ),
        },
      },
    );

  assert(
    result.providerResults.length === 3,
    `Test 10: Expected 3 provider results, got ${result.providerResults.length}.`,
  );

  assert(
    result.evidence.length === 3,
    `Test 10: Expected 3 evidence items, got ${result.evidence.length}.`,
  );

  assert(
    result.status === "confirmed",
    `Test 10: Investigation should be confirmed, got ${result.status}.`,
  );
}

/* -------------------------------------------------------------------------- */
/* Final                                                                      */
/* -------------------------------------------------------------------------- */

if (failures.length > 0) {
  console.error(
    "\n❌ Red Hat tests FAILED\n",
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
    "\n✅ All Red Hat tests PASSED",
  );

  console.log(
    "  ✓ Explicit 'Not affected' status",
  );

  console.log(
    "  ✓ Explicit 'Affected' status",
  );

  console.log(
    "  ✓ Unknown status",
  );

  console.log(
    "  ✓ Missing package_state",
  );

  console.log(
    "  ✓ Multiple products and packages",
  );

  console.log(
    "  ✓ Red Hat failure doesn't break investigation",
  );

  console.log(
    "  ✓ Red Hat timeout",
  );

  console.log(
    "  ✓ Evidence provenance",
  );

  console.log(
    "  ✓ Conflicting statuses for same package",
  );

  console.log(
    "  ✓ All providers succeed",
  );
}
