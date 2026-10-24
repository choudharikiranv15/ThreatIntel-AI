/**
 * Timestamp tracing regression test.
 *
 * Verifies that investigation results use each provider's actual
 * checkedAt/retrievedAt timestamp and never infer timestamps from
 * provider ordering.
 */

import {
  investigateCve,
} from "./engine.js";

import type {
  ProviderResult,
} from "./types.js";

const CVE =
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

/* -------------------------------------------------------------------------- */
/* Test 1: Provider checkedAt timestamps are preserved                        */
/* -------------------------------------------------------------------------- */

{
  const nvdTime =
    "2026-01-15T10:30:00.000Z";
  const cisaTime =
    "2026-01-15T11:45:00.000Z";
  const redhatTime =
    "2026-01-15T09:15:00.000Z";

  const result =
    await investigateCve(
      CVE,
      {
        requestTimeoutMs: 1000,

        providers: {
          nvd: fakeProvider({
            provider: "NVD",
            status: "success",
            error: null,
            checkedAt: nvdTime,
            evidence: {
              id: `NVD:${CVE}`,
              source: "NVD",
              sourceType: "primary",
              retrievedAt: nvdTime,
              url:
                "https://nvd.nist.gov/",
              title: "NVD",
              confidence: "high",
              facts: {},
              extractedFacts: [],
              references: [],
            },
          }),

          cisaKev: fakeProvider({
            provider: "CISA_KEV",
            status: "observed_absence",
            error: null,
            checkedAt: cisaTime,
            evidence: null,
          }),

          redhat: fakeProvider({
            provider: "REDHAT",
            status: "success",
            error: null,
            checkedAt: redhatTime,
            evidence: {
              id: `REDHAT:${CVE}`,
              source: "REDHAT",
              sourceType: "vendor",
              retrievedAt: redhatTime,
              url:
                "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2024-3094.json",
              title:
                "Red Hat CVE Record",
              confidence: "high",
              facts: {
                name: CVE,
                package_state: [],
              },
              extractedFacts: [],
              references: [],
            },
          }),
        },
      },
    );

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

  const redhatProvider =
    result.providerResults.find(
      (provider) =>
        provider.provider === "REDHAT",
    );

  assert(
    nvdProvider?.checkedAt === nvdTime,
    `Test 1: NVD checkedAt should be ${nvdTime}, got ${nvdProvider?.checkedAt}`,
  );

  assert(
    cisaProvider?.checkedAt === cisaTime,
    `Test 1: CISA checkedAt should be ${cisaTime}, got ${cisaProvider?.checkedAt}`,
  );

  assert(
    redhatProvider?.checkedAt ===
    redhatTime,
    `Test 1: Red Hat checkedAt should be ${redhatTime}, got ${redhatProvider?.checkedAt}`,
  );

  const nvdEvidence =
    result.evidence.find(
      (evidence) =>
        evidence.source === "NVD",
    );

  const redhatEvidence =
    result.evidence.find(
      (evidence) =>
        evidence.source === "REDHAT",
    );

  assert(
    nvdEvidence?.retrievedAt === nvdTime,
    `Test 1: NVD evidence retrievedAt should be ${nvdTime}, got ${nvdEvidence?.retrievedAt}`,
  );

  assert(
    redhatEvidence?.retrievedAt ===
    redhatTime,
    `Test 1: Red Hat evidence retrievedAt should be ${redhatTime}, got ${redhatEvidence?.retrievedAt}`,
  );
}

/* -------------------------------------------------------------------------- */
/* Test 2: Vendor impact timestamps use evidence retrievedAt                  */
/* -------------------------------------------------------------------------- */

{
  const redhatTime =
    "2026-02-20T14:22:33.000Z";

  const result =
    await investigateCve(
      CVE,
      {
        requestTimeoutMs: 1000,

        providers: {
          nvd: fakeProvider({
            provider: "NVD",
            status: "success",
            error: null,
            checkedAt:
              "2026-02-20T14:00:00.000Z",
            evidence: {
              id: `NVD:${CVE}`,
              source: "NVD",
              sourceType: "primary",
              retrievedAt:
                "2026-02-20T14:00:00.000Z",
              url:
                "https://nvd.nist.gov/",
              title: "NVD",
              confidence: "high",
              facts: {},
              extractedFacts: [],
              references: [],
            },
          }),

          cisaKev: fakeProvider({
            provider: "CISA_KEV",
            status: "observed_absence",
            error: null,
            checkedAt:
              "2026-02-20T14:10:00.000Z",
            evidence: null,
          }),

          redhat: fakeProvider({
            provider: "REDHAT",
            status: "success",
            error: null,
            checkedAt: redhatTime,
            evidence: {
              id: `REDHAT:${CVE}`,
              source: "REDHAT",
              sourceType: "vendor",
              retrievedAt: redhatTime,
              url:
                "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2024-3094.json",
              title:
                "Red Hat CVE Record",
              confidence: "high",
              facts: {
                name: CVE,
                package_state: [
                  {
                    product_name:
                      "Red Hat Enterprise Linux 8",
                    package_name: "xz",
                    fix_state:
                      "Not affected",
                    cpe:
                      "cpe:/o:redhat:enterprise_linux:8",
                  },
                ],
              },
              extractedFacts: [],
              references: [],
            },
          }),
        },
      },
    );

  assert(
    result.summary.vendorImpact.length === 1,
    `Test 2: Expected 1 vendor impact, got ${result.summary.vendorImpact.length}`,
  );

  const assessment =
    result.summary.vendorImpact[0];

  assert(
    assessment?.retrievedAt === redhatTime,
    `Test 2: Vendor impact retrievedAt should be ${redhatTime}, got ${assessment?.retrievedAt}`,
  );
}

/* -------------------------------------------------------------------------- */
/* Test 3: Timestamps are not inferred from provider ordering                 */
/* -------------------------------------------------------------------------- */

{
  const time1 =
    "2026-03-10T08:00:00.000Z";
  const time2 =
    "2026-03-10T09:00:00.000Z";
  const time3 =
    "2026-03-10T07:00:00.000Z";

  const result =
    await investigateCve(
      CVE,
      {
        requestTimeoutMs: 1000,

        providers: {
          /* First provider - middle timestamp */
          nvd: fakeProvider({
            provider: "NVD",
            status: "success",
            error: null,
            checkedAt: time2,
            evidence: {
              id: `NVD:${CVE}`,
              source: "NVD",
              sourceType: "primary",
              retrievedAt: time2,
              url:
                "https://nvd.nist.gov/",
              title: "NVD",
              confidence: "high",
              facts: {},
              extractedFacts: [],
              references: [],
            },
          }),

          /* Second provider - earliest timestamp */
          cisaKev: fakeProvider({
            provider: "CISA_KEV",
            status: "observed_absence",
            error: null,
            checkedAt: time3,
            evidence: null,
          }),

          /* Third provider - latest timestamp */
          redhat: fakeProvider({
            provider: "REDHAT",
            status: "success",
            error: null,
            checkedAt: time1,
            evidence: {
              id: `REDHAT:${CVE}`,
              source: "REDHAT",
              sourceType: "vendor",
              retrievedAt: time1,
              url:
                "https://access.redhat.com/",
              title: "Red Hat",
              confidence: "high",
              facts: {
                name: CVE,
                package_state: [],
              },
              extractedFacts: [],
              references: [],
            },
          }),
        },
      },
    );

  /* Verify timestamps match exactly, not ordering */
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

  const redhatProvider =
    result.providerResults.find(
      (provider) =>
        provider.provider === "REDHAT",
    );

  assert(
    nvdProvider?.checkedAt === time2,
    `Test 3: NVD should have middle timestamp ${time2}, got ${nvdProvider?.checkedAt}`,
  );

  assert(
    cisaProvider?.checkedAt === time3,
    `Test 3: CISA should have earliest timestamp ${time3}, got ${cisaProvider?.checkedAt}`,
  );

  assert(
    redhatProvider?.checkedAt === time1,
    `Test 3: Red Hat should have latest timestamp ${time1}, got ${redhatProvider?.checkedAt}`,
  );
}

/* -------------------------------------------------------------------------- */
/* Final                                                                      */
/* -------------------------------------------------------------------------- */

if (failures.length > 0) {
  console.error(
    "\n❌ Timestamp tracing tests FAILED\n",
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
    "\n✅ All timestamp tracing tests PASSED",
  );

  console.log(
    "  ✓ Provider checkedAt timestamps preserved",
  );

  console.log(
    "  ✓ Evidence retrievedAt timestamps preserved",
  );

  console.log(
    "  ✓ Vendor impact uses evidence retrievedAt",
  );

  console.log(
    "  ✓ Timestamps not inferred from provider ordering",
  );
}
