/*
 * Correlation, OSV, and assessment behaviour, offline. Each classification has a
 * case that must produce it and, where it matters, a near miss that must not.
 */
import {
  correlate,
  type CorrelationInput,
} from "./correlation/correlate.js";
import { investigateCve } from "./engine.js";
import { evaluatePriorInvestigation } from "./persistence/investigation-policy.js";
import { fetchOsvRecord } from "./sources/osv.js";
import {
  clipAllStrings,
  MAX_TOOL_RESULT_CHARS,
  toToolText,
  VIEW_BUDGET_CHARS,
  viewFromResult,
} from "./tool-result.js";
import type {
  AssessmentStatement,
  Correlation,
  Evidence,
  EvidenceFactRecord,
  ProviderResult,
  SourceId,
} from "./types.js";
import { checkAnswer } from "./verification/check-answer.js";

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) {
    throw new Error(`Assertion failed: ${message}`);
  }
}

const now = new Date().toISOString();
const CVE = "CVE-2099-0001";

const V_C = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H";
const V_U = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";

function evidence(source: SourceId, facts: Record<string, unknown>): Evidence {
  return {
    id: `${source}:${CVE}`,
    source,
    sourceType: source === "REDHAT" ? "vendor" : source === "OSV" ? "community" : "primary",
    retrievedAt: now,
    url: "https://example.test/",
    title: "test",
    confidence: source === "OSV" ? "medium" : "high",
    facts,
    extractedFacts: [],
    references: [],
  };
}

function input(overrides: Partial<CorrelationInput>): CorrelationInput {
  return {
    cvss: { version: "3.1", baseScore: 10, vector: V_C, severity: "CRITICAL", source: "nvd@nist.gov" },
    severity: "CRITICAL",
    kevStatus: "not-listed",
    nvdEvidence: evidence("NVD", {}),
    nvdStatus: "success",
    affectedVersions: [],
    vendorImpact: [],
    packageFixes: [],
    ...overrides,
  };
}

function byTopic(correlations: Correlation[], topic: Correlation["topic"]): Correlation | undefined {
  return correlations.find((item) => item.topic === topic);
}

function testCvss(): void {
  const redhat = (score: string, vector: string | null) =>
    evidence("REDHAT", {
      cvss3: { cvss3_base_score: score, cvss3_scoring_vector: vector },
    });

  const explained = byTopic(
    correlate(input({ redhatEvidence: redhat("9.8", V_U) })),
    "cvss",
  );

  assert(
    explained?.classification === "explained_difference" &&
    explained.explanation.includes("S") &&
    explained.values.some((item) => item.source === "Red Hat" && item.value === 9.8) &&
    explained.values.some((item) => item.source === "nvd@nist.gov" && item.value === 10),
    "different metrics are a scoring difference, with both values kept",
  );

  const contradiction = byTopic(
    correlate(input({ redhatEvidence: redhat("9.8", V_C) })),
    "cvss",
  );

  assert(
    contradiction?.classification === "conflict" &&
    contradiction.reason === "same_vector_different_score",
    "identical metrics with different scores are a genuine conflict",
  );

  assert(
    byTopic(correlate(input({ redhatEvidence: redhat("9.8", null) })), "cvss")
      ?.reason === "score_differs_vector_unavailable",
    "an unexplainable difference must stay a conflict",
  );

  assert(
    byTopic(correlate(input({ redhatEvidence: redhat("10.0", V_C) })), "cvss")
      ?.classification === "agreement",
    "the same score and vector agree",
  );

  assert(
    byTopic(
      correlate(input({ redhatEvidence: redhat("9.8", V_C.replace("3.1", "3.0")) })),
      "cvss",
    )?.reason === "different_cvss_version",
    "the same metrics under different CVSS versions are explainable",
  );

  assert(
    !byTopic(
      correlate(
        input({
          cvss: { version: "4.0", baseScore: 9.3, vector: "CVSS:4.0/AV:N", severity: "CRITICAL", source: "nvd@nist.gov" },
          redhatEvidence: redhat("9.8", V_C),
        }),
      ),
      "cvss",
    ),
    "CVSS v4 and v3 scores must not be compared",
  );

  assert(
    !byTopic(correlate(input({})), "cvss"),
    "one source alone is not an agreement",
  );

  const withCna = byTopic(
    correlate(
      input({
        nvdEvidence: evidence("NVD", {
          metrics: {
            cvssMetricV31: [
              { source: "cna@vendor.example", cvssData: { version: "3.1", baseScore: 7.5, vectorString: V_U } },
            ],
          },
        }),
      }),
    ),
    "cvss",
  );

  assert(
    withCna?.values.some((item) => item.source === "cna@vendor.example"),
    "a CNA score inside the NVD record is a separate source",
  );

  console.log("✓ CVSS separates scoring differences from genuine conflicts");
}

function testSeverity(): void {
  const severity = (redhat: string) =>
    byTopic(
      correlate(input({ redhatEvidence: evidence("REDHAT", { threat_severity: redhat }) })),
      "severity",
    );

  for (const rating of ["Critical", "Important", "Moderate", "Low"]) {
    const item = severity(rating);

    assert(
      item?.classification === "explained_difference" &&
      item.reason === "separate_rating_scales" &&
      item.interpretation?.kind === "approximate_name_alignment",
      `Red Hat's ${rating} must never be agreement with a CVSS severity`,
    );
  }

  const similar = byTopic(
    correlate(
      input({
        severity: "HIGH",
        redhatEvidence: evidence("REDHAT", { threat_severity: "Important" }),
      }),
    ),
    "severity",
  );

  assert(
    similar?.interpretation?.aligned === true &&
    similar.explanation.includes("approximate") &&
    !similar.explanation.includes("equivalent"),
    "Important and HIGH must be labelled as an approximate reading",
  );

  assert(
    severity("Moderate")?.interpretation?.aligned === false,
    "levels that do not line up must say so",
  );

  console.log("✓ Severity is always an approximate reading of two separate scales");
}

function testExploitation(): void {
  const check = (
    kevStatus: CorrelationInput["kevStatus"],
    catalogDate: string | null,
    nvdDate: string | null,
    extra: Partial<CorrelationInput> = {},
  ) =>
    byTopic(
      correlate(
        input({
          kevStatus,
          kevEvidence: catalogDate
            ? evidence("CISA_KEV", { dateAdded: catalogDate })
            : undefined,
          nvdEvidence: evidence("NVD", nvdDate ? { cisaExploitAdd: nvdDate } : {}),
          ...extra,
        }),
      ),
      "exploitation",
    );

  assert(check("listed", "2024-01-01", "2024-01-01")?.classification === "agreement", "same date agrees");
  assert(check("listed", "2024-01-01", "2024-02-02")?.classification === "conflict", "different dates conflict");
  assert(check("listed", "2024-01-01", null)?.reason === "nvd_record_lag", "NVD lag is explainable");
  assert(
    check("not-listed", null, "2024-01-01")?.classification === "conflict",
    "NVD recording an entry the catalog lacks is a genuine conflict",
  );
  assert(check("not-listed", null, null)?.classification === "agreement", "absent from both agrees");

  const failed = check("unknown", null, "2024-01-01");

  assert(
    failed?.classification === "incomplete" &&
    failed.values[0].value === "unknown",
    "a failed KEV check stays unknown even when NVD has an entry",
  );

  const failedNoEntry = check("unknown", null, null);

  assert(
    failedNoEntry?.classification === "incomplete" &&
    failedNoEntry.explanation.includes("does not settle"),
    "a failed KEV check must never become an absence",
  );

  assert(
    check("not-listed", null, null, { nvdEvidence: undefined }) === undefined,
    "without an NVD record there is nothing to compare",
  );

  console.log("✓ Exploitation cross-checks KEV and NVD, and failure stays unknown");
}

function testVendor(): void {
  const row = (status: "affected" | "fixed" | "not_affected" | "unknown", cpe: string | null) => ({
    vendor: "Red Hat",
    productName: "Red Hat Enterprise Linux 8",
    packageName: `pkg-${status}`,
    cpe,
    status,
    originalStatus: status,
    sourceUrl: "https://example.test/",
    retrievedAt: now,
    evidenceId: `REDHAT:${CVE}`,
    reason: status,
  });

  const CPE = "cpe:/o:redhat:enterprise_linux:8";

  const run = (rows: ReturnType<typeof row>[], affected = ["redhat:enterprise_linux 8.0"]) =>
    correlate(
      input({
        redhatEvidence: evidence("REDHAT", {}),
        affectedVersions: affected,
        vendorImpact: rows,
      }),
    ).filter((item) => item.topic === "vendor_assessment");

  const compared = (rows: ReturnType<typeof row>[], affected?: string[]) =>
    run(rows, affected).filter((item) => item.classification !== "incomplete");

  const conflict = run([row("not_affected", CPE)]);

  assert(
    conflict[0]?.classification === "conflict" &&
    conflict[0].scope === "enterprise_linux 8.0",
    "NVD vulnerable and vendor not affected is a genuine conflict",
  );

  const mixed = run([row("not_affected", CPE), row("fixed", CPE)]);

  assert(
    mixed[0]?.classification === "agreement",
    "one unaffected package among fixed ones is not a conflict",
  );

  assert(compared([row("unknown", CPE)]).length === 0, "an unknown assessment proves nothing");
  assert(compared([row("not_affected", "cpe:/o:redhat:other_product:8")]).length === 0, "different products are not compared");
  assert(compared([row("not_affected", null)]).length === 0, "a row without a CPE is not compared");
  assert(compared([row("not_affected", "cpe:/o:redhat:enterprise_linux:9")]).length === 0, "different major versions are not compared");
  assert(
    compared([row("not_affected", CPE)], ["redhat:enterprise_linux >= 8.0, < 9.0"]).length === 0,
    "a range is not matched to one product stream",
  );
  assert(
    compared([row("not_affected", CPE)], ["fedoraproject:fedora 8"]).length === 0,
    "other vendors' products are not compared with Red Hat's",
  );

  /* Nothing is dropped silently: every uncompared record is counted. */
  const partial = run(
    [row("fixed", CPE), row("fixed", "cpe:/o:redhat:other_product:8"), row("fixed", null)],
    ["redhat:enterprise_linux 8.0", "redhat:unmatched_product 1.0", "redhat:ranged >= 1.0, < 2.0"],
  );

  const notCompared = partial.find((item) => item.id === "vendor:not_compared");

  assert(
    partial.some((item) => item.id === "vendor:agreement") &&
    notCompared?.classification === "incomplete" &&
    notCompared.values.find((item) => item.source === "NVD")?.value === 2 &&
    notCompared.values.find((item) => item.source === "Red Hat")?.value === 2,
    `uncompared NVD entries and Red Hat rows must be counted: ${JSON.stringify(notCompared)}`,
  );

  assert(
    !run([row("fixed", CPE)]).some((item) => item.id === "vendor:not_compared"),
    "a fully compared result must not report a coverage gap",
  );

  console.log("✓ Vendor conflicts need one product stream and every package; gaps are counted");
}

function testFixedVersions(): void {
  const run = (
    fixed: string[],
    affected = ["lodash:lodash < 4.17.21"],
    name = "lodash",
  ) =>
    correlate(
      input({
        osvEvidence: evidence("OSV", {}),
        affectedVersions: affected,
        packageFixes: [
          {
            ecosystem: "npm",
            package: name,
            fixedVersions: fixed,
            lastAffectedVersions: [],
            advisoryId: "GHSA-test",
          },
        ],
      }),
    ).filter((item) => item.topic === "fixed_version");

  assert(run(["4.17.21"])[0]?.classification === "agreement", "same fix agrees");
  assert(
    run(["4.17.21", "3.10.2"])[0]?.reason === "partial_branch_coverage",
    "an extra release branch is explainable",
  );
  assert(
    run(["5.0.0"])[0]?.reason === "disjoint_fixed_versions",
    "different fixes for a package tied to its vendor are a genuine conflict",
  );

  /* A false conflict is worse than a missed match. */
  const notComparable = (
    label: string,
    fixed: string[],
    affected: string[],
    name: string,
  ) => {
    const results = run(fixed, affected, name);

    assert(
      results.length === 1 &&
      results[0].classification === "incomplete" &&
      results[0].reason === "package_names_not_comparable" &&
      results[0].explanation.includes("neither agreement nor conflict"),
      `${label} must be not comparable: ${JSON.stringify(results)}`,
    );
  };

  notComparable(
    "an unrelated fork",
    ["9.9.9"],
    ["python:requests < 2.31.0"],
    "org.fork:requests",
  );
  notComparable(
    "a fork that happens to share a fix",
    ["2.31.0"],
    ["python:requests < 2.31.0"],
    "org.fork:requests",
  );
  notComparable(
    "two vendors sharing a product name",
    ["1.0.0"],
    ["alpha:tool < 1.0.0", "beta:tool < 5.0.0"],
    "tool",
  );
  notComparable(
    "a bare name that differs from a different vendor's fix",
    ["9.9.9"],
    ["python:requests < 2.31.0"],
    "requests",
  );
  notComparable(
    "a product with no upper bound to compare",
    ["1.0.0"],
    ["vendor:tool >= 1.0.0"],
    "tool",
  );

  const prefixed = run(
    ["v1.2.3"],
    ["vendor:tool < 1.2.3"],
    "github.com/vendor/tool",
  );

  assert(
    prefixed[0]?.classification === "agreement",
    `v1.2.3 and 1.2.3 are the same version: ${JSON.stringify(prefixed)}`,
  );

  assert(
    run(["2.31.0"], ["python:requests < 2.31.0"], "requests")[0]?.classification === "agreement",
    "a bare package name may still confirm the same fix",
  );

  const vendorConflict = run(
    ["3.0.0"],
    ["vendor:tool < 1.2.3"],
    "github.com/vendor/tool",
  );

  assert(
    vendorConflict[0]?.classification === "conflict",
    "a namespace naming the vendor keeps genuine conflicts detectable",
  );

  const unmatched = run(["2.15.0"], ["apache:log4j < 2.15.0"], "org.apache.logging.log4j:log4j-core");

  assert(
    unmatched[0]?.classification === "incomplete" &&
    unmatched[0].reason === "package_names_not_comparable",
    "similar names must not be assumed to be the same artifact",
  );

  const noFix = run([]);

  assert(
    noFix[0]?.classification === "incomplete" &&
    noFix[0].reason === "no_fixed_version_listed",
    "a package with no fix must be counted, not dropped",
  );

  console.log("✓ Fixed versions compare only exact package names");
}

/* -------------------------------- OSV source -------------------------------- */

const advisory = (overrides: Record<string, unknown> = {}) => ({
  id: "GHSA-aaaa",
  aliases: [CVE],
  modified: now,
  database_specific: { github_reviewed: true, severity: "HIGH" },
  affected: [
    {
      package: { ecosystem: "npm", name: "lodash" },
      versions: ["1.0.0", "1.0.1"],
      ranges: [
        { type: "GIT", events: [{ introduced: "0" }, { fixed: "abc123" }] },
        { type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "4.17.21" }] },
      ],
    },
    {
      package: { ecosystem: "npm", name: "lodash.template" },
      ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { last_affected: "4.5.0" }] }],
    },
  ],
  ...overrides,
});

function fakeOsv(routes: Record<string, () => Response>): void {
  globalThis.fetch = (async (input: string | URL | Request) => {
    const id = decodeURIComponent(String(input).split("/").pop() ?? "");

    return routes[id]?.() ?? new Response("{}", { status: 404 });
  }) as typeof fetch;
}

const rootRecord = (overrides: Record<string, unknown> = {}) => ({
  id: CVE,
  aliases: ["GHSA-aaaa"],
  modified: now,
  affected: [{ versions: ["huge", "list"], ranges: [{ type: "GIT", events: [] }] }],
  ...overrides,
});

async function testOsvSource(): Promise<void> {
  const realFetch = globalThis.fetch;
  const fetchOsv = () => fetchOsvRecord(CVE, { timeoutMs: 1000 });

  try {
    /* Absence vs failure */
    fakeOsv({});
    assert((await fetchOsv()).status === "observed_absence", "404 is an observed absence");

    fakeOsv({ [CVE]: () => new Response("secret-remote-body", { status: 503 }) });

    const failed = await fetchOsv();

    assert(failed.status === "error", "a server error must not become an absence");
    assert(!String(failed.error).includes("secret-remote-body"), "remote bodies must not be forwarded");

    fakeOsv({ [CVE]: () => Response.json({ id: "CVE-1999-0001", aliases: [] }) });
    assert((await fetchOsv()).status === "error", "a record for another CVE must be rejected");

    /* Following the alias */
    fakeOsv({
      [CVE]: () => Response.json(rootRecord()),
      "GHSA-aaaa": () => Response.json(advisory()),
    });

    const found = await fetchOsv();

    assert(found.status === "success", "a record with an advisory succeeds");

    const stored = JSON.stringify(found.evidence?.facts);

    assert(stored.includes("4.17.21"), "the advisory's fix must be stored");
    assert(!stored.includes("abc123"), "git ranges are not versions");
    assert(!stored.includes('"huge"') && !stored.includes('"1.0.1"'), "version lists must not be stored");

    /* Through the engine */
    const investigate = async (osv: ProviderResult) =>
      investigateCve(CVE, {
        requestTimeoutMs: 1000,
        providers: {
          nvd: async () => ({
            provider: "NVD",
            status: "success",
            error: null,
            checkedAt: now,
            evidence: evidence("NVD", { id: CVE }),
          }),
          cisaKev: async () => ({
            provider: "CISA_KEV",
            status: "observed_absence",
            evidence: null,
            error: null,
            checkedAt: now,
          }),
          redhat: async () => ({
            provider: "REDHAT",
            status: "observed_absence",
            evidence: null,
            error: null,
            checkedAt: now,
          }),
          osv: async () => osv,
        },
      });

    const result = await investigate(found);

    const fixes = result.summary.packageFixes ?? [];

    assert(
      fixes[0]?.package === "lodash" &&
      fixes[0].fixedVersions[0] === "4.17.21" &&
      fixes[1]?.package === "lodash.template" &&
      fixes[1].lastAffectedVersions[0] === "4.5.0",
      "packages with fixes come first, and last-affected is kept",
    );
    assert(result.status === "confirmed", "OSV must not change a confirmed investigation");
    assert(
      result.factProvenance.some((fact) => fact.field === "osvPackages"),
      "OSV package data must be a traceable fact",
    );

    /* Advisories that must not count */
    for (const [label, overrides] of [
      ["unreviewed", { database_specific: { github_reviewed: false } }],
      ["withdrawn", { withdrawn: now }],
    ] as const) {
      fakeOsv({
        [CVE]: () => Response.json(rootRecord()),
        "GHSA-aaaa": () => Response.json(advisory(overrides)),
      });

      const excluded = await investigate(await fetchOsv());

      assert(
        (excluded.summary.packageFixes ?? []).length === 0,
        `${label} advisories are not fix evidence`,
      );
    }

    fakeOsv({
      [CVE]: () => Response.json(rootRecord()),
      "GHSA-aaaa": () => Response.json(advisory({ aliases: ["CVE-1999-0001"] })),
    });

    assert(
      (await investigate(await fetchOsv())).summary.packageFixes?.length === 0,
      "an advisory that does not name this CVE cannot speak for it",
    );

    /* A failed advisory is visible, and blocks reuse. */
    fakeOsv({
      [CVE]: () => Response.json(rootRecord()),
      "GHSA-aaaa": () => new Response("{}", { status: 500 }),
    });

    const partial = await investigate(await fetchOsv());

    assert(
      viewFromResult(partial).limitations.some((text) => text.includes("GHSA-aaaa")),
      "a failed advisory must be visible to the LLM",
    );
    assert(
      partial.summary.assessment?.some(
        (item) => item.kind === "gap" && item.statement.includes("GHSA-aaaa"),
      ),
      "a failed advisory must be a stated gap",
    );

    const decide = (item: typeof partial, ageMinutes = 0) => {
      const created = new Date(Date.now() - ageMinutes * 60_000).toISOString();

      return evaluatePriorInvestigation({
        status: item.status,
        createdAt: created,
        providerResults: item.providerResults.map((row) => ({
          ...row,
          checkedAt: created,
        })),
        limitations: item.limitations,
        evidenceCount: item.evidence.length,
        evidenceRetrievedAt: item.evidence.map(() => created),
      }).decision;
    };

    assert(decide(partial) === "reuse", "one failed advisory must not discard core evidence");
    assert(decide(partial, 59) === "reuse", "OSV gaps are reusable within the hour");
    assert(decide(partial, 61) === "refresh", "OSV gaps are retried after an hour");

    /* OSV having no record (closed source) is normal, and is reusable. */
    fakeOsv({});

    const absent = await investigate(await fetchOsv());

    assert(absent.status === "confirmed" && absent.limitations.length === 0, "OSV absence is not a limitation");
    assert(decide(absent) === "reuse", "OSV absence must not block reuse");

    /* An OSV outage is not an absence. */
    const outage = await investigate(failed);

    assert(outage.status === "confirmed", "an OSV outage must not change core status");
    assert(outage.limitations.length === 0, "OSV gaps must not block reuse as limitations");
    assert(decide(outage) === "reuse", "an OSV outage alone must allow reuse");
    assert(decide(outage, 61) === "refresh", "an OSV outage is retried after an hour");

    const outageView = viewFromResult(outage);

    assert(
      outageView.limitations.some((text) => text.includes("OSV")) &&
      outageView.providerResults.some(
        (row) => row.provider === "OSV" && row.status === "error",
      ),
      "reused results must still expose the missing enrichment",
    );

    /* Negative controls: core failures keep blocking reuse. */
    const withFailure = async (source: SourceId) =>
      investigateCve(CVE, {
        requestTimeoutMs: 1000,
        providers: {
          nvd: async () =>
            source === "NVD"
              ? { provider: "NVD", status: "error", evidence: null, error: "down", checkedAt: now }
              : { provider: "NVD", status: "success", error: null, checkedAt: now, evidence: evidence("NVD", { id: CVE }) },
          cisaKev: async () => ({
            provider: "CISA_KEV",
            status: source === "CISA_KEV" ? "error" : "observed_absence",
            evidence: null,
            error: source === "CISA_KEV" ? "down" : null,
            checkedAt: now,
          }),
          redhat: async () => ({
            provider: "REDHAT",
            status: source === "REDHAT" ? "error" : "observed_absence",
            evidence: null,
            error: source === "REDHAT" ? "down" : null,
            checkedAt: now,
          }),
          osv: async () => failed,
        },
      });

    for (const source of ["NVD", "CISA_KEV", "REDHAT"] as const) {
      assert(
        decide(await withFailure(source)) === "refresh",
        `a ${source} failure must keep blocking reuse`,
      );
    }

    /* Advisories are never dropped silently. */
    fakeOsv({
      [CVE]: () => Response.json(rootRecord({ aliases: ["GHSA-aaaa", "GHSA-bbbb", "GHSA-cccc"] })),
      "GHSA-aaaa": () => Response.json(advisory()),
      "GHSA-bbbb": () => Response.json(advisory({ id: "GHSA-bbbb" })),
    });

    const omitted = await investigate(await fetchOsv());

    assert(
      omitted.summary.enrichmentLimitations?.some((text) => text.includes("GHSA-cccc")) &&
      omitted.summary.assessment?.some(
        (item) => item.kind === "gap" && item.statement.includes("GHSA-cccc"),
      ),
      "an advisory beyond the limit must be a stated gap",
    );
    assert(decide(omitted, 61) === "reuse", "a permanent limit must not cause endless retries");

    fakeOsv({ [CVE]: () => Response.json(rootRecord()) });

    const missing = await investigate(await fetchOsv());

    assert(
      missing.summary.enrichmentLimitations?.some((text) => text.includes("GHSA-aaaa")),
      "a listed advisory that cannot be found must be reported",
    );

    assert(
      outage.summary.assessment?.some(
        (item) =>
          item.kind === "gap" && item.statement.includes("not evidence of absence"),
      ),
      "an OSV outage must be a stated gap",
    );
  } finally {
    globalThis.fetch = realFetch;
  }

  console.log("✓ OSV follows reviewed advisories, and absence differs from failure");
}

/* ------------------------------- Assessment --------------------------------- */

export function assertTraceable(
  statements: AssessmentStatement[],
  facts: Pick<EvidenceFactRecord, "id">[],
  evidenceIds: string[],
): void {
  const known = new Set(facts.map((fact) => fact.id));
  const knownEvidence = new Set(evidenceIds);

  for (const item of statements) {
    assert(
      item.kind === "gap" ||
      item.factIds.length + item.providerChecks.length + item.evidenceIds.length > 0,
      `statement cites nothing: ${item.statement}`,
    );

    for (const id of item.factIds) {
      assert(known.has(id), `statement cites unknown fact ${id}: ${item.statement}`);
    }

    for (const id of item.evidenceIds) {
      assert(knownEvidence.has(id), `statement cites unknown evidence ${id}`);
    }
  }
}

async function testAssessment(): Promise<void> {
  const provider = (source: SourceId, facts: Record<string, unknown> | null) => async (): Promise<ProviderResult> => ({
    provider: source,
    status: facts ? "success" : "observed_absence",
    error: null,
    checkedAt: now,
    evidence: facts ? evidence(source, facts) : null,
  });

  const failing = (source: SourceId) => async (): Promise<ProviderResult> => ({
    provider: source,
    status: "error",
    evidence: null,
    error: "unavailable",
    checkedAt: now,
  });

  const nvdFacts = {
    id: CVE,
    cisaExploitAdd: "2024-01-01",
    metrics: {
      cvssMetricV31: [
        { source: "nvd@nist.gov", cvssData: { version: "3.1", baseScore: 10, baseSeverity: "CRITICAL", vectorString: V_C } },
      ],
    },
    configurations: [
      {
        nodes: [
          {
            cpeMatch: [
              { vulnerable: true, criteria: "cpe:2.3:a:lodash:lodash:*:*:*:*:*:*:*:*", versionEndExcluding: "4.17.21" },
            ],
          },
        ],
      },
    ],
  };

  const redhatFacts = {
    name: CVE,
    threat_severity: "Important",
    cvss3: { cvss3_base_score: "9.8", cvss3_scoring_vector: V_U },
    affected_release: [{ product_name: "RHEL 8", advisory: "RHSA-1", package: "lodash-1" }],
    package_state: [],
  };

  const osvFacts = {
    advisories: [
      {
        id: "GHSA-aaaa",
        reviewed: true,
        withdrawn: null,
        packages: [{ ecosystem: "npm", name: "lodash", events: [{ introduced: "0" }, { fixed: "4.17.21" }] }],
      },
    ],
    advisoriesFailed: [],
  };

  const full = await investigateCve(CVE, {
    requestTimeoutMs: 1000,
    providers: {
      nvd: provider("NVD", nvdFacts),
      cisaKev: provider("CISA_KEV", { dateAdded: "2024-01-01" }),
      redhat: provider("REDHAT", redhatFacts),
      osv: provider("OSV", osvFacts),
    },
  });

  const statements = full.summary.assessment ?? [];

  assertTraceable(statements, full.factProvenance, full.evidence.map((item) => item.id));

  const kinds = new Set(statements.map((item) => item.kind));

  assert(
    kinds.has("fact") && kinds.has("inference") && kinds.has("difference"),
    `expected facts, inferences, and differences: ${[...kinds].join()}`,
  );

  /* Negative controls: the traceability check must be able to fail. */
  for (const broken of [
    { ...statements[0], kind: "fact" as const, factIds: [], providerChecks: [], evidenceIds: [] },
    { ...statements[0], factIds: ["fact-999"] },
    { ...statements[0], evidenceIds: ["NVD:other"] },
  ]) {
    let failed = false;

    try {
      assertTraceable([broken], full.factProvenance, full.evidence.map((item) => item.id));
    } catch {
      failed = true;
    }

    assert(failed, "the traceability check must reject an unsupported statement");
  }

  /* Everything failing must read as unknown, never as a clean result. */
  const down = await investigateCve(CVE, {
    requestTimeoutMs: 1000,
    providers: {
      nvd: failing("NVD"),
      cisaKev: failing("CISA_KEV"),
      redhat: failing("REDHAT"),
      osv: failing("OSV"),
    },
  });

  const downStatements = down.summary.assessment ?? [];

  assertTraceable(downStatements, down.factProvenance, []);

  assert(
    downStatements.every((item) => item.kind === "gap"),
    `with every source down only gaps may be stated: ${JSON.stringify(downStatements.filter((item) => item.kind !== "gap"))}`,
  );

  for (const source of ["NVD", "CISA_KEV", "REDHAT", "OSV"]) {
    assert(
      downStatements.some(
        (item) => item.statement.includes(source) && item.statement.includes("not evidence of absence"),
      ),
      `${source} failure must be stated`,
    );
  }

  /* The assessment must pass the engine's own answer check, or the gate would
     flag answers for repeating it. */
  const view = viewFromResult(full);

  /* Nothing is lost by removing repetition from the view. */
  const cvssView = view.summary.correlations.items.find((item) => item.topic === "cvss");
  const severityView = view.summary.correlations.items.find((item) => item.topic === "severity");

  assert(
    cvssView?.classification === "explained_difference" &&
    cvssView.explanation === undefined &&
    view.assessment.items.some(
      (item) =>
        item.kind === "difference" &&
        item.statement.includes("assessed S differently"),
    ) &&
    cvssView.values.some((item) => item.vector === V_C),
    "a disputed value's explanation must reach the LLM once, with its vectors",
  );

  assert(
    severityView?.classification === "explained_difference",
    "severity must stay a difference in the view",
  );

  assert(
    view.assessment.items.every(
      (item) =>
        item.factIds === undefined || item.factIds.length > 0,
    ),
    "empty citation lists must not take up budget",
  );

  const repeated = view.assessment.items.map((item) => item.statement).join("\n");

  assert(
    checkAnswer(`${CVE}\n${repeated}`, [view]).length === 0,
    `the gate must accept the assessment: ${checkAnswer(`${CVE}\n${repeated}`, [view]).join(" ")}`,
  );

  console.log("✓ Assessment statements are traceable, and failures read as gaps");
}

async function testGateConflictClaim(): Promise<void> {
  const provider = (source: SourceId, facts: Record<string, unknown> | null) => async (): Promise<ProviderResult> => ({
    provider: source,
    status: facts ? "success" : "observed_absence",
    error: null,
    checkedAt: now,
    evidence: facts ? evidence(source, facts) : null,
  });

  const conflicted = await investigateCve(CVE, {
    requestTimeoutMs: 1000,
    providers: {
      nvd: provider("NVD", { id: CVE, cisaExploitAdd: "2024-01-01" }),
      cisaKev: provider("CISA_KEV", null),
      redhat: provider("REDHAT", null),
    },
  });

  const view = viewFromResult(conflicted);

  assert(
    view.summary.correlations.items[0]?.classification === "conflict",
    "fixture should hold a conflict",
  );

  assert(
    checkAnswer(`${CVE}: all sources agree on this.`, [view]).length === 1,
    "the gate must catch a claim that sources agree over a conflict",
  );

  const clean = await investigateCve(CVE, {
    requestTimeoutMs: 1000,
    providers: {
      nvd: provider("NVD", { id: CVE }),
      cisaKev: provider("CISA_KEV", null),
      redhat: provider("REDHAT", null),
    },
  });

  assert(
    checkAnswer(`${CVE}: all sources agree on this.`, [viewFromResult(clean)]).length === 0,
    "the same claim passes when no conflict exists",
  );

  console.log("✓ Gate catches a false claim that sources agree");
}

async function testGateAgreementScope(): Promise<void> {
  const provider = (source: SourceId, facts: Record<string, unknown> | null) => async (): Promise<ProviderResult> => ({
    provider: source,
    status: facts ? "success" : "observed_absence",
    error: null,
    checkedAt: now,
    evidence: facts ? evidence(source, facts) : null,
  });

  const result = await investigateCve(CVE, {
    requestTimeoutMs: 1000,
    providers: {
      nvd: provider("NVD", {
        id: CVE,
        metrics: {
          cvssMetricV31: [
            { source: "nvd@nist.gov", cvssData: { version: "3.1", baseScore: 9.8, baseSeverity: "CRITICAL", vectorString: V_U } },
          ],
        },
      }),
      cisaKev: provider("CISA_KEV", null),
      redhat: provider("REDHAT", {
        name: CVE,
        threat_severity: "Critical",
        cvss3: { cvss3_base_score: "9.8", cvss3_scoring_vector: V_U },
      }),
    },
  });

  const view = viewFromResult(result);
  const flagged = (answer: string) => checkAnswer(`${CVE}: ${answer}`, [view]).length > 0;

  assert(!flagged("sources agree on the CVSS score."), "a topic that does agree may be claimed");
  assert(flagged("sources agree on the severity rating."), "approximate severity is not agreement");
  assert(flagged("all sources fully agree."), "a blanket claim fails when any comparison is not agreement");
  assert(!flagged("there is no conflict between sources."), "no conflict is true when only differences exist");

  /* Not comparable must not support agreement. */
  const notComparable = viewFromResult(
    await investigateCve(CVE, {
      requestTimeoutMs: 1000,
      providers: {
        nvd: provider("NVD", {
          id: CVE,
          configurations: [{ nodes: [{ cpeMatch: [{ vulnerable: true, criteria: "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*", versionEndExcluding: "2.15.0" }] }] }],
        }),
        cisaKev: provider("CISA_KEV", null),
        redhat: provider("REDHAT", null),
        osv: provider("OSV", {
          advisories: [{ id: "GHSA-a", reviewed: true, withdrawn: null, packages: [{ ecosystem: "Maven", name: "org.apache.logging.log4j:log4j-core", events: [{ fixed: "2.15.0" }] }] }],
          advisoriesFailed: [],
        }),
      },
    }),
  );

  assert(
    checkAnswer(`${CVE}: sources agree on the fix.`, [notComparable]).length === 1,
    "a fix that was not compared must not support a claim of agreement",
  );

  /* Sweeping vendor claims */
  const vendor = (states: string[]) =>
    investigateCve(CVE, {
      requestTimeoutMs: 1000,
      providers: {
        nvd: provider("NVD", { id: CVE }),
        cisaKev: provider("CISA_KEV", null),
        redhat: provider("REDHAT", {
          name: CVE,
          package_state: states.map((fix_state, index) => ({
            product_name: `P${index}`,
            package_name: "x",
            fix_state,
          })),
        }),
      },
    }).then(viewFromResult);

  const mostlyUnaffected = await vendor([
    "Affected",
    ...Array.from({ length: 1500 }, () => "Not affected"),
  ]);

  assert(
    mostlyUnaffected.summary.vendorImpact.items.length < 1501 &&
    mostlyUnaffected.summary.vendorImpact.statusCounts.not_affected === 1500,
    "status counts must cover rows omitted from the capped list",
  );

  const claim = (view2: typeof mostlyUnaffected, answer: string) =>
    checkAnswer(`${CVE}: ${answer}`, [view2]).length > 0;

  assert(claim(mostlyUnaffected, "all Red Hat products are affected."), "1,500 contrary rows must fail the claim");
  assert(claim(mostlyUnaffected, "every Red Hat package is not affected."), "one affected row must fail the claim");
  assert(claim(mostlyUnaffected, "no Red Hat products are affected."), "one affected row must fail no-products");
  assert(claim(mostlyUnaffected, "Red Hat products are all not affected."), "the reversed wording must also be checked");
  assert(!claim(mostlyUnaffected, "some Red Hat products are affected."), "a partial claim is not sweeping");

  /* Correct statements that resemble sweeping claims */
  assert(!claim(mostlyUnaffected, "not all Red Hat products are affected."), "not all is a partial claim");
  assert(!claim(mostlyUnaffected, "not every Red Hat package is not affected."), "not every is a partial claim");
  assert(!claim(mostlyUnaffected, "no, Red Hat products are affected in some cases."), "an answer of no is not a claim of none");
  assert(claim(mostlyUnaffected, "no supported Red Hat products are affected."), "qualified none is still checked");

  const allAffected = await vendor(["Affected", "Affected"]);
  const allClear = await vendor(["Not affected", "Not affected"]);

  assert(!claim(allAffected, "all Red Hat products are affected."), "a true claim must pass");
  assert(!claim(allClear, "all Red Hat products are not affected."), "a true claim must pass");
  assert(!claim(allClear, "no Red Hat products are affected."), "a true claim must pass");
  assert(claim(allClear, "all Red Hat products are affected."), "a false claim must fail");
  assert(
    !claim(mostlyUnaffected, "the claim that all Red Hat products are affected is incorrect."),
    "correcting the claim must not be flagged",
  );

  const none = await vendor([]);

  assert(
    claim(none, "all Red Hat products are not affected."),
    "a claim with no Red Hat data behind it must fail",
  );

  console.log("✓ Gate checks agreement by topic and sweeping Red Hat claims by status counts");
}

function testResponseLimit(): void {
  const small = { target: CVE, status: "confirmed", list: [1, 2, 3] };

  assert(
    toToolText(small) === JSON.stringify(small),
    "a normal response must be returned untouched",
  );

  const huge = {
    target: CVE,
    status: "confirmed",
    mode: "refreshed",
    summary: {
      cvss: { vector: "CVSS:4.0/AV:N" },
      vendorImpact: {
        items: Array.from({ length: 5000 }, () => ({ product: "x".repeat(500) })),
        total: 5000,
        omitted: 0,
      },
    },
    facts: Array.from({ length: 5000 }, (_, index) => ({ id: `fact-${index}`, claim: "y".repeat(2000) })),
  };

  const text = toToolText(huge);
  const parsed = JSON.parse(text) as typeof huge & { _reducedToFit?: string };

  assert(text.length <= MAX_TOOL_RESULT_CHARS, `a huge response is ${text.length} chars`);
  assert(parsed._reducedToFit, "a reduced response must say so");
  assert(parsed.target === CVE && parsed.status === "confirmed", "identity must survive reduction");
  assert(
    parsed.summary.vendorImpact.total === 5000 &&
    parsed.summary.vendorImpact.omitted === 5000 - parsed.summary.vendorImpact.items.length,
    "capped lists must keep exact counts through reduction",
  );

  /* Clipping may shorten prose, never identifiers. */
  const longVector = `CVSS:4.0/${"AV:N/".repeat(40)}`;

  const clipped = clipAllStrings(
    {
      target: CVE,
      status: "confirmed",
      vector: longVector,
      id: `fact-${"1".repeat(100)}`,
      evidenceId: `NVD:${"2".repeat(100)}`,
      claim: "z".repeat(500),
    },
    45,
  );

  assert(
    clipped.vector === longVector &&
    clipped.id.length > 100 &&
    clipped.evidenceId.length > 100 &&
    clipped.claim.length < 100,
    `clipping must keep identifiers whole and shorten prose: ${JSON.stringify(clipped)}`,
  );

  /* Nothing can defeat the limit, even with no reducible structure. */
  const unshrinkable = Object.fromEntries(
    Array.from({ length: 5000 }, (_, index) => [`key-${index}-${"k".repeat(50)}`, "value"]),
  );

  const last = toToolText({ target: CVE, status: "confirmed", ...unshrinkable });

  assert(last.length <= MAX_TOOL_RESULT_CHARS, "the final fallback must fit");
  assert(
    (JSON.parse(last) as { _reducedToFit?: string; target?: string })._reducedToFit &&
    (JSON.parse(last) as { target?: string }).target === CVE,
    "the final fallback must identify itself and the target",
  );

  console.log("✓ The complete response limit holds, and reduction announces itself");
}

/* The largest result the sources could plausibly produce must still fit. */
async function testWorstCaseSize(): Promise<void> {
  const long = (label: string, length: number) =>
    `${label} ${"x".repeat(length)}`;

  const provider = (source: SourceId, facts: Record<string, unknown>) => async (): Promise<ProviderResult> => ({
    provider: source,
    status: "success",
    error: null,
    checkedAt: now,
    evidence: {
      ...evidence(source, facts),
      title: long("title", 200),
      url: `https://example.test/${"u".repeat(300)}`,
      references: Array.from({ length: 300 }, (_, index) => ({
        title: long(`reference-${index}`, 200),
        url: `https://example.test/${index}/${"r".repeat(200)}`,
        retrieved: false,
      })),
    },
  });

  const result = await investigateCve(CVE, {
    requestTimeoutMs: 1000,
    providers: {
      nvd: provider("NVD", {
        id: CVE,
        descriptions: [{ lang: "en", value: long("description", 20000) }],
        weaknesses: [
          { description: Array.from({ length: 20 }, (_, index) => ({ value: `CWE-${index}` })) },
        ],
        metrics: {
          cvssMetricV31: Array.from({ length: 40 }, (_, index) => ({
            source: `cna-${index}@vendor.example`,
            cvssData: { version: "3.1", baseScore: 1 + (index % 9), vectorString: V_U },
          })),
        },
        configurations: [
          {
            nodes: [
              {
                cpeMatch: Array.from({ length: 500 }, (_, index) => ({
                  vulnerable: true,
                  criteria: `cpe:2.3:a:vendor-${index}:${"p".repeat(120)}${index}:*:*:*:*:*:*:*:*`,
                  versionEndExcluding: "2.0.0",
                })),
              },
            ],
          },
        ],
      }),
      cisaKev: provider("CISA_KEV", {
        vendorProject: long("vendor", 2000),
        product: long("product", 2000),
        vulnerabilityName: long("name", 2000),
        dateAdded: "2024-01-01",
        requiredAction: long("action", 2000),
        knownRansomwareCampaignUse: long("ransomware", 2000),
      }),
      redhat: provider("REDHAT", {
        name: CVE,
        threat_severity: "Low",
        statement: long("statement", 20000),
        cvss3: { cvss3_base_score: "1.0", cvss3_scoring_vector: V_C },
        package_state: Array.from({ length: 2000 }, (_, index) => ({
          product_name: long(`product-${index}`, 150),
          package_name: long(`package-${index}`, 150),
          fix_state: "Affected",
          cpe: `cpe:/a:redhat:thing${index}:1`,
        })),
      }),
      osv: provider("OSV", {
        advisories: [
          {
            id: "GHSA-aaaa",
            reviewed: true,
            withdrawn: null,
            packages: Array.from({ length: 200 }, (_, index) => ({
              ecosystem: "Maven",
              name: long(`package-${index}`, 150),
              events: Array.from({ length: 10 }, (__, fix) => ({ fixed: `${fix}.0.${index}` })),
            })),
          },
        ],
        advisoriesFailed: [],
      }),
    },
  });

  const view = viewFromResult(result);

  // Measured raw, because toToolText would shrink an oversized view.
  const size = JSON.stringify(view).length;

  assert(
    size <= VIEW_BUDGET_CHARS,
    `a worst-case view is ${size} chars, over its ${VIEW_BUDGET_CHARS} budget`,
  );

  assert(
    !toToolText(view).includes("_reducedToFit"),
    "the normal caps, not the emergency reduction, must fit a worst-case view",
  );

  assert(
    VIEW_BUDGET_CHARS + 3500 === MAX_TOOL_RESULT_CHARS,
    "the budget must leave room for the fields around the view",
  );

  assert(
    view.summary.cwe.total === 20 && view.summary.cwe.omitted > 0,
    "the CWE list must be capped with its real total",
  );

  const cvssValues = result.summary.correlations?.find((item) => item.topic === "cvss");
  const cappedCvss = view.summary.correlations.items.find((item) => item.topic === "cvss");

  assert(
    (cvssValues?.values.length ?? 0) > 8 &&
    cappedCvss?.values.length === 8 &&
    cappedCvss.valuesOmitted === (cvssValues?.values.length ?? 0) - 8,
    "correlation values must be capped, with the omission reported",
  );

  const cvssStatement = result.summary.assessment?.find(
    (item) => item.topic === "cvss" && item.kind !== "fact",
  );

  assert(
    cvssStatement &&
    new Set(cvssStatement.evidenceIds).size === cvssStatement.evidenceIds.length,
    "an assessment statement must cite each evidence record once",
  );

  assert(
    view.summary.vendorImpact.total === 2000 &&
    view.summary.vendorImpact.omitted > 0 &&
    view.summary.packageFixes.total === 200 &&
    view.summary.affectedVersions.total === 500,
    "capped lists must report their real totals",
  );

  const v4Vector =
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:A/CR:H/IR:H/AR:H/MAV:N/MAC:L";

  const v4 = viewFromResult(
    await investigateCve(CVE, {
      requestTimeoutMs: 1000,
      providers: {
        nvd: provider("NVD", {
          id: CVE,
          descriptions: [{ lang: "en", value: long("description", 20000) }],
          metrics: {
            cvssMetricV40: [
              { source: "nvd@nist.gov", cvssData: { version: "4.0", baseScore: 9.3, vectorString: v4Vector } },
            ],
          },
        }),
        cisaKev: provider("CISA_KEV", { dateAdded: "2024-01-01", requiredAction: long("action", 5000) }),
        redhat: provider("REDHAT", {
          name: CVE,
          statement: long("statement", 20000),
          package_state: Array.from({ length: 500 }, (_, index) => ({
            product_name: long(`product-${index}`, 8000),
            package_name: long(`package-${index}`, 8000),
            fix_state: "Affected",
          })),
        }),
      },
    }),
  );

  assert(
    JSON.stringify(v4).includes("[truncated]") &&
    v4.summary.vendorImpact.items[0].product.length < 200,
    "this fixture must reach the clipping stage, or the next check proves nothing",
  );

  assert(
    v4.summary.cvss.vector === v4Vector,
    `clipping must not corrupt a CVSS vector: ${v4.summary.cvss.vector}`,
  );

  console.log(`✓ A worst-case result fits in ${size} chars with exact totals`);
}

async function main(): Promise<void> {
  testCvss();
  testSeverity();
  testExploitation();
  testVendor();
  testFixedVersions();
  await testOsvSource();
  await testAssessment();
  await testGateConflictClaim();
  await testGateAgreementScope();
  await testWorstCaseSize();
  testResponseLimit();

  console.log("Correlation tests PASSED");
}

main().catch((error: unknown) => {
  console.error("Correlation tests FAILED");
  console.error(error);
  process.exitCode = 1;
});
