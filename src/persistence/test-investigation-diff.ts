/*
 * Comparison over time against real Postgres: real persistence, real JSONB round
 * trips, and the same re-derivation the plugin uses. Each change category has a
 * case that must produce it, and a near miss that must not.
 */
import { investigateCve } from "../engine.js";
import { viewFromContext } from "../tool-result.js";
import type { ProviderResult, SourceId } from "../types.js";
import { db } from "./db.js";
import {
  boundComparison,
  compareLatestInvestigations,
  compareWithBaseline,
  type ChangeCategory,
  type InvestigationComparison,
} from "./investigation-diff.js";
import { getInvestigationContext } from "./investigation-context.js";
import { replayInvestigation } from "./investigation-replay.js";
import { persistInvestigation } from "./persist-investigation.js";

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) {
    throw new Error(`Assertion failed: ${message}`);
  }
}

const targets: string[] = [];
let counter = 0;

function newTarget(): string {
  counter += 1;

  const target = `CVE-2099-${Date.now()}${counter}`;

  targets.push(target);

  return target;
}

type Scenario = {
  score?: number;
  vector?: string;
  versions?: string[];
  kevDate?: string | null;
  kevFails?: boolean;
  redhatStatus?: string;
  redhatFails?: boolean;
  osvFixed?: string[] | null;
  osvFails?: boolean;
  osvNotChecked?: boolean;
  modified?: string;
  nvdKevDate?: string | null;
};

const V = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";

function result(
  source: SourceId,
  target: string,
  facts: Record<string, unknown> | null,
): ProviderResult {
  const checkedAt = new Date().toISOString();

  return {
    provider: source,
    status: facts ? "success" : "observed_absence",
    error: null,
    checkedAt,
    evidence: facts
      ? {
        id: `${source}:${target}`,
        source,
        sourceType:
          source === "REDHAT" ? "vendor" : source === "OSV" ? "community" : "primary",
        retrievedAt: checkedAt,
        url: "https://example.test/",
        title: "test",
        confidence: source === "OSV" ? "medium" : "high",
        facts,
        extractedFacts: [],
        references: [],
      }
      : null,
  };
}

function failure(source: SourceId): ProviderResult {
  return {
    provider: source,
    status: "error",
    evidence: null,
    error: "unavailable",
    checkedAt: new Date().toISOString(),
  };
}

function run(target: string, scenario: Scenario = {}) {
  const {
    score = 7.5,
    vector = V,
    versions = ["2.0.0"],
    kevDate = null,
    redhatStatus = "Affected",
    osvFixed = ["2.0.0"],
    modified = "2026-01-01T00:00:00.000",
    nvdKevDate = null,
  } = scenario;

  return investigateCve(target, {
    requestTimeoutMs: 1000,
    providers: {
      nvd: async () =>
        result("NVD", target, {
          id: target,
          lastModified: modified,
          ...(nvdKevDate ? { cisaExploitAdd: nvdKevDate } : {}),
          metrics: {
            cvssMetricV31: [
              {
                source: "nvd@nist.gov",
                cvssData: { version: "3.1", baseScore: score, vectorString: vector },
              },
            ],
          },
          configurations: [
            {
              nodes: [
                {
                  cpeMatch: versions.map((version) => ({
                    vulnerable: true,
                    criteria: "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
                    versionEndExcluding: version,
                  })),
                },
              ],
            },
          ],
        }),

      cisaKev: async () =>
        scenario.kevFails
          ? failure("CISA_KEV")
          : result("CISA_KEV", target, kevDate ? { dateAdded: kevDate } : null),

      redhat: async () =>
        scenario.redhatFails
          ? failure("REDHAT")
          : result("REDHAT", target, {
            name: target,
            package_state: [
              {
                product_name: "RHEL 9",
                package_name: "product",
                fix_state: redhatStatus,
              },
            ],
          }),

      osv: scenario.osvNotChecked
        ? null
        : async () =>
          scenario.osvFails
            ? failure("OSV")
            : result(
              "OSV",
              target,
              osvFixed
                ? {
                  advisories: [
                    {
                      id: "GHSA-test",
                      reviewed: true,
                      withdrawn: null,
                      packages: [
                        {
                          ecosystem: "npm",
                          name: "product",
                          events: osvFixed.map((fixed) => ({ fixed })),
                        },
                      ],
                    },
                  ],
                  advisoriesFailed: [],
                }
                : null,
            ),
    },
  });
}

async function history(
  first: Scenario,
  second: Scenario,
): Promise<{ target: string; comparison: InvestigationComparison }> {
  const target = newTarget();

  await persistInvestigation(await run(target, first));
  await persistInvestigation(await run(target, second));

  const comparison = await compareLatestInvestigations(target);

  assert(comparison, "two investigations should be comparable");

  return { target, comparison };
}

function changed(
  comparison: InvestigationComparison,
  field: string,
  category: ChangeCategory,
): boolean {
  return comparison.changes.some(
    (change) => change.field === field && change.category === category,
  );
}

async function testNoChange(): Promise<void> {
  const { comparison } = await history({}, {});

  assert(comparison.noIntelligenceChange, "identical results have no intelligence change");

  assert(
    comparison.changes.length === 0,
    `identical results must report nothing: ${JSON.stringify(comparison.changes)}`,
  );

  assert(
    comparison.baseline.integrity.evidenceRows === "verified" &&
    comparison.baseline.integrity.recordConsistency === "consistent" &&
    comparison.baseline.integrity.fullyVerified &&
    comparison.current.integrity?.fullyVerified === true,
    `an intact pair must verify (the control for the failures below): ${JSON.stringify(comparison.baseline.integrity)}`,
  );

  console.log("✓ Identical investigations report no change");
}

async function testIntelligenceChanges(): Promise<void> {
  const { comparison } = await history(
    { osvFixed: ["2.0.0"] },
    {
      score: 9.8,
      vector: V.replace("S:U", "S:C"),
      versions: ["2.0.0", "3.1.0"],
      kevDate: "2026-02-02",
      nvdKevDate: "2026-02-02",
      redhatStatus: "Not affected",
      osvFixed: ["2.0.0", "3.1.0"],
    },
  );

  for (const field of [
    "cvss.baseScore",
    "cvss.vector",
    "affectedVersions",
    "kevStatus",
    "vendorImpact",
    "packageFixes",
  ]) {
    assert(
      changed(comparison, field, "intelligence_change"),
      `${field} should be an intelligence change: ${JSON.stringify(comparison.changes)}`,
    );
  }

  assert(!comparison.noIntelligenceChange, "a real change must be reported as one");

  const kev = comparison.changes.find((change) => change.field === "kevStatus");

  assert(
    kev?.before === "not-listed" && kev.after === "listed",
    "the KEV change must show both states",
  );

  console.log("✓ Real changes in CVSS, KEV, versions, vendor, and fixes are detected");
}

async function testCollectionDifferences(): Promise<void> {
  /* KEV was listed, then its check failed: nothing is known to have changed. */
  const kev = await history(
    { kevDate: "2026-02-02", nvdKevDate: "2026-02-02" },
    { kevFails: true, nvdKevDate: "2026-02-02" },
  );

  assert(
    changed(kev.comparison, "kevStatus", "collection_difference"),
    `a failed KEV check is a collection difference: ${JSON.stringify(kev.comparison.changes)}`,
  );
  assert(
    !changed(kev.comparison, "kevStatus", "intelligence_change"),
    "a failed check must never read as a KEV removal",
  );
  assert(
    kev.comparison.noIntelligenceChange,
    `a provider failure alone is not an intelligence change: ${JSON.stringify(kev.comparison.changes)}`,
  );

  /* Red Hat data disappearing because the check failed */
  const redhat = await history({}, { redhatFails: true });

  assert(
    changed(redhat.comparison, "vendorImpact", "collection_difference") &&
    changed(redhat.comparison, "providerStatus", "collection_difference") &&
    redhat.comparison.noIntelligenceChange,
    "losing vendor data to an outage is a collection difference",
  );

  /* Recovery is also not a change in the intelligence. */
  const recovery = await history({ redhatFails: true }, {});

  assert(
    changed(recovery.comparison, "vendorImpact", "collection_difference") &&
    recovery.comparison.noIntelligenceChange,
    "a provider recovering is a collection difference",
  );

  /* An investigation from before OSV was added */
  const legacy = await history({ osvNotChecked: true }, {});

  assert(
    changed(legacy.comparison, "packageFixes", "collection_difference") &&
    legacy.comparison.noIntelligenceChange,
    `OSV not having been checked is not new intelligence: ${JSON.stringify(legacy.comparison.changes)}`,
  );

  /* A completed absence turning into a record IS new intelligence. */
  const newRecord = await history({ osvFixed: null }, { osvFixed: ["2.0.0"] });

  assert(
    changed(newRecord.comparison, "evidence", "intelligence_change"),
    "a source newly having a record is an intelligence change",
  );

  console.log("✓ Provider failures and missing checks are never reported as changes");
}

async function testConflicts(): Promise<void> {
  const introduced = await history({}, { nvdKevDate: "2026-02-02" });

  assert(
    introduced.comparison.changes.some(
      (change) =>
        change.field === "conflict" &&
        change.after === "nvd_records_kev_entry_missing_from_catalog" &&
        change.category === "intelligence_change",
    ),
    `a new conflict should be reported: ${JSON.stringify(introduced.comparison.changes)}`,
  );

  const resolved = await history({ nvdKevDate: "2026-02-02" }, {});

  assert(
    resolved.comparison.changes.some(
      (change) =>
        change.field === "conflict" &&
        change.before === "nvd_records_kev_entry_missing_from_catalog" &&
        change.after === null,
    ),
    "a resolved conflict should be reported",
  );

  /* A conflict vanishing because a source failed is not a resolution. */
  const unavailable = await history(
    { nvdKevDate: "2026-02-02" },
    { kevFails: true, nvdKevDate: "2026-02-02" },
  );

  assert(
    unavailable.comparison.changes
      .filter((change) => change.field === "conflict")
      .every((change) => change.category === "collection_difference"),
    "a conflict lost to an outage is not resolved",
  );

  console.log("✓ New and resolved conflicts are detected, and outages resolve nothing");
}

async function testEvidenceRevision(): Promise<void> {
  const { comparison } = await history(
    { modified: "2026-01-01T00:00:00.000" },
    { modified: "2026-03-03T00:00:00.000" },
  );

  const revision = comparison.changes.find((change) => change.field === "evidence");

  assert(
    revision?.scope === "NVD" &&
    revision.explanation.includes("no field this engine extracts changed"),
    `a source revision with no extracted change should say so: ${JSON.stringify(comparison.changes)}`,
  );

  console.log("✓ Source revisions with no extracted change are labelled");
}

async function withoutTrigger(
  table: string,
  trigger: string,
  update: () => Promise<unknown>,
): Promise<void> {
  await db.query(`ALTER TABLE public.${table} DISABLE TRIGGER ${trigger}`);

  try {
    await update();
  } finally {
    await db.query(`ALTER TABLE public.${table} ENABLE TRIGGER ${trigger}`);
  }
}

async function testProcessingDifference(): Promise<void> {
  /*
   * What an older engine would have left behind: a recorded summary that today's
   * engine does not produce from the same evidence.
   */
  const target = newTarget();

  const baselineId = await persistInvestigation(await run(target));

  await withoutTrigger("investigations", "investigations_append_only", () =>
    db.query(
      `UPDATE public.investigations
       SET engine_version = '0.3.0',
           summary = jsonb_set(summary, '{affectedVersions}', '["bare-version-string"]')
       WHERE id = $1`,
      [baselineId],
    ),
  );

  await persistInvestigation(await run(target));

  const comparison = await compareLatestInvestigations(target);

  assert(comparison, "should compare");

  assert(
    changed(comparison, "affectedVersions", "processing_difference"),
    `an extraction change is a processing difference: ${JSON.stringify(comparison.changes)}`,
  );

  assert(
    comparison.noIntelligenceChange,
    `an extraction change must not read as an intelligence change: ${JSON.stringify(comparison.changes)}`,
  );

  console.log("✓ Extraction changes are separated from intelligence changes");
}

async function testTamperedBaseline(): Promise<void> {
  const target = newTarget();

  const baselineId = await persistInvestigation(await run(target));

  await withoutTrigger("evidence", "evidence_append_only", () =>
    db.query(
      `UPDATE public.evidence
       SET raw_payload = jsonb_set(raw_payload, '{lastModified}', '"forged"')
       WHERE investigation_id = $1 AND source = 'NVD'`,
      [baselineId],
    ),
  );

  await persistInvestigation(await run(target));

  const comparison = await compareLatestInvestigations(target);

  assert(
    comparison?.baseline.integrity.evidenceRows === "tampered" &&
    !comparison.baseline.integrity.fullyVerified,
    "a tampered baseline must be reported",
  );

  assert(
    comparison.noIntelligenceChange === null,
    "no conclusion may be drawn from a tampered baseline",
  );

  console.log("✓ A tampered baseline is reported, and no conclusion is drawn");
}

/* Row fingerprints for every table, to prove comparison writes nothing. */
async function fingerprint(target: string): Promise<string> {
  const { rows } = await db.query<{ hash: string }>(
    `SELECT md5(string_agg(row_text, '|' ORDER BY row_text)) AS hash FROM (
       SELECT i::text AS row_text FROM public.investigations i WHERE i.target = $1
       UNION ALL
       SELECT e::text FROM public.evidence e
         JOIN public.investigations i ON i.id = e.investigation_id WHERE i.target = $1
       UNION ALL
       SELECT f::text FROM public.facts f
         JOIN public.investigations i ON i.id = f.investigation_id WHERE i.target = $1
       UNION ALL
       SELECT n::text FROM public.inferences n
         JOIN public.investigations i ON i.id = n.investigation_id WHERE i.target = $1
     ) AS all_rows`,
    [target],
  );

  return rows[0].hash;
}

function deepFreeze<T>(value: T): T {
  if (typeof value === "object" && value !== null && !Object.isFrozen(value)) {
    Object.freeze(value);
    Object.values(value).forEach(deepFreeze);
  }

  return value;
}

async function testIntegrityIsNeverOverstated(): Promise<void> {
  const pair = async (scenario: Scenario = {}) => {
    const target = newTarget();
    const id = await persistInvestigation(await run(target, scenario));

    await persistInvestigation(await run(target, scenario));

    return { target, id };
  };

  /* An edited provider status: no evidence hash covers this. */
  const edited = await pair();

  await withoutTrigger("investigations", "investigations_append_only", () =>
    db.query(
      `UPDATE public.investigations
       SET provider_results = (
         SELECT jsonb_agg(
           CASE WHEN p->>'provider' = 'CISA_KEV'
             THEN p || '{"status":"error","error":"edited"}'::jsonb
             ELSE p END
         )
         FROM jsonb_array_elements(provider_results) p
       )
       WHERE id = $1`,
      [edited.id],
    ),
  );

  const editedComparison = await compareLatestInvestigations(edited.target);

  assert(
    editedComparison?.baseline.integrity.evidenceRows === "verified" &&
    editedComparison.baseline.integrity.recordConsistency === "inconsistent" &&
    !editedComparison.baseline.integrity.fullyVerified &&
    editedComparison.noIntelligenceChange === null,
    `clean hashes must not vouch for an edited record: ${JSON.stringify(editedComparison?.baseline.integrity)}`,
  );

  /* A deleted evidence row: triggers block updates, not deletes. */
  const deleted = await pair();

  await db.query(
    "DELETE FROM public.evidence WHERE investigation_id = $1 AND source = 'NVD'",
    [deleted.id],
  );

  const deletedComparison = await compareLatestInvestigations(deleted.target);
  const deletedReplay = await replayInvestigation(deleted.id);

  assert(
    deletedComparison?.baseline.integrity.evidenceRows === "missing" &&
    !deletedComparison.baseline.integrity.fullyVerified &&
    deletedComparison.noIntelligenceChange === null,
    `a deleted evidence row must be reported: ${JSON.stringify(deletedComparison?.baseline.integrity)}`,
  );
  assert(
    deletedReplay?.reproduced === false &&
    deletedReplay.evidence.some((item) => item.integrity === "missing") &&
    deletedReplay.integrity.evidenceRows === "missing",
    "replay must report the deleted row, and must not reproduce",
  );

  /* An evidence row for a provider recorded as having none */
  const orphan = await pair({ osvFixed: null });

  await withoutTrigger("investigations", "investigations_append_only", () =>
    db.query(
      `UPDATE public.investigations
       SET provider_results = (
         SELECT jsonb_agg(
           CASE WHEN p->>'provider' = 'NVD'
             THEN p || '{"status":"observed_absence","evidence":null}'::jsonb
             ELSE p END
         )
         FROM jsonb_array_elements(provider_results) p
       )
       WHERE id = $1`,
      [orphan.id],
    ),
  );

  const orphanComparison = await compareLatestInvestigations(orphan.target);

  assert(
    orphanComparison?.baseline.integrity.evidenceRows === "inconsistent" &&
    !orphanComparison.baseline.integrity.fullyVerified,
    `evidence the record disowns must be reported: ${JSON.stringify(orphanComparison?.baseline.integrity)}`,
  );

  /* Nothing to verify is not the same as verified. */
  const emptyTarget = newTarget();

  const empty = () =>
    investigateCve(emptyTarget, {
      requestTimeoutMs: 1000,
      providers: {
        nvd: async () => result("NVD", emptyTarget, null),
        cisaKev: async () => result("CISA_KEV", emptyTarget, null),
        redhat: async () => result("REDHAT", emptyTarget, null),
      },
    });

  await persistInvestigation(await empty());
  const emptyId = await persistInvestigation(await empty());

  const emptyComparison = await compareLatestInvestigations(emptyTarget);

  assert(
    emptyComparison?.baseline.integrity.evidenceRows === "none" &&
    !emptyComparison.baseline.integrity.fullyVerified,
    `no evidence must not read as verified: ${JSON.stringify(emptyComparison?.baseline.integrity)}`,
  );
  assert(
    (await replayInvestigation(emptyId))?.integrity.evidenceRows === "none",
    "replay must report that there was no evidence to check",
  );

  console.log("✓ Missing, empty, edited, and disowned evidence is never reported as verified");
}

async function testHistoricalRecordsArePreserved(): Promise<void> {
  /* Recorded 3.3, stored evidence re-derives 7.5, the latest says 9.0. */
  const target = newTarget();

  const baselineId = await persistInvestigation(await run(target));

  await withoutTrigger("investigations", "investigations_append_only", () =>
    db.query(
      `UPDATE public.investigations
       SET engine_version = '0.3.0',
           summary = jsonb_set(summary, '{cvss,baseScore}', '3.3')
       WHERE id = $1`,
      [baselineId],
    ),
  );

  await persistInvestigation(await run(target, { score: 9 }));

  const before = await fingerprint(target);

  const comparison = await compareLatestInvestigations(target);

  const context = await getInvestigationContext(baselineId);

  assert(context, "the baseline should load");

  const frozen = deepFreeze(context);

  await compareWithBaseline(frozen, await run(target, { score: 9 }));
  await replayInvestigation(baselineId);

  assert(
    (await fingerprint(target)) === before,
    "comparing and replaying must not write to stored investigations",
  );

  assert(
    comparison?.baseline.basis === "rederived_from_stored_evidence" &&
    comparison.baseline.recordedEngineVersion === "0.3.0" &&
    comparison.baseline.rederivedWithEngineVersion !== "0.3.0" &&
    comparison.baseline.recorded.cvssBaseScore === 3.3 &&
    comparison.baseline.rederived.cvssBaseScore === 7.5,
    `the baseline must separate recorded and re-derived values: ${JSON.stringify(comparison?.baseline)}`,
  );

  const intelligence = comparison.changes.find(
    (change) =>
      change.field === "cvss.baseScore" &&
      change.category === "intelligence_change",
  );

  assert(
    intelligence?.before === 7.5 &&
    intelligence.after === 9 &&
    intelligence.beforeBasis === "rederived_baseline" &&
    intelligence.afterBasis === "rederived_latest" &&
    intelligence.recordedBefore === 3.3,
    `an intelligence change must show all three values, labelled: ${JSON.stringify(intelligence)}`,
  );

  const processing = comparison.changes.find(
    (change) =>
      change.field === "cvss.baseScore" &&
      change.category === "processing_difference",
  );

  assert(
    processing?.before === 3.3 &&
    processing.after === 7.5 &&
    processing.beforeBasis === "recorded" &&
    processing.afterBasis === "rederived",
    `a processing difference must be labelled: ${JSON.stringify(processing)}`,
  );

  /* Across engine versions, consistency cannot be judged either way. */
  assert(
    comparison.baseline.integrity.recordConsistency === "unverifiable" &&
    !comparison.baseline.integrity.fullyVerified &&
    comparison.noIntelligenceChange === false,
    `an older engine's record is unverifiable, not inconsistent: ${JSON.stringify(comparison.baseline.integrity)}`,
  );

  /* The fresh-result path labels its side as unsaved. */
  const fresh = await compareWithBaseline(context, await run(target, { score: 9 }));

  assert(
    fresh.changes
      .filter((change) => change.category === "intelligence_change")
      .every((change) => change.afterBasis === "current_result") &&
    fresh.current.integrity === null,
    "the fresh path must label its result as current and unsaved",
  );

  console.log("✓ Original records are preserved and labelled apart from re-derived values");
}

async function testLiveResultComparison(): Promise<void> {
  /* The path threatintel_investigate uses: stored baseline, unsaved fresh result. */
  const target = newTarget();

  const baselineId = await persistInvestigation(await run(target));

  const baseline = await getInvestigationContext(baselineId);

  assert(baseline, "baseline should load");

  const comparison = await compareWithBaseline(
    baseline,
    await run(target, { score: 9.1 }),
  );

  assert(
    changed(comparison, "cvss.baseScore", "intelligence_change"),
    "the fresh path should detect a change",
  );
  assert(
    comparison.current.investigationId === null,
    "an unsaved result has no id",
  );

  const bounded = boundComparison(
    {
      ...comparison,
      changes: Array.from({ length: 200 }, () => comparison.changes[0]),
    },
    2500,
  );

  assert(
    JSON.stringify(bounded).length <= 2500 &&
    bounded.omittedChanges > 0 &&
    bounded.changes.length + bounded.omittedChanges === 200,
    "a bounded comparison must fit and count what it dropped",
  );

  console.log("✓ The fresh-result path compares and stays within budget");
}

async function testEdges(): Promise<void> {
  const target = newTarget();

  assert(
    (await compareLatestInvestigations(target)) === null,
    "no history is not comparable",
  );

  await persistInvestigation(await run(target));

  assert(
    (await compareLatestInvestigations(target)) === null,
    "one investigation is not comparable",
  );

  /* OSV evidence survives persistence and replays exactly. */
  const replayTarget = newTarget();

  const id = await persistInvestigation(await run(replayTarget));

  const report = await replayInvestigation(id);

  assert(
    report?.reproduced === true &&
    report.evidence.length === 3 &&
    report.evidence.every((item) => item.integrity === "verified"),
    `an investigation with OSV should replay: ${JSON.stringify(report)}`,
  );

  /* An investigation saved before OSV existed still replays. */
  const legacyTarget = newTarget();

  const legacyId = await persistInvestigation(
    await run(legacyTarget, { osvNotChecked: true }),
  );

  assert(
    (await replayInvestigation(legacyId))?.reproduced === true,
    "an investigation with no OSV result should replay",
  );

  console.log("✓ Short history is handled, and investigations with and without OSV replay");
}

/*
 * Rows saved by v0.3, as they exist in deployed databases: no OSV result, a
 * conflicts array, and none of the fields Phase 4 added.
 */
async function testV03Rows(): Promise<void> {
  const target = newTarget();

  const baselineId = await persistInvestigation(
    await run(target, { osvNotChecked: true }),
  );

  await withoutTrigger("investigations", "investigations_append_only", () =>
    db.query(
      `UPDATE public.investigations
       SET engine_version = '0.3.0',
           summary = (summary - 'correlations' - 'assessment' - 'packageFixes')
             || '{"conflicts":[{"field":"cvss.baseScore","values":[{"source":"nvd@nist.gov","value":10},{"source":"Red Hat","value":9.8}]}]}'::jsonb
       WHERE id = $1`,
      [baselineId],
    ),
  );

  const context = await getInvestigationContext(baselineId);

  assert(context, "a v0.3 row should load");

  const view = viewFromContext(context);

  const legacy = view.summary.correlations.items[0];

  assert(
    legacy?.classification === "conflict" &&
    legacy.reason === "recorded_before_classification" &&
    legacy.values.some((item) => item.source === "Red Hat" && item.value === 9.8),
    `a v0.3 conflict should survive, without claiming a cause: ${JSON.stringify(legacy)}`,
  );

  assert(
    view.assessment.total === 0 && view.summary.packageFixes.total === 0,
    "a v0.3 row has no assessment or package fixes",
  );

  assert(
    !view.providerResults.some((item) => item.provider === "OSV"),
    "a v0.3 row must not claim OSV was checked",
  );

  /* The first v0.4 run after it: OSV is new collection, not new intelligence. */
  await persistInvestigation(await run(target));

  const comparison = await compareLatestInvestigations(target);

  assert(comparison, "a v0.3 baseline should be comparable");

  assert(
    comparison.baseline.recordedEngineVersion === "0.3.0" &&
    comparison.baseline.integrity.recordConsistency === "unverifiable" &&
    comparison.noIntelligenceChange,
    `upgrading must not read as an intelligence change: ${JSON.stringify(comparison.changes)}`,
  );

  assert(
    changed(comparison, "packageFixes", "collection_difference"),
    "OSV appearing after an upgrade is a collection difference",
  );

  console.log("✓ Rows saved by v0.3 load, and upgrading is not a false change");
}

async function main(): Promise<void> {
  const realFetch = globalThis.fetch;

  globalThis.fetch = (async () => {
    throw new Error("comparison must not use the network");
  }) as typeof fetch;

  try {
    await testNoChange();
    await testIntelligenceChanges();
    await testCollectionDifferences();
    await testConflicts();
    await testEvidenceRevision();
    await testProcessingDifference();
    await testTamperedBaseline();
    await testIntegrityIsNeverOverstated();
    await testHistoricalRecordsArePreserved();
    await testLiveResultComparison();
    await testEdges();
    await testV03Rows();

    console.log("Investigation comparison tests PASSED");
  } finally {
    globalThis.fetch = realFetch;

    await db.query(
      "DELETE FROM public.investigations WHERE target = ANY($1::text[])",
      [targets],
    );
    await db.end();
  }
}

main().catch((error: unknown) => {
  console.error("Investigation comparison tests FAILED");
  console.error(error);
  process.exitCode = 1;
});
