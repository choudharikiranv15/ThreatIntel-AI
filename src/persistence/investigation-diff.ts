import type {
  InvestigationResult,
  InvestigationSummary,
  ProviderStatus,
  SourceId,
} from "../types.js";
import { ENGINE_VERSION } from "../version.js";
import { hashPayload } from "./evidence-hash.js";
import { findInvestigationHistory } from "./investigation-history.js";
import {
  getInvestigationContext,
  type InvestigationContext,
} from "./investigation-context.js";
import {
  assessIntegrity,
  rederiveContext,
  type InvestigationIntegrity,
} from "./investigation-replay.js";

/*
 * Separates three reasons two investigations can differ:
 *
 * - intelligence_change: a source that answered both times now says something else.
 * - collection_difference: a source was unavailable or not checked in one of them.
 * - processing_difference: the stored evidence produces a different result under
 *   the current engine, so the extraction logic changed, not the world.
 *
 * The baseline is re-derived from its stored evidence through the current engine
 * before comparing. Both sides then share one engine, so extraction changes
 * cannot look like intelligence changes. This works entirely on copies: stored
 * investigations are never written, and what they originally recorded is reported
 * alongside the re-derived values.
 */

export type ChangeCategory =
  | "intelligence_change"
  | "collection_difference"
  | "processing_difference";

export type InvestigationChange = {
  category: ChangeCategory;
  field: string;
  scope?: string;
  before: unknown;
  after: unknown;

  /** What before and after were read from. */
  beforeBasis: "rederived_baseline" | "recorded";
  afterBasis: "current_result" | "rederived_latest" | "rederived";

  /** The value originally recorded, when re-derivation gives a different one. */
  recordedBefore?: unknown;

  explanation: string;
  sources: string[];
};

type SummaryHeadline = {
  status: string;
  severity: string | null;
  cvssBaseScore: number | null;
  kevStatus: string;
};

export type InvestigationComparison = {
  target: string;
  baseline: {
    investigationId: string;
    createdAt: string;
    basis: "rederived_from_stored_evidence";
    recordedEngineVersion: string | null;
    rederivedWithEngineVersion: string;
    recorded: SummaryHeadline;
    rederived: SummaryHeadline;
    integrity: InvestigationIntegrity;
  };
  current: {
    investigationId: string | null;
    createdAt: string | null;
    integrity: InvestigationIntegrity | null;
  };
  counts: Record<ChangeCategory, number>;

  /** Null when a compared record is unreliable, so no conclusion can be drawn. */
  noIntelligenceChange: boolean | null;
  changes: InvestigationChange[];
  omittedChanges: number;
};

const CATEGORY_ORDER: Record<ChangeCategory, number> = {
  intelligence_change: 0,
  collection_difference: 1,
  processing_difference: 2,
};

type Statuses = Map<string, ProviderStatus>;

function statuses(result: InvestigationResult): Statuses {
  return new Map(
    result.providerResults.map((item) => [item.provider, item.status]),
  );
}

function isCompleted(status: ProviderStatus | undefined): boolean {
  return status === "success" || status === "observed_absence";
}

function vendorKey(row: { productName: string; packageName: string }): string {
  return `${row.productName} / ${row.packageName}`;
}

/** Scores and vectors compared on their own, so a changed source is reported as such. */
function diffSummaries(
  before: InvestigationSummary,
  after: InvestigationSummary,
): {
  field: string;
  scope?: string;
  before: unknown;
  after: unknown;
  provider: SourceId;
}[] {
  const differences: ReturnType<typeof diffSummaries> = [];

  const add = (
    field: string,
    provider: SourceId,
    from: unknown,
    to: unknown,
    scope?: string,
  ) => {
    if (hashPayload(from ?? null) !== hashPayload(to ?? null)) {
      differences.push({
        field,
        provider,
        before: from ?? null,
        after: to ?? null,
        ...(scope ? { scope } : {}),
      });
    }
  };

  add("cvss.baseScore", "NVD", before.cvss.baseScore, after.cvss.baseScore);
  add("cvss.vector", "NVD", before.cvss.vector, after.cvss.vector);
  add("cvss.source", "NVD", before.cvss.source, after.cvss.source);
  add("kevStatus", "CISA_KEV", before.kevStatus, after.kevStatus);

  const beforeVersions = new Set(before.affectedVersions);
  const afterVersions = new Set(after.affectedVersions);

  const addedVersions = after.affectedVersions.filter(
    (item) => !beforeVersions.has(item),
  );

  const removedVersions = before.affectedVersions.filter(
    (item) => !afterVersions.has(item),
  );

  if (addedVersions.length + removedVersions.length > 0) {
    add(
      "affectedVersions",
      "NVD",
      { removed: removedVersions.slice(0, 10), removedTotal: removedVersions.length },
      { added: addedVersions.slice(0, 10), addedTotal: addedVersions.length },
    );
  }

  const beforeVendor = new Map(
    before.vendorImpact.map((row) => [vendorKey(row), row.status]),
  );

  const afterVendor = new Map(
    after.vendorImpact.map((row) => [vendorKey(row), row.status]),
  );

  for (const key of new Set([...beforeVendor.keys(), ...afterVendor.keys()])) {
    add(
      "vendorImpact",
      "REDHAT",
      beforeVendor.get(key),
      afterVendor.get(key),
      key,
    );
  }

  const fixes = (summary: InvestigationSummary) =>
    new Map(
      (summary.packageFixes ?? []).map((fix) => [
        `${fix.ecosystem}/${fix.package}`,
        fix.fixedVersions,
      ]),
    );

  const beforeFixes = fixes(before);
  const afterFixes = fixes(after);

  for (const key of new Set([...beforeFixes.keys(), ...afterFixes.keys()])) {
    add(
      "packageFixes",
      "OSV",
      beforeFixes.get(key),
      afterFixes.get(key),
      key,
    );
  }

  return differences;
}

function diffConflicts(
  before: InvestigationSummary,
  after: InvestigationSummary,
): UnlabelledChange[] {
  const conflictIds = (summary: InvestigationSummary) =>
    new Map(
      (summary.correlations ?? [])
        .filter((item) => item.classification === "conflict")
        .map((item) => [item.id, item]),
    );

  const beforeConflicts = conflictIds(before);
  const afterConflicts = conflictIds(after);

  const changes: UnlabelledChange[] = [];

  for (const [id, item] of afterConflicts) {
    if (!beforeConflicts.has(id)) {
      changes.push({
        category: "intelligence_change",
        field: "conflict",
        scope: id,
        before: null,
        after: item.reason,
        explanation: "A new conflict between sources appeared.",
        sources: item.values.map((value) => value.source),
      });
    }
  }

  for (const [id, item] of beforeConflicts) {
    if (!afterConflicts.has(id)) {
      changes.push({
        category: "intelligence_change",
        field: "conflict",
        scope: id,
        before: item.reason,
        after: null,
        explanation: "An earlier conflict between sources no longer applies.",
        sources: item.values.map((value) => value.source),
      });
    }
  }

  return changes;
}

function isConflictCollectionBound(
  change: UnlabelledChange,
  before: Statuses,
  after: Statuses,
): boolean {
  const providers: Record<string, string> = {
    "CISA_KEV": "CISA_KEV",
    NVD: "NVD",
    "Red Hat": "REDHAT",
    OSV: "OSV",
  };

  return change.sources.some((source) => {
    const provider = providers[source] ?? (source.startsWith("GHSA-") ? "OSV" : "NVD");

    return (
      !isCompleted(before.get(provider)) ||
      !isCompleted(after.get(provider))
    );
  });
}

type UnlabelledChange = Omit<InvestigationChange, "beforeBasis" | "afterBasis">;

function compareResults(
  baseline: InvestigationResult,
  current: InvestigationResult,
  recorded: InvestigationSummary,
  afterBasis: InvestigationChange["afterBasis"],
): InvestigationChange[] {
  const before = statuses(baseline);
  const after = statuses(current);
  const changes: UnlabelledChange[] = [];

  const collectionExplanation = (provider: SourceId) => {
    const from = before.get(provider) ?? "not checked";
    const to = after.get(provider) ?? "not checked";

    return `${provider} was ${from} in the baseline and ${to} now, so this reflects availability, not a change in the intelligence.`;
  };

  for (const difference of diffSummaries(baseline.summary, current.summary)) {
    const comparable =
      isCompleted(before.get(difference.provider)) &&
      isCompleted(after.get(difference.provider));

    changes.push({
      category: comparable ? "intelligence_change" : "collection_difference",
      field: difference.field,
      ...(difference.scope ? { scope: difference.scope } : {}),
      before: difference.before,
      after: difference.after,
      explanation: comparable
        ? `${difference.provider} reported this differently in both completed checks.`
        : collectionExplanation(difference.provider),
      sources: [difference.provider],
    });
  }

  for (const change of diffConflicts(baseline.summary, current.summary)) {
    changes.push(
      isConflictCollectionBound(change, before, after)
        ? {
          ...change,
          category: "collection_difference",
          explanation: `${change.explanation} A source involved was unavailable in one of the investigations, so this may only reflect availability.`,
        }
        : change,
    );
  }

  /* Evidence appearing, disappearing, or being revised at the source */
  const providers = new Set([...before.keys(), ...after.keys()]) as Set<SourceId>;

  for (const provider of providers) {
    const from = before.get(provider);
    const to = after.get(provider);

    const beforeEvidence = baseline.evidence.find((item) => item.source === provider);
    const afterEvidence = current.evidence.find((item) => item.source === provider);

    if (!isCompleted(from) || !isCompleted(to)) {
      if (from !== to) {
        changes.push({
          category: "collection_difference",
          field: "providerStatus",
          scope: provider,
          before: from ?? "not checked",
          after: to ?? "not checked",
          explanation: collectionExplanation(provider),
          sources: [provider],
        });
      }

      continue;
    }

    if (!beforeEvidence && afterEvidence) {
      changes.push({
        category: "intelligence_change",
        field: "evidence",
        scope: provider,
        before: "no record",
        after: "record available",
        explanation: `${provider} now has a record for this CVE.`,
        sources: [provider],
      });
    } else if (beforeEvidence && !afterEvidence) {
      changes.push({
        category: "intelligence_change",
        field: "evidence",
        scope: provider,
        before: "record available",
        after: "no record",
        explanation: `${provider} no longer has a record for this CVE.`,
        sources: [provider],
      });
    } else if (
      beforeEvidence &&
      afterEvidence &&
      hashPayload(beforeEvidence.facts) !== hashPayload(afterEvidence.facts)
    ) {
      const tracked = changes.some(
        (change) =>
          change.sources.includes(provider) &&
          change.category === "intelligence_change",
      );

      if (!tracked) {
        changes.push({
          category: "intelligence_change",
          field: "evidence",
          scope: provider,
          before: beforeEvidence.retrievedAt,
          after: afterEvidence.retrievedAt,
          explanation: `${provider} revised its record, but no field this engine extracts changed.`,
          sources: [provider],
        });
      }
    }
  }

  /* Where re-derivation changed a value, keep what was originally recorded. */
  const originals = new Map(
    diffSummaries(comparableRecorded(recorded), baseline.summary).map((item) => [
      `${item.field}|${item.scope ?? ""}`,
      item.before,
    ]),
  );

  return changes.map((change) => {
    const key = `${change.field}|${change.scope ?? ""}`;

    return {
      ...change,
      beforeBasis: "rederived_baseline",
      afterBasis,
      ...(originals.has(key) ? { recordedBefore: originals.get(key) } : {}),
    };
  });
}

/* Older records may lack fields added since. */
function comparableRecorded(
  recorded: InvestigationSummary,
): InvestigationSummary {
  return {
    ...recorded,
    vendorImpact: recorded.vendorImpact ?? [],
    affectedVersions: recorded.affectedVersions ?? [],
  };
}

function processingChanges(
  recorded: InvestigationSummary,
  rederived: InvestigationSummary,
  statusChanged: boolean,
  label: string,
): InvestigationChange[] {
  const changes: InvestigationChange[] = diffSummaries(
    comparableRecorded(recorded),
    rederived,
  ).map((difference) => ({
    category: "processing_difference",
    field: difference.field,
    ...(difference.scope ? { scope: difference.scope } : {}),
    before: difference.before,
    after: difference.after,
    beforeBasis: "recorded",
    afterBasis: "rederived",
    explanation: `The ${label} evidence gives this result under the current engine, so extraction logic changed rather than the source.`,
    sources: [difference.provider],
  }));

  if (statusChanged) {
    changes.push({
      category: "processing_difference",
      field: "status",
      before: "recorded",
      after: "re-derived differently",
      beforeBasis: "recorded",
      afterBasis: "rederived",
      explanation: `The ${label} evidence gives a different status under the current engine.`,
      sources: [],
    });
  }

  return changes;
}

function headline(
  status: string,
  summary: InvestigationSummary,
): SummaryHeadline {
  return {
    status,
    severity: summary.severity ?? null,
    cvssBaseScore: summary.cvss?.baseScore ?? null,
    kevStatus: summary.kevStatus ?? "unknown",
  };
}

function isUnreliable(integrity: InvestigationIntegrity): boolean {
  return (
    integrity.evidenceRows === "tampered" ||
    integrity.evidenceRows === "missing" ||
    integrity.evidenceRows === "inconsistent" ||
    integrity.recordConsistency === "inconsistent"
  );
}

function finish(
  baseline: InvestigationContext,
  rederived: InvestigationResult,
  current: Omit<InvestigationComparison["current"], "integrity">,
  currentIntegrity: InvestigationIntegrity | null,
  changes: InvestigationChange[],
): InvestigationComparison {
  const counts: Record<ChangeCategory, number> = {
    intelligence_change: 0,
    collection_difference: 0,
    processing_difference: 0,
  };

  for (const change of changes) {
    counts[change.category] += 1;
  }

  const integrity = assessIntegrity(baseline, rederived);

  const unreliable =
    isUnreliable(integrity) ||
    (currentIntegrity !== null && isUnreliable(currentIntegrity));

  return {
    target: baseline.investigation.target,
    baseline: {
      investigationId: baseline.investigation.id,
      createdAt: baseline.investigation.createdAt,
      basis: "rederived_from_stored_evidence",
      recordedEngineVersion: baseline.investigation.engineVersion,
      rederivedWithEngineVersion: ENGINE_VERSION,
      recorded: headline(
        baseline.investigation.status,
        baseline.investigation.summary as unknown as InvestigationSummary,
      ),
      rederived: headline(rederived.status, rederived.summary),
      integrity,
    },
    current: {
      ...current,
      integrity: currentIntegrity,
    },
    counts,
    noIntelligenceChange: unreliable ? null : counts.intelligence_change === 0,
    changes: [...changes].sort(
      (a, b) => CATEGORY_ORDER[a.category] - CATEGORY_ORDER[b.category],
    ),
    omittedChanges: 0,
  };
}

/**
 * Compares a stored investigation with a result that has just been produced.
 */
export async function compareWithBaseline(
  baseline: InvestigationContext,
  current: InvestigationResult,
): Promise<InvestigationComparison> {
  const rederived = await rederiveContext(baseline);

  const recorded =
    baseline.investigation.summary as unknown as InvestigationSummary;

  return finish(
    baseline,
    rederived,
    { investigationId: null, createdAt: null },
    null,
    [
      ...compareResults(rederived, current, recorded, "current_result"),
      ...processingChanges(
        recorded,
        rederived.summary,
        rederived.status !== baseline.investigation.status,
        "baseline's stored",
      ),
    ],
  );
}

/**
 * Compares the two most recent stored investigations of a target.
 */
export async function compareLatestInvestigations(
  target: string,
): Promise<InvestigationComparison | null> {
  const history = await findInvestigationHistory(
    target.trim().toUpperCase(),
  );

  if (history.length < 2) {
    return null;
  }

  const [latest, previous] = await Promise.all([
    getInvestigationContext(history[0].id),
    getInvestigationContext(history[1].id),
  ]);

  if (!latest || !previous) {
    return null;
  }

  const [latestDerived, previousDerived] = await Promise.all([
    rederiveContext(latest),
    rederiveContext(previous),
  ]);

  const previousRecorded =
    previous.investigation.summary as unknown as InvestigationSummary;

  return finish(
    previous,
    previousDerived,
    {
      investigationId: latest.investigation.id,
      createdAt: latest.investigation.createdAt,
    },
    assessIntegrity(latest, latestDerived),
    [
      ...compareResults(
        previousDerived,
        latestDerived,
        previousRecorded,
        "rederived_latest",
      ),
      ...processingChanges(
        previousRecorded,
        previousDerived.summary,
        previousDerived.status !== previous.investigation.status,
        "baseline's stored",
      ),
      ...processingChanges(
        latest.investigation.summary as unknown as InvestigationSummary,
        latestDerived.summary,
        latestDerived.status !== latest.investigation.status,
        "latest investigation's stored",
      ),
    ],
  );
}

/**
 * Keeps a comparison within a tool-result budget, dropping the least important
 * changes first and reporting how many were dropped.
 */
export function boundComparison(
  comparison: InvestigationComparison,
  maxChars: number,
): InvestigationComparison {
  const changes = [...comparison.changes];

  const render = (): InvestigationComparison => ({
    ...comparison,
    changes,
    omittedChanges: comparison.changes.length - changes.length,
  });

  while (
    changes.length > 0 &&
    JSON.stringify(render()).length > maxChars
  ) {
    changes.pop();
  }

  return render();
}
