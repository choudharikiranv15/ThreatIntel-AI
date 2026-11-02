import type {
  Correlation,
  CorrelationValue,
  CvssDetails,
  Evidence,
  KevStatus,
  PackageFix,
  ProviderStatus,
  VendorImpactAssessment,
} from "../types.js";

/*
 * Compares what independent sources say about the same thing. It never picks a
 * winner: each result names every source's value and states whether the sources
 * disagree about the same thing (conflict) or are answering different questions
 * (explained_difference). Pairs it cannot compare with confidence are reported
 * as incomplete, or skipped, rather than guessed at.
 */

export type CorrelationInput = {
  cvss: CvssDetails;
  severity: string | null;
  kevStatus: KevStatus;
  nvdEvidence?: Evidence;
  kevEvidence?: Evidence;
  redhatEvidence?: Evidence;
  osvEvidence?: Evidence;
  nvdStatus: ProviderStatus | null;
  affectedVersions: string[];
  vendorImpact: VendorImpactAssessment[];
  packageFixes: PackageFix[];
};

type Score = {
  source: string;
  score: number;
  vector: string | null;
  version: string | null;
  evidenceId: string;
};

function record(value: unknown): Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function text(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

/* Metric pairs only, so 3.0 and 3.1 vectors can be compared metric by metric. */
function vectorMetrics(vector: string | null): Map<string, string> {
  return new Map(
    (vector ?? "")
      .split("/")
      .filter((part) => !part.startsWith("CVSS:") && part.includes(":"))
      .map((part) => part.split(":") as [string, string]),
  );
}

function differingMetrics(vectors: (string | null)[]): string[] {
  const parsed = vectors.map(vectorMetrics);

  const names = new Set(parsed.flatMap((metrics) => [...metrics.keys()]));

  return [...names].filter(
    (name) => new Set(parsed.map((metrics) => metrics.get(name))).size > 1,
  );
}

function collectScores(input: CorrelationInput): Score[] {
  const { cvss, nvdEvidence, redhatEvidence } = input;

  if (cvss.baseScore === null) {
    return [];
  }

  const scores = new Map<string, Score>([
    [
      cvss.source ?? "NVD",
      {
        source: cvss.source ?? "NVD",
        score: cvss.baseScore,
        vector: cvss.vector,
        version: cvss.version,
        evidenceId: nvdEvidence?.id ?? "",
      },
    ],
  ]);

  for (const list of Object.values(record(nvdEvidence?.facts.metrics))) {
    for (const metric of Array.isArray(list) ? list : []) {
      const data = record(record(metric).cvssData);
      const source = text(record(metric).source) ?? "NVD";

      if (
        typeof data.baseScore === "number" &&
        data.version === cvss.version &&
        !scores.has(source)
      ) {
        scores.set(source, {
          source,
          score: data.baseScore,
          vector: text(data.vectorString),
          version: text(data.version),
          evidenceId: nvdEvidence?.id ?? "",
        });
      }
    }
  }

  const redhat = record(redhatEvidence?.facts.cvss3);
  const redhatScore = Number(redhat.cvss3_base_score ?? Number.NaN);

  // Red Hat publishes CVSS v3 scores here, so only v3 can be compared.
  if (
    redhatEvidence &&
    Number.isFinite(redhatScore) &&
    cvss.version?.startsWith("3")
  ) {
    const vector = text(redhat.cvss3_scoring_vector);

    scores.set("Red Hat", {
      source: "Red Hat",
      score: redhatScore,
      vector,
      version: vector?.match(/^CVSS:([\d.]+)/)?.[1] ?? null,
      evidenceId: redhatEvidence.id,
    });
  }

  return [...scores.values()];
}

function correlateCvss(input: CorrelationInput): Correlation[] {
  const scores = collectScores(input);

  if (scores.length < 2) {
    return [];
  }

  const values: CorrelationValue[] = scores.map((item) => ({
    source: item.source,
    value: item.score,
    vector: item.vector,
    evidenceId: item.evidenceId,
  }));

  const base = {
    id: "cvss",
    topic: "cvss" as const,
    scope: `CVSS v${input.cvss.version?.split(".")[0]}`,
    values,
  };

  const scoresDiffer = new Set(scores.map((item) => item.score)).size > 1;
  const vectors = scores.map((item) => item.vector);
  const metrics = differingMetrics(vectors);

  if (vectors.some((vector) => vector === null) && scoresDiffer) {
    return [{
      ...base,
      classification: "conflict",
      reason: "score_differs_vector_unavailable",
      explanation:
        "Sources give different scores, and a missing vector means the difference cannot be explained.",
    }];
  }

  if (scoresDiffer && metrics.length === 0) {
    const versions = new Set(scores.map((item) => item.version));

    return [versions.size > 1
      ? {
        ...base,
        classification: "explained_difference",
        reason: "different_cvss_version",
        explanation:
          "Sources rate the same metrics but use different CVSS versions, whose formulas differ.",
      }
      : {
        ...base,
        classification: "conflict",
        reason: "same_vector_different_score",
        explanation:
          "Sources give different scores for identical metrics, which CVSS does not allow, so at least one record is wrong.",
      }];
  }

  if (metrics.length > 0) {
    return [{
      ...base,
      classification: "explained_difference",
      reason: "scoring_authority_assessment",
      explanation: `Scoring authorities assessed ${metrics.join(", ")} differently${scoresDiffer ? ", which accounts for the different scores" : ", reaching the same score"}. Neither value is an error; report both.`,
    }];
  }

  return [{
    ...base,
    classification: "agreement",
    reason: "same_score_and_vector",
    explanation: "Sources give the same score and vector.",
  }];
}

/* Red Hat's scale is its own, and is not derived from CVSS. This approximate
   alignment of level names is this engine's reading, not a statement by either. */
const REDHAT_SEVERITY: Record<string, string> = {
  critical: "CRITICAL",
  important: "HIGH",
  moderate: "MEDIUM",
  low: "LOW",
};

function correlateSeverity(input: CorrelationInput): Correlation[] {
  const redhat = text(input.redhatEvidence?.facts.threat_severity);

  if (!input.severity || !redhat || !input.redhatEvidence) {
    return [];
  }

  const approximate = REDHAT_SEVERITY[redhat.toLowerCase()];
  const aligned = approximate === input.severity.toUpperCase();

  return [{
    id: "severity",
    topic: "severity",
    scope: null,
    classification: "explained_difference",
    reason: "separate_rating_scales",
    interpretation: {
      kind: "approximate_name_alignment",
      aligned,
    },
    explanation: aligned
      ? `Red Hat's "${redhat}" and CVSS "${input.severity}" are similar levels by approximate interpretation only. They are separate scales, so this is not agreement between them.`
      : `Red Hat rates impact on its own products on its own scale, separate from CVSS, so "${redhat}" and "${input.severity}" are not a CVSS disagreement.`,
    values: [
      {
        source: input.cvss.source ?? "NVD",
        value: input.severity,
        evidenceId: input.nvdEvidence?.id ?? null,
      },
      {
        source: "Red Hat",
        value: redhat,
        evidenceId: input.redhatEvidence.id,
      },
    ],
  }];
}

function correlateExploitation(input: CorrelationInput): Correlation[] {
  const { kevStatus, kevEvidence, nvdEvidence } = input;

  const catalogDate = text(kevEvidence?.facts.dateAdded);
  const nvdDate = text(nvdEvidence?.facts.cisaExploitAdd);
  const nvdModified = text(nvdEvidence?.facts.lastModified);

  const values: CorrelationValue[] = [
    {
      source: "CISA_KEV",
      value: kevStatus === "listed" ? catalogDate ?? "listed" : kevStatus,
      evidenceId: kevEvidence?.id ?? null,
    },
    {
      source: "NVD",
      value: nvdDate ?? "no KEV field",
      evidenceId: nvdEvidence?.id ?? null,
    },
  ];

  const base = {
    id: "exploitation",
    topic: "exploitation" as const,
    scope: null,
    values,
  };

  if (kevStatus === "unknown") {
    return [{
      ...base,
      classification: "incomplete",
      reason: "kev_check_failed",
      explanation: nvdDate
        ? `The CISA KEV check failed. NVD records a KEV entry dated ${nvdDate}, so check KEV directly; KEV status stays unknown.`
        : "The CISA KEV check failed, so exploitation status is unknown. NVD having no KEV field does not settle it.",
    }];
  }

  // Without an NVD record, there is nothing to compare KEV against.
  if (!nvdEvidence) {
    return [];
  }

  if (kevStatus === "listed") {
    if (!nvdDate) {
      return [{
        ...base,
        classification: "explained_difference",
        reason: "nvd_record_lag",
        explanation: `CISA KEV lists this CVE, but the NVD record${nvdModified ? ` (last modified ${nvdModified})` : ""} has no KEV field yet. The catalog is the primary source.`,
      }];
    }

    return [nvdDate === catalogDate
      ? {
        ...base,
        classification: "agreement",
        reason: "same_kev_date",
        explanation: "CISA KEV and NVD record the same KEV date.",
      }
      : {
        ...base,
        classification: "conflict",
        reason: "kev_date_mismatch",
        explanation: "CISA KEV and NVD record different KEV dates.",
      }];
  }

  return [nvdDate
    ? {
      ...base,
      classification: "conflict",
      reason: "nvd_records_kev_entry_missing_from_catalog",
      explanation: `NVD records a KEV entry dated ${nvdDate}, but the current catalog has none. The entry may have been removed, or a record may be wrong.`,
    }
    : {
      ...base,
      classification: "agreement",
      reason: "absent_from_both",
      explanation: "Neither the CISA KEV catalog nor the NVD record shows a KEV entry. This does not establish that exploitation has not occurred.",
    }];
}

type NvdEntry = {
  vendor: string;
  product: string;
  constraints: string[];
};

function parseAffected(entry: string): NvdEntry | null {
  const space = entry.indexOf(" ");
  const [vendor, product] = entry.slice(0, space).split(":");

  return space > 0 && vendor && product
    ? {
      vendor,
      product,
      constraints: entry.slice(space + 1).split(", "),
    }
    : null;
}

function correlateRedHat(input: CorrelationInput): Correlation[] {
  const { redhatEvidence, nvdEvidence } = input;

  if (!redhatEvidence || !nvdEvidence) {
    return [];
  }

  /* Red Hat rows carry CPEs, which match NVD's far better than product names. */
  const rowsByProduct = new Map<string, VendorImpactAssessment[]>();

  for (const row of input.vendorImpact) {
    const match = row.cpe?.match(/^cpe:\/[aoh]:redhat:([^:]+):(\d+)/);

    if (match) {
      const key = `${match[1]}|${match[2]}`;

      rowsByProduct.set(key, [...(rowsByProduct.get(key) ?? []), row]);
    }
  }

  const correlations: Correlation[] = [];
  const comparedRows = new Set<VendorImpactAssessment>();
  let agreeing = 0;
  let nvdNotCompared = 0;

  for (const entry of input.affectedVersions.map(parseAffected)) {
    if (entry?.vendor !== "redhat") {
      continue;
    }

    const version = entry.constraints[0];

    const rows =
      // A range cannot be matched to one Red Hat product stream.
      entry.constraints.length === 1 && /^\d/.test(version)
        ? rowsByProduct.get(`${entry.product}|${version.split(".")[0]}`)
        : undefined;

    if (!rows || rows.some((row) => row.status === "unknown")) {
      nvdNotCompared += 1;
      continue;
    }

    rows.forEach((row) => comparedRows.add(row));

    // Rows are per package, so one unaffected package settles nothing.
    if (rows.every((row) => row.status === "not_affected")) {
      correlations.push({
        id: `vendor:${entry.product}:${version}`,
        topic: "vendor_assessment",
        scope: `${entry.product} ${version}`,
        classification: "conflict",
        reason: "nvd_vulnerable_vendor_not_affected",
        explanation:
          "NVD lists this product as vulnerable, but Red Hat marks every assessed package in it as not affected. Treat the vendor's own assessment as a claim to verify against installed packages.",
        values: [
          {
            source: "NVD",
            value: "vulnerable",
            evidenceId: nvdEvidence.id,
          },
          {
            source: "Red Hat",
            value: "not_affected",
            evidenceId: redhatEvidence.id,
          },
        ],
      });
    } else {
      agreeing += 1;
    }
  }

  if (agreeing > 0) {
    correlations.push({
      id: "vendor:agreement",
      topic: "vendor_assessment",
      scope: `${agreeing} Red Hat product stream${agreeing === 1 ? "" : "s"}`,
      classification: "agreement",
      reason: "nvd_and_vendor_agree_affected",
      explanation:
        "NVD lists these products as vulnerable, and Red Hat reports an affected or fixed package in each.",
      values: [
        { source: "NVD", value: "vulnerable", evidenceId: nvdEvidence.id },
        { source: "Red Hat", value: "affected or fixed", evidenceId: redhatEvidence.id },
      ],
    });
  }

  const rowsNotCompared = input.vendorImpact.length - comparedRows.size;

  if (nvdNotCompared + rowsNotCompared > 0) {
    correlations.push({
      id: "vendor:not_compared",
      topic: "vendor_assessment",
      scope: `${nvdNotCompared} NVD Red Hat entries, ${rowsNotCompared} Red Hat rows`,
      classification: "incomplete",
      reason: "records_not_compared",
      explanation:
        "These records have no matching product stream on the other side, so NVD and Red Hat were not compared for them. This is neither agreement nor conflict.",
      values: [
        { source: "NVD", value: nvdNotCompared, evidenceId: nvdEvidence.id },
        { source: "Red Hat", value: rowsNotCompared, evidenceId: redhatEvidence.id },
      ],
    });
  }

  return correlations;
}

function normalizeVersion(version: string): string {
  return version.replace(/^v(?=\d)/i, "");
}

function correlateFixedVersions(input: CorrelationInput): Correlation[] {
  const { nvdEvidence, osvEvidence, packageFixes } = input;

  if (!nvdEvidence || !osvEvidence || packageFixes.length === 0) {
    return [];
  }

  /* NVD's "< X" is the first version outside the range, so it names a fix. */
  const products = new Map<string, { vendors: Set<string>; ends: Set<string> }>();

  for (const entry of input.affectedVersions.map(parseAffected)) {
    if (!entry) {
      continue;
    }

    const key = entry.product.toLowerCase();

    const product =
      products.get(key) ?? { vendors: new Set<string>(), ends: new Set<string>() };

    product.vendors.add(entry.vendor.toLowerCase());

    for (const item of entry.constraints) {
      if (item.startsWith("< ")) {
        product.ends.add(normalizeVersion(item.slice(2)));
      }
    }

    products.set(key, product);
  }

  const correlations: Correlation[] = [];
  const notComparable: string[] = [];
  const noFixListed: string[] = [];

  for (const fix of packageFixes) {
    const label = `${fix.ecosystem}/${fix.package}`;

    if (fix.fixedVersions.length === 0) {
      noFixListed.push(label);
      continue;
    }

    const parts = fix.package.toLowerCase().split(/[:/]/);
    const name = parts[parts.length - 1];
    const namespaced = parts.length > 1;

    const namespaceTokens = parts
      .slice(0, -1)
      .flatMap((part) => part.split(/[._-]/));

    const product = products.get(name);
    const vendor = product?.vendors.size === 1
      ? [...product.vendors][0]
      : undefined;

    /*
     * A same-named package is only the same software if nothing says otherwise.
     * Anything uncertain is reported as not comparable, never as a conflict:
     * log4j and log4j-core differ, and org.fork:requests is not python:requests.
     */
    if (
      !product ||
      !vendor ||
      product.ends.size === 0 ||
      (namespaced && !namespaceTokens.includes(vendor))
    ) {
      notComparable.push(label);
      continue;
    }

    const fixed = fix.fixedVersions.map(normalizeVersion);
    const shared = fixed.filter((version) => product.ends.has(version));

    const allMatch =
      shared.length === product.ends.size &&
      shared.length === fixed.length;

    // Only a name tied to its vendor is firm enough to call a mismatch a conflict.
    const identityConfirmed = namespaced || vendor === name;

    if (shared.length === 0 && !identityConfirmed) {
      notComparable.push(label);
      continue;
    }

    const base = {
      id: `fixed:${label}`,
      topic: "fixed_version" as const,
      scope: label,
      values: [
        {
          source: "NVD",
          value: [...product.ends].join(", "),
          evidenceId: nvdEvidence.id,
        },
        {
          source: fix.advisoryId,
          value: fix.fixedVersions.join(", "),
          evidenceId: osvEvidence.id,
        },
      ],
    };

    if (allMatch) {
      correlations.push({
        ...base,
        classification: "agreement",
        reason: "same_fixed_versions",
        explanation: "NVD's range end and the advisory name the same fixed versions.",
      });
    } else if (shared.length > 0) {
      correlations.push({
        ...base,
        classification: "explained_difference",
        reason: "partial_branch_coverage",
        explanation: "The sources share a fixed version but cover different release branches.",
      });
    } else {
      correlations.push({
        ...base,
        classification: "conflict",
        reason: "disjoint_fixed_versions",
        explanation: "NVD's range end and the advisory name entirely different fixed versions for the same vendor's package.",
      });
    }
  }

  if (notComparable.length + noFixListed.length > 0) {
    const examples = [...notComparable, ...noFixListed].slice(0, 3).join(", ");

    correlations.push({
      id: "fixed:not_comparable",
      topic: "fixed_version",
      scope: `${notComparable.length + noFixListed.length} package${notComparable.length + noFixListed.length === 1 ? "" : "s"}`,
      classification: "incomplete",
      reason: notComparable.length > 0
        ? "package_names_not_comparable"
        : "no_fixed_version_listed",
      explanation: `${notComparable.length} package(s) could not be confidently matched to an NVD product, and ${noFixListed.length} list no fixed version, so their fixes were not cross-checked. This is neither agreement nor conflict. Includes: ${examples}.`,
      values: [
        { source: "OSV", value: notComparable.length + noFixListed.length, evidenceId: osvEvidence.id },
      ],
    });
  }

  return correlations;
}

const CLASSIFICATION_ORDER: Record<Correlation["classification"], number> = {
  conflict: 0,
  incomplete: 1,
  explained_difference: 2,
  agreement: 3,
};

export function correlate(input: CorrelationInput): Correlation[] {
  return [
    ...correlateCvss(input),
    ...correlateSeverity(input),
    ...correlateExploitation(input),
    ...correlateRedHat(input),
    ...correlateFixedVersions(input),
  ].sort(
    (a, b) =>
      CLASSIFICATION_ORDER[a.classification] -
      CLASSIFICATION_ORDER[b.classification],
  );
}
