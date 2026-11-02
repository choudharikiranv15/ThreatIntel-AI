import {
  fetchNvdCve,
} from "./sources/nvd.js";

import {
  normalizeInvalidProviderResult,
} from "./validation.js";

import {
  fetchCisaKev,
} from "./sources/cisa-kev.js";

import {
  fetchRedHatCve,
} from "./sources/redhat.js";

import {
  verifyCvssClaim,
  type CvssClaim,
} from "./verification/index.js";

import type {
  ClaimVerification,
  Evidence,
  EvidenceConflict,
  EvidenceFactRecord,
  InferenceRecord,
  InvestigationResult,
  KevStatus,
  CvssDetails,
  ProviderResult,
  VendorImpactAssessment,
} from "./types.js";

import type {
  InvestigationProviders,
} from "./providers.js";

export interface InvestigationConfig {
  nvdApiKey?: string;
  requestTimeoutMs: number;
  signal?: AbortSignal;
  providers?: Partial<InvestigationProviders>;
}

export function verifyInvestigationCvssClaim(
  result: InvestigationResult,
  claim: CvssClaim,
): ClaimVerification {
  return verifyCvssClaim({
    claim,
    observed: result.summary.cvss,
    factProvenance: result.factProvenance,
  });
}

/* -------------------------------------------------------------------------- */
/* Helpers                                                                    */
/* -------------------------------------------------------------------------- */

function isCve(value: string): boolean {
  return /^CVE-\d{4}-\d{4,}$/i.test(
    value.trim(),
  );
}

function getString(
  object: Record<string, unknown>,
  key: string,
): string | undefined {
  const value = object[key];

  return typeof value === "string"
    ? value
    : undefined;
}

function getNumber(
  object: Record<string, unknown>,
  key: string,
): number | undefined {
  const value = object[key];

  return typeof value === "number"
    ? value
    : undefined;
}

function getNestedObject(
  object: Record<string, unknown>,
  key: string,
): Record<string, unknown> | undefined {
  const value = object[key];

  if (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value)
  ) {
    return value as Record<
      string,
      unknown
    >;
  }

  return undefined;
}

function getArray(
  object: Record<string, unknown>,
  key: string,
): unknown[] | undefined {
  const value = object[key];

  return Array.isArray(value)
    ? value
    : undefined;
}

function errorMessage(
  error: unknown,
): string {
  return error instanceof Error
    ? error.message
    : String(error);
}

function assignEvidenceId(
  cveId: string,
  evidence: Evidence,
): Evidence {
  return {
    ...evidence,
    id: `${evidence.source}:${cveId}`,
  };
}

/* -------------------------------------------------------------------------- */
/* CVSS extraction                                                            */
/* -------------------------------------------------------------------------- */

function extractCvss(
  evidence: Evidence,
): CvssDetails {
  const metrics = getNestedObject(
    evidence.facts,
    "metrics",
  );

  if (!metrics) {
    return {
      version: null,
      baseScore: null,
      vector: null,
      severity: null,
    };
  }

  /*
   * Prefer the newest CVSS version available.
   *
   * NVD can expose:
   * CVSS v4
   * CVSS v3.1
   * CVSS v3.0
   * CVSS v2
   */
  const metricNames = [
    "cvssMetricV40",
    "cvssMetricV31",
    "cvssMetricV30",
    "cvssMetricV2",
  ];

  for (
    const metricName of metricNames
  ) {
    const metricsArray =
      metrics[metricName];

    if (
      !Array.isArray(metricsArray) ||
      metricsArray.length === 0
    ) {
      continue;
    }

    /*
     * One version can hold scores from several sources (NVD, the CNA, CISA).
     * Prefer NVD's own, and report whichever source was used.
     */
    const candidates =
      metricsArray.filter(
        (metric): metric is Record<string, unknown> =>
          typeof metric === "object" &&
          metric !== null &&
          !Array.isArray(metric) &&
          getNestedObject(
            metric as Record<string, unknown>,
            "cvssData",
          ) !== undefined,
      );

    const metricObject =
      candidates.find(
        (metric) => metric.source === "nvd@nist.gov",
      ) ??
      candidates.find(
        (metric) => metric.type === "Primary",
      ) ??
      candidates[0];

    if (!metricObject) {
      continue;
    }

    const cvssData =
      getNestedObject(
        metricObject,
        "cvssData",
      ) as Record<string, unknown>;

    const version =
      getString(
        cvssData,
        "version",
      ) ?? null;

    const baseScore =
      getNumber(
        cvssData,
        "baseScore",
      ) ?? null;

    const vector =
      getString(
        cvssData,
        "vectorString",
      ) ?? null;

    /*
     * NVD sometimes provides severity
     * on the outer metric object.
     */
    const severity =
      getString(
        metricObject,
        "baseSeverity",
      ) ??
      getString(
        cvssData,
        "baseSeverity",
      ) ??
      null;

    return {
      version,
      baseScore,
      vector,
      severity,
      source:
        getString(
          metricObject,
          "source",
        ) ?? null,
    };
  }

  return {
    version: null,
    baseScore: null,
    vector: null,
    severity: null,
  };
}

/* -------------------------------------------------------------------------- */
/* CWE extraction                                                             */
/* -------------------------------------------------------------------------- */

function extractCwe(
  evidence: Evidence,
): string[] {
  const weaknesses =
    getArray(
      evidence.facts,
      "weaknesses",
    );

  if (!weaknesses) {
    return [];
  }

  const cwes = new Set<string>();

  for (
    const weakness of weaknesses
  ) {
    if (
      typeof weakness !== "object" ||
      weakness === null ||
      Array.isArray(weakness)
    ) {
      continue;
    }

    const weaknessObject =
      weakness as Record<
        string,
        unknown
      >;

    const descriptions =
      weaknessObject.description;

    if (
      !Array.isArray(descriptions)
    ) {
      continue;
    }

    for (
      const description of descriptions
    ) {
      if (
        typeof description !== "object" ||
        description === null ||
        Array.isArray(description)
      ) {
        continue;
      }

      const descriptionObject =
        description as Record<
          string,
          unknown
        >;

      const value =
        descriptionObject.value;

      if (
        typeof value === "string"
      ) {
        cwes.add(value);
      }
    }
  }

  return Array.from(cwes);
}

/* -------------------------------------------------------------------------- */
/* Affected version extraction                                               */
/* -------------------------------------------------------------------------- */

function extractAffectedVersions(
  evidence: Evidence,
): string[] {
  const configurations =
    getArray(
      evidence.facts,
      "configurations",
    );

  if (!configurations) {
    return [];
  }

  const versions = new Set<string>();

  /*
   * NVD configuration trees can be deeply nested. Only cpeMatch entries marked
   * vulnerable count: the others describe the platform a product runs on.
   * Each entry keeps its product, because a bare version is meaningless when
   * one CVE spans many vendors.
   */
  function addMatch(
    match: Record<string, unknown>,
  ): void {
    const criteria = match.criteria;

    if (
      match.vulnerable !== true ||
      typeof criteria !== "string"
    ) {
      return;
    }

    const [, , , vendor, product, version] =
      criteria.split(":");

    if (!vendor || !product) {
      return;
    }

    const constraints = [
      [">=", match.versionStartIncluding],
      [">", match.versionStartExcluding],
      ["<=", match.versionEndIncluding],
      ["<", match.versionEndExcluding],
    ]
      .filter(([, value]) => typeof value === "string")
      .map(([operator, value]) => `${operator} ${value}`);

    if (
      constraints.length === 0 &&
      version &&
      version !== "-"
    ) {
      constraints.push(
        version === "*" ? "(all versions)" : version,
      );
    }

    if (constraints.length > 0) {
      versions.add(
        `${vendor}:${product} ${constraints.join(", ")}`,
      );
    }
  }

  function walk(
    value: unknown,
  ): void {
    if (
      typeof value !== "object" ||
      value === null
    ) {
      return;
    }

    if (Array.isArray(value)) {
      value.forEach(walk);

      return;
    }

    const object =
      value as Record<
        string,
        unknown
      >;

    if (object.negate === true) {
      return;
    }

    if (Array.isArray(object.cpeMatch)) {
      for (const match of object.cpeMatch) {
        if (typeof match === "object" && match !== null) {
          addMatch(match as Record<string, unknown>);
        }
      }

      return;
    }

    Object.values(object).forEach(walk);
  }

  walk(configurations);

  return Array.from(versions);
}

/* -------------------------------------------------------------------------- */
/* Confirmed facts                                                            */
/* -------------------------------------------------------------------------- */

type TaggedFact = {
  claim: string;
  field: string;
};

function extractNvdFacts(
  cveId: string,
  evidence: Evidence,
): {
  facts: TaggedFact[];
  cvss: CvssDetails;
  cwes: string[];
  affectedVersions: string[];
} {
  const facts: TaggedFact[] = [];

  const cvss =
    extractCvss(evidence);

  const cwes =
    extractCwe(evidence);

  const affectedVersions =
    extractAffectedVersions(
      evidence,
    );

  facts.push({
    claim: `${cveId} has an authoritative NVD CVE record.`,
    field: "nvdRecord",
  });

  const vulnStatus =
    getString(
      evidence.facts,
      "vulnStatus",
    );

  if (vulnStatus) {
    facts.push({
      claim: `${cveId} NVD record status: ${vulnStatus}.`,
      field: "nvdStatus",
    });
  }

  const descriptions =
    getArray(
      evidence.facts,
      "descriptions",
    );

  if (descriptions) {
    const english =
      descriptions.find(
        (item) => {
          if (
            typeof item !== "object" ||
            item === null ||
            Array.isArray(item)
          ) {
            return false;
          }

          const object =
            item as Record<
              string,
              unknown
            >;

          return (
            object.lang === "en" &&
            typeof object.value ===
            "string"
          );
        },
      );

    if (
      english &&
      typeof english ===
      "object" &&
      !Array.isArray(english)
    ) {
      const description =
        getString(
          english as Record<
            string,
            unknown
          >,
          "value",
        );

      if (description) {
        facts.push({
          claim: `${cveId} description: ${description}`,
          field: "description",
        });
      }
    }
  }

  if (
    cvss.baseScore !== null ||
    cvss.vector !== null
  ) {
    const parts: string[] = [];

    if (cvss.version) {
      parts.push(
        `CVSS v${cvss.version}`,
      );
    }

    if (
      cvss.baseScore !== null
    ) {
      parts.push(
        `base score ${cvss.baseScore}`,
      );
    }

    if (cvss.vector) {
      parts.push(
        `vector ${cvss.vector}`,
      );
    }

    if (cvss.source) {
      parts.push(
        `scored by ${cvss.source}`,
      );
    }

    if (parts.length > 0) {
      facts.push({
        claim: `${cveId} NVD CVSS: ${parts.join(", ")}.`,
        field: "cvss",
      });
    }
  }

  if (cwes.length > 0) {
    facts.push({
      claim: `${cveId} is associated with ${cwes.join(", ")} according to NVD.`,
      field: "cwe",
    });
  }

  return {
    facts,
    cvss,
    cwes,
    affectedVersions,
  };
}

/* -------------------------------------------------------------------------- */
/* CISA facts                                                                 */
/* -------------------------------------------------------------------------- */

function extractCisaFacts(
  cveId: string,
  evidence: Evidence,
): string[] {
  const facts: string[] = [];

  const source =
    evidence.facts;

  facts.push(
    `${cveId} is listed in the CISA Known Exploited Vulnerabilities (KEV) catalog.`,
  );

  const vendor =
    getString(
      source,
      "vendorProject",
    );

  const product =
    getString(
      source,
      "product",
    );

  const vulnerabilityName =
    getString(
      source,
      "vulnerabilityName",
    );

  const dateAdded =
    getString(
      source,
      "dateAdded",
    );

  const requiredAction =
    getString(
      source,
      "requiredAction",
    );

  const ransomwareUse =
    getString(
      source,
      "knownRansomwareCampaignUse",
    );

  if (vendor || product) {
    facts.push(
      `CISA KEV identifies the affected product as ${[
        vendor,
        product,
      ]
        .filter(Boolean)
        .join(" / ")}.`,
    );
  }

  if (vulnerabilityName) {
    facts.push(
      `CISA KEV vulnerability name: ${vulnerabilityName}.`,
    );
  }

  if (dateAdded) {
    facts.push(
      `${cveId} was added to the CISA KEV catalog on ${dateAdded}.`,
    );
  }

  if (requiredAction) {
    facts.push(
      `CISA KEV required action: ${requiredAction}`,
    );
  }

  if (ransomwareUse) {
    facts.push(
      `CISA KEV ransomware campaign use field: ${ransomwareUse}.`,
    );
  }

  return facts;
}

/* -------------------------------------------------------------------------- */
/* Red Hat facts                                                              */
/* -------------------------------------------------------------------------- */

function redHatCvssScore(
  evidence: Evidence,
): number | null {
  const cvss3 =
    getNestedObject(
      evidence.facts,
      "cvss3",
    );

  const score = Number(
    cvss3?.cvss3_base_score ?? Number.NaN,
  );

  return Number.isFinite(score)
    ? score
    : null;
}

function extractRedHatFacts(
  cveId: string,
  evidence: Evidence,
): TaggedFact[] {
  const facts: TaggedFact[] = [];

  const source =
    evidence.facts;

  facts.push({
    claim: `${cveId} has a Red Hat Security Data API record.`,
    field: "redhatRecord",
  });

  const threatSeverity =
    getString(
      source,
      "threat_severity",
    );

  if (threatSeverity) {
    facts.push({
      claim: `Red Hat threat severity: ${threatSeverity}.`,
      field: "redhatSeverity",
    });
  }

  const cvssScore =
    redHatCvssScore(evidence);

  if (cvssScore !== null) {
    facts.push({
      claim: `Red Hat CVSS v3 base score: ${cvssScore}.`,
      field: "redhatCvss",
    });
  }

  const statement =
    getString(
      source,
      "statement",
    );

  if (statement) {
    facts.push({
      claim: `Red Hat statement: ${statement}`,
      field: "statement",
    });
  }

  return facts;
}

/* -------------------------------------------------------------------------- */
/* Red Hat vendor impact extraction                                           */
/* -------------------------------------------------------------------------- */

function normalizeRedHatFixState(
  fixState: string | undefined,
): {
  status: "affected" | "not_affected" | "unknown";
  reason: string;
} {
  if (!fixState) {
    return {
      status: "unknown",
      reason: "No fix_state provided",
    };
  }

  const normalized =
    fixState.trim().toLowerCase();

  /*
   * Red Hat fix_state values:
   *
   * Recognized states from the API documentation and observed values:
   * - "Affected"
   * - "Not affected"
   * - "Fix deferred"
   * - "Will not fix"
   * - "Out of support scope"
   * - "New"
   * - "Under investigation"
   */

  if (normalized === "affected") {
    return {
      status: "affected",
      reason: fixState,
    };
  }

  if (normalized === "not affected") {
    return {
      status: "not_affected",
      reason: fixState,
    };
  }

  /*
   * All other states are treated as unknown.
   *
   * This includes:
   * - "Fix deferred" (not yet fixed, but also not explicitly "affected")
   * - "Will not fix" (ambiguous - affected but won't be fixed?)
   * - "Out of support scope"
   * - "Under investigation"
   * - Any unrecognized values
   */
  return {
    status: "unknown",
    reason: fixState,
  };
}

function extractRedHatVendorImpact(
  cveId: string,
  evidence: Evidence,
): VendorImpactAssessment[] {
  const assessments: VendorImpactAssessment[] = [];

  /*
   * affected_release lists products where Red Hat shipped a fix.
   * package_state does not repeat them.
   */
  const releases =
    getArray(
      evidence.facts,
      "affected_release",
    ) ?? [];

  for (const release of releases) {
    if (
      typeof release !== "object" ||
      release === null ||
      Array.isArray(release)
    ) {
      continue;
    }

    const releaseObject =
      release as Record<string, unknown>;

    const productName =
      getString(
        releaseObject,
        "product_name",
      );

    if (!productName) {
      continue;
    }

    const advisory =
      getString(
        releaseObject,
        "advisory",
      );

    const originalStatus = advisory
      ? `Fixed by ${advisory}`
      : "Fixed";

    assessments.push({
      vendor: "Red Hat",
      productName,
      packageName:
        getString(
          releaseObject,
          "package",
        ) ?? "unspecified",
      cpe:
        getString(
          releaseObject,
          "cpe",
        ) ?? null,
      status: "fixed",
      originalStatus,
      sourceUrl: evidence.url,
      retrievedAt:
        evidence.retrievedAt,
      evidenceId: evidence.id,
      reason: originalStatus,
    });
  }

  const packageState =
    getArray(
      evidence.facts,
      "package_state",
    ) ?? [];

  for (
    const state of packageState
  ) {
    if (
      typeof state !== "object" ||
      state === null ||
      Array.isArray(state)
    ) {
      continue;
    }

    const stateObject =
      state as Record<
        string,
        unknown
      >;

    const productName =
      getString(
        stateObject,
        "product_name",
      );

    const packageName =
      getString(
        stateObject,
        "package_name",
      );

    const fixState =
      getString(
        stateObject,
        "fix_state",
      );

    const cpe =
      getString(
        stateObject,
        "cpe",
      ) ?? null;

    if (!productName || !packageName) {
      continue;
    }

    const normalized =
      normalizeRedHatFixState(
        fixState,
      );

    assessments.push({
      vendor: "Red Hat",
      productName,
      packageName,
      cpe,
      status: normalized.status,
      originalStatus:
        fixState ?? "unknown",
      sourceUrl: evidence.url,
      retrievedAt:
        evidence.retrievedAt,
      evidenceId: evidence.id,
      reason: normalized.reason,
    });
  }

  return assessments;
}

/* -------------------------------------------------------------------------- */
/* Conflicting evidence                                                       */
/* -------------------------------------------------------------------------- */

function findCvssConflicts(
  cvss: CvssDetails,
  nvdEvidence: Evidence | undefined,
  redhatEvidence: Evidence | undefined,
): EvidenceConflict[] {
  if (cvss.baseScore === null) {
    return [];
  }

  const scores = new Map<string, number>([
    [cvss.source ?? "NVD", cvss.baseScore],
  ]);

  const metrics =
    nvdEvidence
      ? getNestedObject(
        nvdEvidence.facts,
        "metrics",
      ) ?? {}
      : {};

  for (const list of Object.values(metrics)) {
    for (const metric of Array.isArray(list) ? list : []) {
      const object = (metric ?? {}) as Record<string, unknown>;

      const data =
        getNestedObject(object, "cvssData");

      const score =
        data && getNumber(data, "baseScore");

      if (
        score !== undefined &&
        data?.version === cvss.version
      ) {
        const source =
          getString(object, "source") ?? "NVD";

        if (!scores.has(source)) {
          scores.set(source, score);
        }
      }
    }
  }

  const redhatScore =
    redhatEvidence && cvss.version?.startsWith("3")
      ? redHatCvssScore(redhatEvidence)
      : null;

  if (redhatScore !== null) {
    scores.set("Red Hat", redhatScore);
  }

  if (new Set(scores.values()).size < 2) {
    return [];
  }

  return [
    {
      field: "cvss.baseScore",
      values: Array.from(
        scores,
        ([source, value]) => ({ source, value }),
      ),
    },
  ];
}

/* -------------------------------------------------------------------------- */
/* Inferences                                                                 */
/* -------------------------------------------------------------------------- */

function addInference(
  inferences: string[],
  inferenceProvenance: InferenceRecord[],
  claim: string,
  supportingFactIds: string[],
): void {
  const id =
    `inference-${inferenceProvenance.length + 1}`;

  inferences.push(claim);

  inferenceProvenance.push({
    id,
    claim,
    supportingFactIds,
  });
}

function buildInferences(
  cveId: string,
  summary: InvestigationResult["summary"],
  factProvenance: EvidenceFactRecord[],
  kevCatalogVersion: string | undefined,
): {
  inferences: string[];
  provenance: InferenceRecord[];
} {
  const inferences: string[] = [];
  const provenance: InferenceRecord[] = [];

  /*
   * These are deliberately conservative.
   *
   * They are not presented as source facts.
   */

  if (
    summary.cvss.vector?.includes(
      "AV:N",
    )
  ) {
    const supportingFactIds =
      factProvenance
        .filter((fact) =>
          fact.field === "cvss"
        )
        .map((fact) => fact.id);

    const claim =
      `${cveId} has a network attack vector according to the retrieved CVSS vector; internet-facing or remotely reachable assets should therefore receive elevated review priority.`;

    addInference(
      inferences,
      provenance,
      claim,
      supportingFactIds,
    );
  }

  if (
    summary.kevStatus ===
    "listed"
  ) {
    const supportingFactIds =
      factProvenance
        .filter((fact) =>
          fact.field === "kev" &&
          fact.claim.includes(
            "listed in the CISA Known Exploited Vulnerabilities",
          )
        )
        .map((fact) => fact.id);

    const claim =
      `${cveId} has confirmed CISA KEV inclusion, which supports prioritizing remediation and threat hunting.`;

    addInference(
      inferences,
      provenance,
      claim,
      supportingFactIds,
    );
  }

  if (
    summary.kevStatus ===
    "not-listed"
  ) {
    const claim =
      `CISA KEV${kevCatalogVersion ? ` catalog version ${kevCatalogVersion}` : ""} did not contain ${cveId} at retrieval time; this does not establish that exploitation has not occurred.`;

    addInference(
      inferences,
      provenance,
      claim,
      [],
    );
  }

  return {
    inferences,
    provenance,
  };
}

/* -------------------------------------------------------------------------- */
/* SOC guidance                                                               */
/* -------------------------------------------------------------------------- */

function buildAnalystGuidance(
  cveId: string,
  kevStatus: KevStatus,
): string[] {
  const guidance: string[] = [
    `Identify all assets where ${cveId} may be installed.`,

    "Verify installed package and library versions against affected versions documented by authoritative sources.",

    "Review operating-system, package-manager, authentication, process, and network telemetry for potentially affected systems.",

    "Prioritize internet-facing and remotely accessible systems when the retrieved CVSS evidence supports a network attack vector.",

    "Do not infer compromise solely from the presence of a vulnerable version; correlate with exploitation and host telemetry.",

    "If an affected system is confirmed, follow the relevant vendor or distribution remediation procedure.",
  ];

  if (
    kevStatus === "listed"
  ) {
    guidance.unshift(
      `${cveId} is listed in CISA KEV; prioritize remediation and threat hunting for potentially affected assets.`,
    );
  }

  if (
    kevStatus === "not-listed"
  ) {
    guidance.push(
      `${cveId} was not present in CISA KEV at retrieval time. Do not treat KEV absence as proof that the vulnerability is harmless.`,
    );
  }

  if (
    kevStatus === "unknown"
  ) {
    guidance.push(
      `CISA KEV status could not be verified during this investigation. Do not assume either listed or not-listed status.`,
    );
  }

  return guidance;
}

/* -------------------------------------------------------------------------- */
/* Provider result helpers                                                    */
/* -------------------------------------------------------------------------- */

/**
 * Converts a provider failure into an explicit investigation limitation.
 *
 * ProviderResult intentionally preserves the machine-readable state while
 * this helper creates the human-readable explanation used by the report.
 */
function providerFailureLimitation(
  result: ProviderResult,
): string | null {
  if (
    result.status !== "error" &&
    result.status !== "timeout"
  ) {
    return null;
  }

  const reason =
    result.error ??
    "Unknown provider error.";

  if (result.status === "timeout") {
    return `${result.provider} lookup timed out: ${reason}`;
  }

  return `${result.provider} lookup failed: ${reason}`;
}

/**
 * Determines whether a provider completed its check successfully.
 *
 * Both "success" and "observed_absence" mean that the provider itself
 * completed normally. "observed_absence" is therefore NOT a failure.
 */
function providerCheckCompleted(
  result: ProviderResult,
): boolean {
  return (
    result.status === "success" ||
    result.status === "observed_absence"
  );
}

function addConfirmedFact(
  confirmedFacts: string[],
  factProvenance: EvidenceFactRecord[],
  claim: string,
  evidenceId: string,
  field?: string,
): void {
  const id = `fact-${factProvenance.length + 1}`;

  confirmedFacts.push(claim);

  factProvenance.push({
    id,
    claim,
    evidenceId,
    ...(field ? { field } : {}),
  });
}

/* -------------------------------------------------------------------------- */
/* Investigation                                                              */
/* -------------------------------------------------------------------------- */

export async function investigateCve(
  target: string,
  config: InvestigationConfig,
): Promise<InvestigationResult> {
  const rawTarget =
    String(target ?? "");

  const cveId =
    rawTarget
      .trim()
      .toUpperCase();

  /*
   * Validate target.
   */
  if (!isCve(cveId)) {
    return {
      target: rawTarget,

      targetType: "cve",

      investigationType:
        "vulnerability",

      status: "failed",

      summary: {
        severity: null,

        cvss: {
          version: null,
          baseScore: null,
          vector: null,
          severity: null,
        },

        kevStatus: "unknown",

        cwe: [],

        affectedVersions: [],

        vendorImpact: [],
      },

      confirmedFacts: [],

      factProvenance: [],

      inferences: [],

      inferenceProvenance: [],

      evidence: [],

      providerResults: [],

      limitations: [
        `Unsupported target format: ${rawTarget}`,
        "Currently supported target format is CVE-YYYY-NNNN.",
      ],

      analystGuidance: [],
    };
  }

  const evidence: Evidence[] = [];

  const limitations: string[] = [];

  const coreLimitations: string[] = [];

  const confirmedFacts: string[] = [];
  const factProvenance: EvidenceFactRecord[] = [];

  /*
   * ------------------------------------------------------------------------
   * PROVIDER DEPENDENCY INJECTION
   *
   * Production uses the real NVD and CISA adapters.
   *
   * Tests can replace either provider with a deterministic fake provider.
   *
   * This keeps investigation orchestration independent from the concrete
   * implementation of external intelligence sources.
   * ------------------------------------------------------------------------
   */

  const providers: InvestigationProviders = {
    nvd: (
      cveId,
    ) =>
      fetchNvdCve(
        cveId,
        {
          apiKey:
            config.nvdApiKey,
          timeoutMs:
            config.requestTimeoutMs,
          signal: config.signal,
        },
      ),

    cisaKev: (
      cveId,
    ) =>
      fetchCisaKev(
        cveId,
        config.requestTimeoutMs,
        config.signal,
      ),

    redhat: (
      cveId,
    ) =>
      fetchRedHatCve(
        cveId,
        {
          timeoutMs:
            config.requestTimeoutMs,
          signal: config.signal,
        },
      ),

    ...config.providers,
  };

  /*
   * NVD, CISA, and Red Hat are independent sources.
   *
   * Run them concurrently so a slow source does not unnecessarily block
   * another independent source.
   *
   * Promise.allSettled provides a second defensive boundary: even if a
   * provider implementation unexpectedly throws, the investigation can
   * preserve the failure as ProviderResult instead of collapsing entirely.
   */

  const [
    nvdSettled,
    cisaSettled,
    redhatSettled,
  ] =
    await Promise.allSettled([
      providers.nvd(cveId),
      providers.cisaKev(cveId),
      providers.redhat(cveId),
    ]);

  const providerResults: ProviderResult[] = [];

  let nvdProviderResult: ProviderResult;

  if (nvdSettled.status === "fulfilled") {
    nvdProviderResult =
      normalizeInvalidProviderResult(
        nvdSettled.value,
        "NVD",
      );
  } else {
    nvdProviderResult = {
      provider: "NVD",
      status: "error",
      evidence: null,
      error:
        nvdSettled.reason instanceof Error
          ? nvdSettled.reason.message
          : String(nvdSettled.reason),
      checkedAt:
        new Date().toISOString(),
    };
  }

  let cisaProviderResult: ProviderResult;

  if (cisaSettled.status === "fulfilled") {
    cisaProviderResult =
      normalizeInvalidProviderResult(
        cisaSettled.value,
        "CISA_KEV",
      );
  } else {
    cisaProviderResult = {
      provider: "CISA_KEV",
      status: "error",
      evidence: null,
      error:
        cisaSettled.reason instanceof Error
          ? cisaSettled.reason.message
          : String(cisaSettled.reason),
      checkedAt:
        new Date().toISOString(),
    };
  }

  providerResults.push(
    nvdProviderResult,
    cisaProviderResult,
  );

  let redhatProviderResult: ProviderResult;

  if (redhatSettled.status === "fulfilled") {
    redhatProviderResult =
      normalizeInvalidProviderResult(
        redhatSettled.value,
        "REDHAT",
      );
  } else {
    redhatProviderResult = {
      provider: "REDHAT",
      status: "error",
      evidence: null,
      error:
        redhatSettled.reason instanceof Error
          ? redhatSettled.reason.message
          : String(redhatSettled.reason),
      checkedAt:
        new Date().toISOString(),
    };
  }

  providerResults.push(redhatProviderResult);

  /* ----------------------------------------------------------------------- */
  /* NVD                                                                      */
  /* ----------------------------------------------------------------------- */

  let nvdEvidence:
    | Evidence
    | undefined;

  /*
   * Only actual evidence enters the evidence collection.
   *
   * ProviderResult itself is kept separately in providerResults.
   */
  if (
    nvdProviderResult.status ===
    "success" &&
    nvdProviderResult.evidence
  ) {
    nvdEvidence = assignEvidenceId(
      cveId,
      nvdProviderResult.evidence,
    );

    evidence.push(nvdEvidence);
  }

  if (
    nvdProviderResult.status ===
    "observed_absence"
  ) {
    /*
     * A completed check, not a failure: it must not count toward "failed".
     */
    limitations.push(
      `NVD successfully responded but returned no matching record for ${cveId}.`,
    );
  }

  const nvdFailure =
    providerFailureLimitation(
      nvdProviderResult,
    );

  if (nvdFailure) {
    limitations.push(
      nvdFailure,
    );
    coreLimitations.push(
      nvdFailure,
    );
  }

  /* ----------------------------------------------------------------------- */
  /* CISA                                                                      */
  /* ----------------------------------------------------------------------- */

  let kevStatus:
    | KevStatus = "unknown";

  let cisaEvidence:
    | Evidence
    | undefined;

  /*
   * A successful CISA match means the CVE is listed.
   */
  if (
    cisaProviderResult.status ===
    "success" &&
    cisaProviderResult.evidence
  ) {
    cisaEvidence = assignEvidenceId(
      cveId,
      cisaProviderResult.evidence,
    );

    evidence.push(cisaEvidence);

    kevStatus =
      "listed";
  }

  /*
   * A successful CISA lookup with no match is an observed absence.
   *
   * This is a valid result, NOT an error.
   */
  if (
    cisaProviderResult.status ===
    "observed_absence"
  ) {
    kevStatus =
      "not-listed";
  }

  /*
   * Request failure means UNKNOWN.
   *
   * Never convert a timeout/error into "not listed".
   */
  const cisaFailure =
    providerFailureLimitation(
      cisaProviderResult,
    );

  if (cisaFailure) {
    kevStatus =
      "unknown";

    limitations.push(
      cisaFailure,
    );
    coreLimitations.push(
      cisaFailure,
    );
  }

  /* ----------------------------------------------------------------------- */
  /* Extract structured NVD intelligence                                      */
  /* ----------------------------------------------------------------------- */

  let cvss: CvssDetails = {
    version: null,
    baseScore: null,
    vector: null,
    severity: null,
  };

  let cwes: string[] = [];

  let affectedVersions: string[] =
    [];

  const nvdRejected =
    nvdEvidence?.facts.vulnStatus === "Rejected";

  if (nvdEvidence) {
    const extracted =
      extractNvdFacts(
        cveId,
        nvdEvidence,
      );

    for (const fact of extracted.facts) {
      addConfirmedFact(
        confirmedFacts,
        factProvenance,
        fact.claim,
        nvdEvidence.id,
        fact.field,
      );
    }

    cvss =
      extracted.cvss;

    cwes =
      extracted.cwes;

    affectedVersions =
      extracted.affectedVersions;

    if (nvdRejected) {
      limitations.push(
        `NVD marks ${cveId} as Rejected. Do not treat it as a valid vulnerability without checking the rejection reason.`,
      );
    }
  }

  /* ----------------------------------------------------------------------- */
  /* CISA facts                                                               */
  /* ----------------------------------------------------------------------- */

  if (cisaEvidence) {
    for (const fact of extractCisaFacts(
      cveId,
      cisaEvidence,
    )) {
      addConfirmedFact(
        confirmedFacts,
        factProvenance,
        fact,
        cisaEvidence.id,
        "kev",
      );
    }
  }

  /* ----------------------------------------------------------------------- */
  /* Red Hat                                                                  */
  /* ----------------------------------------------------------------------- */

  let redhatEvidence:
    | Evidence
    | undefined;

  if (
    redhatProviderResult.status ===
    "success" &&
    redhatProviderResult.evidence
  ) {
    redhatEvidence = assignEvidenceId(
      cveId,
      redhatProviderResult.evidence,
    );

    evidence.push(redhatEvidence);
  }

  const redhatFailure =
    providerFailureLimitation(
      redhatProviderResult,
    );

  if (redhatFailure) {
    limitations.push(
      redhatFailure,
    );
  }

  /* ----------------------------------------------------------------------- */
  /* Vendor impact extraction                                                 */
  /* ----------------------------------------------------------------------- */

  const vendorImpact =
    redhatEvidence
      ? extractRedHatVendorImpact(
        cveId,
        redhatEvidence,
      )
      : [];

  if (redhatEvidence) {
    for (const fact of extractRedHatFacts(
      cveId,
      redhatEvidence,
    )) {
      addConfirmedFact(
        confirmedFacts,
        factProvenance,
        fact.claim,
        redhatEvidence.id,
        fact.field,
      );
    }
  }

  /* ----------------------------------------------------------------------- */
  /* Summary                                                                  */
  /* ----------------------------------------------------------------------- */

  const severity =
    cvss.severity ??
    (
      cvss.baseScore !== null
        ? scoreToSeverity(
          cvss.baseScore,
        )
        : null
    );

  const summary:
    InvestigationResult["summary"] =
  {
    severity,

    cvss: {
      ...cvss,
      severity,
    },

    kevStatus,

    cwe: cwes,

    affectedVersions,

    vendorImpact,

    conflicts:
      findCvssConflicts(
        cvss,
        nvdEvidence,
        redhatEvidence,
      ),
  };

  /* ----------------------------------------------------------------------- */
  /* Inferences                                                               */
  /* ----------------------------------------------------------------------- */

  const inferenceResult =
    buildInferences(
      cveId,
      summary,
      factProvenance,
      cisaProviderResult.catalogVersion,
    );

  const inferences =
    inferenceResult.inferences;

  const inferenceProvenance =
    inferenceResult.provenance;

  /* ----------------------------------------------------------------------- */
  /* Status                                                                   */
  /* ----------------------------------------------------------------------- */

  const nvdCompleted =
    providerCheckCompleted(
      nvdProviderResult,
    );

  const cisaCompleted =
    providerCheckCompleted(
      cisaProviderResult,
    );

  const hasNvdEvidence =
    Boolean(nvdEvidence);

  const hasCisaEvidence =
    Boolean(cisaEvidence);

  let status:
    InvestigationResult["status"];

  /*
   * CONFIRMED
   *
   * NVD returned a valid record and CISA completed its check.
   *
   * CISA observed absence counts as a completed check. It should NOT force
   * the whole investigation into "partial" merely because there is no KEV
   * record.
   *
   * Red Hat enrichment failures do NOT affect the core investigation status.
   *
   * Example:
   *
   * NVD = success
   * CISA = observed_absence
   * Red Hat = error
   *
   * => confirmed
   */
  if (
    hasNvdEvidence &&
    !nvdRejected &&
    nvdCompleted &&
    cisaCompleted
  ) {
    status =
      "confirmed";
  }

  /*
   * PARTIAL
   *
   * At least one provider returned usable evidence, but the complete
   * investigation could not be fully established.
   *
   * Examples:
   *
   * NVD success + CISA timeout
   * NVD success + CISA error
   * NVD observed absence + CISA listed
   * NVD record marked Rejected
   */
  else if (
    hasNvdEvidence ||
    hasCisaEvidence
  ) {
    status =
      "partial";
  }

  /*
   * FAILED
   *
   * No usable evidence was returned and one or more core provider failures
   * occurred.
   */
  else if (
    coreLimitations.length > 0
  ) {
    status =
      "failed";
  }

  /*
   * NOT FOUND
   *
   * Both authoritative providers completed successfully but neither
   * produced evidence.
   *
   * In practice this generally means NVD observed absence and CISA
   * observed absence.
   */
  else {
    status =
      "not-found";
  }

  /* ----------------------------------------------------------------------- */
  /* SOC guidance                                                             */
  /* ----------------------------------------------------------------------- */

  const analystGuidance =
    status === "not-found"
      ? [
        `${cveId} was not found in NVD or CISA KEV. Check the identifier for typos; a recently assigned CVE may not be published yet.`,
        "Do not treat this result as evidence that the identifier is harmless.",
      ]
      : buildAnalystGuidance(
        cveId,
        kevStatus,
      );

  if (nvdRejected) {
    analystGuidance.unshift(
      `NVD marks ${cveId} as Rejected; confirm the rejection reason before acting on the guidance below.`,
    );
  }

  /* ----------------------------------------------------------------------- */
  /* Final result                                                             */
  /* ----------------------------------------------------------------------- */

  return {
    target: cveId,

    targetType: "cve",

    investigationType:
      "vulnerability",

    status,

    summary,

    confirmedFacts,

    factProvenance,

    inferences,

    inferenceProvenance,

    evidence,

    providerResults,

    limitations,

    analystGuidance,
  };
}

/* -------------------------------------------------------------------------- */
/* CVSS severity fallback                                                      */
/* -------------------------------------------------------------------------- */

function scoreToSeverity(
  score: number,
): string {
  if (score >= 9.0) {
    return "CRITICAL";
  }

  if (score >= 7.0) {
    return "HIGH";
  }

  if (score >= 4.0) {
    return "MEDIUM";
  }

  if (score > 0) {
    return "LOW";
  }

  return "NONE";
}