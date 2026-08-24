import {
  fetchNvdCve,
} from "./sources/nvd.js";

import {
  fetchCisaKev,
} from "./sources/cisa-kev.js";

import type {
  Evidence,
  InvestigationResult,
  KevStatus,
  CvssDetails,
} from "./types.js";

export interface InvestigationConfig {
  nvdApiKey?: string;
  requestTimeoutMs: number;
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

    const firstMetric =
      metricsArray[0];

    if (
      typeof firstMetric !== "object" ||
      firstMetric === null ||
      Array.isArray(firstMetric)
    ) {
      continue;
    }

    const metricObject =
      firstMetric as Record<
        string,
        unknown
      >;

    const cvssData =
      getNestedObject(
        metricObject,
        "cvssData",
      );

    if (!cvssData) {
      continue;
    }

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
   * NVD configuration trees can be deeply nested.
   *
   * We recursively inspect nodes and collect
   * explicit versionStart/versionEnd fields.
   */
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
      for (const item of value) {
        walk(item);
      }

      return;
    }

    const object =
      value as Record<
        string,
        unknown
      >;

    const versionStartIncluding =
      object.versionStartIncluding;

    const versionStartExcluding =
      object.versionStartExcluding;

    const versionEndIncluding =
      object.versionEndIncluding;

    const versionEndExcluding =
      object.versionEndExcluding;

    if (
      typeof versionStartIncluding ===
      "string"
    ) {
      versions.add(
        `>= ${versionStartIncluding}`,
      );
    }

    if (
      typeof versionStartExcluding ===
      "string"
    ) {
      versions.add(
        `> ${versionStartExcluding}`,
      );
    }

    if (
      typeof versionEndIncluding ===
      "string"
    ) {
      versions.add(
        `<= ${versionEndIncluding}`,
      );
    }

    if (
      typeof versionEndExcluding ===
      "string"
    ) {
      versions.add(
        `< ${versionEndExcluding}`,
      );
    }

    /*
     * CPE 2.3 version field.
     */
    const cpeMatch =
      object.cpe23Uri;

    if (
      typeof cpeMatch === "string"
    ) {
      const match =
        cpeMatch.match(
          /^cpe:2\.3:[^:]+:[^:]+:[^:]+:([^:]+):/,
        );

      if (match?.[1]) {
        versions.add(
          match[1],
        );
      }
    }

    for (
      const child of Object.values(
        object,
      )
    ) {
      walk(child);
    }
  }

  for (
    const configuration of configurations
  ) {
    walk(configuration);
  }

  return Array.from(versions);
}

/* -------------------------------------------------------------------------- */
/* Confirmed facts                                                            */
/* -------------------------------------------------------------------------- */

function extractNvdFacts(
  cveId: string,
  evidence: Evidence,
): {
  facts: string[];
  cvss: CvssDetails;
  cwes: string[];
  affectedVersions: string[];
} {
  const facts: string[] = [];

  const cvss =
    extractCvss(evidence);

  const cwes =
    extractCwe(evidence);

  const affectedVersions =
    extractAffectedVersions(
      evidence,
    );

  facts.push(
    `${cveId} has an authoritative NVD CVE record.`,
  );

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
        facts.push(
          `${cveId} description: ${description}`,
        );
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

    if (parts.length > 0) {
      facts.push(
        `${cveId} NVD CVSS: ${parts.join(", ")}.`,
      );
    }
  }

  if (cwes.length > 0) {
    facts.push(
      `${cveId} is associated with ${cwes.join(", ")} according to NVD.`,
    );
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
/* Inferences                                                                 */
/* -------------------------------------------------------------------------- */

function buildInferences(
  cveId: string,
  summary: InvestigationResult["summary"],
): string[] {
  const inferences: string[] = [];

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
    inferences.push(
      `${cveId} has a network attack vector according to the retrieved CVSS vector; internet-facing or remotely reachable assets should therefore receive elevated review priority.`,
    );
  }

  if (
    summary.kevStatus ===
    "listed"
  ) {
    inferences.push(
      `${cveId} has confirmed CISA KEV inclusion, which supports prioritizing remediation and threat hunting.`,
    );
  }

  if (
    summary.kevStatus ===
    "not-listed"
  ) {
    inferences.push(
      `CISA KEV did not contain ${cveId} at retrieval time; this does not establish that exploitation has not occurred.`,
    );
  }

  return inferences;
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
      },

      confirmedFacts: [],

      inferences: [],

      evidence: [],

      limitations: [
        `Unsupported target format: ${rawTarget}`,
        "Currently supported target format is CVE-YYYY-NNNN.",
      ],

      analystGuidance: [],
    };
  }

  const evidence: Evidence[] = [];

  const limitations: string[] = [];

  const confirmedFacts: string[] = [];

  /*
   * ------------------------------------------------------------------------
   * IMPORTANT PERFORMANCE FIX
   *
   * NVD and CISA are independent.
   *
   * They must NOT run sequentially.
   * ------------------------------------------------------------------------
   */

  const [
    nvdResult,
    cisaResult,
  ] = await Promise.allSettled([
    fetchNvdCve(
      cveId,
      {
        apiKey:
          config.nvdApiKey,
        timeoutMs:
          config.requestTimeoutMs,
      },
    ),

    fetchCisaKev(
      cveId,
      config.requestTimeoutMs,
    ),
  ]);

  /* ----------------------------------------------------------------------- */
  /* NVD                                                                      */
  /* ----------------------------------------------------------------------- */

  let nvdEvidence:
    | Evidence
    | undefined;

  if (
    nvdResult.status ===
    "fulfilled"
  ) {
    if (nvdResult.value) {
      nvdEvidence =
        nvdResult.value;

      evidence.push(
        nvdEvidence,
      );
    } else {
      limitations.push(
        `NVD successfully responded but returned no matching record for ${cveId}.`,
      );
    }
  } else {
    limitations.push(
      `NVD lookup failed: ${errorMessage(nvdResult.reason)}`,
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

  if (
    cisaResult.status ===
    "fulfilled"
  ) {
    if (cisaResult.value) {
      cisaEvidence =
        cisaResult.value;

      evidence.push(
        cisaEvidence,
      );

      kevStatus = "listed";
    } else {
      /*
       * This is NOT an error.
       *
       * The catalog was successfully checked
       * and the CVE was absent.
       */
      kevStatus =
        "not-listed";

      confirmedFacts.push(
        `${cveId} was not found in the CISA Known Exploited Vulnerabilities catalog at retrieval time.`,
      );
    }
  } else {
    /*
     * Request failure means UNKNOWN.
     *
     * Never convert a timeout/error into "not listed".
     */
    kevStatus =
      "unknown";

    limitations.push(
      `CISA KEV lookup failed: ${errorMessage(cisaResult.reason)}`,
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

  if (nvdEvidence) {
    const extracted =
      extractNvdFacts(
        cveId,
        nvdEvidence,
      );

    confirmedFacts.push(
      ...extracted.facts,
    );

    cvss =
      extracted.cvss;

    cwes =
      extracted.cwes;

    affectedVersions =
      extracted.affectedVersions;
  }

  /* ----------------------------------------------------------------------- */
  /* CISA facts                                                               */
  /* ----------------------------------------------------------------------- */

  if (cisaEvidence) {
    confirmedFacts.push(
      ...extractCisaFacts(
        cveId,
        cisaEvidence,
      ),
    );
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

  const summary: InvestigationResult["summary"] =
  {
    severity,

    cvss: {
      ...cvss,
      severity,
    },

    kevStatus,

    cwe: cwes,

    affectedVersions,
  };

  /* ----------------------------------------------------------------------- */
  /* Inferences                                                               */
  /* ----------------------------------------------------------------------- */

  const inferences =
    buildInferences(
      cveId,
      summary,
    );

  /* ----------------------------------------------------------------------- */
  /* Status                                                                   */
  /* ----------------------------------------------------------------------- */

  const hasNvdEvidence =
    Boolean(nvdEvidence);

  const hasCisaEvidence =
    Boolean(cisaEvidence);

  let status:
    InvestigationResult["status"];

  if (
    hasNvdEvidence &&
    hasCisaEvidence &&
    limitations.length === 0
  ) {
    status = "confirmed";
  } else if (
    hasNvdEvidence ||
    hasCisaEvidence
  ) {
    status = "partial";
  } else if (
    limitations.length > 0
  ) {
    status = "failed";
  } else {
    status = "not-found";
  }

  /* ----------------------------------------------------------------------- */
  /* SOC guidance                                                             */
  /* ----------------------------------------------------------------------- */

  const analystGuidance =
    buildAnalystGuidance(
      cveId,
      kevStatus,
    );

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

    inferences,

    evidence,

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