import { fetchNvdCve } from "./sources/nvd.js";
import { fetchCisaKev } from "./sources/cisa-kev.js";

export interface InvestigationConfig {
  nvdApiKey?: string;
  requestTimeoutMs: number;
}

export interface EvidenceItem {
  source: string;
  retrievedAt: string;
  url: string;
  title: string;
  facts: Record<string, unknown>;
}

export interface InvestigationResult {
  target: string;

  /**
   * confirmed:
   *   A valid CVE record was found and authoritative evidence was collected.
   *
   * partial:
   *   At least one authoritative source responded, but some requested
   *   evidence could not be collected.
   *
   * not-found:
   *   No authoritative source returned a record for the CVE.
   *
   * failed:
   *   The investigation could not be meaningfully performed.
   */
  status: "confirmed" | "not-found" | "partial" | "failed";

  evidence: EvidenceItem[];

  /**
   * Facts directly derived from retrieved evidence.
   * These should not contain unsupported assumptions.
   */
  findings: string[];

  /**
   * Problems encountered while collecting evidence.
   */
  limitations: string[];

  /**
   * Conservative SOC recommendations.
   */
  analystGuidance: string[];
}

function isCve(value: string): boolean {
  return /^CVE-\d{4}-\d{4,}$/i.test(value.trim());
}

function getString(
  object: Record<string, unknown>,
  key: string
): string | undefined {
  const value = object[key];

  return typeof value === "string" ? value : undefined;
}

function getNestedObject(
  object: Record<string, unknown>,
  key: string
): Record<string, unknown> | undefined {
  const value = object[key];

  if (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value)
  ) {
    return value as Record<string, unknown>;
  }

  return undefined;
}

function extractNvdFindings(
  cveId: string,
  evidence: EvidenceItem
): string[] {
  const findings: string[] = [];
  const facts = evidence.facts;

  /*
   * NVD 2.0 stores the actual CVE information under:
   *
   * cve
   *   ├── id
   *   ├── descriptions
   *   ├── metrics
   *   ├── weaknesses
   *   └── configurations
   *
   * Our NVD source stores that CVE object directly in facts.
   */

  const descriptions = facts["descriptions"];

  if (Array.isArray(descriptions)) {
    const englishDescription = descriptions.find((item) => {
      if (
        typeof item !== "object" ||
        item === null ||
        Array.isArray(item)
      ) {
        return false;
      }

      const entry = item as Record<string, unknown>;

      return (
        entry.lang === "en" &&
        typeof entry.value === "string"
      );
    });

    if (
      englishDescription &&
      typeof englishDescription === "object" &&
      !Array.isArray(englishDescription)
    ) {
      const description = getString(
        englishDescription as Record<string, unknown>,
        "value"
      );

      if (description) {
        findings.push(
          `${cveId} description: ${description}`
        );
      }
    }
  }

  /*
   * Extract CVSS information.
   *
   * NVD may expose CVSS v4, v3.1, v3.0, or v2 depending on the CVE.
   */
  const metrics = getNestedObject(facts, "metrics");

  if (metrics) {
    const metricCandidates = [
      "cvssMetricV40",
      "cvssMetricV31",
      "cvssMetricV30",
      "cvssMetricV2"
    ];

    for (const metricName of metricCandidates) {
      const metric = metrics[metricName];

      if (!Array.isArray(metric) || metric.length === 0) {
        continue;
      }

      const firstMetric = metric[0];

      if (
        typeof firstMetric !== "object" ||
        firstMetric === null ||
        Array.isArray(firstMetric)
      ) {
        continue;
      }

      const metricObject =
        firstMetric as Record<string, unknown>;

      const cvssData = getNestedObject(
        metricObject,
        "cvssData"
      );

      if (!cvssData) {
        continue;
      }

      const baseScore = cvssData["baseScore"];
      const vectorString = cvssData["vectorString"];
      const version = cvssData["version"];

      const details: string[] = [];

      if (typeof version === "string") {
        details.push(`CVSS v${version}`);
      }

      if (typeof baseScore === "number") {
        details.push(`base score ${baseScore}`);
      }

      if (typeof vectorString === "string") {
        details.push(`vector ${vectorString}`);
      }

      if (details.length > 0) {
        findings.push(
          `${cveId} NVD severity metrics: ${details.join(", ")}.`
        );
      }

      break;
    }
  }

  /*
   * Extract CWE information.
   */
  const weaknesses = facts["weaknesses"];

  if (Array.isArray(weaknesses)) {
    const cwes = new Set<string>();

    for (const weakness of weaknesses) {
      if (
        typeof weakness !== "object" ||
        weakness === null ||
        Array.isArray(weakness)
      ) {
        continue;
      }

      const weaknessObject =
        weakness as Record<string, unknown>;

      const descriptions =
        weaknessObject["description"];

      if (!Array.isArray(descriptions)) {
        continue;
      }

      for (const description of descriptions) {
        if (
          typeof description !== "object" ||
          description === null ||
          Array.isArray(description)
        ) {
          continue;
        }

        const descriptionObject =
          description as Record<string, unknown>;

        const value = descriptionObject["value"];

        if (typeof value === "string") {
          cwes.add(value);
        }
      }
    }

    if (cwes.size > 0) {
      findings.push(
        `${cveId} is associated with ${Array.from(cwes).join(", ")} according to NVD.`
      );
    }
  }

  return findings;
}

function extractCisaKevFindings(
  cveId: string,
  evidence: EvidenceItem
): string[] {
  const findings: string[] = [];

  const facts = evidence.facts;

  const vendorProject = getString(
    facts,
    "vendorProject"
  );

  const product = getString(facts, "product");

  const vulnerabilityName = getString(
    facts,
    "vulnerabilityName"
  );

  const dateAdded = getString(
    facts,
    "dateAdded"
  );

  const requiredAction = getString(
    facts,
    "requiredAction"
  );

  const ransomwareUse = getString(
    facts,
    "knownRansomwareCampaignUse"
  );

  findings.push(
    `${cveId} is listed in the CISA Known Exploited Vulnerabilities (KEV) catalog.`
  );

  if (vendorProject || product) {
    const affectedComponent = [
      vendorProject,
      product
    ]
      .filter(Boolean)
      .join(" / ");

    findings.push(
      `CISA KEV identifies the affected product as ${affectedComponent}.`
    );
  }

  if (vulnerabilityName) {
    findings.push(
      `CISA KEV vulnerability name: ${vulnerabilityName}.`
    );
  }

  if (dateAdded) {
    findings.push(
      `${cveId} was added to the CISA KEV catalog on ${dateAdded}.`
    );
  }

  if (requiredAction) {
    findings.push(
      `CISA KEV required action: ${requiredAction}`
    );
  }

  if (ransomwareUse) {
    findings.push(
      `CISA KEV ransomware campaign use field: ${ransomwareUse}.`
    );
  }

  return findings;
}

function buildAnalystGuidance(
  cveId: string,
  isKevListed: boolean
): string[] {
  const guidance: string[] = [
    `Identify all assets where ${cveId} may be installed.`,
    "Verify the installed package and library versions against the affected versions documented by authoritative vendors.",
    "Review operating-system, package-manager, authentication, process, and network telemetry.",
    "Prioritize internet-facing and remotely accessible systems.",
  ];

  if (isKevListed) {
    guidance.unshift(
      `${cveId} is present in CISA KEV; prioritize remediation and threat-hunting for potentially affected assets.`
    );
  }

  guidance.push(
    "If an affected system is confirmed, follow the relevant vendor or distribution remediation procedure.",
    "Do not treat absence from CISA KEV as proof that a vulnerability is harmless.",
    "Do not infer compromise solely from the presence of a vulnerable version; correlate with exploitation and host telemetry."
  );

  return guidance;
}

export async function investigateCve(
  target: string,
  config: InvestigationConfig
): Promise<InvestigationResult> {
  const rawTarget = String(target ?? "");
  const cveId = rawTarget.trim().toUpperCase();

  /*
   * Input validation.
   */
  if (!isCve(cveId)) {
    return {
      target: rawTarget,
      status: "failed",
      evidence: [],
      findings: [],
      limitations: [
        `Unsupported target format: ${rawTarget}`,
        "Currently supported target format is CVE-YYYY-NNNN."
      ],
      analystGuidance: []
    };
  }

  const evidence: EvidenceItem[] = [];
  const limitations: string[] = [];
  const findings: string[] = [];

  /*
   * ---------------------------------------------------------
   * NVD
   * ---------------------------------------------------------
   */
  try {
    const nvd = await fetchNvdCve(cveId, {
      apiKey: config.nvdApiKey,
      timeoutMs: config.requestTimeoutMs
    });

    if (nvd) {
      evidence.push(nvd);

      findings.push(
        `${cveId} has an authoritative NVD CVE record.`
      );

      findings.push(
        ...extractNvdFindings(cveId, nvd)
      );
    } else {
      limitations.push(
        `NVD returned no matching record for ${cveId}.`
      );
    }
  } catch (error) {
    limitations.push(
      `NVD lookup failed: ${error instanceof Error
        ? error.message
        : String(error)
      }`
    );
  }

  /*
   * ---------------------------------------------------------
   * CISA KEV
   * ---------------------------------------------------------
   */
  let isKevListed = false;

  try {
    const kev = await fetchCisaKev(
      cveId,
      config.requestTimeoutMs
    );

    if (kev) {
      isKevListed = true;

      evidence.push(kev);

      findings.push(
        ...extractCisaKevFindings(cveId, kev)
      );
    } else {
      findings.push(
        `${cveId} was not found in the CISA Known Exploited Vulnerabilities catalog at retrieval time.`
      );
    }
  } catch (error) {
    limitations.push(
      `CISA KEV lookup failed: ${error instanceof Error
        ? error.message
        : String(error)
      }`
    );
  }

  /*
   * ---------------------------------------------------------
   * Determine status
   * ---------------------------------------------------------
   *
   * IMPORTANT:
   *
   * "confirmed" means an authoritative CVE record exists.
   * It does NOT mean that two sources responded.
   *
   * If CISA succeeds but NVD fails, we return partial.
   */
  let status: InvestigationResult["status"];

  const hasNvdEvidence = evidence.some(
    (item) => item.source === "NVD"
  );

  const hasKevEvidence = evidence.some(
    (item) => item.source === "CISA KEV"
  );

  if (hasNvdEvidence && hasKevEvidence) {
    status = "confirmed";
  } else if (hasNvdEvidence || hasKevEvidence) {
    status = limitations.length > 0
      ? "partial"
      : "confirmed";
  } else if (limitations.length > 0) {
    status = "failed";
  } else {
    status = "not-found";
  }

  /*
   * ---------------------------------------------------------
   * SOC guidance
   * ---------------------------------------------------------
   */
  const analystGuidance = buildAnalystGuidance(
    cveId,
    isKevListed
  );

  /*
   * ---------------------------------------------------------
   * Final result
   * ---------------------------------------------------------
   */
  return {
    target: cveId,
    status,
    evidence,
    findings,
    limitations,
    analystGuidance
  };
}