import type {
  Evidence,
  ProviderResult,
} from "../types.js";

interface CisaKevEntry {
  cveID?: string;
  vendorProject?: string;
  product?: string;
  vulnerabilityName?: string;
  dateAdded?: string;
  shortDescription?: string;
  requiredAction?: string;
  dueDate?: string;
  knownRansomwareCampaignUse?: string;
  notes?: string;
}

interface CisaKevCatalog {
  title?: string;
  catalogVersion?: string;
  dateReleased?: string;
  count?: number;
  vulnerabilities?: CisaKevEntry[];
}

export const KEV_URL =
  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

function isTimeoutError(
  error: unknown,
): boolean {
  return (
    error instanceof DOMException &&
    error.name === "TimeoutError"
  );
}

export async function fetchCisaKev(
  cveId: string,
  timeoutMs: number,
): Promise<ProviderResult> {
  const normalized =
    cveId.trim().toUpperCase();

  const checkedAt =
    new Date().toISOString();

  try {
    const response = await fetch(
      KEV_URL,
      {
        method: "GET",

        headers: {
          Accept: "application/json",
          "User-Agent":
            "ThreatIntel-AI-Engine/0.3.0",
        },

        signal:
          AbortSignal.timeout(timeoutMs),
      },
    );

    if (!response.ok) {
      let body = "";

      try {
        body = await response.text();
      } catch {
        // Ignore response-body parsing failures.
      }

      const suffix = body
        ? ` - ${body.slice(0, 300)}`
        : "";

      throw new Error(
        `CISA KEV request failed: HTTP ${response.status} ${response.statusText}${suffix}`,
      );
    }

    const catalog =
      (await response.json()) as CisaKevCatalog;

    if (
      !Array.isArray(
        catalog.vulnerabilities,
      )
    ) {
      throw new Error(
        "CISA KEV response did not contain a vulnerabilities array.",
      );
    }

    const entry =
      catalog.vulnerabilities.find(
        (item) =>
          typeof item.cveID === "string" &&
          item.cveID.toUpperCase() === normalized,
      );

    /*
     * Successful lookup + no matching entry
     * is an OBSERVED ABSENCE.
     *
     * It does NOT mean:
     *
     * "not exploited"
     * "safe"
     * "no active exploitation"
     */
    if (!entry) {
      return {
        provider: "CISA_KEV",
        status: "observed_absence",
        evidence: null,
        error: null,
        checkedAt,
      };
    }

    const evidence: Evidence = {
      source: "CISA_KEV",

      sourceType: "primary",

      retrievedAt: checkedAt,

      url: KEV_URL,

      title:
        `CISA KEV Entry - ${normalized}`,

      confidence: "high",

      facts: {
        cveID: entry.cveID,
        vendorProject:
          entry.vendorProject,
        product:
          entry.product,
        vulnerabilityName:
          entry.vulnerabilityName,
        dateAdded:
          entry.dateAdded,
        shortDescription:
          entry.shortDescription,
        requiredAction:
          entry.requiredAction,
        dueDate:
          entry.dueDate,
        knownRansomwareCampaignUse:
          entry.knownRansomwareCampaignUse,
        notes:
          entry.notes,
      },

      extractedFacts: [],

      references: [],
    };

    return {
      provider: "CISA_KEV",
      status: "success",
      evidence,
      error: null,
      checkedAt,
    };
  } catch (error) {
    const timeout =
      isTimeoutError(error);

    return {
      provider: "CISA_KEV",
      status: timeout
        ? "timeout"
        : "error",
      evidence: null,
      error:
        error instanceof Error
          ? error.message
          : String(error),
      checkedAt,
    };
  }
}