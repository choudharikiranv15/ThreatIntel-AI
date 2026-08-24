import type { Evidence } from "../types.js";

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

export async function fetchCisaKev(
  cveId: string,
  timeoutMs: number,
): Promise<Evidence | null> {
  const normalized =
    cveId.trim().toUpperCase();

  const response = await fetch(
    KEV_URL,
    {
      method: "GET",

      headers: {
        Accept: "application/json",
        "User-Agent":
          "ThreatIntel-AI-Engine/0.2.0",
      },

      signal: AbortSignal.timeout(timeoutMs),
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
   * IMPORTANT:
   *
   * null means:
   *
   * "CISA successfully checked the catalog,
   * and the CVE was not present."
   *
   * It does NOT mean:
   *
   * "CISA failed."
   */
  if (!entry) {
    return null;
  }

  const retrievedAt =
    new Date().toISOString();

  return {
    source: "CISA_KEV",

    retrievedAt,

    url: KEV_URL,

    title:
      `CISA KEV Entry - ${normalized}`,

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
  };
}