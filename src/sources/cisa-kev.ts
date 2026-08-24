export interface CisaKevResult {
  source: "CISA KEV";
  retrievedAt: string;
  url: string;
  title: string;
  facts: Record<string, unknown>;
}

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

const KEV_URL =
  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

export async function fetchCisaKev(
  cveId: string,
  timeoutMs: number
): Promise<CisaKevResult | null> {
  const normalized =
    cveId.trim().toUpperCase();

  const response = await fetch(
    KEV_URL,
    {
      method: "GET",

      headers: {
        Accept: "application/json",
        "User-Agent":
          "ThreatIntel-AI-Engine/0.1.0"
      },

      signal:
        AbortSignal.timeout(timeoutMs)
    }
  );

  if (!response.ok) {
    throw new Error(
      `CISA KEV request failed: HTTP ${response.status} ${response.statusText}`
    );
  }

  const catalog =
    (await response.json()) as CisaKevCatalog;

  if (
    !Array.isArray(
      catalog.vulnerabilities
    )
  ) {
    throw new Error(
      "CISA KEV response did not contain a vulnerabilities array."
    );
  }

  const entry =
    catalog.vulnerabilities.find(
      (item) =>
        typeof item.cveID === "string" &&
        item.cveID.toUpperCase() === normalized
    );

  if (!entry) {
    return null;
  }

  const retrievedAt =
    new Date().toISOString();

  return {
    source: "CISA KEV",

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
        entry.notes
    }
  };
}