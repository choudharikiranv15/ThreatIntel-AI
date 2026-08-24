export interface NvdCveResult {
  source: "NVD";
  retrievedAt: string;
  url: string;
  title: string;
  facts: Record<string, unknown>;
}

interface NvdOptions {
  apiKey?: string;
  timeoutMs: number;
}

interface NvdResponse {
  resultsPerPage?: number;
  startIndex?: number;
  totalResults?: number;

  vulnerabilities?: Array<{
    cve?: Record<string, unknown>;
  }>;
}

function createTimeoutSignal(
  timeoutMs: number
): AbortSignal {
  return AbortSignal.timeout(timeoutMs);
}

export async function fetchNvdCve(
  cveId: string,
  options: NvdOptions
): Promise<NvdCveResult | null> {
  const normalized = cveId
    .trim()
    .toUpperCase();

  const url =
    "https://services.nvd.nist.gov/rest/json/cves/2.0?" +
    `cveId=${encodeURIComponent(normalized)}`;

  const headers: Record<string, string> = {
    Accept: "application/json",
    "User-Agent": "ThreatIntel-AI-Engine/0.1.0"
  };

  /*
   * NVD accepts the API key through the apiKey header.
   */
  if (
    options.apiKey &&
    options.apiKey.trim().length > 0
  ) {
    headers["apiKey"] = options.apiKey.trim();
  }

  const response = await fetch(url, {
    method: "GET",
    headers,
    signal: createTimeoutSignal(
      options.timeoutMs
    )
  });

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
      `NVD request failed: HTTP ${response.status} ${response.statusText}${suffix}`
    );
  }

  const data =
    (await response.json()) as NvdResponse;

  /*
   * NVD returns:
   *
   * {
   *   vulnerabilities: [
   *     {
   *       cve: {...}
   *     }
   *   ]
   * }
   */
  const vulnerability =
    data.vulnerabilities?.[0]?.cve;

  if (!vulnerability) {
    return null;
  }

  /*
   * Verify that the returned record actually belongs
   * to the requested CVE.
   */
  const returnedId = vulnerability["id"];

  if (
    typeof returnedId === "string" &&
    returnedId.toUpperCase() !== normalized
  ) {
    throw new Error(
      `NVD returned unexpected CVE ${returnedId} for requested ${normalized}`
    );
  }

  return {
    source: "NVD",

    retrievedAt:
      new Date().toISOString(),

    url,

    title:
      `NVD CVE Record - ${normalized}`,

    facts: vulnerability
  };
}