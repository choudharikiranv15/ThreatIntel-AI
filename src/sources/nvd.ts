import type { Evidence } from "../types.js";

export interface NvdOptions {
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

function createTimeoutSignal(timeoutMs: number): AbortSignal {
  return AbortSignal.timeout(timeoutMs);
}

export async function fetchNvdCve(
  cveId: string,
  options: NvdOptions,
): Promise<Evidence | null> {
  const normalized = cveId.trim().toUpperCase();

  const url =
    "https://services.nvd.nist.gov/rest/json/cves/2.0?" +
    `cveId=${encodeURIComponent(normalized)}`;

  const headers: Record<string, string> = {
    Accept: "application/json",
    "User-Agent": "ThreatIntel-AI-Engine/0.2.0",
  };

  if (
    options.apiKey &&
    options.apiKey.trim().length > 0
  ) {
    headers.apiKey = options.apiKey.trim();
  }

  const response = await fetch(url, {
    method: "GET",
    headers,
    signal: createTimeoutSignal(options.timeoutMs),
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
      `NVD request failed: HTTP ${response.status} ${response.statusText}${suffix}`,
    );
  }

  const data = (await response.json()) as NvdResponse;

  const vulnerability =
    data.vulnerabilities?.[0]?.cve;

  if (!vulnerability) {
    return null;
  }

  /*
   * Defensive verification:
   *
   * Never trust the first returned record blindly.
   */
  const returnedId = vulnerability.id;

  if (
    typeof returnedId !== "string" ||
    returnedId.toUpperCase() !== normalized
  ) {
    throw new Error(
      `NVD returned unexpected CVE ${String(returnedId)} for requested ${normalized}`,
    );
  }

  return {
    source: "NVD",

    retrievedAt: new Date().toISOString(),

    url,

    title: `NVD CVE Record - ${normalized}`,

    facts: vulnerability,
  };
}