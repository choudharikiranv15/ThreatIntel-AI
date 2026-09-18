import type {
  Evidence,
  ProviderResult,
} from "../types.js";

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

function createTimeoutSignal(
  timeoutMs: number,
): AbortSignal {
  return AbortSignal.timeout(timeoutMs);
}

function isTimeoutError(error: unknown): boolean {
  return (
    error instanceof DOMException &&
    error.name === "TimeoutError"
  );
}

function extractReferences(
  vulnerability: Record<string, unknown>,
): Array<{
  title: string;
  url: string;
  retrieved: boolean;
}> {
  const references =
    vulnerability.references;

  if (!Array.isArray(references)) {
    return [];
  }

  const result: Array<{
    title: string;
    url: string;
    retrieved: boolean;
  }> = [];

  for (const reference of references) {
    if (
      typeof reference !== "object" ||
      reference === null ||
      Array.isArray(reference)
    ) {
      continue;
    }

    const object =
      reference as Record<string, unknown>;

    const url = object.url;

    if (typeof url !== "string") {
      continue;
    }

    result.push({
      title: url,
      url,
      retrieved: false,
    });
  }

  return result;
}

export async function fetchNvdCve(
  cveId: string,
  options: NvdOptions,
): Promise<ProviderResult> {
  const normalized =
    cveId.trim().toUpperCase();

  const checkedAt =
    new Date().toISOString();

  const url =
    "https://services.nvd.nist.gov/rest/json/cves/2.0?" +
    `cveId=${encodeURIComponent(normalized)}`;

  try {
    const headers: Record<string, string> = {
      Accept: "application/json",
      "User-Agent":
        "ThreatIntel-AI-Engine/0.3.0",
    };

    if (
      options.apiKey &&
      options.apiKey.trim().length > 0
    ) {
      headers.apiKey =
        options.apiKey.trim();
    }

    const response = await fetch(url, {
      method: "GET",
      headers,
      signal: createTimeoutSignal(
        options.timeoutMs,
      ),
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

    const data =
      (await response.json()) as NvdResponse;

    const vulnerability =
      data.vulnerabilities?.[0]?.cve;

    if (!vulnerability) {
      return {
        provider: "NVD",
        status: "observed_absence",
        evidence: null,
        error: null,
        checkedAt,
      };
    }

    /*
     * Defensive verification:
     *
     * Never trust the first returned record blindly.
     */
    const returnedId =
      vulnerability.id;

    if (
      typeof returnedId !== "string" ||
      returnedId.toUpperCase() !== normalized
    ) {
      throw new Error(
        `NVD returned unexpected CVE ${String(returnedId)} for requested ${normalized}`,
      );
    }

    const evidence: Evidence = {
      source: "NVD",

      sourceType: "primary",

      retrievedAt: checkedAt,

      url,

      title:
        `NVD CVE Record - ${normalized}`,

      confidence: "high",

      facts: vulnerability,

      extractedFacts: [],

      references:
        extractReferences(vulnerability),
    };

    return {
      provider: "NVD",
      status: "success",
      evidence,
      error: null,
      checkedAt,
    };
  } catch (error) {
    const timeout =
      isTimeoutError(error);

    return {
      provider: "NVD",
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