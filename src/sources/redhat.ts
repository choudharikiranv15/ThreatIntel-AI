import type {
  Evidence,
  ProviderResult,
} from "../types.js";

export interface RedHatOptions {
  timeoutMs: number;
}

interface RedHatCveResponse extends Record<string, unknown> {
  name?: string;
  package_state?: unknown[];
}

function isTimeoutError(
  error: unknown,
): boolean {
  return (
    error instanceof DOMException &&
    error.name === "TimeoutError"
  );
}

export async function fetchRedHatCve(
  cveId: string,
  options: RedHatOptions,
): Promise<ProviderResult> {
  const normalized =
    cveId.trim().toUpperCase();

  const checkedAt =
    new Date().toISOString();

  const url =
    `https://access.redhat.com/hydra/rest/securitydata/cve/${encodeURIComponent(normalized)}.json`;

  try {
    const response = await fetch(url, {
      method: "GET",
      headers: {
        Accept: "application/json",
        "User-Agent":
          "ThreatIntel-AI-Engine/0.3.0",
      },
      signal: AbortSignal.timeout(
        options.timeoutMs,
      ),
    });

    /*
     * Red Hat answers 404 for CVEs it does not track. The check completed,
     * so this is an observed absence, not a provider failure.
     */
    if (response.status === 404) {
      return {
        provider: "REDHAT",
        status: "observed_absence",
        evidence: null,
        error: null,
        checkedAt,
      };
    }

    if (!response.ok) {
      // The response body is remote text and is not forwarded to the LLM.
      throw new Error(
        `Red Hat API request failed: HTTP ${response.status} ${response.statusText}`,
      );
    }

    const data =
      (await response.json()) as RedHatCveResponse;

    /*
     * Defensive verification:
     *
     * Verify the returned CVE identifier matches the request.
     */
    const returnedId =
      data.name;

    if (
      typeof returnedId !== "string" ||
      returnedId.toUpperCase() !== normalized
    ) {
      throw new Error(
        `Red Hat API returned unexpected CVE ${String(returnedId)} for requested ${normalized}`,
      );
    }

    /*
     * Red Hat API returns a record even for CVEs with no package data.
     *
     * An empty or missing package_state is NOT an error; it means Red Hat
     * has no specific product/package assessment for this CVE.
     */

    const evidence: Evidence = {
      id: `REDHAT:${normalized}`,

      source: "REDHAT",

      sourceType: "vendor",

      retrievedAt: checkedAt,

      url,

      title:
        `Red Hat CVE Record - ${normalized}`,

      confidence: "high",

      facts: {
        ...data,
        package_state: data.package_state ?? [],
        _http_status: response.status,
      },

      extractedFacts: [],

      references: [],
    };

    return {
      provider: "REDHAT",
      status: "success",
      evidence,
      error: null,
      checkedAt,
    };
  } catch (error) {
    const timeout =
      isTimeoutError(error);

    return {
      provider: "REDHAT",
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
