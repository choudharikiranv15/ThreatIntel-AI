import type {
  Evidence,
  ProviderResult,
} from "../types.js";

export interface RedHatOptions {
  timeoutMs: number;
}

interface RedHatPackageState {
  product_name?: string;
  package_name?: string;
  fix_state?: string;
  cpe?: string;
}

interface RedHatCveResponse {
  name?: string;
  threat_severity?: string;
  statement?: string;
  package_state?: RedHatPackageState[];
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
        `Red Hat API request failed: HTTP ${response.status} ${response.statusText}${suffix}`,
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
        name: data.name,
        threat_severity: data.threat_severity,
        statement: data.statement,
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
