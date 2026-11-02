import type {
  Evidence,
  ProviderResult,
} from "../types.js";
import { ENGINE_VERSION } from "../version.js";

import { requestSignal } from "./request-signal.js";

export interface OsvOptions {
  timeoutMs: number;
  signal?: AbortSignal;
}

interface OsvRecord {
  id?: string;
  aliases?: string[];
  modified?: string;
  published?: string;
  withdrawn?: string;
  severity?: unknown[];
  affected?: {
    package?: { ecosystem?: string; name?: string };
    ranges?: {
      type?: string;
      events?: Record<string, string>[];
    }[];
  }[];
  database_specific?: {
    github_reviewed?: boolean;
    severity?: string;
  };
}

const API_URL = "https://api.osv.dev/v1/vulns";

/* One CVE rarely has more than one GHSA advisory; this bounds the request count. */
const MAX_ADVISORIES = 2;

function isTimeoutError(error: unknown): boolean {
  return (
    error instanceof DOMException &&
    error.name === "TimeoutError"
  );
}

async function getRecord(
  id: string,
  options: OsvOptions,
): Promise<OsvRecord | null> {
  const response = await fetch(
    `${API_URL}/${encodeURIComponent(id)}`,
    {
      method: "GET",
      headers: {
        Accept: "application/json",
        "User-Agent": `ThreatIntel-AI-Engine/${ENGINE_VERSION}`,
      },
      signal: requestSignal(options.timeoutMs, options.signal),
    },
  );

  if (response.status === 404) {
    return null;
  }

  if (!response.ok) {
    // The response body is remote text and is not forwarded to the LLM.
    throw new Error(
      `OSV request failed: HTTP ${response.status} ${response.statusText}`,
    );
  }

  return (await response.json()) as OsvRecord;
}

function packageRanges(record: OsvRecord) {
  return (record.affected ?? []).map((item) => ({
    ecosystem: item.package?.ecosystem ?? null,
    name: item.package?.name ?? null,
    // Git ranges name commits, not versions an analyst can act on.
    events: (item.ranges ?? [])
      .filter((range) => range.type !== "GIT")
      .flatMap((range) => range.events ?? []),
  }));
}

/**
 * OSV's CVE records hold only upstream git ranges. Package names and fixed
 * versions live in the GHSA advisory aliased to the CVE, so that is followed too.
 * Distribution records are not followed: they can number in the dozens, and
 * they repeat vendor data this engine already takes from the vendor.
 */
export async function fetchOsvRecord(
  cveId: string,
  options: OsvOptions,
): Promise<ProviderResult> {
  const normalized = cveId.trim().toUpperCase();
  const checkedAt = new Date().toISOString();

  try {
    const root = await getRecord(normalized, options);

    if (!root) {
      return {
        provider: "OSV",
        status: "observed_absence",
        evidence: null,
        error: null,
        checkedAt,
      };
    }

    const identifiers = [root.id, ...(root.aliases ?? [])].map((id) =>
      String(id).toUpperCase(),
    );

    if (!identifiers.includes(normalized)) {
      throw new Error(
        `OSV returned unexpected record ${String(root.id)} for requested ${normalized}`,
      );
    }

    const allAdvisoryIds = (root.aliases ?? [])
      .filter((id) => id.startsWith("GHSA-"));

    const advisoryIds = allAdvisoryIds.slice(0, MAX_ADVISORIES);
    const advisoriesOmitted = allAdvisoryIds.slice(MAX_ADVISORIES);

    const advisories: Record<string, unknown>[] = [];
    const advisoriesNotFound: string[] = [];
    const advisoriesFailed: string[] = [];

    for (const id of advisoryIds) {
      try {
        const advisory = await getRecord(id, options);

        if (!advisory) {
          advisoriesNotFound.push(id);
          continue;
        }

        // An advisory that does not name this CVE cannot speak for it.
        if (!(advisory.aliases ?? []).includes(normalized)) {
          advisoriesNotFound.push(id);
          continue;
        }

        advisories.push({
          id: advisory.id,
          modified: advisory.modified,
          withdrawn: advisory.withdrawn ?? null,
          reviewed: advisory.database_specific?.github_reviewed === true,
          severity: advisory.database_specific?.severity ?? null,
          packages: packageRanges(advisory),
        });
      } catch {
        advisoriesFailed.push(id);
      }
    }

    const evidence: Evidence = {
      id: `OSV:${normalized}`,
      source: "OSV",
      sourceType: "community",
      retrievedAt: checkedAt,
      url: `https://osv.dev/vulnerability/${encodeURIComponent(normalized)}`,
      title: `OSV Record - ${normalized}`,
      confidence: "medium",
      // Enumerated version lists are dropped: they can reach many kilobytes
      // and add nothing the ranges do not state.
      facts: {
        id: root.id,
        aliases: root.aliases ?? [],
        modified: root.modified,
        published: root.published,
        withdrawn: root.withdrawn ?? null,
        severity: root.severity ?? [],
        advisories,
        advisoriesNotFound,
        advisoriesFailed,
        advisoriesOmitted,
      },
      extractedFacts: [],
      references: [],
    };

    return {
      provider: "OSV",
      status: "success",
      evidence,
      error: null,
      checkedAt,
    };
  } catch (error) {
    return {
      provider: "OSV",
      status: isTimeoutError(error) ? "timeout" : "error",
      evidence: null,
      error: error instanceof Error ? error.message : String(error),
      checkedAt,
    };
  }
}
