import type {
  Evidence,
  ProviderResult,
} from "../types.js";
import { ENGINE_VERSION } from "../version.js";

import { fetchWithRetry, type RetryPolicy } from "./request-signal.js";

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

export interface CisaKevCatalog {
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

export type KevCatalogSnapshot = {
  catalog: CisaKevCatalog;
  /** When this copy of the catalog was downloaded. */
  fetchedAt: string;
};

export async function fetchKevCatalog(
  timeoutMs: number,
  signal?: AbortSignal,
  retry?: RetryPolicy,
): Promise<KevCatalogSnapshot> {
  const fetchedAt = new Date().toISOString();

  const response = await fetchWithRetry(
    KEV_URL,
    {
      method: "GET",
      headers: {
        Accept: "application/json",
        "User-Agent": `ThreatIntel-AI-Engine/${ENGINE_VERSION}`,
      },
    },
    { timeoutMs, signal, retry },
  );

  if (!response.ok) {
    // The response body is remote text and is not forwarded to the LLM.
    throw new Error(
      `CISA KEV request failed: HTTP ${response.status} ${response.statusText}`,
    );
  }

  const catalog = (await response.json()) as CisaKevCatalog;

  if (!Array.isArray(catalog.vulnerabilities)) {
    throw new Error(
      "CISA KEV response did not contain a vulnerabilities array.",
    );
  }

  return { catalog, fetchedAt };
}

/**
 * Shares one catalog download across lookups until it expires, so monitoring
 * many CVEs does not download about 1.5 MB per CVE. A failed download is not
 * cached, so the next lookup tries again.
 */
export function createKevCatalogCache(
  load: () => Promise<KevCatalogSnapshot>,
  ttlMs: number,
): () => Promise<KevCatalogSnapshot> {
  let cached: { snapshot: KevCatalogSnapshot; expiresAt: number } | null = null;
  let pending: Promise<KevCatalogSnapshot> | null = null;

  return () => {
    if (cached && Date.now() < cached.expiresAt) {
      return Promise.resolve(cached.snapshot);
    }

    pending ??= load()
      .then((snapshot) => {
        cached = { snapshot, expiresAt: Date.now() + ttlMs };
        return snapshot;
      })
      .finally(() => {
        pending = null;
      });

    return pending;
  };
}

export async function fetchCisaKev(
  cveId: string,
  timeoutMs: number,
  signal?: AbortSignal,
  options: {
    retry?: RetryPolicy;
    catalog?: () => Promise<KevCatalogSnapshot>;
  } = {},
): Promise<ProviderResult> {
  const normalized =
    cveId.trim().toUpperCase();

  let checkedAt =
    new Date().toISOString();

  try {
    const snapshot = await (
      options.catalog ??
      (() => fetchKevCatalog(timeoutMs, signal, options.retry))
    )();

    const { catalog } = snapshot;

    // A shared catalog is reported as of its download, not as of this lookup.
    checkedAt = snapshot.fetchedAt;

    const entry =
      (catalog.vulnerabilities ?? []).find(
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
        catalogVersion: catalog.catalogVersion,
      };
    }

    const evidence: Evidence = {
      id: `CISA_KEV:${normalized}`,

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
      catalogVersion: catalog.catalogVersion,
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