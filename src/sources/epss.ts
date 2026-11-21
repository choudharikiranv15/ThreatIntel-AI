import type { Evidence, ExploitPrediction, ProviderResult } from "../types.js";
import { ENGINE_VERSION } from "../version.js";
import { fetchWithRetry, type RetryPolicy } from "./request-signal.js";

/*
 * FIRST's Exploit Prediction Scoring System: the estimated probability that a
 * CVE is exploited in the wild in the next 30 days, rescored daily. It is a
 * model's estimate, not an observation, and it is reported as such: CISA KEV
 * remains the only source of confirmed exploitation.
 */

export interface EpssOptions {
    timeoutMs: number;
    signal?: AbortSignal;
    retry?: RetryPolicy;
}

const API_URL = "https://api.first.org/data/v1/epss";

/** Bands used for alerts, so daily movement within a band never interrupts anyone. */
export function epssBand(probability: number): ExploitPrediction["band"] {
    if (probability >= 0.5) return "high";
    if (probability >= 0.1) return "elevated";
    return "low";
}

type EpssRow = { cve?: unknown; epss?: unknown; percentile?: unknown; date?: unknown };

/** Pure: reads one CVE's row from an API answer. Null when EPSS has no score for it. */
export function parseEpss(cveId: string, body: unknown): { probability: number; percentile: number; scoreDate: string } | null {
    const rows = ((body ?? {}) as { data?: unknown }).data;

    if (!Array.isArray(rows)) {
        throw new Error("EPSS answered without a data list");
    }

    const row = (rows as EpssRow[]).find((item) => String(item.cve ?? "").toUpperCase() === cveId);

    if (!row) {
        return null;
    }

    const probability = Number(row.epss);
    const percentile = Number(row.percentile);
    const scoreDate = String(row.date ?? "");

    if (!Number.isFinite(probability) || probability < 0 || probability > 1 || !Number.isFinite(percentile) || percentile < 0 || percentile > 1 || !/^\d{4}-\d{2}-\d{2}$/.test(scoreDate)) {
        throw new Error("EPSS answered with an unreadable score");
    }

    return { probability, percentile, scoreDate };
}

function isTimeoutError(error: unknown): boolean {
    return error instanceof DOMException && error.name === "TimeoutError";
}

export async function fetchEpssRecord(cveId: string, options: EpssOptions): Promise<ProviderResult> {
    const normalized = cveId.trim().toUpperCase();
    const checkedAt = new Date().toISOString();
    const url = `${API_URL}?cve=${encodeURIComponent(normalized)}`;

    try {
        const response = await fetchWithRetry(
            url,
            { method: "GET", headers: { Accept: "application/json", "User-Agent": `ThreatIntel-AI-Engine/${ENGINE_VERSION}` } },
            { timeoutMs: options.timeoutMs, signal: options.signal, retry: options.retry },
        );

        if (!response.ok) {
            // The response body is remote text and is not forwarded to the LLM.
            throw new Error(`EPSS request failed: HTTP ${response.status} ${response.statusText}`);
        }

        const score = parseEpss(normalized, await response.json());

        if (!score) {
            // New or rejected CVEs have no score yet: an answer, not a failure.
            return { provider: "EPSS", status: "observed_absence", evidence: null, error: null, checkedAt };
        }

        const evidence: Evidence = {
            id: `EPSS:${normalized}:${score.scoreDate}`,
            source: "EPSS",
            sourceType: "community",
            retrievedAt: checkedAt,
            url,
            title: `FIRST EPSS score - ${normalized}`,
            confidence: "medium",
            facts: { epss: score.probability, percentile: score.percentile, scoreDate: score.scoreDate },
            extractedFacts: [],
            references: [],
        };

        return { provider: "EPSS", status: "success", evidence, error: null, checkedAt };
    } catch (error) {
        return {
            provider: "EPSS",
            status: isTimeoutError(error) ? "timeout" : "error",
            evidence: null,
            error: error instanceof Error ? error.message : String(error),
            checkedAt,
        };
    }
}

/** The prediction as the investigation summary states it, from stored evidence. */
export function predictionFrom(evidence: Evidence): ExploitPrediction | null {
    const facts = evidence.facts as Record<string, unknown>;
    const probability = Number(facts.epss);
    const percentile = Number(facts.percentile);
    const scoreDate = typeof facts.scoreDate === "string" ? facts.scoreDate : null;

    if (!Number.isFinite(probability) || !Number.isFinite(percentile) || !scoreDate) {
        return null;
    }

    return { probability, percentile, scoreDate, band: epssBand(probability), evidenceId: evidence.id };
}
