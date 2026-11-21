/*
 * EPSS, offline: the parser on recorded answers, the adapter's statuses, the
 * investigation fact and summary, enrichment failures, replay from stored
 * evidence, the tool view, and the watchlist alert rule.
 */
import fs from "node:fs";
import path from "node:path";

import { investigateCve } from "./engine.js";
import type { InvestigationChange, InvestigationComparison } from "./persistence/investigation-diff.js";
import { rederiveContext } from "./persistence/investigation-replay.js";
import { epssBand, fetchEpssRecord, parseEpss } from "./sources/epss.js";
import { viewFromResult } from "./tool-result.js";
import type { InvestigationResult, ProviderResult } from "./types.js";
import { decideAlerts } from "./watch/alerts.js";

function assert(condition: unknown, message: string): asserts condition {
    if (!condition) {
        throw new Error(`Assertion failed: ${message}`);
    }
}

const fixture = (name: string) => JSON.parse(fs.readFileSync(path.join(process.cwd(), "test-fixtures", "epss", name), "utf8"));
const CVE = "CVE-2024-3400";
const AT = "2026-11-21T00:00:00.000Z";

/* --------------------------------- Parsing --------------------------------- */

function testParsing(): void {
    const found = parseEpss(CVE, fixture("found.json"));

    assert(found?.probability === 0.99999 && found.percentile === 1 && found.scoreDate === "2026-11-21", `the recorded score is read: ${JSON.stringify(found)}`);
    assert(parseEpss("CVE-2026-999999", fixture("none.json")) === null, "no score is no record, not an error");
    assert(parseEpss("CVE-2020-0001", fixture("found.json")) === null, "a row for another CVE is never used");

    for (const bad of [{}, { data: [{ cve: CVE, epss: "1.7", percentile: "0.5", date: "2026-11-21" }] }, { data: [{ cve: CVE, epss: "0.2", percentile: "0.5", date: "yesterday" }] }]) {
        let threw = false;

        try {
            parseEpss(CVE, bad);
        } catch {
            threw = true;
        }

        assert(threw, `an unreadable answer is an error, never a score: ${JSON.stringify(bad)}`);
    }

    assert(epssBand(0.0999) === "low" && epssBand(0.1) === "elevated" && epssBand(0.4999) === "elevated" && epssBand(0.5) === "high", "bands: under 10%, 10 to 50%, 50% and above");

    console.log("✓ EPSS answers are read strictly, and missing scores are no record");
}

async function testAdapter(): Promise<void> {
    const realFetch = globalThis.fetch;
    const urls: string[] = [];
    let reply: () => Response = () => Response.json(fixture("found.json"));

    globalThis.fetch = (async (input: string | URL | Request) => {
        urls.push(String(input));
        return reply();
    }) as typeof fetch;

    const options = { timeoutMs: 2000, retry: { attempts: 1, maxDelayMs: 1, budgetMs: 1 } };

    try {
        const ok = await fetchEpssRecord("cve-2024-3400", options);

        assert(ok.status === "success" && ok.provider === "EPSS" && ok.evidence?.id === "EPSS:CVE-2024-3400:2026-11-21" && urls[0] === "https://api.first.org/data/v1/epss?cve=CVE-2024-3400", "a score becomes evidence tied to its score date");

        reply = () => Response.json(fixture("none.json"));
        assert((await fetchEpssRecord("CVE-2026-999999", options)).status === "observed_absence", "an unscored CVE is no record");

        reply = () => new Response("down", { status: 503 });
        const failed = await fetchEpssRecord(CVE, options);

        assert(failed.status === "error" && !String(failed.error).includes("down"), "a failure is an error, without the remote body");

        reply = () => Response.json({ data: [{ cve: CVE, epss: "nope", percentile: "1", date: "2026-11-21" }] });
        assert((await fetchEpssRecord(CVE, options)).status === "error", "an unreadable score is an error, never a number");
    } finally {
        globalThis.fetch = realFetch;
    }

    console.log("✓ The EPSS adapter separates scores, no record, and failures");
}

/* ------------------------------ Investigations ------------------------------ */

const provider = (result: ProviderResult) => async () => result;
const nvd: ProviderResult = {
    provider: "NVD",
    status: "success",
    error: null,
    checkedAt: AT,
    evidence: { id: `NVD:${CVE}`, source: "NVD", sourceType: "primary", retrievedAt: AT, url: "https://nvd.nist.gov/", title: "NVD", confidence: "high", facts: {}, extractedFacts: [], references: [] },
};
const absent = (name: "CISA_KEV" | "REDHAT"): ProviderResult => ({ provider: name, status: "observed_absence", error: null, checkedAt: AT, evidence: null });
const epssResult = (probability: number): ProviderResult => ({
    provider: "EPSS",
    status: "success",
    error: null,
    checkedAt: AT,
    evidence: { id: `EPSS:${CVE}:2026-11-21`, source: "EPSS", sourceType: "community", retrievedAt: AT, url: `https://api.first.org/data/v1/epss?cve=${CVE}`, title: "FIRST EPSS", confidence: "medium", facts: { epss: probability, percentile: 0.97, scoreDate: "2026-11-21" }, extractedFacts: [], references: [] },
});

const investigate = (epss?: ProviderResult | "throw" | null) =>
    investigateCve(CVE, {
        requestTimeoutMs: 1000,
        providers: {
            nvd: provider(nvd),
            cisaKev: provider(absent("CISA_KEV")),
            redhat: provider(absent("REDHAT")),
            ...(epss === undefined ? {} : { epss: epss === null ? null : epss === "throw" ? async () => Promise.reject(new Error("boom")) : provider(epss) }),
        },
    });

async function testInvestigation(): Promise<InvestigationResult> {
    const scored = await investigate(epssResult(0.2345));
    const prediction = scored.summary.exploitPrediction;

    assert(prediction?.probability === 0.2345 && prediction.band === "elevated" && prediction.scoreDate === "2026-11-21" && prediction.evidenceId.startsWith("EPSS:"), `the summary carries the prediction: ${JSON.stringify(prediction)}`);
    assert(scored.evidence.some((e) => e.source === "EPSS"), "the score is kept as evidence");

    const fact = JSON.stringify(scored).match(/FIRST EPSS estimates a 23\.4% probability of exploitation in the next 30 days, higher than 97\.0% of scored CVEs \(scored 2026-11-21\)\. This is a model estimate, not observed exploitation\./);

    assert(fact, "a cited fact states the estimate, the percentile, the date, and that it is not observed exploitation");
    assert(scored.summary.kevStatus === "not-listed", "EPSS never changes the exploitation status, which only KEV establishes");

    const without = await investigate();
    const noScore = await investigate({ provider: "EPSS", status: "observed_absence", error: null, checkedAt: AT, evidence: null });
    const broken = await investigate("throw");

    assert(without.summary.exploitPrediction === undefined, "a caller that did not ask EPSS gets no EPSS field at all");
    assert(noScore.summary.exploitPrediction === null, "an unscored CVE is stated as such");
    assert(broken.summary.exploitPrediction === undefined && (broken.summary.enrichmentLimitations ?? []).some((l) => /EPSS/.test(l)), "an EPSS failure is a visible enrichment limitation");
    assert(broken.status === without.status && JSON.stringify(broken.limitations) === JSON.stringify(without.limitations), "and it never changes the investigation's status or core limitations");

    /* The tool view shows it. */
    const view = viewFromResult(scored) as unknown as { summary: { exploitPrediction?: { band: string } } };

    assert(view.summary.exploitPrediction?.band === "elevated", "the tool view carries the prediction");

    console.log("✓ EPSS adds a cited estimate to investigations, and its failures never block them");
    return scored;
}

async function testReplay(scored: InvestigationResult): Promise<void> {
    const context = {
        investigation: {
            id: "inv-1",
            target: CVE,
            targetType: "cve",
            investigationType: "cve",
            status: scored.status,
            summary: scored.summary,
            providerResults: scored.providerResults,
            limitations: scored.limitations,
            analystGuidance: [],
            engineVersion: null,
            createdAt: AT,
        },
        evidence: scored.evidence.map((e) => ({ id: e.id, source: e.source, sourceEvidenceId: e.id, rawPayload: e.facts })),
    } as never;

    const replayed = await rederiveContext(context);

    assert(JSON.stringify(replayed.summary.exploitPrediction) === JSON.stringify(scored.summary.exploitPrediction), "replaying stored evidence gives the same prediction");

    console.log("✓ Stored EPSS evidence replays to the same prediction");
}

/* ------------------------------- Watch alerts ------------------------------- */

function testAlerts(): void {
    const current = { providerResults: [{ provider: "NVD", status: "success" }, { provider: "CISA_KEV", status: "success" }] } as unknown as InvestigationResult;
    const comparison = (before: unknown, after: unknown): InvestigationComparison => ({
        target: CVE,
        baseline: {
            investigationId: "b",
            createdAt: AT,
            basis: "rederived_from_stored_evidence",
            recordedEngineVersion: "0.13.0",
            rederivedWithEngineVersion: "0.13.0",
            recorded: { status: "confirmed", severity: null, cvssBaseScore: null, kevStatus: "not-listed" },
            rederived: { status: "confirmed", severity: null, cvssBaseScore: null, kevStatus: "not-listed" },
            integrity: { evidenceRows: "verified", recordConsistency: "consistent", fullyVerified: true } as never,
        },
        current: { investigationId: null, createdAt: null, integrity: null },
        counts: { intelligence_change: 1, collection_difference: 0, processing_difference: 0 },
        noIntelligenceChange: false,
        changes: [{ category: "intelligence_change", field: "exploitPrediction.band", before, after, beforeBasis: "rederived_baseline", afterBasis: "current_result", explanation: "", sources: ["EPSS"] } as InvestigationChange],
        omittedChanges: 0,
    });

    const rise = decideAlerts(comparison("low", "elevated"), current);

    assert(rise.outcome === "changes_detected" && rise.events.length === 1 && /FIRST EPSS now rates exploitation in the next 30 days as elevated \(was low\)/.test(rise.events[0].explanation), "a rise between bands alerts");
    assert(decideAlerts(comparison("elevated", "high"), current).events.length === 1, "so does elevated to high");
    assert(decideAlerts(comparison("high", "low"), current).events.length === 0, "a fall does not interrupt anyone");
    assert(decideAlerts(comparison(null, "high"), current).events.length === 0, "nor does a first score");

    console.log("✓ The watchlist alerts only when EPSS moves up a band");
}

async function main(): Promise<void> {
    testParsing();
    await testAdapter();
    const scored = await testInvestigation();
    await testReplay(scored);
    testAlerts();
    console.log("EPSS logic tests PASSED");
}

main().catch((error) => {
    console.error("EPSS logic tests FAILED");
    console.error(error);
    process.exitCode = 1;
});
