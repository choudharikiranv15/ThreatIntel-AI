/*
 * Alert triage, offline: indicator extraction from real-looking alert text,
 * the two checking stages, the shared limit, ranking, the result size, and
 * the answer check over triaged indicators.
 */
import fs from "node:fs";
import path from "node:path";

import type { Indicator } from "./lookup/indicator.js";
import type { LookupPayload } from "./lookup/lookup.js";
import { parseAbuseIpDb, parseOtx, parseVirusTotal, type LookupSourceId, type SourceResult } from "./lookup/sources.js";
import { MAX_TOOL_RESULT_CHARS } from "./tool-result.js";
import { extractIndicators, refangText } from "./triage/extract.js";
import { buildTriageTool, triageSettings } from "./triage/tool.js";
import { runTriage, type TriagePayload } from "./triage/triage.js";
import { checkIndicatorAnswer, extractTriageLookups } from "./verification/check-indicators.js";

function assert(condition: unknown, message: string): asserts condition {
    if (!condition) {
        throw new Error(`Assertion failed: ${message}`);
    }
}

const fixture = (name: string) => JSON.parse(fs.readFileSync(path.join(process.cwd(), "test-fixtures", "lookup", name), "utf8"));

const ALERT = `
[SentinelOne] Threat detected on host FIN-WS-0142 (10.20.4.17) user CORP\\j.doe
Process: C:\\Users\\j.doe\\AppData\\Local\\Temp\\svchost.exe  parent: winword.exe  script: stage2.ps1 report.py
SHA256: 275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F  MD5: 44d88612fea8a8f36de82e1278abb02f
Padding: 0000000000000000000000000000000000000000000000000000000000000000
Network: connected to 185.220.101[.]47:443 and 8.8.8.8, beacon to hxxps://cdn-update[.]top/gate.php?id=42
DNS: opmanager[.]pro, login.microsoftonline.com, fileserver.corp, printer.local
Sender: billing@paypa1-secure[.]com  Console: https://usea1-001.sentinelone.net/incidents/42
Agent version 23.4.2.14, Windows 10.0.19041 build, metadata 169.254.169.254
`;

/* -------------------------------- Extraction -------------------------------- */

function testExtraction(): void {
    assert(refangText("hxxps[:]//evil[.]com/a and 1.2.3[.]4 and a[at]b[.]com") === "https://evil.com/a and 1.2.3.4 and a@b.com", "defanged text is restored");

    const x = extractIndicators(ALERT);
    const values = x.indicators.map((i) => `${i.type}:${i.value}`);
    const has = (v: string) => values.includes(v);

    for (const expected of [
        "sha256:275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
        "md5:44d88612fea8a8f36de82e1278abb02f",
        "url:https://cdn-update.top/gate.php?id=42",
        "domain:cdn-update.top",
        "ipv4:185.220.101.47",
        "ipv4:8.8.8.8",
        "domain:opmanager.pro",
        "domain:paypa1-secure.com",
    ]) {
        assert(has(expected), `extracted ${expected}: ${values.join(" ")}`);
    }

    assert(!values.some((v) => /svchost\.exe|winword\.exe|stage2|report\.py/.test(v)), `file names are not domains: ${values.join(" ")}`);
    assert(!values.some((v) => /^ipv4:(10\.|23\.4|169\.254)/.test(v)) && !values.some((v) => /0000000000/.test(v)), "version numbers, padding, and internal addresses are not checked");
    assert(!values.some((v) => /corp|local|microsoftonline|sentinelone/.test(v)), "internal names and console domains are not checked");
    assert(x.internal >= 3, `internal values are counted: ${x.internal}`);
    assert(x.infrastructure.includes("microsoftonline.com") && x.infrastructure.includes("sentinelone.net"), `console domains are named as skipped: ${x.infrastructure}`);
    assert(x.indicators[0].type === "sha256" && x.indicators.at(-1)?.type === "domain", "hashes first, domains last");

    const capped = extractIndicators(Array.from({ length: 40 }, (_, i) => `45.33.${i}.9`).join(" "), { maxIndicators: 25 });

    assert(capped.indicators.length === 25 && capped.overCap.length === 15, "the cap holds and the rest are listed");

    console.log("✓ Indicators are extracted from alert text; file names, versions, padding, internal and console values are not checked");
}

/* -------------------------------- Orchestration ----------------------------- */

const make = (source: LookupSourceId, parsed: Pick<SourceResult, "status" | "facts">): SourceResult => ({
    source,
    checkedAt: new Date().toISOString(),
    reference: `https://example.test/${source}`,
    error: null,
    ...parsed,
});

function fakeDeps() {
    const calls: string[] = [];
    const recorded: string[] = [];
    let hourly = 0;

    const fetchSource = async (source: LookupSourceId, indicator: Indicator): Promise<SourceResult> => {
        calls.push(`${source}:${indicator.value}`);

        if (source === "virustotal") {
            return make(source, parseVirusTotal(200, fixture(indicator.type === "ipv4" ? "virustotal-ip.json" : "virustotal-file.json"), indicator.type));
        }

        if (source === "abuseipdb" && indicator.value === "185.220.101.47") {
            return make(source, parseAbuseIpDb(fixture("abuseipdb-reported.json")));
        }

        if (source === "otx" && indicator.value === "opmanager.pro") {
            return make(source, parseOtx(fixture("otx-domain.json")));
        }

        return make(source, { status: "observed_absence", facts: null });
    };

    return {
        calls,
        recorded,
        setHourly: (n: number) => (hourly = n),
        deps: {
            fetchSource,
            store: {
                cachedResult: async () => null,
                callsToday: async () => 0,
                // As the database counts: earlier lookups this hour plus the distinct ids recorded since.
                lookupsLastHour: async () => hourly + new Set(recorded).size,
                recordLookup: async (id: string) => {
                    recorded.push(id);
                },
            },
        },
    };
}

const SETTINGS = triageSettings({ abuseipdbApiKey: "test", virustotalApiKey: "test", requestTimeoutMs: 2000 });

async function testOrchestration(): Promise<void> {
    const fake = fakeDeps();
    const outcome = await runTriage(ALERT, "discord:111", SETTINGS, fake.deps);

    assert(!("error" in outcome), `the alert is triaged: ${JSON.stringify(outcome).slice(0, 200)}`);

    const { payload, lookups } = outcome;
    const vt = fake.calls.filter((c) => c.startsWith("virustotal:")).map((c) => c.slice(11));

    assert(vt.includes("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f") && vt.includes("https://cdn-update.top/gate.php?id=42"), `VirusTotal checks hashes and URLs: ${vt}`);
    assert(vt.includes("185.220.101.47") && vt.includes("opmanager.pro"), `and indicators another service flagged: ${vt}`);
    assert(!vt.includes("8.8.8.8") && !vt.includes("paypa1-secure.com"), `but not quiet IPs and domains, to save its quota: ${vt}`);
    assert(vt.indexOf("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f") < vt.indexOf("185.220.101.47"), "hashes are asked before flagged addresses");

    assert(new Set(fake.recorded).size === 1, "the whole triage is recorded under one lookup id, so it counts once per hour");

    const order = payload.results.map((r) => r.tier);

    assert(order.join(",") === [...order].sort((a, b) => ["flagged", "weak", "quiet", "unchecked"].indexOf(a) - ["flagged", "weak", "quiet", "unchecked"].indexOf(b)).join(","), `results are ranked by tier: ${order}`);
    assert(payload.lookFirst.includes("185.220.101.47") && payload.lookFirst.includes("opmanager.pro") && !payload.lookFirst.includes("8.8.8.8"), `look-first lists the flagged ones only: ${payload.lookFirst}`);
    assert(payload.results.find((r) => r.indicator === "8.8.8.8")?.tier === "quiet", "an address no free service reports is quiet, and VirusTotal is not spent on it");
    assert(payload.found.internal >= 3 && payload.found.skippedInfrastructure.length === 2, "what was not sent is reported");
    assert(lookups.length === payload.results.length, "full evidence is kept for every indicator");

    /* The per-person limit is checked once for the whole triage: one lookup left is enough. */
    const lastOne = fakeDeps();

    lastOne.setHourly(19);
    const fits = await runTriage(ALERT, "discord:111", SETTINGS, lastOne.deps);

    assert(!("error" in fits) && fits.payload.results.every((r) => r.tier !== "unchecked"), "a triage started with one lookup left checks every indicator");

    fake.setHourly(20);
    const limited = await runTriage(ALERT, "discord:111", SETTINGS, fake.deps);

    assert("error" in limited && limited.error === "rate_limited", "the hourly limit applies to the triage as a whole");

    /* Nothing to check. */
    const none = await runTriage("Host 10.0.0.5 talked to fileserver.corp", "u", SETTINGS, fakeDeps().deps);

    assert("error" in none && none.error === "no_indicators" && /internal/.test(none.message), "only internal values: refused, and says why");
    assert("error" in (await runTriage("", "u", SETTINGS, fakeDeps().deps)), "empty input is refused");

    console.log("✓ Free services check everything, VirusTotal only what matters, the triage counts once, and results are ranked by evidence");
}

async function testToolAndGate(): Promise<void> {
    /* 25 noisy indicators still fit the tool result limit. */
    const many = Array.from({ length: 25 }, (_, i) => `45.33.${i}.9`).join("\n");
    const tool = buildTriageTool({ requesterSenderId: "discord:111" }, SETTINGS, fakeDeps().deps);
    const out = await tool.execute("x", { text: `${many}\n${ALERT}` });
    const parsed = JSON.parse(out.content[0].text) as TriagePayload;

    assert(out.content[0].text.length <= MAX_TOOL_RESULT_CHARS && parsed.kind === "triage" && parsed.results.length === 25, `25 results fit the limit: ${out.content[0].text.length}`);
    assert(!out.content[0].text.includes("pulses") && (out.details as { lookups: LookupPayload[] }).lookups.length === 25, "the model reads the summary; full evidence is in details");

    /* The answer check sees every triaged indicator. */
    const lookups = extractTriageLookups(out.details);

    assert(lookups.length === 25, "the answer check reads the triaged lookups");

    const real = await buildTriageTool({ requesterSenderId: "u" }, SETTINGS, fakeDeps().deps).execute("y", { text: ALERT });
    const triaged = extractTriageLookups(real.details);

    assert(checkIndicatorAnswer("paypa1-secure.com is safe.", triaged).some((f) => /not proof of safety/.test(f)), "calling a quiet triaged indicator safe is flagged");
    assert(checkIndicatorAnswer("AbuseIPDB gives 185.220.101.47 an abuse confidence of 40%.", triaged).some((f) => /40%/.test(f)), "a misquoted figure for a triaged indicator is flagged");
    assert(checkIndicatorAnswer("AbuseIPDB gives 185.220.101.47 an abuse confidence of 100%.", triaged).length === 0, "a correct figure passes");

    console.log("✓ The triage result fits the limit, and the answer check covers every triaged indicator");
}

async function main(): Promise<void> {
    testExtraction();
    await testOrchestration();
    await testToolAndGate();
    console.log("Alert triage logic tests PASSED");
}

main().catch((error) => {
    console.error("Alert triage logic tests FAILED");
    console.error(error);
    process.exitCode = 1;
});
