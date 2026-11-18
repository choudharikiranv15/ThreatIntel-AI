/*
 * Indicator lookup, offline: input handling, each service's parser on recorded
 * responses, the summary, limits, error handling, key handling, and the
 * answer-gate checks. Database behaviour is in persistence/test-lookup.ts.
 */
import fs from "node:fs";
import path from "node:path";

import { parseIndicator, refang, type Indicator } from "./lookup/indicator.js";
import { runLookup, summarise, type LookupPayload, type LookupSettings } from "./lookup/lookup.js";
import {
    lookupSource,
    parseAbuseIpDb,
    parseGreyNoise,
    parseInternetDb,
    parseOtx,
    type LookupSourceId,
    type SourceResult,
} from "./lookup/sources.js";
import { buildLookupTool, lookupSettings } from "./lookup/tool.js";
import { MAX_TOOL_RESULT_CHARS } from "./tool-result.js";
import { checkIndicatorAnswer } from "./verification/check-indicators.js";

function assert(condition: unknown, message: string): asserts condition {
    if (!condition) {
        throw new Error(`Assertion failed: ${message}`);
    }
}

const fixture = (name: string) => JSON.parse(fs.readFileSync(path.join(process.cwd(), "test-fixtures", "lookup", name), "utf8"));

/* ------------------------------ Input handling ----------------------------- */

function testIndicators(): void {
    const ok = (input: string, value: string, type: string) => {
        const result = parseIndicator(input);

        assert(!("error" in result) && result.value === value && result.type === type, `${input} -> ${type} ${value}: ${JSON.stringify(result)}`);
    };

    ok("194.127.178.21", "194.127.178.21", "ipv4");
    ok("194.127.178[.]21", "194.127.178.21", "ipv4");
    ok("  `194[.]127[.]178[.]21`  ", "194.127.178.21", "ipv4");
    ok("hxxps://cdn.bad-host[.]example/payload.bin".replace("example", "com"), "cdn.bad-host.com", "domain");
    ok("OPManager[.]PRO", "opmanager.pro", "domain");
    ok("evil[dot]com", "evil.com", "domain");
    ok("275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F", "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "sha256");
    ok("3d5ee8429ef00824c0351cba507dfeb92b54f83b", "3d5ee8429ef00824c0351cba507dfeb92b54f83b", "sha1");
    ok("44d88612fea8a8f36de82e1278abb02f", "44d88612fea8a8f36de82e1278abb02f", "md5");

    assert(!("error" in parseIndicator("http://example-c2.com/path?secret=1")) && (parseIndicator("http://example-c2.com/path?secret=1") as Indicator).note, "a URL is reduced to its host, and says so");

    /* Never sent anywhere: private, internal, reserved. */
    for (const address of ["10.0.0.5", "172.16.4.1", "192.168.1.10", "127.0.0.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "224.0.0.1", "255.255.255.255", "198.18.0.1", "192.0.2.10", "203.0.113.7"]) {
        const result = parseIndicator(address);

        assert("error" in result && result.error === "not_public", `${address} must be refused as not public`);
    }

    for (const name of ["fileserver.corp", "printer.local", "db.internal", "intranet.lan", "host.home", "x.onion", "a.test"]) {
        const result = parseIndicator(name);

        assert("error" in result && result.error === "not_public", `${name} must be refused as internal`);
    }

    for (const junk of ["", "   ", "localhost", "not an indicator", "1.2.3", "999.1.1.1", "-bad-.com", "a".repeat(400), "exa mple.com"]) {
        assert("error" in parseIndicator(junk), `junk must be refused: ${junk.slice(0, 30)}`);
    }

    assert((parseIndicator(42 as unknown as string) as { error: string }).error === "invalid_indicator", "a non-string is refused");
    assert((parseIndicator("2001:4860:4860::8888") as { error: string }).error === "unsupported", "IPv6 is reported as unsupported");
    assert(refang("hxxp://a[.]b[:]8080") === "http://a.b:8080", "defanging is reversed");

    console.log("✓ Indicators are normalised from defanged forms; private, internal, and junk input is refused");
}

/* --------------------------------- Parsers --------------------------------- */

function testParsers(): void {
    const idb = parseInternetDb(200, fixture("internetdb-found.json"));

    assert(idb.status === "success" && (idb.facts?.ports as number[]).includes(53) && (idb.facts?.hostnames as string[]).includes("dns.google"), "InternetDB facts are read");
    assert(parseInternetDb(404, fixture("internetdb-none.json")).status === "observed_absence", "InternetDB 404 is no record, not an error");

    assert(parseGreyNoise(404, fixture("greynoise-none.json")).status === "observed_absence", "GreyNoise 'not observed' is no record");

    const scanner = parseGreyNoise(200, fixture("greynoise-malicious.json"));

    assert(scanner.status === "success" && scanner.facts?.classification === "malicious" && scanner.facts.noise === true, "a GreyNoise scanner is read");
    assert(parseGreyNoise(200, fixture("greynoise-riot.json")).facts?.riot === true, "a GreyNoise known service is read");

    const reported = parseAbuseIpDb(fixture("abuseipdb-reported.json"));

    assert(reported.status === "success" && reported.facts?.abuseConfidenceScore === 100 && reported.facts.totalReports === 1, "AbuseIPDB reports are read");

    const clean = parseAbuseIpDb(fixture("abuseipdb-clean.json"));

    assert(clean.status === "observed_absence" && clean.facts?.isWhitelisted === true, "AbuseIPDB with no reports is no record, and the allowlist flag is kept");

    const domain = parseOtx(fixture("otx-domain.json"));

    assert(domain.status === "success" && domain.facts?.pulseCount === 18, `OTX report count is read: ${domain.facts?.pulseCount}`);
    assert((domain.facts?.pulses as Array<{ name: string }>)[0].name.includes("Akira"), "OTX report names are kept");
    assert(parseOtx(fixture("otx-hash.json")).facts?.pulseCount === 50, "OTX file hashes are read");
    assert(parseOtx(fixture("otx-none.json")).status === "observed_absence", "OTX with no reports is no record");

    const benign = parseOtx(fixture("otx-ip-benign.json"));

    assert(benign.status === "observed_absence" && benign.facts?.acceptedFalsePositive === true, "an OTX accepted false positive is kept");

    console.log("✓ Each service's recorded answer parses, with 'no record' kept apart from failure");
}

/* --------------------------------- Summary --------------------------------- */

const result = (source: LookupSourceId, parsed: Pick<SourceResult, "status" | "facts">): SourceResult => ({
    source, checkedAt: "2026-11-18T12:00:00.000Z", reference: null, error: null, ...parsed,
});

function testSummary(): void {
    const bad = summarise([
        result("abuseipdb", parseAbuseIpDb(fixture("abuseipdb-reported.json"))),
        result("otx", parseOtx(fixture("otx-domain.json"))),
        result("greynoise", parseGreyNoise(200, fixture("greynoise-malicious.json"))),
        result("internetdb", parseInternetDb(200, fixture("internetdb-found.json"))),
    ]);

    assert(bad.threatReports.length === 3 && /AbuseIPDB \(abuse confidence 100%, 1 reports/.test(bad.statement) && /18 community reports/.test(bad.statement), `threat reports are stated with their figures: ${bad.statement}`);
    assert(bad.exposure.some((entry) => /open ports 53, 443/.test(entry)) && !bad.threatReports.some((entry) => /InternetDB/.test(entry)), "open ports are exposure, never a threat report");

    const quiet = summarise([
        result("abuseipdb", { status: "not_configured", facts: null }),
        result("otx", parseOtx(fixture("otx-none.json"))),
        result("greynoise", parseGreyNoise(404, fixture("greynoise-none.json"))),
    ]);

    assert(/No service reports it as malicious/.test(quiet.statement) && !/safe|clean/i.test(quiet.statement), `absence is stated as no reports, never as safe: ${quiet.statement}`);
    assert(/Not checked: AbuseIPDB \(no API key\)/.test(quiet.statement), "an unconfigured service is named as not checked");

    const benign = summarise([result("otx", parseOtx(fixture("otx-ip-benign.json"))), result("greynoise", parseGreyNoise(200, fixture("greynoise-riot.json")))]);

    assert(benign.knownBenign.length === 2 && /Known benign according to/.test(benign.statement), "benign markers are stated as such");

    console.log("✓ The summary separates threat reports, exposure, benign markers, and what was not checked");
}

/* ------------------------------ Orchestration ------------------------------ */

const SETTINGS: LookupSettings = lookupSettings({ requestTimeoutMs: 2000, abuseipdbApiKey: "test-key-not-real" });

function fakeStore(overrides: Partial<{ cached: SourceResult | null; calls: number; perHour: number }> = {}) {
    const recorded: Array<{ indicator: Indicator; results: SourceResult[] }> = [];

    return {
        recorded,
        store: {
            cachedResult: async (_i: Indicator, source: LookupSourceId) => (overrides.cached && overrides.cached.source === source ? overrides.cached : null),
            callsToday: async () => overrides.calls ?? 0,
            lookupsLastHour: async () => overrides.perHour ?? 0,
            recordLookup: async (_id: string, indicator: Indicator, _by: string, results: SourceResult[]) => {
                recorded.push({ indicator, results });
            },
        },
    };
}

async function testOrchestration(): Promise<void> {
    let calls: LookupSourceId[] = [];
    const fetchSource = async (source: LookupSourceId) => {
        calls.push(source);
        return result(source, { status: "observed_absence", facts: null });
    };

    /* A private address is refused before anything is sent or recorded. */
    const privateStore = fakeStore();
    const refused = await runLookup("169.254.169.254", "u1", SETTINGS, { fetchSource, store: privateStore.store });

    assert("error" in refused && calls.length === 0 && privateStore.recorded.length === 0, "the metadata address is never sent or recorded");

    /* An IP goes to all four; a hash only to OTX. */
    const ipStore = fakeStore();
    const ip = (await runLookup("194.127.178[.]21", "u1", SETTINGS, { fetchSource, store: ipStore.store })) as LookupPayload;

    assert(calls.sort().join(",") === "abuseipdb,greynoise,internetdb,otx" && ip.indicator === "194.127.178.21", `an IP is checked by all four services: ${calls}`);
    assert(ipStore.recorded[0].results.length === 4, "every source result is recorded");

    calls = [];
    await runLookup("44d88612fea8a8f36de82e1278abb02f", "u1", SETTINGS, { fetchSource, store: fakeStore().store });
    assert(calls.join(",") === "otx", `a hash is checked only by OTX: ${calls}`);

    /* Cache, budget, and per-person limit. */
    calls = [];
    const cached = { ...result("otx", parseOtx(fixture("otx-domain.json"))), cached: true };
    const fromCache = (await runLookup("opmanager.pro", "u1", SETTINGS, { fetchSource, store: fakeStore({ cached }).store })) as LookupPayload;

    assert(calls.length === 0 && fromCache.sources[0].cached === true && fromCache.notes.some((note) => /reused/.test(note)), "a recent answer is reused and labelled");

    calls = [];
    const spent = (await runLookup("opmanager.pro", "u1", SETTINGS, { fetchSource, store: fakeStore({ calls: 99_999 }).store })) as LookupPayload;

    assert(calls.length === 0 && spent.sources[0].status === "budget_exhausted" && /budget is used/.test(spent.summary.statement), "an exhausted daily budget stops calls and is stated");

    const limited = await runLookup("opmanager.pro", "u1", SETTINGS, { fetchSource, store: fakeStore({ perHour: 20 }).store });

    assert("error" in limited && limited.error === "rate_limited", "the per-person hourly limit is enforced");

    /* The requester is the runtime's, never the model's. */
    const seen: string[] = [];
    const store = fakeStore().store;
    const tool = buildLookupTool({ requesterSenderId: "discord:111" }, SETTINGS, {
        fetchSource,
        store: { ...store, lookupsLastHour: async (by: string) => (seen.push(by), 0) },
    });
    const output = await tool.execute("x", { indicator: "opmanager.pro", requesterSenderId: "discord:999" } as never);

    assert(seen[0] === "discord:111", "the hourly limit counts the real requester, not one named in arguments");
    assert(output.content[0].text.length <= MAX_TOOL_RESULT_CHARS, "the tool result fits the size limit");

    console.log("✓ Lookups route by type, reuse answers, respect budgets and per-person limits, and never send refused input");
}

/* ------------------------------ Network edges ------------------------------ */

async function testNetwork(): Promise<void> {
    const realFetch = globalThis.fetch;
    const requests: Array<{ url: string; headers: Record<string, string> }> = [];
    let reply: () => Response = () => new Response("{}", { status: 200 });

    globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
        requests.push({ url: String(input), headers: Object.fromEntries(new Headers(init?.headers).entries()) });
        return reply();
    }) as typeof fetch;

    const ip: Indicator = { value: "194.127.178.21", type: "ipv4" };
    const options = { timeoutMs: 2000, retry: { attempts: 1, maxDelayMs: 1, budgetMs: 1 }, keys: { abuseipdb: "SECRET-KEY-123" } };

    try {
        reply = () => Response.json(fixture("abuseipdb-reported.json"));
        const abuse = await lookupSource("abuseipdb", ip, options);

        assert(abuse.status === "success" && requests[0].headers.key === "SECRET-KEY-123" && !requests[0].url.includes("SECRET"), "the key travels in a header, never in the URL");

        reply = () => new Response("{}", { status: 401 });
        const refused = await lookupSource("abuseipdb", ip, options);

        assert(refused.status === "error" && !JSON.stringify(refused).includes("SECRET"), "a refused key is reported without echoing it");

        reply = () => new Response("{}", { status: 429 });
        assert((await lookupSource("otx", ip, options)).status === "rate_limited", "429 is reported as rate limited");

        reply = () => new Response("not json", { status: 200 });
        assert((await lookupSource("otx", ip, options)).status === "error", "an unreadable answer is an error, never a clean result");

        requests.length = 0;
        assert((await lookupSource("abuseipdb", ip, { ...options, keys: {} })).status === "not_configured" && requests.length === 0, "without a key, AbuseIPDB is not called");

        assert((await lookupSource("internetdb", { value: "a.com", type: "domain" }, options)).status === "not_applicable", "a service never receives a type it does not cover");
    } finally {
        globalThis.fetch = realFetch;
    }

    console.log("✓ Keys stay in headers, failures are never read as clean, and unconfigured services are not called");
}

/* -------------------------------- Answer gate ------------------------------ */

function payload(sources: SourceResult[], indicator = "194.127.178.21"): LookupPayload {
    return { indicator, type: "ipv4", summary: summarise(sources), sources, notes: [] };
}

function testGate(): void {
    const quiet = payload([
        result("abuseipdb", parseAbuseIpDb(fixture("abuseipdb-clean.json").data.isWhitelisted ? { data: { ...fixture("abuseipdb-clean.json").data, isWhitelisted: false } } : {})),
        result("otx", parseOtx(fixture("otx-none.json"))),
    ]);

    assert(checkIndicatorAnswer("194.127.178.21 is safe.", [quiet]).some((f) => /not proof of safety/.test(f)), "'safe' from mere absence is flagged");
    assert(checkIndicatorAnswer("194.127.178[.]21 appears to be clean.", [quiet]).length === 1, "a defanged mention is matched too");
    assert(checkIndicatorAnswer("No service has reported 194.127.178.21.", [quiet]).length === 0, "'no reports' wording passes");
    assert(checkIndicatorAnswer("No reports does not mean 194.127.178.21 is safe.", [quiet]).length === 0, "a negated safety claim passes");

    const benign = payload([result("otx", parseOtx(fixture("otx-ip-benign.json")))], "8.8.8.8");

    assert(checkIndicatorAnswer("8.8.8.8 is benign; OTX lists it as a known false positive.", [benign]).length === 0, "'benign' is allowed when a service says so");

    const notConfigured = payload([result("abuseipdb", { status: "not_configured", facts: null }), result("otx", parseOtx(fixture("otx-none.json")))]);

    assert(checkIndicatorAnswer("AbuseIPDB reports 194.127.178.21 with a score of 0.", [notConfigured]).some((f) => /was not checked/.test(f)), "a result from an unchecked service is flagged");
    assert(checkIndicatorAnswer("AbuseIPDB was not checked because no API key is configured.", [notConfigured]).length === 0, "saying it was not checked passes");

    const reported = payload([result("abuseipdb", parseAbuseIpDb(fixture("abuseipdb-reported.json"))), result("otx", parseOtx(fixture("otx-domain.json")))]);

    assert(checkIndicatorAnswer("AbuseIPDB gives an abuse confidence of 85%.", [reported]).some((f) => /85%/.test(f)), "a misquoted confidence score is flagged");
    assert(checkIndicatorAnswer("AbuseIPDB gives an abuse confidence of 100% from 1 report.", [reported]).length === 0, "a correct quote passes");
    assert(checkIndicatorAnswer("AbuseIPDB lists 40 reports for it.", [reported]).some((f) => /40 AbuseIPDB reports/.test(f)), "a misquoted report count is flagged");
    assert(checkIndicatorAnswer("OTX has 25 pulses for it.", [reported]).some((f) => /25 OTX reports/.test(f)), "a misquoted OTX count is flagged");
    assert(checkIndicatorAnswer("OTX has 18 pulses for it.", [reported]).length === 0, "a correct OTX count passes");
    assert(checkIndicatorAnswer("Unrelated text about CVE-2024-3094.", []).length === 0, "no lookups, no findings");

    console.log("✓ The answer gate catches 'safe' from absence, unchecked services, and misquoted figures");
}

async function main(): Promise<void> {
    testIndicators();
    testParsers();
    testSummary();
    await testOrchestration();
    await testNetwork();
    testGate();
    console.log("Indicator lookup logic tests PASSED");
}

main().catch((error) => {
    console.error("Indicator lookup logic tests FAILED");
    console.error(error);
    process.exitCode = 1;
});
