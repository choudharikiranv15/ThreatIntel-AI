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
    parseVirusTotal,
    reserveVirusTotalCall,
    resetVirusTotalCallsForTesting,
    virusTotalUrlId,
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
    ok("hxxps://cdn.bad-host[.]example/payload.bin".replace("example", "com"), "https://cdn.bad-host.com/payload.bin", "url");
    ok("OPManager[.]PRO", "opmanager.pro", "domain");
    ok("evil[dot]com", "evil.com", "domain");
    ok("275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F", "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "sha256");
    ok("3d5ee8429ef00824c0351cba507dfeb92b54f83b", "3d5ee8429ef00824c0351cba507dfeb92b54f83b", "sha1");
    ok("44d88612fea8a8f36de82e1278abb02f", "44d88612fea8a8f36de82e1278abb02f", "md5");

    /* URLs are looked up whole, with credentials and fragments removed, and only on public hosts. */
    const url = parseIndicator("hxxp://user:pa55@Example-C2[.]com/path?q=1#frag") as Indicator;

    assert(url.type === "url" && url.value === "http://example-c2.com/path?q=1", `a URL keeps its path and query, loses credentials and fragment: ${JSON.stringify(url)}`);
    assert(/Credentials in the URL were removed/.test(url.note ?? "") && /look up example-c2\.com/.test(url.note ?? ""), "and says so, pointing to the host lookup");

    for (const internal of ["http://169.254.169.254/latest/meta-data/", "https://10.0.0.5/admin", "http://intranet.corp/x", "http://localhost:8080/"]) {
        const result = parseIndicator(internal);

        assert("error" in result, `a URL on a non-public host is refused: ${internal}`);
    }

    assert((parseIndicator("javascript:alert(1)") as { error?: string }).error !== undefined, "a non-web scheme is refused");
    assert((parseIndicator("file:///etc/passwd") as { error?: string }).error === "unsupported", "file URLs are refused");

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

    /* AbuseIPDB reports it no longer rates as abusive are not a threat report (seen live: 118.25.6.39, 8.8.8.8). */
    const zero = (data: Record<string, unknown>) => result("abuseipdb", parseAbuseIpDb({ data: { abuseConfidenceScore: 0, ...data } }));
    const stale = summarise([zero({ totalReports: 2, numDistinctUsers: 2 })]);

    assert(stale.threatReports.length === 0 && stale.lowConfidence.length === 1, "0% confidence reports are low confidence, not a threat report");
    assert(/No service reports it as malicious/.test(stale.statement) && /Past reports the service no longer rates as abusive: AbuseIPDB \(2 past reports from 2 reporters, abuse confidence 0%\)/.test(stale.statement), `and the statement says so: ${stale.statement}`);

    const allowlisted = summarise([zero({ totalReports: 199, numDistinctUsers: 64, isWhitelisted: true })]);

    assert(!/Reported as malicious/.test(allowlisted.statement) && allowlisted.knownBenign.length === 1, `an allowlisted address is never called malicious: ${allowlisted.statement}`);

    const scored = summarise([result("abuseipdb", parseAbuseIpDb({ data: { abuseConfidenceScore: 1, totalReports: 3, numDistinctUsers: 1 } }))]);

    assert(scored.threatReports.length === 1 && /abuse confidence 1%/.test(scored.statement), "any confidence above zero is a threat report, with its figure");

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

    /* An IP goes to all five; a hash to OTX and VirusTotal; a URL to VirusTotal and OTX. */
    const ipStore = fakeStore();
    const ip = (await runLookup("194.127.178[.]21", "u1", SETTINGS, { fetchSource, store: ipStore.store })) as LookupPayload;

    assert(calls.sort().join(",") === "abuseipdb,greynoise,internetdb,otx,virustotal" && ip.indicator === "194.127.178.21", `an IP is checked by all five services: ${calls}`);
    assert(ipStore.recorded[0].results.length === 5, "every source result is recorded");

    calls = [];
    await runLookup("44d88612fea8a8f36de82e1278abb02f", "u1", SETTINGS, { fetchSource, store: fakeStore().store });
    assert(calls.sort().join(",") === "otx,virustotal", `a hash is checked by OTX and VirusTotal: ${calls}`);

    calls = [];
    const urlLookup = (await runLookup("hxxps://evil[.]com/login", "u1", SETTINGS, { fetchSource, store: fakeStore().store })) as LookupPayload;
    assert(calls.sort().join(",") === "otx,virustotal" && urlLookup.type === "url" && /look up evil\.com/.test(urlLookup.note ?? ""), `a URL is checked by the URL services: ${calls}`);

    /* Cache, budget, and per-person limit. */
    calls = [];
    const cached = { ...result("otx", parseOtx(fixture("otx-domain.json"))), cached: true };
    const fromCache = (await runLookup("opmanager.pro", "u1", SETTINGS, { fetchSource, store: fakeStore({ cached }).store })) as LookupPayload;

    assert(
        calls.join(",") === "virustotal" && fromCache.sources.find((s) => s.source === "otx")?.cached === true && fromCache.notes.some((note) => /reused/.test(note)),
        `a recent answer is reused and labelled; only the uncached service is called: ${calls}`,
    );

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

        /* VirusTotal: key in the x-apikey header, report reads only, 404 is no record, per-minute limit. */
        const vt = { ...options, keys: { virustotal: "VT-SECRET-456" }, virustotalPerMinute: 4 };
        const methods: string[] = [];

        globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
            requests.push({ url: String(input), headers: Object.fromEntries(new Headers(init?.headers).entries()) });
            methods.push(init?.method ?? "GET");
            return reply();
        }) as typeof fetch;

        resetVirusTotalCallsForTesting();
        requests.length = 0;
        reply = () => Response.json(fixture("virustotal-url.json"));

        const page = "http://www.eicar.org/download/eicar.com.txt";
        const vtUrl = await lookupSource("virustotal", { value: page, type: "url" }, vt);

        assert(vtUrl.status === "success" && requests[0].url === `https://www.virustotal.com/api/v3/urls/${virusTotalUrlId(page)}`, `a URL is read by its VirusTotal id: ${requests[0]?.url}`);
        assert(requests[0].headers["x-apikey"] === "VT-SECRET-456" && !requests[0].url.includes("VT-SECRET") && !JSON.stringify(vtUrl).includes("VT-SECRET"), "the VirusTotal key stays in the header and out of results");
        assert(virusTotalUrlId(page) === "aHR0cDovL3d3dy5laWNhci5vcmcvZG93bmxvYWQvZWljYXIuY29tLnR4dA", "the URL id is unpadded base64url, as VirusTotal defines it");
        assert(/^https:\/\/www\.virustotal\.com\/gui\/url\/[0-9a-f]{64}$/.test(vtUrl.reference ?? ""), "the reference links to the URL's report page");

        reply = () => new Response(JSON.stringify(fixture("virustotal-none.json")), { status: 404 });
        assert((await lookupSource("virustotal", { value: "0".repeat(63) + "1", type: "sha256" }, vt)).status === "observed_absence", "an unknown hash is no record, not an error");

        reply = () => Response.json(fixture("virustotal-ip.json"));
        await lookupSource("virustotal", { value: "8.8.8.8", type: "ipv4" }, vt);
        await lookupSource("virustotal", { value: "opmanager.pro", type: "domain" }, vt);

        const fifth = requests.length;
        const overLimit = await lookupSource("virustotal", { value: "8.8.4.4", type: "ipv4" }, vt);

        assert(overLimit.status === "rate_limited" && requests.length === fifth, "a fifth request within a minute is not sent");
        assert(methods.every((method) => method === "GET") && requests.every((r) => !/\/analyse|\/scan|\/files$|\/urls$/.test(r.url)), "nothing is ever submitted for scanning");

        requests.length = 0;
        resetVirusTotalCallsForTesting();
        assert((await lookupSource("virustotal", ip, { ...options, keys: {} })).status === "not_configured" && requests.length === 0, "without a key, VirusTotal is not called");

        const now = 1_000_000;
        resetVirusTotalCallsForTesting();
        for (let i = 0; i < 4; i += 1) reserveVirusTotalCall(4, now + i);
        assert(!reserveVirusTotalCall(4, now + 59_000) && reserveVirusTotalCall(4, now + 60_001), "the per-minute window slides");
        resetVirusTotalCallsForTesting();
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

    const vtDomain = payload([result("virustotal", parseVirusTotal(200, fixture("virustotal-domain.json"), "domain"))], "opmanager.pro");

    assert(checkIndicatorAnswer("VirusTotal: 20 of 92 engines flag opmanager.pro as malicious.", [vtDomain]).some((f) => /20 VirusTotal detections/.test(f)), "a misquoted VirusTotal count is flagged");
    assert(checkIndicatorAnswer("VirusTotal: 11 of 92 engines flag opmanager.pro as malicious.", [vtDomain]).length === 0, "a correct VirusTotal count passes");
    assert(checkIndicatorAnswer("VirusTotal shows 1 engine rating opmanager.pro suspicious.", [vtDomain]).length === 0, "the suspicious count is checked against suspicious");

    const vtMissing = payload([result("virustotal", { status: "not_configured", facts: null })], "opmanager.pro");

    assert(checkIndicatorAnswer("VirusTotal flagged opmanager.pro with 11 detections.", [vtMissing]).some((f) => /was not checked/.test(f)), "a VirusTotal result without a VirusTotal check is flagged");

    console.log("✓ The answer gate catches 'safe' from absence, unchecked services, and misquoted figures");
}

function testVirusTotal(): void {
    const ip = parseVirusTotal(200, fixture("virustotal-ip.json"), "ipv4");
    const f = ip.facts as Record<string, unknown>;

    assert(ip.status === "success" && f.malicious === 1 && f.engines === 92 && f.asOwner === "Google LLC" && f.asn === 15169 && (f.flaggedMalicious as unknown[]).length === 1, `IP reports are read: ${JSON.stringify(f).slice(0, 200)}`);

    const file = parseVirusTotal(200, fixture("virustotal-file.json"), "sha256").facts as Record<string, unknown>;

    assert(file.malicious === 65 && file.engines === 67 && file.threatLabel === "virus.eicar/test" && (file.flaggedMalicious as unknown[]).length === 8, "file reports give the label, and list at most 8 engines; unsupported types are not counted");

    const url = parseVirusTotal(200, fixture("virustotal-url.json"), "url").facts as Record<string, unknown>;

    assert(url.malicious === 12 && url.suspicious === 1 && typeof url.finalUrl === "string", "URL reports are read");
    assert(parseVirusTotal(404, fixture("virustotal-none.json"), "sha256").status === "observed_absence", "404 is no record");

    /* The summary: detections are counts, a clean scan is not 'safe', suspicious alone is low confidence. */
    const flagged = summarise([result("virustotal", parseVirusTotal(200, fixture("virustotal-file.json"), "sha256"))]);

    assert(/VirusTotal \(65 of 67 engines flag it malicious, labelled virus\.eicar\/test\)/.test(flagged.statement), `detections are stated as counts with the label: ${flagged.statement}`);

    const none = summarise([result("virustotal", parseVirusTotal(200, fixture("virustotal-badip.json"), "ipv4"))]);

    assert(/No detections: VirusTotal \(0 of 92 engines\)/.test(none.statement) && !/safe|clean/i.test(none.statement), `no detections is stated as such: ${none.statement}`);

    const suspicious = summarise([result("virustotal", parseVirusTotal(200, { data: { attributes: { last_analysis_stats: { malicious: 0, suspicious: 2, harmless: 60, undetected: 30 } } } }, "domain"))]);

    assert(suspicious.threatReports.length === 0 && /2 of 92 engines rate it suspicious/.test(suspicious.statement), "suspicious without malicious is not a threat report");

    console.log("✓ VirusTotal reports are read as engine counts, and stated without overclaiming");
}

async function main(): Promise<void> {
    testIndicators();
    testVirusTotal();
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
