/*
 * Team memory, offline: how history is stated, how it reaches lookups and
 * triage, retro-hunt matching, and the retro-hunt post. The database queries
 * are tested in persistence/test-memory.ts.
 */
import { formatRetroHuntAlert } from "./feed/format.js";
import type { Indicator } from "./lookup/indicator.js";
import { runLookup, type LookupPayload } from "./lookup/lookup.js";
import type { LookupSourceId, SourceResult } from "./lookup/sources.js";
import { lookupSettings } from "./lookup/tool.js";
import { historyStatement, retroHuntMatches, RETRO_MAX_PER_CYCLE, type TeamHistory } from "./memory/history.js";
import { triageSettings } from "./triage/tool.js";
import { runTriage } from "./triage/triage.js";

function assert(condition: unknown, message: string): asserts condition {
    if (!condition) {
        throw new Error(`Assertion failed: ${message}`);
    }
}

/* -------------------------------- Statements -------------------------------- */

function testStatements(): void {
    const none = historyStatement({ previousLookups: 0, analysts: 0, firstAt: null, lastAt: null, feed: [] });
    const once = historyStatement({ previousLookups: 1, analysts: 1, firstAt: "2026-11-12T10:00:00Z", lastAt: "2026-11-12T10:00:00Z", feed: [] });
    const many = historyStatement({
        previousLookups: 3,
        analysts: 2,
        firstAt: "2026-11-01T10:00:00Z",
        lastAt: "2026-11-18T09:00:00Z",
        feed: [{ title: "Akira loader returns", source: "Unit 42", url: "https://unit42.example/a", date: "2026-11-18T00:00:00Z", posted: true }],
    });

    assert(none === "Not looked up by the team before.", none);
    assert(once === "Looked up once before by the team (2026-11-12).", once);
    assert(/Looked up 3 times before by 2 analysts \(first 2026-11-01, last 2026-11-18\)\./.test(many) && /Listed as an indicator in "Akira loader returns" \(Unit 42, 2026-11-18\), posted to the threat feed\./.test(many), many);
    assert(!/discord:|requested_by|\d{17,}/.test(many), "who looked it up is never shown");

    console.log("✓ Team history is stated as counts and dates, never who");
}

/* ------------------------- Lookups and triage get it ------------------------- */

const make = (source: LookupSourceId): SourceResult => ({ source, status: "observed_absence", checkedAt: new Date().toISOString(), reference: null, facts: null, error: null });

function fakeStore() {
    return {
        cachedResult: async () => null,
        callsToday: async () => 0,
        lookupsLastHour: async () => 0,
        recordLookup: async () => undefined,
    };
}

async function testLookups(): Promise<void> {
    const seen: Array<{ indicator: string; lookupId: string }> = [];
    const known: TeamHistory = {
        previousLookups: 2,
        analysts: 1,
        firstAt: "2026-11-10T00:00:00Z",
        lastAt: "2026-11-18T00:00:00Z",
        feed: [{ title: "Tor exits in loader campaign", source: "The DFIR Report", url: "https://dfir.example/x", date: "2026-11-19T00:00:00Z", posted: true }],
        statement: "",
    };
    known.statement = historyStatement(known);

    const history = async (indicator: Indicator, lookupId: string) => {
        seen.push({ indicator: indicator.value, lookupId });
        return indicator.value === "185.220.101.47" ? known : { ...known, previousLookups: 0, feed: [], statement: "Not looked up by the team before." };
    };

    const deps = { fetchSource: async (source: LookupSourceId) => make(source), store: fakeStore(), history };
    const settings = lookupSettings({ abuseipdbApiKey: "k" });
    const single = (await runLookup("185.220.101[.]47", "u", settings, deps)) as LookupPayload;

    assert(single.history?.previousLookups === 2 && /Listed as an indicator in "Tor exits in loader campaign"/.test(single.history.statement), "a lookup carries the team history");
    assert(seen.length === 1 && /^[0-9a-f-]{36}$/.test(seen[0].lookupId), "history excludes the lookup being made, by its id");

    /* With the real store missing, nothing touches the database. */
    const quiet = (await runLookup("8.8.8.8", "u", settings, { fetchSource: deps.fetchSource, store: fakeStore() })) as LookupPayload;

    assert(quiet.history === undefined, "no history source, no history");

    /* A failing history never fails the lookup. */
    const failing = (await runLookup("8.8.8.8", "u", settings, { ...deps, history: async () => Promise.reject(new Error("db down")) })) as LookupPayload;

    assert(!("error" in failing) && failing.history === undefined && failing.sources.length > 0, "a history failure leaves the lookup intact");

    /* Triage: history once per indicator, and only shown when there is something to say. */
    seen.length = 0;
    const triaged = await runTriage("connections to 185.220.101.47 and 45.33.10.9, hash 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "u", triageSettings({ abuseipdbApiKey: "k", virustotalApiKey: "k" }), deps);

    assert(!("error" in triaged), "the triage runs");
    assert(seen.length === 3 && new Set(seen.map((s) => s.lookupId)).size === 1, `history is asked once per indicator, under the triage's one id: ${seen.length}`);

    const tor = triaged.payload.results.find((r) => r.indicator === "185.220.101.47")!;
    const other = triaged.payload.results.find((r) => r.indicator === "45.33.10.9")!;

    assert(/Looked up 2 times before/.test(tor.seenBefore ?? "") && other.seenBefore === undefined, "seenBefore appears only where the team or the feed knows the indicator");

    console.log("✓ Lookups and triage carry team history, without blocking on it or repeating it");
}

/* -------------------------------- Retro-hunt -------------------------------- */

async function testRetroHunt(): Promise<void> {
    const asked: string[][] = [];
    const query = async (values: string[]) => {
        asked.push(values);
        return [
            { indicator: "185.220.101.47", n: 2, last: new Date("2026-11-18T09:00:00Z") },
            { indicator: "opmanager.pro", n: 1, last: new Date("2026-11-19T09:00:00Z") },
        ];
    };

    const matches = await retroHuntMatches(
        [
            { itemKey: "unit42:akira", iocs: [{ value: "185.220.101[.]47", type: "ipv4" }, { value: "svchost.exe", type: "filename" }, { value: "10.0.0.5", type: "ipv4" }] },
            { itemKey: "dfir-report:x", iocs: [{ value: "opmanager[.]pro" }, { value: "185.220.101.47" }] },
        ],
        query,
    );

    assert(asked.length === 1 && asked[0].includes("185.220.101.47") && asked[0].includes("opmanager.pro"), `defanged indicators are matched in plain form: ${asked[0]}`);
    assert(!asked[0].some((v) => /svchost|10\.0\.0\.5/.test(v)), "file names and internal addresses are never looked for");
    assert(matches.length === 2 && matches[0].indicator === "opmanager.pro" && matches[0].published === "opmanager[.]pro", "matches keep the published form, most recent lookup first");
    assert(matches.find((m) => m.indicator === "185.220.101.47")?.itemKey === "unit42:akira", "an indicator in two articles is reported once, for the first");

    assert((await retroHuntMatches([{ itemKey: "x", iocs: [{ value: "evil.exe", type: "filename" }] }], async () => assert(false, "no query without indicators") as never)).length === 0, "no indicators, no query");

    const many = await retroHuntMatches(
        [{ itemKey: "big", iocs: Array.from({ length: 12 }, (_, i) => ({ value: `45.33.${i}.9` })) }],
        async (values) => values.map((v, i) => ({ indicator: v, n: 1, last: new Date(Date.UTC(2026, 10, 1 + i)) })),
    );

    assert(many.length === RETRO_MAX_PER_CYCLE, "at most a handful of retro-hunt posts per cycle");

    /* The post. */
    const post = formatRetroHuntAlert({
        published: "185.220.101[.]47",
        title: "Akira @everyone returns <@123>",
        source: "Unit 42",
        url: "https://unit42.paloaltonetworks.com/akira/",
        lookups: 2,
        lastAt: "2026-11-18T09:00:00Z",
        days: 90,
    });

    assert(post.includes("**Retro-hunt match**") && post.includes("`185.220.101[.]47` was looked up by the team 2 times in the last 90 days (last on 2026-11-18)"), post);
    assert(!post.includes("@everyone") && !post.includes("<@123>"), "article titles cannot ping anyone");
    assert(post.includes("<https://unit42.paloaltonetworks.com/akira/>") && post.length < 1950, "the link does not unfurl, and the post fits Discord");

    console.log("✓ Retro-hunt finds earlier lookups in new articles, defanged or not, and posts them safely");
}

async function main(): Promise<void> {
    testStatements();
    await testLookups();
    await testRetroHunt();
    console.log("Team memory logic tests PASSED");
}

main().catch((error) => {
    console.error("Team memory logic tests FAILED");
    console.error(error);
    process.exitCode = 1;
});
