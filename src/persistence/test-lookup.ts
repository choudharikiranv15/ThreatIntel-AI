/*
 * Indicator lookups against real PostgreSQL: the cache, daily budgets, the
 * per-person hourly limit, recording, and pruning.
 */
import { randomUUID } from "node:crypto";

import type { Indicator } from "../lookup/indicator.js";
import { runLookup } from "../lookup/lookup.js";
import type { LookupSourceId, SourceResult } from "../lookup/sources.js";
import * as store from "../lookup/store.js";
import { lookupSettings } from "../lookup/tool.js";
import { db } from "./db.js";

function assert(condition: unknown, message: string): asserts condition {
    if (!condition) {
        throw new Error(`Assertion failed: ${message}`);
    }
}

const RUN = `t${Date.now() % 1_000_000}`;
const ip: Indicator = { value: `198.51.${Date.now() % 200}.9`.replace("198.51.", "45.33."), type: "ipv4" };
const who = `discord:${RUN}`;

const make = (source: LookupSourceId, status: SourceResult["status"], extra: Partial<SourceResult> = {}): SourceResult => ({
    source,
    status,
    checkedAt: new Date().toISOString(),
    reference: null,
    facts: status === "success" ? { pulseCount: 3 } : null,
    error: null,
    ...extra,
});

async function main(): Promise<void> {
    try {
        /* Recording and the cache. */
        await store.recordLookup(randomUUID(), ip, who, [make("otx", "success"), make("greynoise", "error"), make("abuseipdb", "not_configured")]);

        const cached = await store.cachedResult(ip, "otx", 12);

        assert(cached?.cached === true && cached.status === "success" && (cached.facts as { pulseCount: number }).pulseCount === 3, "a recent answer is served from the cache");
        assert((await store.cachedResult(ip, "greynoise", 12)) === null, "a failure is never cached");
        assert((await store.cachedResult(ip, "otx", 0)) === null, "an answer older than the cache window is not reused");

        /* Budgets count real calls only. */
        const before = await store.callsToday("abuseipdb");

        await store.recordLookup(randomUUID(), ip, who, [make("abuseipdb", "not_configured"), make("otx", "success", { cached: true })]);
        assert((await store.callsToday("abuseipdb")) === before, "an unconfigured service does not use budget");

        const otxBefore = await store.callsToday("otx");

        await store.recordLookup(randomUUID(), ip, who, [make("otx", "success", { cached: true })]);
        assert((await store.callsToday("otx")) === otxBefore, "a cached answer does not use budget");

        await store.recordLookup(randomUUID(), ip, who, [make("otx", "observed_absence")]);
        assert((await store.callsToday("otx")) === otxBefore + 1, "a real call uses budget");

        /* Per-person limit counts lookups, not rows. */
        assert((await store.lookupsLastHour(who)) === 4, `four lookups by this person in the last hour: ${await store.lookupsLastHour(who)}`);
        assert((await store.lookupsLastHour(`${who}-other`)) === 0, "another person's lookups are not counted");

        /* End to end, with the real store and a fake network. */
        const settings = { ...lookupSettings({}), perUserPerHour: 5 };
        let calls = 0;
        const fetchSource = async (source: LookupSourceId) => (calls += 1, make(source, "observed_absence"));

        const first = await runLookup(ip.value, who, settings, { fetchSource });

        assert(!("error" in first) && first.sources.length === 4, "the lookup runs and is recorded");

        const otxCallsBefore = calls;
        const second = await runLookup(ip.value, who, settings, { fetchSource });

        assert("error" in second && second.error === "rate_limited", "the sixth lookup within the hour is refused");
        assert(calls === otxCallsBefore, "a refused lookup calls no service");

        const reused = await runLookup(ip.value, `${who}-b`, settings, { fetchSource });

        assert(!("error" in reused) && reused.sources.every((source) => source.cached) && calls === otxCallsBefore, "another person's identical lookup is served from the cache");

        /* Budget exhaustion through the real ledger. */
        const tight = { ...settings, cacheHours: 0, dailyBudgets: { internetdb: 0, greynoise: 0, abuseipdb: 0, otx: 0 } };
        const spent = await runLookup("opmanager.pro", `${who}-c`, tight, { fetchSource });

        assert(!("error" in spent) && spent.sources.every((source) => source.status === "budget_exhausted"), "an exhausted budget is enforced from the database");

        /* Pruning keeps recent history. */
        await store.pruneLookups();
        assert((await store.lookupsLastHour(who)) >= 4, "pruning keeps recent lookups");

        console.log("✓ Lookups are cached, budgeted, limited per person, and recorded");
        console.log("Indicator lookup database tests PASSED");
    } finally {
        await db.query("DELETE FROM public.indicator_lookups WHERE requested_by LIKE $1", [`${who}%`]).catch(() => undefined);
        await db.end();
    }
}

main().catch((error) => {
    console.error("Indicator lookup database tests FAILED");
    console.error(error);
    process.exitCode = 1;
});
