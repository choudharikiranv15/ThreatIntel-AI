/*
 * Team memory against real PostgreSQL: earlier lookups and feed articles are
 * found for an indicator, the current lookup is excluded, defanged article
 * indicators match, and a retro-hunt alert is queued once.
 */
import { randomUUID } from "node:crypto";

import { insertRetroAlert } from "../feed/store.js";
import type { Indicator } from "../lookup/indicator.js";
import * as lookups from "../lookup/store.js";
import type { SourceResult } from "../lookup/sources.js";
import { retroHuntMatches, teamHistory } from "../memory/history.js";
import { db } from "./db.js";

function assert(condition: unknown, message: string): asserts condition {
    if (!condition) {
        throw new Error(`Assertion failed: ${message}`);
    }
}

const RUN = `mem${Date.now() % 1_000_000}`;
const ip: Indicator = { value: `45.33.${Date.now() % 200}.77`, type: "ipv4" };
const fresh: Indicator = { value: `45.34.${Date.now() % 200}.78`, type: "ipv4" };
const itemKey = `unit42:${RUN}`;
const result = (): SourceResult => ({ source: "otx", status: "observed_absence", checkedAt: new Date().toISOString(), reference: null, facts: null, error: null });

async function main(): Promise<void> {
    const runId = randomUUID();

    try {
        /* Two earlier lookups by two people, and the one being made now. */
        await lookups.recordLookup(randomUUID(), ip, `discord:${RUN}-a`, [result()]);
        await lookups.recordLookup(randomUUID(), ip, `discord:${RUN}-b`, [result()]);

        const current = randomUUID();

        await lookups.recordLookup(current, ip, `discord:${RUN}-a`, [result()]);

        /* A feed article that published the indicator defanged. */
        await db.query(
            `INSERT INTO public.feed_items (item_key, source, title, url, published_at, iocs, priority, confidence, content_hash, state, last_published_at, expires_at)
             VALUES ($1, 'unit42', $2, 'https://unit42.example/memory-test', now(), $3::jsonb, 'P3', 'high', 'x', 'published', now(), now() + interval '30 days')`,
            [itemKey, `Memory test article ${RUN}`, JSON.stringify([{ type: "ipv4", value: ip.value.replace(/\./g, "[.]"), source: "https://unit42.example/memory-test" }])],
        );

        const history = await teamHistory(ip, current);

        assert(history.previousLookups === 2 && history.analysts === 2, `earlier lookups are counted, the current one excluded: ${JSON.stringify(history)}`);
        assert(history.feed.length === 1 && history.feed[0].source === "Unit 42" && history.feed[0].posted, `a defanged article indicator is matched: ${JSON.stringify(history.feed)}`);
        assert(/Looked up 2 times before by 2 analysts/.test(history.statement) && /posted to the threat feed/.test(history.statement), history.statement);
        assert(!history.statement.includes(`discord:${RUN}`) && !/discord:/.test(history.statement), "who looked it up is never shown");

        const none = await teamHistory(fresh, randomUUID());

        assert(none.previousLookups === 0 && none.feed.length === 0 && none.statement === "Not looked up by the team before.", "an unknown indicator has no history");

        /* Retro-hunt with the real query. */
        const matches = await retroHuntMatches([{ itemKey: `dfir-report:${RUN}`, iocs: [{ value: ip.value.replace(/\./g, "[.]"), type: "ipv4" }, { value: fresh.value, type: "ipv4" }] }]);

        assert(matches.length === 1 && matches[0].indicator === ip.value && matches[0].lookups === 3, `only indicators the team looked up are matched: ${JSON.stringify(matches)}`);

        /* A retro-hunt alert is queued once per article and indicator. */
        assert(await insertRetroAlert(runId, itemKey, ip.value, "retro test"), "the first alert is queued");
        assert(!(await insertRetroAlert(randomUUID(), itemKey, ip.value, "retro test again")), "the same match is never queued twice");

        const { rows } = await db.query("SELECT channel, kind, field, delivery_status FROM public.watch_events WHERE fingerprint = $1", [`retro:${itemKey}:${ip.value}`]);

        assert(rows.length === 1 && rows[0].channel === "feed" && rows[0].field === "retro_hunt" && rows[0].delivery_status === "pending", "it goes to the feed channel through the outbox");

        console.log("✓ Team history and retro-hunt work against the database, without naming anyone");
        console.log("Team memory database tests PASSED");
    } finally {
        await db.query("DELETE FROM public.watch_events WHERE fingerprint LIKE $1", [`retro:%${RUN}%`]).catch(() => undefined);
        await db.query("DELETE FROM public.feed_items WHERE item_key = $1", [itemKey]).catch(() => undefined);
        await db.query("DELETE FROM public.indicator_lookups WHERE requested_by LIKE $1", [`discord:${RUN}%`]).catch(() => undefined);
        await db.end();
    }
}

main().catch((error) => {
    console.error("Team memory database tests FAILED");
    console.error(error);
    process.exitCode = 1;
});
