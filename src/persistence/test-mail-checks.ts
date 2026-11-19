/*
 * MXToolbox checks against real PostgreSQL: the cache, the daily budget, the
 * per-person hourly limit, recording, and pruning. Headers are never stored.
 */
import fs from "node:fs";
import path from "node:path";
import { randomUUID } from "node:crypto";

import { runHeaderAnalysis, type HeaderAnalysisPayload } from "../email/analyze.js";
import type { MailCheck, MailCheckCommand } from "../email/mxtoolbox.js";
import * as store from "../email/store.js";
import { headerAnalysisSettings } from "../email/tool.js";
import { db } from "./db.js";

function assert(condition: unknown, message: string): asserts condition {
    if (!condition) {
        throw new Error(`Assertion failed: ${message}`);
    }
}

const RUN = `m${Date.now() % 1_000_000}`;
const who = `discord:${RUN}`;
const domain = `${RUN}.example-mail.com`;
const headers = fs.readFileSync(path.join(process.cwd(), "test-fixtures", "email", "legit.txt"), "utf8").replace(/gmail\.com/g, domain);

const make = (command: MailCheckCommand, argument: string, status: MailCheck["status"] = "success", extra: Partial<MailCheck> = {}): MailCheck => ({
    command,
    argument,
    status,
    checkedAt: new Date().toISOString(),
    reference: null,
    facts: status === "success" ? { records: ["v=DMARC1; p=reject"], failed: [], warnings: [], passed: [], policy: "reject" } : null,
    error: null,
    ...extra,
});

async function main(): Promise<void> {
    try {
        /* Recording and the cache. */
        await store.recordMailChecks(randomUUID(), who, [make("dmarc", domain), make("spf", domain, "error")]);

        const cached = await store.cachedMailCheck("dmarc", domain, 24);

        assert(cached?.cached === true && cached.facts?.policy === "reject", "a recent answer is served from the cache");
        assert((await store.cachedMailCheck("spf", domain, 24)) === null, "a failure is never cached");
        assert((await store.cachedMailCheck("dmarc", domain, 0)) === null, "an answer older than the cache window is not reused");

        /* The budget counts real calls only. */
        const before = await store.mailCallsToday();

        await store.recordMailChecks(randomUUID(), who, [make("dkim", `${domain}:s1`, "budget_exhausted"), make("dmarc", domain, "success", { cached: true })]);
        assert((await store.mailCallsToday()) === before, "budget-exhausted and cached checks do not use budget");

        await store.recordMailChecks(randomUUID(), who, [make("spf", domain)]);
        assert((await store.mailCallsToday()) === before + 1, "a real call uses budget");

        /* The per-person limit counts analyses, not rows. */
        assert((await store.analysesLastHour(who)) === 3, `three analyses by this person in the last hour: ${await store.analysesLastHour(who)}`);
        assert((await store.analysesLastHour(`${who}-other`)) === 0, "another person's analyses are not counted");

        /* End to end with the real store and a fake MXToolbox. */
        let calls = 0;
        const fetchRecord = async (command: MailCheckCommand, argument: string) => (calls += 1, make(command, argument));
        const settings = { ...headerAnalysisSettings({ mxtoolboxApiKey: "test-key-not-real" }), perUserPerHour: 5 };
        const first = (await runHeaderAnalysis(headers, `${who}-b`, settings, { fetchRecord })) as HeaderAnalysisPayload;

        assert(first.dnsChecks.length === 3 && first.dnsChecks.filter((c) => c.cached).length === 1 && calls === 2, `cached DMARC is reused, SPF and DKIM are fetched: ${calls}`);

        const { rows } = await db.query("SELECT count(*)::int AS n FROM public.mail_checks WHERE requested_by = $1", [`${who}-b`]);
        const stored = await db.query("SELECT facts::text AS f, argument FROM public.mail_checks WHERE requested_by = $1", [`${who}-b`]);

        assert(rows[0].n === 3, "every check is recorded");
        assert(stored.rows.every((r) => !/analyst@example\.org|second\.recipient|Quarterly report/.test(`${r.f} ${r.argument}`)), "no header content, recipient, or subject is stored");

        calls = 0;
        await runHeaderAnalysis(headers, `${who}-c`, settings, { fetchRecord });
        assert(calls === 0, "a second analysis of the same sender is served from the cache");

        /* Budget exhaustion through the real ledger. */
        const tight = { ...settings, cacheHours: 0, dailyBudget: 0 };
        const spent = (await runHeaderAnalysis(headers, `${who}-d`, tight, { fetchRecord })) as HeaderAnalysisPayload;

        assert(calls === 0 && spent.dnsChecks.every((c) => c.status === "budget_exhausted"), "an exhausted budget is enforced from the database");

        await store.pruneMailChecks();
        assert((await store.analysesLastHour(who)) >= 3, "pruning keeps recent checks");

        console.log("✓ MXToolbox checks are cached, budgeted, limited per person, and recorded without header content");
        console.log("Mail check database tests PASSED");
    } finally {
        await db.query("DELETE FROM public.mail_checks WHERE requested_by LIKE $1", [`${who}%`]).catch(() => undefined);
        await db.end();
    }
}

main().catch((error) => {
    console.error("Mail check database tests FAILED");
    console.error(error);
    process.exitCode = 1;
});
