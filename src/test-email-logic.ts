/*
 * Email header analysis, offline: parsing, authentication results, sender
 * mismatches, the Received chain, privacy, MXToolbox parsing and limits, and
 * the answer-gate check. Database behaviour is in persistence/test-mail-checks.ts.
 */
import fs from "node:fs";
import path from "node:path";

import { plannedChecks, runHeaderAnalysis, type HeaderAnalysisPayload, type HeaderAnalysisSettings } from "./email/analyze.js";
import { analyseHeaders, decodeWords, MAX_HEADER_INPUT, organisationalDomain, splitHeaders, type HeaderAnalysis } from "./email/headers.js";
import { lookupMailRecord, parseMxToolbox, type MailCheck, type MailCheckCommand } from "./email/mxtoolbox.js";
import { buildHeaderTool, headerAnalysisSettings } from "./email/tool.js";
import { MAX_TOOL_RESULT_CHARS } from "./tool-result.js";
import { checkEmailAnswer } from "./verification/check-email.js";
import { findDisclosures } from "./verification/disclosure-guard.js";

function assert(condition: unknown, message: string): asserts condition {
    if (!condition) {
        throw new Error(`Assertion failed: ${message}`);
    }
}

const text = (name: string) => fs.readFileSync(path.join(process.cwd(), "test-fixtures", "email", name), "utf8");
const json = (name: string) => JSON.parse(text(name));
const codes = (a: HeaderAnalysis) => a.findings.map((f) => f.code);
const analysed = (name: string) => {
    const result = analyseHeaders(text(name));

    assert(!("error" in result), `${name} parses: ${JSON.stringify(result)}`);
    return result;
};

/* --------------------------------- Parsing -------------------------------- */

function testParsing(): void {
    const headers = splitHeaders("Subject: one\n two\nFrom: a@b.com\n\nReceived: from body (x [203.0.113.9])");

    assert(headers.length === 2 && headers[0].value === "one two", "folded lines are unfolded, and the body is never read");
    assert(decodeWords("=?UTF-8?B?WW91ciBhY2NvdW50?= =?utf-8?Q?is_limited?=").includes("Your account"), "encoded words are decoded");
    assert(organisationalDomain("mail.paypal.co.uk") === "paypal.co.uk" && organisationalDomain("a.b.example.com") === "example.com", "organisational domains handle common second-level registries");

    /* A normal, authenticated message. */
    const legit = analysed("legit.txt");

    assert(legit.authentication?.authservId === "mx.google.com" && legit.authentication.spf?.result === "pass" && legit.authentication.dkim[0]?.result === "pass" && legit.authentication.dmarc?.result === "pass", "the receiving server's results are read");
    assert(legit.from?.domain === "gmail.com" && legit.originatingIp === "209.85.220.41", `the sender and sending server are found: ${legit.originatingIp}`);
    assert(!legit.hops.some((hop) => hop.fromIp === "203.0.113.66"), "a Received line in the body is not a hop");
    assert(legit.findings.every((f) => f.severity === "info"), `an authenticated, aligned message has no concerns: ${codes(legit)}`);
    assert(legit.dkimSignatures[0]?.domain === "gmail.com" && legit.dkimSignatures[0].selector === "20230601", "the DKIM signature's domain and selector are read");

    /* A spoofed phish, with a forged Authentication-Results further down. */
    const phish = analysed("phish.txt");

    assert(phish.authentication?.dmarc?.result === "fail" && phish.authentication.spf?.result === "softfail", "only the topmost Authentication-Results is used");
    assert(phish.otherAuthResults === 1 && codes(phish).includes("extra_auth_results"), "a lower, possibly forged, result is reported as ignored");

    for (const code of ["dmarc_fail", "spf_fail", "dkim_none", "reply_to_mismatch", "display_name_spoof", "hop_time_order", "x_originating_ip"]) {
        assert(codes(phish).includes(code), `the phish shows ${code}: ${codes(phish)}`);
    }

    assert(phish.originatingIp === "185.220.101.47", `the first public hop is the sending server, not localhost: ${phish.originatingIp}`);
    assert(phish.subject === "Your account has been limited", `the subject is decoded: ${phish.subject}`);

    /* Microsoft 365: no server name, composite authentication, DKIM for another domain. */
    const microsoft = analysed("microsoft.txt");

    assert(microsoft.authentication?.authservId === null && microsoft.authentication.spf?.result === "pass", "a result list without a server name is read from the start");

    for (const code of ["dmarc_fail", "compauth_fail", "dkim_unaligned", "return_path_mismatch"]) {
        assert(codes(microsoft).includes(code), `the Microsoft sample shows ${code}: ${codes(microsoft)}`);
    }

    /* Refusals. */
    assert("error" in analyseHeaders(""), "empty input is refused");
    assert("error" in analyseHeaders("hello, can you check this email for me?"), "text without headers is refused");
    assert("error" in analyseHeaders(`Received: x\n${"X-Pad: y\n".repeat(MAX_HEADER_INPUT / 8)}`), "oversized input is refused");
    assert("error" in analyseHeaders(42 as unknown as string), "a non-string is refused");

    console.log("✓ Headers are parsed; the receiving server's results, sender mismatches, and the sending server are found");
}

/* --------------------------------- Privacy -------------------------------- */

async function testPrivacy(): Promise<void> {
    const payload = (await runHeaderAnalysis(text("phish.txt"), "u1", settings({ apiKey: undefined }), { store: fakeStore().store })) as HeaderAnalysisPayload;
    const out = JSON.stringify(payload);

    assert(payload.recipientCount === 3 && !/victim\.(one|two|three)@/.test(out), "recipients are counted, never returned");
    assert(!/analyst@example\.org/.test(JSON.stringify(await runHeaderAnalysis(text("legit.txt"), "u1", settings({ apiKey: undefined }), { store: fakeStore().store }))), "the analyst's own address is not returned");
    assert(findDisclosures(payload.statement, { secrets: [], names: [], models: [] }).length === 0, "the statement passes the disclosure guard");

    console.log("✓ Recipient addresses are never returned, and nothing but the sender domain leaves the gateway");
}

/* -------------------------------- MXToolbox -------------------------------- */

function settings(overrides: Partial<HeaderAnalysisSettings["options"]> & { dnsChecks?: boolean; perUserPerHour?: number; dailyBudget?: number } = {}): HeaderAnalysisSettings {
    const base = headerAnalysisSettings({ mxtoolboxApiKey: "MXT-SECRET-789", requestTimeoutMs: 2000 });

    return {
        ...base,
        dnsChecks: overrides.dnsChecks ?? true,
        perUserPerHour: overrides.perUserPerHour ?? base.perUserPerHour,
        dailyBudget: overrides.dailyBudget ?? base.dailyBudget,
        options: { ...base.options, ...("apiKey" in overrides ? { apiKey: overrides.apiKey } : {}) },
    };
}

function fakeStore(overrides: Partial<{ cached: MailCheck | null; calls: number; perHour: number }> = {}) {
    const recorded: MailCheck[][] = [];

    return {
        recorded,
        store: {
            cachedMailCheck: async (command: MailCheckCommand) => (overrides.cached?.command === command ? overrides.cached : null),
            mailCallsToday: async () => overrides.calls ?? 0,
            analysesLastHour: async () => overrides.perHour ?? 0,
            recordMailChecks: async (_id: string, _by: string, checks: MailCheck[]) => {
                recorded.push(checks);
            },
        },
    };
}

async function testMxToolbox(): Promise<void> {
    const dmarc = parseMxToolbox("dmarc", json("mxtoolbox-dmarc.json"));
    const spf = parseMxToolbox("spf", json("mxtoolbox-spf.json"));
    const dkim = parseMxToolbox("dkim", json("mxtoolbox-dkim.json"));
    const missing = parseMxToolbox("dmarc", json("mxtoolbox-dmarc-missing.json"));

    assert(dmarc.policy === "reject" && dmarc.records[0].startsWith("v=DMARC1"), `the DMARC policy is read: ${dmarc.policy}`);
    assert(spf.allQualifier === "~all", `the SPF 'all' qualifier is read: ${spf.allQualifier}`);
    assert(dkim.failed.length === 1 && dkim.records.length === 1, "a DKIM problem MXToolbox reports is kept");
    assert(missing.records.length === 0 && /No DMARC Record found/.test(missing.failed[0]), "a missing record is a failed check");

    /* Planning: SPF and DMARC for the From domain, and one DKIM key; never an internal domain. */
    assert(plannedChecks(analysed("legit.txt")).map((c) => `${c.command}:${c.argument}`).join(" ") === "spf:gmail.com dmarc:gmail.com dkim:gmail.com:20230601", "the legit sample plans three checks");
    assert(plannedChecks(analysed("microsoft.txt")).map((c) => c.argument).join(" ") === "contoso-billing.com contoso-billing.com outlook.com:selector1", "a DKIM key of another domain is checked when that is all there is");

    const internal = analyseHeaders("From: it@helpdesk.corp\nReceived: from a (b [10.0.0.1]) by c; Wed, 18 Nov 2026 08:00:00 +0000") as HeaderAnalysis;

    assert(plannedChecks(internal).length === 0, "an internal sender domain is never sent anywhere");

    /* Orchestration. */
    let calls: string[] = [];
    const fetchRecord = async (command: MailCheckCommand, argument: string): Promise<MailCheck> => {
        calls.push(`${command}:${argument}`);
        return { command, argument, status: "success", checkedAt: new Date().toISOString(), reference: null, facts: parseMxToolbox(command, json(`mxtoolbox-${command}.json`)), error: null };
    };

    const none = fakeStore();
    const unconfigured = (await runHeaderAnalysis(text("legit.txt"), "u1", settings({ apiKey: undefined }), { fetchRecord, store: none.store })) as HeaderAnalysisPayload;

    assert(calls.length === 0 && unconfigured.dnsChecks.every((c) => c.status === "not_configured") && none.recorded[0]?.length === 0, "without a key, nothing is sent or recorded, and the analysis still runs");

    calls = [];
    const real = fakeStore();
    const full = (await runHeaderAnalysis(text("legit.txt"), "u1", settings(), { fetchRecord, store: real.store })) as HeaderAnalysisPayload;

    assert(calls.length === 3 && real.recorded[0].length === 3 && /Sender domain DNS \(MXToolbox\): SPF gmail\.com: record published, ends ~all/.test(full.statement), `checks are made, recorded, and stated: ${full.statement}`);

    calls = [];
    const cachedCheck = { ...(await fetchRecord("dmarc", "gmail.com")), cached: true };
    calls = [];
    const reused = (await runHeaderAnalysis(text("legit.txt"), "u1", settings(), { fetchRecord, store: fakeStore({ cached: cachedCheck }).store })) as HeaderAnalysisPayload;

    assert(calls.length === 2 && !calls.includes("dmarc:gmail.com") && reused.notes.some((n) => /reused/.test(n)), "a cached check is reused and labelled");

    calls = [];
    const spent = (await runHeaderAnalysis(text("legit.txt"), "u1", settings({ dailyBudget: 1 }), { fetchRecord, store: fakeStore({ calls: 0 }).store })) as HeaderAnalysisPayload;

    assert(calls.length === 1 && spent.dnsChecks.filter((c) => c.status === "budget_exhausted").length === 2, "the daily budget is enforced within one analysis");

    calls = [];
    const limited = (await runHeaderAnalysis(text("legit.txt"), "u1", settings({ perUserPerHour: 2 }), { fetchRecord, store: fakeStore({ perHour: 2 }).store })) as HeaderAnalysisPayload;

    assert(calls.length === 0 && limited.dnsChecks.every((c) => c.status === "rate_limited") && limited.findings.length >= 0, "the per-person limit stops DNS checks but not the analysis");

    calls = [];
    await runHeaderAnalysis(text("legit.txt"), "u1", settings({ dnsChecks: false }), { fetchRecord, store: fakeStore().store });
    assert(calls.length === 0, "DNS checks can be turned off");

    /* The tool: the requester is the runtime's, and the result fits. */
    const seen: string[] = [];
    const store = fakeStore().store;
    const tool = buildHeaderTool({ requesterSenderId: "discord:111" }, settings(), { fetchRecord, store: { ...store, analysesLastHour: async (by: string) => (seen.push(by), 0) } });
    const output = await tool.execute("x", { headers: text("phish.txt"), requesterSenderId: "discord:999" } as never);

    assert(seen[0] === "discord:111" && output.content[0].text.length <= MAX_TOOL_RESULT_CHARS, "the limit counts the real requester, and the result fits the size limit");

    console.log("✓ MXToolbox answers are parsed; checks are planned, cached, budgeted, limited, and never sent for internal domains");
}

async function testNetwork(): Promise<void> {
    const realFetch = globalThis.fetch;
    const requests: Array<{ url: string; headers: Record<string, string> }> = [];
    let reply: () => Response = () => Response.json(json("mxtoolbox-dmarc.json"));

    globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
        requests.push({ url: String(input), headers: Object.fromEntries(new Headers(init?.headers).entries()) });
        return reply();
    }) as typeof fetch;

    const options = { apiKey: "MXT-SECRET-789", timeoutMs: 2000, retry: { attempts: 1, maxDelayMs: 1, budgetMs: 1 } };

    try {
        const ok = await lookupMailRecord("dmarc", "gmail.com", options);

        assert(ok.status === "success" && requests[0].url === "https://api.mxtoolbox.com/api/v1/Lookup/dmarc/?argument=gmail.com", `the documented lookup URL is used: ${requests[0]?.url}`);
        assert(requests[0].headers.authorization === "MXT-SECRET-789" && !requests[0].url.includes("MXT-SECRET"), "the key travels in the Authorization header only");

        await lookupMailRecord("dkim", "gmail.com:20230601", options);
        assert(requests[1].url.endsWith("argument=gmail.com%3A20230601"), "the DKIM selector is passed as domain:selector");

        reply = () => new Response("[]", { status: 429 });
        assert((await lookupMailRecord("spf", "gmail.com", options)).status === "rate_limited", "the plan's daily limit is reported as rate limited");

        reply = () => new Response("{}", { status: 401 });
        const refused = await lookupMailRecord("spf", "gmail.com", options);

        assert(refused.status === "error" && !JSON.stringify(refused).includes("MXT-SECRET"), "a refused key is reported without echoing it");

        reply = () => Response.json({ IsError: true });
        assert((await lookupMailRecord("spf", "gmail.com", options)).status === "error", "an MXToolbox error is never read as a clean record");

        requests.length = 0;
        assert((await lookupMailRecord("spf", "gmail.com", { ...options, apiKey: undefined })).status === "not_configured" && requests.length === 0, "without a key, MXToolbox is not called");
    } finally {
        globalThis.fetch = realFetch;
    }

    console.log("✓ The MXToolbox key stays in its header, limits and errors are reported, and nothing is called without a key");
}

/* -------------------------------- Answer gate ------------------------------ */

async function testGate(): Promise<void> {
    const phish = (await runHeaderAnalysis(text("phish.txt"), "u1", settings({ apiKey: undefined }), { store: fakeStore().store })) as HeaderAnalysisPayload;
    const legit = (await runHeaderAnalysis(text("legit.txt"), "u1", settings({ apiKey: undefined }), { store: fakeStore().store })) as HeaderAnalysisPayload;

    assert(checkEmailAnswer("DMARC passed for paypal.com.", [phish]).some((f) => /DMARC passed, but .* fail/.test(f)), "a false 'DMARC passed' is flagged");
    assert(checkEmailAnswer("SPF passed, so the sender is authorised.", [phish]).some((f) => /SPF passed, but .* softfail/.test(f)), "a softfail reported as a pass is flagged");
    assert(checkEmailAnswer("SPF soft-failed, DKIM was not signed, and DMARC failed.", [phish]).length === 0, "an accurate account passes");
    assert(checkEmailAnswer("DMARC did not pass.", [phish]).length === 0, "a negated pass is read as a failure");
    assert(checkEmailAnswer("DKIM failed for gmail.com.", [legit]).some((f) => /DKIM failed, but .* pass/.test(f)), "a false failure is flagged too");
    assert(checkEmailAnswer("SPF and DKIM passed.", [phish]).length === 0, "a clause naming two mechanisms is not judged");
    assert(checkEmailAnswer("DMARC passed.", []).length === 0, "no analysis, no findings");

    console.log("✓ The answer gate flags SPF, DKIM, and DMARC results that contradict the receiving server");
}

async function main(): Promise<void> {
    testParsing();
    await testPrivacy();
    await testMxToolbox();
    await testNetwork();
    await testGate();
    console.log("Email header analysis logic tests PASSED");
}

main().catch((error) => {
    console.error("Email header analysis logic tests FAILED");
    console.error(error);
    process.exitCode = 1;
});
