/*
 * PII protection, offline: what the redactor removes and keeps, that analysis
 * still works on redacted text, the gateway end to end against a local fake
 * provider, and real values coming back only in replies.
 */
import fs from "node:fs";
import http from "node:http";
import type { AddressInfo } from "node:net";
import path from "node:path";

import { analyseHeaders, type HeaderAnalysis } from "./email/headers.js";
import { createGatewayHandler, upstreamsFrom } from "./privacy/gateway.js";
import { privacySettings, processRedactor, registerPrivacy } from "./privacy/index.js";
import { PLACEHOLDER, Redactor, redactRequestBody } from "./privacy/redact.js";
import { extractIndicators } from "./triage/extract.js";
import { registerAnswerGate } from "./verification/answer-gate.js";

function assert(condition: unknown, message: string): asserts condition {
    if (!condition) {
        throw new Error(`Assertion failed: ${message}`);
    }
}

const ALERT = String.raw`[SentinelOne] Threat detected on FIN-WS-0142 (10.20.4.17) user CORP\j.doe
Path: C:\Users\j.doe\AppData\Local\Temp\svchost.exe  parent C:\Windows\System32\cmd.exe
ComputerName=FIN-WS-0142.corp.local TargetUserName="Jane Doe" User: Arjun Mehta src_ip=185.220.101.47 dst=8.8.8.8 gw=192.168.1.1
Hash 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f beacon https://cdn-update.top/gate.php?id=42 meta 169.254.169.254
password=Hunter2! Authorization: Bearer abcdefghijklmnop1234 api_key: sk-or-v1-0123456789abcdef0123456789abcdef
Reported by Kiran Choudhari, phone +91 98765 43210, at Wed, 18 Nov 2026 08:02:10 +0000
Lateral movement to dc01.ad.corp.local; the user called back on +1 415 555 0100.`;

const PERSONAL = ["j.doe", "Jane Doe", "Arjun Mehta", "Kiran Choudhari", "FIN-WS-0142.corp.local", "dc01.ad.corp.local", "10.20.4.17", "192.168.1.1", "98765 43210", "415 555 0100", "Hunter2!", "abcdefghijklmnop1234", "sk-or-v1-0123"];
const PUBLIC = ["185.220.101.47", "8.8.8.8", "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "https://cdn-update.top/gate.php?id=42", "169.254.169.254", "svchost.exe", String.raw`C:\Windows\System32\cmd.exe`, "Wed, 18 Nov 2026 08:02:10 +0000"];

/* --------------------------------- Redaction -------------------------------- */

function testRedaction(): void {
    const redactor = new Redactor({ terms: ["Kiran Choudhari"] });
    const out = redactor.redact(ALERT);

    for (const value of PERSONAL) {
        assert(!out.includes(value), `personal or internal value removed: ${value}\n${out}`);
    }

    for (const value of PUBLIC) {
        assert(out.includes(value), `public indicator or ordinary text kept: ${value}\n${out}`);
    }

    assert(/CORP\\PII_USER_[0-9a-f]{8}/.test(out) && /Users\\PII_USER_[0-9a-f]{8}\\AppData/.test(out), "accounts and user folders keep their shape");
    const asAccount = out.match(/CORP\\(PII_USER_[0-9a-f]{8})/)?.[1];
    const asFolder = out.match(/Users\\(PII_USER_[0-9a-f]{8})/)?.[1];

    assert(asAccount && asAccount === asFolder, `the same person gets the same placeholder everywhere: ${asAccount} ${asFolder}`);
    assert(out.includes("password=[REDACTED-SECRET]") && !redactor.restore(out).includes("Hunter2!"), "secrets are removed and never restored");

    const restored = redactor.restore(out);

    for (const value of ["j.doe", "Jane Doe", "Arjun Mehta", "Kiran Choudhari", "FIN-WS-0142.corp.local", "10.20.4.17"]) {
        assert(restored.includes(value), `restored for the reply: ${value}`);
    }

    assert(new Redactor().redact("user=j.doe") !== new Redactor().redact("user=j.doe"), "placeholders are keyed by a per-process secret");
    assert(redactor.redact("user=j.doe") === redactor.redact("user=j.doe"), "and stable within a process");
    assert(redactor.redact(out) === out, "redacting twice changes nothing");

    console.log("✓ People, accounts, internal hosts and addresses, phones and secrets are removed; public indicators stay");
}

function testAnalysisStillWorks(): void {
    const redactor = new Redactor();
    const phish = redactor.redact(fs.readFileSync(path.join(process.cwd(), "test-fixtures", "email", "phish.txt"), "utf8"));

    assert(!/victim\.(one|two|three)@/.test(phish) && !/billing@/.test(phish), "recipients and sender local parts are removed from headers");

    const analysis = analyseHeaders(phish) as HeaderAnalysis;
    const codes = analysis.findings.map((f) => f.code);

    for (const code of ["dmarc_fail", "spf_fail", "reply_to_mismatch", "display_name_spoof"]) {
        assert(codes.includes(code), `header analysis still finds ${code} on redacted headers: ${codes}`);
    }

    assert(analysis.from?.domain === "paypa1-secure.com" && analysis.originatingIp === "185.220.101.47", "the sender domain and sending server survive redaction");

    const extracted = extractIndicators(redactor.redact(ALERT)).indicators.map((i) => i.value);

    assert(extracted.includes("185.220.101.47") && extracted.includes("cdn-update.top") && !extracted.some((v) => /PII_/i.test(v)), `triage still finds the public indicators, and no placeholder: ${extracted}`);

    console.log("✓ Header analysis and triage work the same on redacted text");
}

function testBody(): void {
    const redactor = new Redactor();
    const body = {
        model: "nvidia/nemotron:free",
        tools: [{ type: "function", function: { name: "threatintel_triage_alert", description: "user=example" } }],
        messages: [
            { role: "system", content: "Owner: user=j.doe" },
            { role: "user", content: [{ type: "text", text: String.raw`check CORP\j.doe on 10.1.2.3` }] },
            { role: "assistant", content: null, tool_calls: [{ id: "call_1", type: "function", function: { name: "threatintel_triage_alert", arguments: JSON.stringify({ text: "From: Jane Doe <jane@example.org>" }) } }] },
            { role: "tool", tool_call_id: "call_1", content: "host=FIN-WS-0142" },
        ],
    };
    const { body: out, stats } = redactRequestBody(body, redactor);
    const text = JSON.stringify(out.messages);

    assert(!/j\.doe|10\.1\.2\.3|Jane Doe|jane@|FIN-WS-0142/.test(text), `every message is redacted, including tool calls and results: ${text}`);
    assert(JSON.stringify(out.tools) === JSON.stringify(body.tools) && out.model === body.model, "tool definitions and the model are untouched");
    assert((out.messages as { role: string }[]).map((m) => m.role).join() === "system,user,assistant,tool" && (stats.USER ?? 0) >= 2, "roles are kept and counts reported");

    console.log("✓ Every message in a request is redacted; tools and settings are not");
}

/* ---------------------------------- Gateway --------------------------------- */

async function listen(handler: http.RequestListener): Promise<{ server: http.Server; port: number }> {
    const server = http.createServer(handler);

    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
    return { server, port: (server.address() as AddressInfo).port };
}

async function testGateway(): Promise<void> {
    const received: { body: string; auth?: string; path?: string }[] = [];
    const upstream = await listen((req, res) => {
        let body = "";

        req.on("data", (c) => (body += c));
        req.on("end", () => {
            received.push({ body, auth: req.headers.authorization, path: req.url });
            res.writeHead(200, { "content-type": "text/event-stream" });
            res.write('data: {"choices":[{"delta":{"content":"PII_USER_"}}]}\n\n');
            res.end("data: [DONE]\n\n");
        });
    });

    const redactor = new Redactor();
    const logs: string[] = [];
    const handler = createGatewayHandler(
        { port: 0, maxBodyBytes: 4096, upstreams: { test: `http://127.0.0.1:${upstream.port}/api/v1` } },
        redactor,
        { info: (m) => logs.push(m), warn: (m) => logs.push(m) },
    );
    const gateway = await listen((req, res) => void handler(req, res));
    const base = `http://127.0.0.1:${gateway.port}`;

    try {
        const response = await fetch(`${base}/test/chat/completions`, {
            method: "POST",
            headers: { authorization: "Bearer KEY-123", "content-type": "application/json" },
            body: JSON.stringify({ model: "m", stream: true, messages: [{ role: "user", content: String.raw`user CORP\j.doe on 10.9.8.7 hit 185.220.101.47` }] }),
        });
        const streamed = await response.text();

        assert(response.status === 200 && streamed.includes("data: [DONE]"), "the provider's stream comes back unchanged");
        assert(received[0].path === "/api/v1/chat/completions" && received[0].auth === "Bearer KEY-123", "the request reaches the provider's own path with its key");
        assert(!/j\.doe|10\.9\.8\.7/.test(received[0].body) && received[0].body.includes("185.220.101.47"), `the provider sees no PII, but the indicator: ${received[0].body}`);
        assert(logs.every((l) => !/j\.doe|10\.9\.8\.7|KEY-123/.test(l)), "logs carry counts, never content or keys");

        const unknown = await fetch(`${base}/evil.example/chat/completions`, { method: "POST", body: "{}" });

        assert(unknown.status === 404, "only allowlisted providers are reachable");

        const before = received.length;
        const notJson = await fetch(`${base}/test/chat/completions`, { method: "POST", body: "user=j.doe raw text" });

        assert(notJson.status === 400 && received.length === before, "what cannot be parsed is refused, never forwarded");

        const big = await fetch(`${base}/test/chat/completions`, { method: "POST", body: JSON.stringify({ messages: [{ role: "user", content: "x".repeat(10_000) }] }) });

        assert(big.status === 413 && received.length === before, "oversized requests are refused");

        /* A non-local caller is refused before anything is read. */
        let status = 0;
        await handler(
            { socket: { remoteAddress: "10.0.0.9" }, url: "/test/chat/completions", method: "POST", headers: {} } as unknown as http.IncomingMessage,
            { writeHead: (s: number) => (status = s), end: () => undefined, headersSent: false } as unknown as http.ServerResponse,
        );
        assert(status === 403, "callers other than this machine are refused");
    } finally {
        gateway.server.close();
        upstream.server.close();
    }

    const ups = upstreamsFrom({ plain: "http://insecure.example/v1", "bad name!": "https://x.example", extra: "https://api.example.com/v1/" });

    assert(!("plain" in ups) && !("bad name!" in ups) && ups.extra === "https://api.example.com/v1" && ups.openrouter.startsWith("https://"), "only https upstreams with plain names are accepted");

    console.log("✓ The gateway redacts, forwards only to allowlisted providers for local callers, and refuses what it cannot redact");
}

/* --------------------------- Replies and settings --------------------------- */

async function testReplies(): Promise<void> {
    assert(
        registerPrivacy({ registerService: () => assert(false, "no service when disabled"), on: () => assert(false, "no hooks when disabled") } as never, {}) === undefined && !privacySettings({}).enabled,
        "the gateway is off unless enabled",
    );

    const services: { id: string }[] = [];
    const privacyHooks = new Map<string, (event: any, context?: any) => any>();
    const redactor = new Redactor();
    const restore = registerPrivacy(
        { registerService: (s: unknown) => services.push(s as { id: string }), on: (name: string, h: any) => privacyHooks.set(name, h) } as never,
        { privacyGatewayEnabled: true },
        redactor,
    );

    assert(restore && services[0]?.id === "threatintel-privacy-gateway", "enabling starts the gateway and returns the restore step");

    /* OpenClaw may register the plugin more than once in a process: every registration shares one table. */
    const fakeApi = (warnings: string[] = []) => ({ registerService: () => undefined, on: () => undefined, logger: { warn: (m: string) => warnings.push(m) } }) as never;
    const first = processRedactor(["Kiran Choudhari"]);
    const warnings: string[] = [];
    const secondRestore = registerPrivacy(fakeApi(warnings), { privacyGatewayEnabled: true, piiTerms: ["Kiran Choudhari"] })!;
    const issuedByGateway = first.redact(String.raw`user CORP\j.doe reported by Kiran Choudhari`);

    assert(processRedactor([]) === first, "the redactor is one per process");
    assert(secondRestore(issuedByGateway) === String.raw`user CORP\j.doe reported by Kiran Choudhari` && warnings.length === 0, "a later registration restores placeholders the gateway issued");
    assert(secondRestore(`seen ${new Redactor().placeholder("USER", "x")}`).includes("PII_USER_") && warnings.some((w) => /1 placeholder\(s\) in a reply could not be restored/.test(w) && !/x/.test(w.replace(/placeholder|reply|could|not|restored/g, ""))), "an unresolvable placeholder is logged by count, never by value");

    /* Tool calls: this plugin's tools run on the gateway and get real values back; internet-facing tools do not. */
    const toolCall = privacyHooks.get("before_tool_call")!;
    const modelSaw = redactor.redact(ALERT);
    const triageCall = toolCall({ toolName: "threatintel_triage_alert", params: { text: modelSaw } });

    assert(triageCall?.params.text === redactor.restore(modelSaw) && triageCall.params.text.includes(String.raw`CORP\j.doe`), "a ThreatIntel tool receives the real values");
    assert(
        extractIndicators(triageCall.params.text).internal >= 4 && extractIndicators(triageCall.params.text).internal > extractIndicators(modelSaw).internal,
        `so triage counts internal values again, which placeholders hid: ${extractIndicators(triageCall.params.text).internal} vs ${extractIndicators(modelSaw).internal}`,
    );
    assert(triageCall.params.text.includes("185.220.101.47") && modelSaw.includes("185.220.101.47"), "public indicators were never changed on either side");
    assert(toolCall({ toolName: "web_search", params: { query: `who is ${redactor.placeholder("USER", "j.doe")}` } }) === undefined, "web search keeps the placeholders: a query never carries the data out");
    assert(toolCall({ toolName: "threatintel_lookup_indicator", params: { indicator: "185.220.101.47" } }) === undefined, "arguments without placeholders are untouched");
    assert(
        JSON.stringify(toolCall({ toolName: "threatintel_analyze_email_headers", params: { headers: redactor.redact("From: Jane Doe <jane@example.org>"), nested: [{ x: redactor.redact("user=j.doe") }] } })?.params) ===
            JSON.stringify({ headers: "From: Jane Doe <jane@example.org>", nested: [{ x: "user=j.doe" }] }),
        "nested arguments are restored too",
    );

    /* What the model saw had placeholders; the reply posted to chat has the real values. */
    const hooks = new Map<string, (event: any, context: any) => any>();
    registerAnswerGate({ logger: { warn: () => undefined }, on: (name: string, h: any) => hooks.set(name, h) } as never, { transformOutbound: restore });

    const sending = hooks.get("message_sending")!;
    const payloadSending = hooks.get("reply_payload_sending")!;
    const seen = redactor.redact(String.raw`user CORP\j.doe on 10.20.4.17`);

    assert(sending({ content: "No placeholders here." }, {}) === undefined && payloadSending({ payload: { text: "plain" } }, {}) === undefined, "a reply without placeholders is untouched");
    assert(sending({ content: `Account seen: ${seen}` }, {})?.content === String.raw`Account seen: user CORP\j.doe on 10.20.4.17`, "message delivery gets the real values back");
    assert(payloadSending({ payload: { text: seen, replyToId: "7" } }, {})?.payload.text === String.raw`user CORP\j.doe on 10.20.4.17`, "and so does payload delivery, keeping its fields");

    const foreign = new Redactor().placeholder("NAME", "Someone Else");

    assert(sending({ content: `Seen: ${foreign}` }, {})?.content === undefined, "a placeholder this process did not make stays as it is");

    /* With an evidence warning on the same reply, both apply. */
    hooks.get("after_tool_call")!(
        { toolName: "threatintel_lookup_indicator", result: { details: { indicator: "45.33.1.9", type: "ipv4", sources: [], summary: { statement: "No service reports it as malicious.", knownBenign: [], threatReports: [] } } } },
        { sessionKey: "s1" },
    );

    const both = sending({ content: `45.33.1.9 is safe; seen on ${seen}` }, { sessionKey: "s1" })?.content as string;

    assert(both?.startsWith("⚠️") && both.includes(String.raw`CORP\j.doe`) && !PLACEHOLDER.test(both), `the warning is kept and the values restored: ${both}`);
    PLACEHOLDER.lastIndex = 0;

    console.log("✓ The gateway is opt-in; replies get real values back and keep the evidence warning");
}

async function main(): Promise<void> {
    testRedaction();
    testAnalysisStillWorks();
    testBody();
    await testGateway();
    await testReplies();
    console.log("PII protection logic tests PASSED");
}

main().catch((error) => {
    console.error("PII protection logic tests FAILED");
    console.error(error);
    process.exitCode = 1;
});
