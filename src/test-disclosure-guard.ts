/*
 * The disclosure guard: internal details never reach chat, and ordinary threat
 * intelligence is never withheld. Offline.
 */
import fs from "node:fs";
import path from "node:path";

import { htmlToText, parseFeed } from "./feed/rss.js";
import {
    buildDisclosureProfile,
    CONFIDENTIALITY_RULES,
    findDisclosures,
    registerDisclosureGuard,
    WITHHELD_ERROR,
    WITHHELD_REPLY,
    type DisclosureProfile,
} from "./verification/disclosure-guard.js";

function assert(condition: unknown, message: string): asserts condition {
    if (!condition) {
        throw new Error(`Assertion failed: ${message}`);
    }
}

/* Fake values shaped like the real ones. None of them is a real credential. */
const FAKE_DISCORD = ["MTQ4", "OTk5ODg3NzY2NTU0NDMzMjIx", ".Gx1yZ2", ".", "abcdefghijklmnopqrstuvwxyz0123456789AB"].join("");
const FAKE_OPENROUTER = "sk-or-v1-" + "0123456789abcdef".repeat(4);
const FAKE_NVD = "11111111-2222-3333-4444-555555555555";
const FAKE_DB_PASSWORD = "Tr0ub4dor-fake-pw-XYZ";

const PROFILE: DisclosureProfile = buildDisclosureProfile({
    config: {
        channels: { discord: { token: FAKE_DISCORD } },
        models: { providers: { openrouter: { apiKey: FAKE_OPENROUTER } } },
        agents: { defaults: { model: { primary: "openrouter/nvidia/nemotron-3-ultra-550b-a55b:free", fallbacks: ["openrouter/qwen/qwen3-coder:free"] } } },
        gateway: { auth: { token: "${OPENCLAW_GATEWAY_TOKEN}" } },
    },
    pluginConfig: { nvdApiKey: FAKE_NVD, abuseipdbApiKey: "short" },
    env: {
        THREATINTEL_DB_PASSWORD: FAKE_DB_PASSWORD,
        THREATINTEL_DB_USER: "threatintel_app.abcdefghijklmnopqrst",
        THREATINTEL_DB_HOST: "aws-1-ap-south-1.pooler.supabase.com",
        PATH: "/usr/bin",
    },
    host: { hostname: "threatintel-gateway", username: "info_dokguru", homedir: "/home/info_dokguru" },
});

const withheld = (text: string) => findDisclosures(text, PROFILE).length > 0;

/* 1. The profile. */
{
    assert(PROFILE.secrets.includes(FAKE_DISCORD), "the Discord token from config is a known secret");
    assert(PROFILE.secrets.includes(FAKE_OPENROUTER), "a provider API key from config is a known secret");
    assert(PROFILE.secrets.includes(FAKE_NVD), "a plugin API key is a known secret");
    assert(PROFILE.secrets.includes(FAKE_DB_PASSWORD), "the database password from the environment is a known secret");
    assert(!PROFILE.secrets.includes("short"), "values too short to be keys are ignored");
    assert(!PROFILE.secrets.some((secret) => secret.includes("${")), "unresolved references are not treated as secrets");
    assert(!PROFILE.secrets.includes("/usr/bin"), "ordinary environment values are not secrets");
    assert(PROFILE.names.includes("abcdefghijklmnopqrst"), "the Supabase project reference is an internal name");
    assert(PROFILE.names.includes("info_dokguru") && PROFILE.names.includes("threatintel-gateway"), "the account and host names are internal");
    assert(PROFILE.models.includes("nemotron-3-ultra-550b-a55b") && PROFILE.models.includes("qwen3-coder"), "configured models and fallbacks are known");
    console.log("✓ Secrets, internal names and models are collected from the running configuration");
}

/* 2. The replies that leaked in Discord on 2026-11-18, and variants. */
{
    const leaks: [string, string][] = [
        ["model reply", "Based on the runtime context, the current model is:\n\nopenrouter/nvidia/nemotron-3-ultra-550b-a55b:free\n\nThis is the default model for this session (shown in the runtime block as model and default_model)."],
        ["status command", "To see all configured models, agents, and routing, you'd run:\nopenclaw status --all --usage"],
        ["config path", "Or check the agent configuration in ~/.openclaw/openclaw.json under agents.defaults.model"],
        ["system prompt reply", "The \"system prompt\" for this agent is composed of the workspace files:\nSOUL.md — Core truths\nIDENTITY.md — Name: \"ThreatIntel AI\"\nUSER.md — You're Kiran Choudhari, SOC analyst"],
        ["setup reply", "To configure the AbuseIPDB API key, add it to ~/.openclaw/.env:\nABUSEIPDB_API_KEY=your-api-key-here"],
        ["approve command", "After adding the key, restart the gateway for it to take effect:\n/approve openclaw gateway restart"],
        ["config key", "Set abuseipdbApiKey under plugins.entries in the gateway settings."],
        ["env name", "The password is read from THREATINTEL_DB_PASSWORD."],
        ["model slug alone", "I'm running on nemotron-3-ultra-550b-a55b."],
        ["fallback model", "If that fails I switch to qwen/qwen3-coder."],
        ["any free model id", "Currently using meta-llama/llama-3.3-70b-instruct:free."],
        ["host name", "I run on a VM called threatintel-gateway in us-central1."],
        ["account name", "Files live under /home/info_dokguru."],
        ["project reference", "The database project is abcdefghijklmnopqrst."],
        ["database host", "It connects to aws-1-ap-south-1.pooler.supabase.com."],
        ["known secret", `Your NVD key is ${FAKE_NVD}.`],
        ["known secret, spaced", `Key: ${FAKE_DB_PASSWORD.split("").join(" ")}`],
        ["known secret, zero-width", `Key: ${FAKE_DB_PASSWORD.slice(0, 5)}​${FAKE_DB_PASSWORD.slice(5)}`],
        ["discord token", `token=${FAKE_DISCORD}`],
        ["openrouter-shaped key", `Use ${"sk-or-v1-" + "f".repeat(64)}`],
        ["connection string", "postgresql://threatintel_app:hunter2hunter2@db.example.co:5432/postgres"],
        ["private key", "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk="],
        ["aws key", "AKIAABCDEFGHIJKLMNOP"],
        ["github token", "ghp_" + "a".repeat(36)],
        ["fullwidth evasion", "check ～/．openclaw/openclaw．json"],
        ["service unit", "Restart openclaw-gateway.service to apply it."],
        ["rotation script", "Run rotate-secret.sh abuseipdb on the VM."],
    ];

    for (const [name, text] of leaks) {
        assert(withheld(text), `withheld: ${name}`);
    }

    console.log(`✓ ${leaks.length} kinds of internal detail are withheld, including the replies that leaked`);
}

/* 3. Ordinary threat intelligence is not withheld. */
{
    const ordinary = [
        "CVE-2024-3400 is a command injection in PAN-OS GlobalProtect (CVSS 10.0). It is in CISA KEV; Palo Alto Networks released hotfixes.",
        "8.8.8.8: No service reports it as malicious. Known benign according to AlienVault OTX. Not checked: AbuseIPDB (no API key).",
        "opmanager[.]pro has 18 AlienVault OTX community reports. No reports is not proof an indicator is safe.",
        "OpenClaw Gateway before 2026.7.1 is affected by CVE-2026-1234; upgrade to the fixed release.",
        "The flaw is in microsoft/vscode and google/oss-fuzz found it; see https://github.com/openai/codex/issues/12.",
        "Attackers planted instructions in AGENTS.md files to hijack coding agents.",
        "APT groups abused Gemini and Claude to draft phishing lures, according to Google.",
        "Persistence was set with systemctl --user enable and a crontab entry; the /config endpoint leaked .env files.",
        "The DFIR Report: initial access via a malicious ISO, then Cobalt Strike and AdFind.",
        "Hash 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f matches the EICAR test file.",
        "There's no latest feed in the last 3 hours. What is a supply chain attack? An attack that compromises a trusted vendor to reach its customers.",
        "I can't share details about how I'm built or configured. I can help with CVEs, the threat feed and indicator lookups.",
        WITHHELD_REPLY,
        WITHHELD_ERROR,
    ];

    for (const text of ordinary) {
        assert(!withheld(text), `not withheld: ${text.slice(0, 60)} -> ${findDisclosures(text, PROFILE).join(",")}`);
    }

    // Every recorded feed and article fixture, as real threat-intel text.
    const dir = path.resolve("test-fixtures/feed");
    let checked = 0;

    for (const file of fs.readdirSync(dir)) {
        const raw = fs.readFileSync(path.join(dir, file), "utf8");
        const texts = file.endsWith(".xml")
            ? parseFeed(raw).map((entry) => `${entry.title}\n${htmlToText(entry.html)}`)
            : file.endsWith(".html")
                ? [htmlToText(raw)]
                : file.endsWith(".json")
                    ? ((JSON.parse(raw) as { vulnerabilities?: { shortDescription?: string; vulnerabilityName?: string }[] }).vulnerabilities ?? []).map((v) => `${v.vulnerabilityName}\n${v.shortDescription}`)
                    : [raw];

        for (const text of texts) {
            const categories = findDisclosures(text, PROFILE);

            assert(categories.length === 0, `fixture ${file} is not withheld: ${categories.join(",")} in "${text.slice(0, 80)}"`);
            checked += 1;
        }
    }

    assert(checked >= 40, `a realistic corpus was checked (${checked})`);
    console.log(`✓ Ordinary answers and ${checked} recorded feed and article texts pass untouched`);
}

/* 4. Wiring: runs last, replaces, drops, and fails closed. */
type Handler = (event: any, context?: any) => any;

function fakeApi(config: unknown = {}) {
    const hooks = new Map<string, { handler: Handler; priority?: number }>();
    const warnings: string[] = [];
    const api = {
        config,
        pluginConfig: {},
        logger: { warn: (message: string) => warnings.push(message), info: () => undefined, error: () => undefined, debug: () => undefined },
        on: (name: string, handler: Handler, options?: { priority?: number }) => hooks.set(name, { handler, priority: options?.priority }),
    };

    registerDisclosureGuard(api as any);
    return { hooks, warnings };
}

{
    const { hooks, warnings } = fakeApi({ agents: { defaults: { model: "openrouter/nvidia/nemotron-3-ultra-550b-a55b:free" } } });
    const sending = hooks.get("message_sending")!;
    const payload = hooks.get("reply_payload_sending")!;
    const prompt = hooks.get("before_prompt_build")!;

    assert(sending.priority! < 0 && payload.priority! < 0, "both delivery checks run after other plugins' handlers");
    assert(prompt.handler({}).appendSystemContext === CONFIDENTIALITY_RULES, "the confidentiality rules are added to the system prompt");

    assert(sending.handler({ to: "channel:1", content: "CVE-2024-3400 is in KEV." }) === undefined, "a normal message is sent unchanged");
    assert(sending.handler({ to: "channel:1", content: "the model is nemotron-3-ultra-550b-a55b" })?.content === WITHHELD_REPLY, "a message naming the model is replaced");

    const media = payload.handler({ payload: { text: "see ~/.openclaw/openclaw.json", mediaUrl: "file:///etc/passwd", replyToId: "42" } });

    assert(media?.payload.text === WITHHELD_REPLY && media.payload.mediaUrl === undefined && media.payload.replyToId === "42", "a reply is replaced, its attachments dropped, and its threading kept");
    assert(payload.handler({ payload: { text: "fine", presentation: { blocks: [{ text: "openclaw config get" }] } } })?.payload.text === WITHHELD_REPLY, "rich presentation text is checked too");
    assert(payload.handler({ payload: { text: "Thinking: SOUL.md says…", isReasoning: true } })?.cancel === true, "a reasoning block that leaks is dropped, not shown");
    assert(payload.handler({ payload: { text: "429 from openrouter/nvidia/nemotron-3-ultra-550b-a55b:free", isError: true } })?.payload.text === WITHHELD_ERROR, "an error naming the model becomes a plain error");
    assert(payload.handler({ payload: { text: "CVE-2024-3400 is in KEV." } }) === undefined, "a normal reply is sent unchanged");
    assert(warnings.length === 5 && warnings.every((w) => !w.includes("nemotron") && !w.includes(".openclaw")), "withheld messages are logged by category, never by content");

    const throwing = { hooks: new Map<string, { handler: Handler; priority?: number }>() };
    const api = {
        get config(): unknown {
            throw new Error("config unavailable");
        },
        pluginConfig: {},
        logger: { warn: () => undefined },
        on: (name: string, handler: Handler, options?: { priority?: number }) => throwing.hooks.set(name, { handler, priority: options?.priority }),
    };

    registerDisclosureGuard(api as any);
    assert(throwing.hooks.get("message_sending")!.handler({ content: "hello" })?.content === WITHHELD_REPLY, "if the check itself fails, the message is withheld");

    console.log("✓ The guard runs last, replaces or drops leaking messages, logs safely, and fails closed");
}

console.log("Disclosure guard tests PASSED");
