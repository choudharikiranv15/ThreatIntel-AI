/*
 * The watchlist relies on OpenClaw behaviour that its types mark as internal:
 * deliverOutboundPayloads with skipQueue keeps a send out of OpenClaw's own
 * retry queue, so our outbox is the only retry owner. This test fails if an
 * OpenClaw upgrade changes that, before it can cause duplicate alerts.
 *
 * Runs in a child process with a throwaway state directory, because OpenClaw
 * reads its state location once at load. No message reaches Discord: without a
 * gateway, no Discord adapter is loaded, and the send fails after queueing.
 */
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createRequire } from "node:module";

const PINNED_OPENCLAW = "2026.7.1-2";

function assert(condition: unknown, message: string): asserts condition {
    if (!condition) {
        throw new Error(`Assertion failed: ${message}`);
    }
}

const require = createRequire(import.meta.url);

function queueEntries(state: string): number {
    const file = path.join(state, "state", "openclaw.sqlite");

    if (!fs.existsSync(file)) {
        return 0;
    }

    const { DatabaseSync } = require("node:sqlite") as typeof import("node:sqlite");
    const db = new DatabaseSync(file, { readOnly: true });

    try {
        return (db.prepare("select count(*) as n from delivery_queue_entries").get() as { n: number }).n;
    } finally {
        db.close();
    }
}

/* One send, in a fresh process and state directory. */
function sendOnce(skipQueue: boolean): { error: string; queued: number } {
    const state = fs.mkdtempSync(path.join(os.tmpdir(), "threatintel-delivery-contract-"));

    const child = spawnSync(
        process.execPath,
        [
            "--no-warnings",
            "--input-type=module",
            "-e",
            `
            const { deliverOutboundPayloads } = await import("openclaw/plugin-sdk/outbound-runtime");
            try {
                await deliverOutboundPayloads({
                    cfg: { channels: { discord: { enabled: true, token: "contract-test-invalid" } } },
                    channel: "discord",
                    to: "channel:100000000000000009",
                    payloads: [{ text: "contract test" }],
                    skipQueue: ${skipQueue},
                });
                console.log("RESULT sent");
            } catch (error) {
                console.log("RESULT " + String(error && error.message));
            }
            `,
        ],
        {
            cwd: process.cwd(),
            env: { ...process.env, OPENCLAW_STATE_DIR: state },
            encoding: "utf8",
            timeout: 60_000,
        },
    );

    const line = (child.stdout ?? "").split("\n").find((text) => text.startsWith("RESULT ")) ?? "";
    const queued = queueEntries(state);

    try {
        fs.rmSync(state, { recursive: true, force: true });
    } catch {
        // The child has exited, so this is only a slow file handle on Windows.
    }

    return { error: line.slice("RESULT ".length) || (child.stderr ?? "").slice(0, 300), queued };
}

/* One delivery through this plugin's own deliverer, in a fresh process and state. */
function runDeliverer(factory: "createDirectDeliverer" | "createQueueDeliverer"): {
    result: { status?: string } | null;
    queued: number;
    stderr: string;
} {
    const state = fs.mkdtempSync(path.join(os.tmpdir(), "threatintel-delivery-contract-"));
    const module = new URL("./watch/delivery.js", import.meta.url).href;

    const child = spawnSync(
        process.execPath,
        [
            "--no-warnings",
            "--input-type=module",
            "-e",
            `
            const delivery = await import(${JSON.stringify(module)});
            const deliver = delivery.${factory}(
                () => ({ channels: { discord: { enabled: true, token: "contract-test-invalid" } } }),
                "channel:100000000000000009",
            );
            console.log("RESULT " + JSON.stringify(await deliver("contract test")));
            `,
        ],
        {
            cwd: process.cwd(),
            env: { ...process.env, OPENCLAW_STATE_DIR: state },
            encoding: "utf8",
            timeout: 60_000,
        },
    );

    const line = (child.stdout ?? "").split("\n").find((text) => text.startsWith("RESULT ")) ?? "";
    const queued = queueEntries(state);

    try {
        fs.rmSync(state, { recursive: true, force: true });
    } catch {
        // The child has exited, so this is only a slow file handle on Windows.
    }

    return {
        result: line ? (JSON.parse(line.slice("RESULT ".length)) as { status?: string }) : null,
        queued,
        stderr: (child.stderr ?? "").slice(0, 300),
    };
}

function main(): void {
    // OpenClaw does not export its package.json, so read the installed copy.
    const installed = (
        JSON.parse(
            fs.readFileSync(path.join(process.cwd(), "node_modules", "openclaw", "package.json"), "utf8"),
        ) as { version: string }
    ).version;

    assert(
        installed === PINNED_OPENCLAW,
        `OpenClaw ${installed} is installed, but the watchlist's delivery path is verified only on ${PINNED_OPENCLAW}. Re-run this test and the isolated delivery probe before upgrading.`,
    );

    console.log(`✓ OpenClaw is the pinned ${PINNED_OPENCLAW}`);

    /* Control: a normal send is queued, which proves this test can see the queue. */
    const queuedSend = sendOnce(false);

    assert(
        queuedSend.queued === 1,
        `a send without skipQueue must be queued by OpenClaw (found ${queuedSend.queued}; ${queuedSend.error})`,
    );

    console.log("✓ Control: a normal send enters OpenClaw's retry queue");

    /* The behaviour the outbox depends on */
    const directSend = sendOnce(true);

    assert(
        directSend.queued === 0,
        `skipQueue must keep the send out of OpenClaw's retry queue (found ${directSend.queued}). Our outbox would no longer be the only retry owner.`,
    );

    assert(
        directSend.error.length > 0 && directSend.error !== "sent",
        "the contract send must fail without a gateway, never deliver",
    );

    console.log("✓ skipQueue keeps sends out of OpenClaw's queue, so the outbox is the only retry owner");

    /* Our own deliverers, against the real OpenClaw delivery code */
    const direct = runDeliverer("createDirectDeliverer");

    assert(
        direct.result?.status === "failed" && direct.queued === 0,
        `the direct deliverer must fail without queueing, leaving retries to our outbox: ${JSON.stringify(direct)}`,
    );

    console.log("✓ The direct deliverer never puts an alert in OpenClaw's queue");

    const fallback = runDeliverer("createQueueDeliverer");

    assert(
        fallback.queued === 1 && fallback.result?.status === "handed_off",
        `once OpenClaw queues an alert, the fallback must hand it off so our outbox never resends it: ${JSON.stringify(fallback)}`,
    );

    console.log("✓ The fallback hands off exactly when OpenClaw's queue holds the alert");

    console.log("OpenClaw delivery contract tests PASSED");
}

try {
    main();
} catch (error) {
    console.error("OpenClaw delivery contract tests FAILED");
    console.error(error);
    process.exitCode = 1;
}
