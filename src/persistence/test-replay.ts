/*
 * Runs against real Postgres. Checks the migrated schema's guarantees, and that
 * replay reproduces an investigation and notices tampering.
 */
import { randomUUID } from "node:crypto";

import { investigateCve } from "../engine.js";
import type { ProviderResult, SourceId } from "../types.js";
import { ENGINE_VERSION } from "../version.js";
import { db } from "./db.js";
import { hashPayload } from "./evidence-hash.js";
import { replayInvestigation } from "./investigation-replay.js";
import { persistInvestigation } from "./persist-investigation.js";

function assert(condition: unknown, message: string): asserts condition {
    if (!condition) {
        throw new Error(`Assertion failed: ${message}`);
    }
}

const now = new Date().toISOString();

function provider(
    source: SourceId,
    facts: Record<string, unknown> | null,
): () => Promise<ProviderResult> {
    return async () => ({
        provider: source,
        status: facts ? "success" : "observed_absence",
        error: null,
        checkedAt: now,
        evidence: facts
            ? {
                id: `${source}:x`,
                source,
                sourceType: source === "REDHAT" ? "vendor" : "primary",
                retrievedAt: now,
                url: "https://example.test/",
                title: "test",
                confidence: "high",
                facts,
                extractedFacts: [],
                references: [],
            }
            : null,
    });
}

async function main(): Promise<void> {
    const target = `CVE-2099-${Date.now()}`;

    try {
        assert(
            hashPayload({ b: 1, a: [{ d: 1, c: 2 }] }) ===
            hashPayload({ a: [{ c: 2, d: 1 }], b: 1 }),
            "hash must not depend on key order",
        );

        const result = await investigateCve(target, {
            requestTimeoutMs: 1000,
            providers: {
                nvd: provider("NVD", {
                    id: target,
                    vulnStatus: "Analyzed",
                    descriptions: [{ lang: "en", value: "Test description." }],
                    metrics: {
                        cvssMetricV31: [
                            {
                                source: "nvd@nist.gov",
                                cvssData: {
                                    version: "3.1",
                                    baseScore: 9.8,
                                    vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                },
                            },
                        ],
                    },
                }),
                cisaKev: provider("CISA_KEV", null),
                redhat: provider("REDHAT", {
                    name: target,
                    threat_severity: "Critical",
                }),
            },
        });

        const id = await persistInvestigation(result);

        /* An intact investigation reproduces exactly, with no network. */
        const realFetch = globalThis.fetch;

        globalThis.fetch = (async () => {
            throw new Error("replay must not use the network");
        }) as typeof fetch;

        const clean = await replayInvestigation(id);

        assert(
            clean?.reproduced === true,
            `replay should reproduce: ${JSON.stringify(clean?.differences)}`,
        );
        assert(
            clean.recordedEngineVersion === ENGINE_VERSION,
            "engine version should be recorded",
        );
        assert(
            clean.evidence.length === 2 &&
            clean.evidence.every((item) => item.integrity === "verified"),
            "stored evidence should verify after a JSONB round trip",
        );

        console.log("✓ Replay reproduces an intact investigation offline");

        /* Rows cannot be rewritten. */
        let rejected = false;

        try {
            await db.query(
                "UPDATE public.evidence SET title = 'edited' WHERE investigation_id = $1",
                [id],
            );
        } catch {
            rejected = true;
        }

        assert(rejected, "evidence updates must be rejected");

        console.log("✓ Append-only trigger rejects updates");

        /* Negative control: bypass the trigger, as an admin could. */
        const client = await db.connect();

        try {
            await client.query("BEGIN");
            await client.query(
                "ALTER TABLE public.evidence DISABLE TRIGGER evidence_append_only",
            );
            await client.query(
                `UPDATE public.evidence
                 SET raw_payload = jsonb_set(
                     raw_payload,
                     '{metrics,cvssMetricV31,0,cvssData,baseScore}',
                     '1.0'
                 )
                 WHERE investigation_id = $1 AND source = 'NVD'`,
                [id],
            );
            await client.query(
                "ALTER TABLE public.evidence ENABLE TRIGGER evidence_append_only",
            );
            await client.query("COMMIT");
        } finally {
            client.release();
        }

        const tampered = await replayInvestigation(id);

        assert(tampered?.reproduced === false, "tampering must fail replay");
        assert(
            tampered.evidence.some((item) => item.integrity === "tampered"),
            "tampered evidence must fail its hash",
        );
        assert(
            tampered.differences.some((text) => text.startsWith("summary")),
            "tampered evidence must change the replayed summary",
        );

        globalThis.fetch = realFetch;

        console.log("✓ Replay detects tampered evidence");

        /* API roles get nothing on Supabase, because RLS is on with no policies. */
        const rls = await db.query<{ relname: string; relrowsecurity: boolean }>(
            `SELECT relname, relrowsecurity FROM pg_class
             WHERE relnamespace = 'public'::regnamespace
               AND relname IN ('investigations', 'evidence', 'facts', 'inferences')`,
        );

        assert(
            rls.rows.length === 4 &&
            rls.rows.every((row) => row.relrowsecurity),
            "RLS must be enabled on all four tables",
        );

        const role = `rls_${randomUUID().replaceAll("-", "")}`;
        const rlsClient = await db.connect();

        try {
            await rlsClient.query("BEGIN");
            await rlsClient.query(`CREATE ROLE ${role}`);
            await rlsClient.query(`GRANT USAGE ON SCHEMA public TO ${role}`);
            await rlsClient.query(`GRANT SELECT ON public.investigations TO ${role}`);
            await rlsClient.query(`SET LOCAL ROLE ${role}`);

            const visible = await rlsClient.query(
                "SELECT id FROM public.investigations",
            );

            assert(visible.rows.length === 0, "API roles must see no rows");
        } finally {
            await rlsClient.query("ROLLBACK");
            rlsClient.release();
        }

        console.log("✓ RLS hides rows from API roles but not the owner");

        console.log("Replay and integrity tests PASSED");
    } finally {
        await db.query(
            "DELETE FROM public.investigations WHERE target = $1",
            [target],
        );
        await db.end();
    }
}

main().catch((error: unknown) => {
    console.error("Replay and integrity tests FAILED");
    console.error(error);
    process.exitCode = 1;
});
