/*
 * The least-privilege database role from migration 004, on real PostgreSQL:
 * it can do everything the plugin does, and nothing else.
 */
import pg from "pg";

import { db } from "./db.js";

function assert(condition: unknown, message: string): asserts condition {
    if (!condition) {
        throw new Error(`Assertion failed: ${message}`);
    }
}

const PASSWORD = `test-${Math.random().toString(36).slice(2)}`;

async function refused(client: pg.Client, sql: string): Promise<boolean> {
    try {
        await client.query(sql);
        return false;
    } catch {
        return true;
    }
}

async function main(): Promise<void> {
    /* Set up as the administrator, as the deployment script does. */
    await db.query(`ALTER ROLE threatintel_app WITH PASSWORD '${PASSWORD}'`);
    await db.query("CREATE SCHEMA IF NOT EXISTS app_role_probe");
    await db.query("CREATE TABLE IF NOT EXISTS app_role_probe.private_data (secret text)");
    await db.query("INSERT INTO app_role_probe.private_data VALUES ('not for the plugin')");

    const { rows: [role] } = await db.query(
        "SELECT rolsuper, rolbypassrls, rolcreaterole, rolcreatedb, rolreplication FROM pg_roles WHERE rolname = 'threatintel_app'",
    );

    assert(
        role && !role.rolsuper && !role.rolbypassrls && !role.rolcreaterole && !role.rolcreatedb && !role.rolreplication,
        `the role has no administrative attributes: ${JSON.stringify(role)}`,
    );

    const app = new pg.Client({
        host: process.env.THREATINTEL_DB_HOST ?? "localhost",
        port: Number(process.env.THREATINTEL_DB_PORT ?? 5432),
        database: process.env.THREATINTEL_DB_NAME ?? "threatintel",
        user: "threatintel_app",
        password: PASSWORD,
    });

    await app.connect();

    try {
        /* Everything the plugin needs. */
        const { rows: [me] } = await app.query("SELECT current_user");

        assert(me.current_user === "threatintel_app", "connected as the plugin role");

        await app.query("SELECT count(*) FROM public.investigations");
        await app.query("SELECT count(*) FROM public.evidence");
        await app.query("SELECT count(*) FROM public.facts");
        await app.query("SELECT count(*) FROM public.inferences");

        await app.query("INSERT INTO public.watchlist (target) VALUES ('CVE-2099-4040') ON CONFLICT DO NOTHING");
        await app.query("UPDATE public.watchlist SET enabled = true WHERE target = 'CVE-2099-4040'");
        await app.query(
            `INSERT INTO public.watch_events (target, check_id, kind, fingerprint, explanation, deliverable, delivery_status)
             VALUES ('CVE-2099-4040', gen_random_uuid(), 'intelligence_change', 'app-role-probe', 'probe', false, 'not_deliverable')
             ON CONFLICT (fingerprint) DO NOTHING`,
        );
        await app.query("UPDATE public.feed_state SET last_error = last_error WHERE id = 1");
        await app.query("INSERT INTO public.feed_runs DEFAULT VALUES");
        await app.query("SELECT count(*) FROM public.feed_items");

        const { rows: visible } = await app.query("SELECT target FROM public.watchlist WHERE target = 'CVE-2099-4040'");

        assert(visible.length === 1, "row-level security lets the plugin role see its own rows");

        await app.query("DELETE FROM public.watch_events WHERE fingerprint = 'app-role-probe'");
        await app.query("DELETE FROM public.watchlist WHERE target = 'CVE-2099-4040'");

        /* And nothing else. */
        assert(await refused(app, "SELECT * FROM app_role_probe.private_data"), "another schema's data cannot be read");
        assert(await refused(app, "CREATE TABLE public.app_role_new (x int)"), "no tables can be created");
        assert(await refused(app, "DROP TABLE public.feed_runs"), "plugin tables cannot be dropped");
        assert(await refused(app, "ALTER TABLE public.watchlist DISABLE ROW LEVEL SECURITY"), "row-level security cannot be switched off");
        assert(await refused(app, "CREATE ROLE app_role_escalation LOGIN"), "no roles can be created");
        assert(await refused(app, "SELECT rolpassword FROM pg_authid"), "password hashes cannot be read");
        assert(await refused(app, "TRUNCATE public.investigations"), "tables cannot be truncated");

        console.log("✓ The plugin role can do everything the plugin needs, and nothing else");
    } finally {
        await app.end();
        await db.query("DROP SCHEMA IF EXISTS app_role_probe CASCADE");
        await db.query("ALTER ROLE threatintel_app WITH PASSWORD NULL");
    }

    console.log("App role tests PASSED");
}

main()
    .catch((error) => {
        console.error("App role tests FAILED");
        console.error(error);
        process.exitCode = 1;
    })
    .finally(() => db.end());
