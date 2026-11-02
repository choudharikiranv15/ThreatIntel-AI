import { readFileSync } from "node:fs";

import { Pool, type PoolConfig } from "pg";

const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1", "::1"]);

/**
 * Remote connections are encrypted by default. Certificate verification needs
 * the provider's CA, so it is opt-in: set THREATINTEL_DB_SSL=verify-full and
 * THREATINTEL_DB_SSL_CA to the CA file (Supabase offers it under Database
 * settings). THREATINTEL_DB_SSL=disable turns TLS off.
 */
export function resolveSsl(
    host: string,
    env: NodeJS.ProcessEnv,
): PoolConfig["ssl"] {
    const mode = env.THREATINTEL_DB_SSL;

    if (mode === "disable") {
        return false;
    }

    if (mode === "verify-full") {
        return {
            rejectUnauthorized: true,
            ...(env.THREATINTEL_DB_SSL_CA
                ? { ca: readFileSync(env.THREATINTEL_DB_SSL_CA, "utf8") }
                : {}),
        };
    }

    if (mode === "require") {
        return { rejectUnauthorized: false };
    }

    // Leave local connections and an explicit PGSSLMODE to pg's own handling.
    return LOCAL_HOSTS.has(host) || env.PGSSLMODE
        ? undefined
        : { rejectUnauthorized: false };
}

const host = process.env.THREATINTEL_DB_HOST ?? "localhost";

const poolConfig: PoolConfig = {
    host,
    ssl: resolveSsl(host, process.env),
    port: Number(process.env.THREATINTEL_DB_PORT ?? 5432),
    database: process.env.THREATINTEL_DB_NAME ?? "threatintel",
    user: process.env.THREATINTEL_DB_USER ?? "postgres",
    password: process.env.THREATINTEL_DB_PASSWORD,

    max: Number(process.env.THREATINTEL_DB_POOL_SIZE ?? 10),

    idleTimeoutMillis: 30_000,
    connectionTimeoutMillis: 5_000,
};

export const db = new Pool(poolConfig);

/**
 * Database errors can name hosts, users, and project identifiers. Tool results
 * reach the LLM and chat channels, so they only get a generic message; the full
 * error goes to the gateway log.
 */
export function safeDatabaseError(
    action: string,
    error: unknown,
): string {
    console.error(`ThreatIntel ${action} failed:`, error);

    const code = (error as { code?: unknown } | null)?.code;

    return typeof code === "string" && /^[A-Z0-9_]{3,20}$/.test(code)
        ? `${action} failed (database error ${code}).`
        : `${action} failed (database error).`;
}

export async function checkDatabaseConnection(): Promise<void> {
    const client = await db.connect();

    try {
        await client.query("SELECT 1");
    } finally {
        client.release();
    }
}

export async function closeDatabase(): Promise<void> {
    await db.end();
}