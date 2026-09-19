import { Pool, type PoolConfig } from "pg";

const poolConfig: PoolConfig = {
    host: process.env.THREATINTEL_DB_HOST ?? "localhost",
    port: Number(process.env.THREATINTEL_DB_PORT ?? 5432),
    database: process.env.THREATINTEL_DB_NAME ?? "threatintel",
    user: process.env.THREATINTEL_DB_USER ?? "postgres",
    password: process.env.THREATINTEL_DB_PASSWORD,

    max: Number(process.env.THREATINTEL_DB_POOL_SIZE ?? 10),

    idleTimeoutMillis: 30_000,
    connectionTimeoutMillis: 5_000,
};

export const db = new Pool(poolConfig);

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