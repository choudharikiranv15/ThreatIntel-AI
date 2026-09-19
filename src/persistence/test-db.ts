import { checkDatabaseConnection, closeDatabase } from "./db.js";

async function main(): Promise<void> {
    try {
        await checkDatabaseConnection();

        console.log("✅ PostgreSQL connection successful");
    } catch (error) {
        console.error("❌ PostgreSQL connection failed");

        if (error instanceof Error) {
            console.error(error.message);
        } else {
            console.error(error);
        }

        process.exitCode = 1;
    } finally {
        await closeDatabase();
    }
}

void main();