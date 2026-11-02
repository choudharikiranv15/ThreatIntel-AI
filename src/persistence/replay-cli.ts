import { closeDatabase } from "./db.js";
import { replayInvestigation } from "./investigation-replay.js";

const [investigationId] = process.argv.slice(2);

if (!investigationId) {
    console.error("Usage: npm run replay -- <investigation-id>");
    process.exitCode = 2;
} else {
    try {
        const report = await replayInvestigation(investigationId);

        console.log(JSON.stringify(report, null, 2));

        if (!report?.reproduced) {
            process.exitCode = 1;
        }
    } finally {
        await closeDatabase();
    }
}
