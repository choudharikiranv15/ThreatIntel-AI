import {
    getPriorInvestigation,
} from "./investigation-prior.js";

import {
    closeDatabase,
} from "./db.js";

async function main(): Promise<void> {
    try {
        console.log(
            "Testing prior investigation retrieval...",
        );

        const result =
            await getPriorInvestigation(
                "CVE-2024-3094",
            );

        if (!result.found) {
            throw new Error(
                "Expected prior investigation to be found",
            );
        }

        if (!result.latestInvestigation) {
            throw new Error(
                "Expected latest investigation metadata",
            );
        }

        if (!result.context) {
            throw new Error(
                "Expected investigation context",
            );
        }

        console.log(
            `Target: ${result.target}`,
        );

        console.log(
            `Found: ${result.found}`,
        );

        console.log(
            `Latest status: ${result.latestInvestigation.status}`,
        );

        console.log(
            `Latest ID: ${result.latestInvestigation.id}`,
        );

        console.log(
            `Evidence: ${result.context.evidence.length}`,
        );

        console.log(
            `Facts: ${result.context.facts.length}`,
        );

        console.log(
            `Inferences: ${result.context.inferences.length}`,
        );

        if (
            result.context.investigation.id !==
            result.latestInvestigation.id
        ) {
            throw new Error(
                "Latest investigation ID does not match retrieved context",
            );
        }

        if (
            result.context.investigation.target !==
            "CVE-2024-3094"
        ) {
            throw new Error(
                "Unexpected investigation target",
            );
        }

        if (
            result.context.evidence.length === 0
        ) {
            throw new Error(
                "Expected prior investigation evidence",
            );
        }

        if (
            result.context.facts.length === 0
        ) {
            throw new Error(
                "Expected prior investigation facts",
            );
        }

        if (
            result.context.inferences.length === 0
        ) {
            throw new Error(
                "Expected prior investigation inferences",
            );
        }

        console.log(
            "✅ Prior investigation retrieval PASSED",
        );

        const missing =
            await getPriorInvestigation(
                "CVE-9999-9999",
            );

        if (missing.found) {
            throw new Error(
                "Expected unknown target to have no prior investigation",
            );
        }

        if (missing.latestInvestigation !== null) {
            throw new Error(
                "Expected no latest investigation for unknown target",
            );
        }

        if (missing.context !== null) {
            throw new Error(
                "Expected no context for unknown target",
            );
        }

        console.log(
            "✅ No-prior-investigation test PASSED",
        );

        console.log(
            "✅ Prior investigation tests PASSED",
        );
    } catch (error) {
        console.error(
            "❌ Prior investigation tests FAILED",
        );

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