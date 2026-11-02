import {
    getInvestigationContext,
} from "./investigation-context.js";

import {
    closeDatabase,
} from "./db.js";

import {
    deleteSeededInvestigation,
    seedInvestigation,
} from "./test-seed.js";

const TARGET = `CVE-2099-${Date.now()}`;

async function main(): Promise<void> {
    try {
        console.log(
            "Testing investigation context retrieval...",
        );

        const investigationId =
            await seedInvestigation(TARGET);

        const context =
            await getInvestigationContext(
                investigationId,
            );

        if (!context) {
            throw new Error(
                "Expected investigation context, but none was found",
            );
        }

        console.log(
            `Target: ${context.investigation.target}`,
        );

        console.log(
            `Status: ${context.investigation.status}`,
        );

        console.log(
            `Evidence: ${context.evidence.length}`,
        );

        console.log(
            `Facts: ${context.facts.length}`,
        );

        console.log(
            `Inferences: ${context.inferences.length}`,
        );

        if (
            context.investigation.id !==
            investigationId
        ) {
            throw new Error(
                "Returned investigation ID does not match requested ID",
            );
        }

        if (
            context.investigation.target !==
            TARGET
        ) {
            throw new Error(
                "Unexpected investigation target",
            );
        }

        if (context.evidence.length === 0) {
            throw new Error(
                "Expected at least one evidence record",
            );
        }

        if (context.facts.length === 0) {
            throw new Error(
                "Expected at least one fact record",
            );
        }

        if (context.inferences.length === 0) {
            throw new Error(
                "Expected at least one inference record",
            );
        }

        for (const fact of context.facts) {
            if (!fact.evidenceId) {
                throw new Error(
                    `Fact ${fact.id} has no evidence relationship`,
                );
            }

            const evidenceExists =
                context.evidence.some(
                    (evidence) =>
                        evidence.id === fact.evidenceId,
                );

            if (!evidenceExists) {
                throw new Error(
                    `Fact ${fact.id} references missing evidence ${fact.evidenceId}`,
                );
            }
        }

        for (const inference of context.inferences) {
            for (const factId of inference.supportingFactIds) {
                const factExists =
                    inference.supportingFacts.some(
                        (fact) =>
                            fact.sourceFactId === factId,
                    );

                if (!factExists) {
                    throw new Error(
                        `Inference ${inference.id} references unresolved fact ${factId}`,
                    );
                }
            }
        }

        console.log(
            "✅ Investigation graph relationships PASSED",
        );

        const missingContext =
            await getInvestigationContext(
                "00000000-0000-0000-0000-000000000000",
            );

        if (missingContext !== null) {
            throw new Error(
                "Expected null for unknown investigation",
            );
        }

        console.log(
            "✅ No-context test PASSED",
        );

        console.log(
            "✅ Investigation context tests PASSED",
        );
    } catch (error) {
        console.error(
            "❌ Investigation context tests FAILED",
        );

        if (error instanceof Error) {
            console.error(error.message);
        } else {
            console.error(error);
        }

        process.exitCode = 1;
    } finally {
        await deleteSeededInvestigation(TARGET);
        await closeDatabase();
    }
}

void main();