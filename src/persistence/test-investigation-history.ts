import {
  findInvestigationHistory,
} from "./investigation-history.js";
import { db, closeDatabase } from "./db.js";

const TEST_TARGET =
  "TEST-CVE-HISTORY-001";

async function cleanup(): Promise<void> {
  await db.query(
    `
      DELETE FROM investigations
      WHERE target = $1
    `,
    [TEST_TARGET],
  );
}

async function main(): Promise<void> {
  try {
    console.log(
      "Testing investigation history retrieval...",
    );

    // Start from a clean test state.
    await cleanup();

    // Verify that no history exists initially.
    const emptyHistory =
      await findInvestigationHistory(
        TEST_TARGET,
      );

    if (emptyHistory.length !== 0) {
      throw new Error(
        `Expected no initial investigations, found ${emptyHistory.length}`,
      );
    }

    console.log(
      "✓ Empty-history test PASSED",
    );

    // Create two controlled test investigations.
    const olderResult =
      await db.query<{ id: string }>(
        `
          INSERT INTO investigations (
            target,
            target_type,
            investigation_type,
            status,
            summary,
            provider_results,
            limitations,
            analyst_guidance
          )
          VALUES (
            $1,
            'cve',
            'vulnerability',
            'partial',
            '{}'::jsonb,
            '[]'::jsonb,
            '[]'::jsonb,
            '[]'::jsonb
          )
          RETURNING id
        `,
        [TEST_TARGET],
      );

    // Ensure created_at differs so ordering is deterministic.
    await new Promise(
      (resolve) =>
        setTimeout(resolve, 50),
    );

    const newerResult =
      await db.query<{ id: string }>(
        `
          INSERT INTO investigations (
            target,
            target_type,
            investigation_type,
            status,
            summary,
            provider_results,
            limitations,
            analyst_guidance
          )
          VALUES (
            $1,
            'cve',
            'vulnerability',
            'confirmed',
            '{}'::jsonb,
            '[]'::jsonb,
            '[]'::jsonb,
            '[]'::jsonb
          )
          RETURNING id
        `,
        [TEST_TARGET],
      );

    const olderId =
      olderResult.rows[0].id;

    const newerId =
      newerResult.rows[0].id;

    console.log(
      `Created test investigations: ${olderId}, ${newerId}`,
    );

    // Retrieve history.
    const history =
      await findInvestigationHistory(
        TEST_TARGET,
      );

    console.log(
      `Retrieved ${history.length} investigation(s)`,
    );

    for (const investigation of history) {
      console.log(
        `${investigation.createdAt} | ` +
        `${investigation.status} | ` +
        `${investigation.id}`,
      );
    }

    // Verify count.
    if (history.length !== 2) {
      throw new Error(
        `Expected 2 investigations, found ${history.length}`,
      );
    }

    // Verify newest → oldest ordering.
    if (
      history[0].id !== newerId ||
      history[1].id !== olderId
    ) {
      throw new Error(
        "Investigation history is not ordered newest-to-oldest",
      );
    }

    // Verify returned statuses.
    if (
      history[0].status !== "confirmed" ||
      history[1].status !== "partial"
    ) {
      throw new Error(
        "Investigation history returned unexpected statuses",
      );
    }

    // Verify target mapping.
    if (
      history[0].target !== TEST_TARGET ||
      history[1].target !== TEST_TARGET
    ) {
      throw new Error(
        "Investigation history returned an unexpected target",
      );
    }

    console.log(
      "✓ Existing-history test PASSED",
    );

    // Verify unknown target returns no history.
    const noHistory =
      await findInvestigationHistory(
        "TEST-CVE-NO-HISTORY",
      );

    if (noHistory.length !== 0) {
      throw new Error(
        `Expected no investigations, found ${noHistory.length}`,
      );
    }

    console.log(
      "✓ No-history test PASSED",
    );

    console.log(
      "✓ Investigation history tests PASSED",
    );
  } catch (error) {
    console.error(
      "✗ Investigation history tests FAILED",
    );

    if (error instanceof Error) {
      console.error(error.message);
    } else {
      console.error(error);
    }

    process.exitCode = 1;
  } finally {
    // Always remove test data, even when an assertion fails.
    try {
      await cleanup();
      console.log(
        `🧹 Test data removed: ${TEST_TARGET}`,
      );
    } catch (cleanupError) {
      console.error(
        "Failed to clean up investigation history test data:",
      );

      if (
        cleanupError instanceof Error
      ) {
        console.error(
          cleanupError.message,
        );
      } else {
        console.error(cleanupError);
      }

      process.exitCode = 1;
    }

    await closeDatabase();
  }
}

void main();