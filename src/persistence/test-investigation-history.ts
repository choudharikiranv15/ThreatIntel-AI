import {
  findInvestigationHistory,
} from "./investigation-history.js";
import { closeDatabase } from "./db.js";

async function main(): Promise<void> {
  try {
    console.log("Testing investigation history retrieval...");

    const history =
      await findInvestigationHistory("CVE-2024-3094");

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

    if (history.length !== 2) {
      throw new Error(
        `Expected 2 investigations, found ${history.length}`,
      );
    }

    if (
      history[0].status !== "confirmed" ||
      history[1].status !== "partial"
    ) {
      throw new Error(
        "Investigation history is not ordered correctly",
      );
    }

    console.log("? Existing-history test PASSED");

    const noHistory =
      await findInvestigationHistory(
        "CVE-9999-99999",
      );

    if (noHistory.length !== 0) {
      throw new Error(
        `Expected no investigations, found ${noHistory.length}`,
      );
    }

    console.log("? No-history test PASSED");
    console.log("? Investigation history tests PASSED");
  } catch (error) {
    console.error(
      "? Investigation history tests FAILED",
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
