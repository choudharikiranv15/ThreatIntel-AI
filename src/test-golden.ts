import {
  investigateCve,
} from "./engine.js";

const CVE =
  "CVE-2024-3094";

const result =
  await investigateCve(
    CVE,
    {
      requestTimeoutMs: 15000,
    },
  );

console.log(
  JSON.stringify(
    result,
    null,
    2,
  ),
);

const failures: string[] = [];

/* -------------------------------------------------------------------------- */
/* Basic result checks                                                        */
/* -------------------------------------------------------------------------- */

if (
  result.target !== CVE
) {
  failures.push(
    `Expected target ${CVE}, got ${result.target}`,
  );
}

if (
  result.targetType !== "cve"
) {
  failures.push(
    `Expected targetType=cve, got ${result.targetType}`,
  );
}

if (
  result.investigationType !==
  "vulnerability"
) {
  failures.push(
    "Expected investigationType=vulnerability",
  );
}

/* -------------------------------------------------------------------------- */
/* NVD                                                                         */
/* -------------------------------------------------------------------------- */

const nvdEvidence =
  result.evidence.find(
    (e) => e.source === "NVD",
  );

if (!nvdEvidence) {
  failures.push(
    "NVD evidence was not returned.",
  );
}

/* -------------------------------------------------------------------------- */
/* CVSS                                                                        */
/* -------------------------------------------------------------------------- */

if (
  result.summary.cvss
    .baseScore !== 10.0
) {
  failures.push(
    `Expected CVSS base score 10.0, got ${String(
      result.summary.cvss.baseScore,
    )}`,
  );
}

if (
  result.summary.cvss
    .version !== "3.1"
) {
  failures.push(
    `Expected CVSS version 3.1, got ${String(
      result.summary.cvss.version,
    )}`,
  );
}

if (
  result.summary.cvss
    .severity !== "CRITICAL"
) {
  failures.push(
    `Expected severity CRITICAL, got ${String(
      result.summary.cvss.severity,
    )}`,
  );
}

if (
  result.summary.cvss
    .vector !==
  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
) {
  failures.push(
    `Unexpected CVSS vector: ${String(
      result.summary.cvss.vector,
    )}`,
  );
}

/* -------------------------------------------------------------------------- */
/* CWE                                                                         */
/* -------------------------------------------------------------------------- */

if (
  !result.summary.cwe.includes(
    "CWE-506",
  )
) {
  failures.push(
    "Expected CWE-506 in extracted weaknesses.",
  );
}

/* -------------------------------------------------------------------------- */
/* CISA KEV                                                                    */
/* -------------------------------------------------------------------------- */

/*
 * IMPORTANT:
 *
 * This test does NOT hard-code "listed" or "not-listed"
 * because the CISA catalog is live and can legitimately
 * change over time.
 *
 * We only verify that the engine returns one of the
 * explicitly defined states.
 */
const validKevStatuses =
  new Set([
    "listed",
    "not-listed",
    "unknown",
  ]);

if (
  !validKevStatuses.has(
    result.summary.kevStatus,
  )
) {
  failures.push(
    `Invalid KEV status: ${String(
      result.summary.kevStatus,
    )}`,
  );
}

/* -------------------------------------------------------------------------- */
/* Evidence integrity                                                         */
/* -------------------------------------------------------------------------- */

for (
  const evidence of result.evidence
) {
  if (!evidence.source) {
    failures.push(
      "Evidence item is missing source.",
    );
  }

  if (!evidence.retrievedAt) {
    failures.push(
      `Evidence item ${evidence.source} is missing retrievedAt.`,
    );
  }

  if (!evidence.url) {
    failures.push(
      `Evidence item ${evidence.source} is missing URL.`,
    );
  }

  if (!evidence.facts) {
    failures.push(
      `Evidence item ${evidence.source} is missing facts.`,
    );
  }
}

/* -------------------------------------------------------------------------- */
/* Confirmed facts vs inference                                               */
/* -------------------------------------------------------------------------- */

if (
  result.confirmedFacts.length === 0
) {
  failures.push(
    "No confirmed facts were produced.",
  );
}

if (
  result.inferences.length === 0
) {
  failures.push(
    "No explicit inference section was produced.",
  );
}

/* -------------------------------------------------------------------------- */
/* Safety checks                                                              */
/* -------------------------------------------------------------------------- */

/*
 * We don't want the engine claiming that a vulnerable
 * version automatically means compromise.
 */
const combinedText =
  [
    ...result.confirmedFacts,
    ...result.inferences,
    ...result.analystGuidance,
  ]
    .join("\n")
    .toLowerCase();

if (
  combinedText.includes(
    "presence of a vulnerable version confirms compromise",
  )
) {
  failures.push(
    "Engine incorrectly treats vulnerable-version presence as proof of compromise.",
  );
}

/*
 * KEV failure must never be represented as "not-listed".
 */
if (
  result.limitations.some(
    (limitation) =>
      limitation
        .toLowerCase()
        .includes(
          "cisa kev lookup failed",
        ),
  ) &&
  result.summary.kevStatus ===
  "not-listed"
) {
  failures.push(
    "CISA lookup failure was incorrectly converted to not-listed.",
  );
}

/* -------------------------------------------------------------------------- */
/* Final                                                                       */
/* -------------------------------------------------------------------------- */

if (failures.length > 0) {
  console.error(
    "\n❌ Golden test FAILED\n",
  );

  for (
    const failure of failures
  ) {
    console.error(
      `  - ${failure}`,
    );
  }

  process.exitCode = 1;
} else {
  console.log(
    "\n✅ Golden test PASSED",
  );

  console.log(
    `CVE: ${result.target}`,
  );

  console.log(
    `Severity: ${result.summary.severity}`,
  );

  console.log(
    `CVSS: ${result.summary.cvss.baseScore}`,
  );

  console.log(
    `KEV: ${result.summary.kevStatus}`,
  );

  console.log(
    `Evidence sources: ${result.evidence
      .map((e) => e.source)
      .join(", ")}`,
  );
}