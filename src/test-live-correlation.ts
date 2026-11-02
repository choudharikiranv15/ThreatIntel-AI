/*
 * Against live NVD, CISA, Red Hat, and OSV. Pins what these public records said
 * when this was written, so a failure can mean a source changed its data.
 */
import { investigateCve } from "./engine.js";
import {
  toToolText,
  VIEW_BUDGET_CHARS,
  viewFromResult,
} from "./tool-result.js";

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) {
    throw new Error(`Assertion failed: ${message}`);
  }
}

const pause = () => new Promise((done) => setTimeout(done, 7000));

async function investigate(cve: string) {
  const result = await investigateCve(cve, { requestTimeoutMs: 30000 });

  const statuses = Object.fromEntries(
    result.providerResults.map((item) => [item.provider, item.status]),
  );

  const view = viewFromResult(result);
  // Measured raw, because toToolText would shrink an oversized view.
  const size = JSON.stringify(view).length;

  // The view budget leaves room for the decision, persistence, and comparison.
  assert(
    size <= VIEW_BUDGET_CHARS,
    `${cve}: view is ${size} chars, over its ${VIEW_BUDGET_CHARS} budget`,
  );

  assert(
    !toToolText(view).includes("_reducedToFit"),
    `${cve}: a real record must never need the emergency reduction`,
  );

  const kinds = new Set(view.assessment.items.map((item) => item.kind));

  assert(
    view.assessment.omitted === 0,
    `${cve}: the assessment must not be cut: ${view.assessment.omitted} omitted`,
  );

  console.log(
    `${cve}: view ${size} chars, vendorImpact ${view.summary.vendorImpact.items.length}/${view.summary.vendorImpact.total}, packageFixes ${view.summary.packageFixes.items.length}/${view.summary.packageFixes.total}, assessment ${[...kinds].join("+")}, ${JSON.stringify(statuses)}`,
  );

  await pause();

  return { result, statuses };
}

async function main(): Promise<void> {
  /* A scoring difference that the vectors explain */
  const log4j = await investigate("CVE-2021-44228");

  const cvss = log4j.result.summary.correlations?.find(
    (item) => item.topic === "cvss",
  );

  assert(
    cvss?.classification === "explained_difference" &&
    cvss.explanation.includes("S") &&
    cvss.values.some((item) => item.source === "Red Hat" && item.value === 9.8) &&
    cvss.values.some((item) => item.source === "nvd@nist.gov" && item.value === 10),
    `Log4Shell's CVSS difference should be explained: ${JSON.stringify(cvss)}`,
  );

  const severity = log4j.result.summary.correlations?.find(
    (item) => item.topic === "severity",
  );

  assert(
    severity?.classification === "explained_difference" &&
    severity.interpretation?.kind === "approximate_name_alignment",
    "severity must stay an approximate reading on real records",
  );

  assert(
    log4j.result.summary.correlations?.find((item) => item.topic === "exploitation")
      ?.classification === "agreement",
    "KEV and NVD should agree on Log4Shell's KEV date",
  );

  assert(
    log4j.result.summary.packageFixes?.some(
      (fix) =>
        fix.package === "org.apache.logging.log4j:log4j-core" &&
        fix.fixedVersions.includes("2.15.0"),
    ),
    "OSV should provide log4j-core's fixed version",
  );

  /* The new coverage records must not crowd out real data. */
  const log4jView = viewFromResult(log4j.result);

  assert(
    log4jView.summary.vendorImpact.items.length >= 5 &&
    log4jView.summary.packageFixes.items.length >= 5,
    `Log4Shell must keep at least 5 vendor rows and 5 fixes: ${log4jView.summary.vendorImpact.items.length}, ${log4jView.summary.packageFixes.items.length}`,
  );

  /* An ecosystem package whose fix can be cross-checked exactly */
  const requests = await investigate("CVE-2023-32681");

  assert(
    requests.result.summary.correlations?.find(
      (item) => item.id === "fixed:PyPI/requests",
    )?.classification === "agreement",
    "NVD and OSV should agree on the requests fix",
  );

  /* OSV has nothing for closed source, and that must be an absence */
  const windows = await investigate("CVE-2021-34527");

  assert(
    windows.statuses.OSV === "observed_absence" &&
    windows.statuses.REDHAT === "observed_absence" &&
    windows.result.status === "confirmed",
    "closed-source absence should be a clean absence",
  );

  /* Real Red Hat products matched by CPE */
  const kernel = await investigate("CVE-2022-0847");

  assert(
    kernel.result.summary.correlations?.some(
      (item) => item.topic === "vendor_assessment",
    ),
    "NVD and Red Hat CPEs should match for the Dirty Pipe kernel CVE",
  );

  assert(
    kernel.result.summary.correlations?.some(
      (item) => item.id === "vendor:not_compared",
    ),
    "uncompared Red Hat records should be counted on real data",
  );

  /* The largest record found: 1,800+ Red Hat rows must still fit */
  await investigate("CVE-2023-44487");

  console.log("Live correlation tests PASSED");
}

main().catch((error: unknown) => {
  console.error("Live correlation tests FAILED");
  console.error(error);
  process.exitCode = 1;
});
