import type {
  AssessmentStatement,
  EvidenceFactRecord,
  InferenceRecord,
  InvestigationSummary,
  ProviderResult,
  SourceId,
} from "../types.js";

/*
 * States what is established, inferred, disputed, and unknown, with what each
 * statement rests on. Built only from extracted data, never from LLM output.
 */

function factIds(
  facts: EvidenceFactRecord[],
  ...fields: string[]
): string[] {
  return facts
    .filter((fact) => fact.field && fields.includes(fact.field))
    .map((fact) => fact.id);
}

function providerState(
  providerResults: ProviderResult[],
  provider: SourceId,
): ProviderResult["status"] | "not_checked" {
  return (
    providerResults.find((result) => result.provider === provider)?.status ??
    "not_checked"
  );
}

function completed(
  status: ProviderResult["status"] | "not_checked",
): boolean {
  return status === "success" || status === "observed_absence";
}

export function buildAssessment(
  summary: InvestigationSummary,
  facts: EvidenceFactRecord[],
  inferences: InferenceRecord[],
  providerResults: ProviderResult[],
): AssessmentStatement[] {
  const statements: AssessmentStatement[] = [];

  const add = (
    statement: Omit<AssessmentStatement, "factIds" | "providerChecks" | "evidenceIds"> &
      Partial<Pick<AssessmentStatement, "factIds" | "providerChecks" | "evidenceIds">>,
  ) => {
    statements.push({
      factIds: [],
      providerChecks: [],
      evidenceIds: [],
      ...statement,
    });
  };

  /* Disputes come first: they change how everything below should be read. */
  for (const correlation of summary.correlations ?? []) {
    // Levels that only look alike have no disagreement to explain. The
    // correlation itself stays available, labelled as approximate.
    if (
      correlation.classification === "agreement" ||
      correlation.interpretation?.aligned === true
    ) {
      continue;
    }

    const kind =
      correlation.classification === "conflict"
        ? "conflict"
        : correlation.classification === "incomplete"
          ? "gap"
          : "difference";

    add({
      topic: correlation.topic,
      kind,
      statement: `${correlation.scope ? `${correlation.scope}: ` : ""}${correlation.explanation}`,
      // Several sources can sit in one evidence record, such as CNAs in NVD's.
      evidenceIds: [
        ...new Set(
          correlation.values.flatMap((item) =>
            item.evidenceId ? [item.evidenceId] : [],
          ),
        ),
      ],
    });
  }

  /* Exploitation */
  const kevFacts = factIds(facts, "kev");

  if (summary.kevStatus === "listed") {
    add({
      topic: "exploitation",
      kind: "fact",
      statement: "CISA KEV lists this CVE as known to be exploited.",
      factIds: kevFacts,
    });
  } else if (summary.kevStatus === "not-listed") {
    add({
      topic: "exploitation",
      kind: "fact",
      statement:
        "This CVE is absent from the checked CISA KEV catalog. That does not establish that exploitation has not occurred.",
      providerChecks: ["CISA_KEV"],
    });
  } else {
    add({
      topic: "exploitation",
      kind: "gap",
      statement: "CISA KEV status is unknown because the check did not complete.",
      providerChecks: ["CISA_KEV"],
    });
  }

  /* Severity */
  const { cvss } = summary;

  if (cvss.baseScore !== null) {
    add({
      topic: "cvss",
      kind: "fact",
      statement: `CVSS base score ${cvss.baseScore}${cvss.severity ? ` (${cvss.severity})` : ""}${cvss.source ? `, scored by ${cvss.source}` : ""}.`,
      factIds: factIds(facts, "cvss"),
    });
  } else {
    add({
      topic: "cvss",
      kind: "gap",
      statement: "No retrieved source provided a CVSS score in NVD's record.",
      providerChecks: ["NVD"],
    });
  }

  /* Remediation */
  const fixedPackages = (summary.packageFixes ?? []).filter(
    (fix) => fix.fixedVersions.length > 0,
  );

  const vendorRows = summary.vendorImpact;
  const fixedRows = vendorRows.filter((row) => row.status === "fixed");

  if (fixedPackages.length > 0) {
    add({
      topic: "fixed_version",
      kind: "fact",
      statement: `A reviewed OSV advisory lists fixed versions for ${fixedPackages.length} ecosystem package${fixedPackages.length === 1 ? "" : "s"}.`,
      factIds: factIds(facts, "osvPackages"),
    });
  }

  if (fixedRows.length > 0) {
    add({
      topic: "fixed_version",
      kind: "fact",
      statement: `Red Hat has shipped fixes in ${fixedRows.length} product package${fixedRows.length === 1 ? "" : "s"}. These are backports, so their version numbers are not comparable to upstream fixes.`,
      factIds: factIds(facts, "redhatImpact"),
    });
  }

  if (fixedPackages.length === 0 && fixedRows.length === 0) {
    add({
      topic: "fixed_version",
      kind: "gap",
      statement:
        "No retrieved source lists a fixed package version. A fix may still exist, so check the vendor directly.",
      providerChecks: ["OSV", "REDHAT"],
    });
  }

  /* Vendor coverage */
  const redhat = providerState(providerResults, "REDHAT");

  if (vendorRows.length > 0) {
    add({
      topic: "vendor_assessment",
      kind: "fact",
      statement: `Red Hat assesses ${vendorRows.length} product package${vendorRows.length === 1 ? "" : "s"}. Red Hat is the only vendor checked, so other vendors' products are not covered.`,
      factIds: factIds(facts, "redhatImpact"),
    });
  } else {
    add({
      topic: "vendor_assessment",
      kind: "gap",
      statement: completed(redhat)
        ? "Red Hat has no assessment for this CVE, and no other vendor was checked. This does not mean products are unaffected."
        : "No vendor assessment is available because the Red Hat check did not complete.",
      providerChecks: ["REDHAT"],
    });
  }

  /* NVD analysis */
  if (summary.affectedVersions.length === 0) {
    add({
      topic: "affected_product",
      kind: "gap",
      statement: "NVD lists no affected product versions for this CVE.",
      providerChecks: ["NVD"],
    });
  }

  /* Partial OSV data; a full OSV failure is reported with failed sources below. */
  if (providerState(providerResults, "OSV") === "success") {
    for (const limitation of summary.enrichmentLimitations ?? []) {
      add({
        topic: "fixed_version",
        kind: "gap",
        statement: limitation,
        providerChecks: ["OSV"],
      });
    }
  }

  /* Failed sources */
  for (const result of providerResults) {
    if (!completed(result.status)) {
      add({
        topic: "provider",
        kind: "gap",
        statement: `${result.provider} did not respond successfully, so its data is missing. This is not evidence of absence.`,
        providerChecks: [result.provider],
      });
    }
  }

  /* Inferences */
  for (const inference of inferences) {
    add({
      topic: "inference",
      kind: "inference",
      statement: inference.claim,
      factIds: inference.supportingFactIds,
      providerChecks:
        inference.supportingFactIds.length === 0 ? ["CISA_KEV"] : [],
    });
  }

  return statements;
}
