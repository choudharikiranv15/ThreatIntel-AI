import type { Confidence, Evaluation, Exploitation, Priority, RawItem, Severity } from "./types.js";

/*
 * Deterministic priority rules. Every result carries the reasons it was given,
 * so an analyst can see why an item was posted or dropped. Lists come from
 * plugin config, so scope changes need no code change.
 *
 *   P1  Bio/Pharma relevance with exploitation or high/critical severity,
 *       or confirmed exploitation of an in-scope product, log source, or
 *       manufacturing OT system.
 *   P2  An in-scope security product with exploitation or high/critical
 *       severity, Bio/Pharma relevance at lower severity, or reported
 *       exploitation of manufacturing OT.
 *   P3  An in-scope log source or platform with exploitation or high/critical
 *       severity, confirmed exploitation of anything else, or a research
 *       article that publishes indicators to hunt.
 *   ignore  Everything else.
 */

export type ScopeConfig = {
    /** Words that tie an item to the Bio/Pharma industry. "Healthcare" alone is never one. */
    bioPharmaTerms: string[];
    /** Products used in Bio/Pharma environments: LIMS, lab, manufacturing, OT. */
    bioPharmaProducts: string[];
    securityProducts: string[];
    logSources: string[];
};

/** Industry terms used when none are configured. Generic healthcare words are deliberately absent. */
export const DEFAULT_BIOPHARMA_TERMS = [
    "pharmaceutical",
    "pharmaceuticals",
    "biopharma",
    "biopharmaceutical",
    "biotech",
    "biotechnology",
    "life sciences",
    "drug discovery",
    "drug development",
    "drug manufacturing",
    "clinical trial",
    "clinical trials",
    "clinical research",
    "laboratory information management",
    "LIMS",
    "electronic lab notebook",
    "GxP",
    "good manufacturing practice",
    "21 CFR Part 11",
    "bioreactor",
    "bioprocessing",
    "vaccine manufacturer",
    "vaccine manufacturing",
];

/* Sectors that, for an ICS advisory, mean manufacturing or chemical process control. */
const MANUFACTURING_SECTORS = /^(critical manufacturing|chemical|healthcare and public health)$/i;

function escape(term: string): string {
    return term.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** Terms present as whole words or phrases, case-insensitive. */
export function matchTerms(text: string, terms: string[]): string[] {
    return terms.filter((term) => {
        const trimmed = term.trim();

        return trimmed.length > 1 && new RegExp(`(?:^|[^a-z0-9])${escape(trimmed)}(?![a-z0-9])`, "i").test(text);
    });
}

const SEVERE: Severity[] = ["critical", "high"];

/** More CVEs than this in one item make it a bundle of third-party fixes. */
export const BUNDLE_LIMIT = 10;

export function evaluate(item: RawItem, scope: ScopeConfig, kevCves: ReadonlySet<string>): Evaluation {
    const title = `${item.title}\n${item.products.join("\n")}`;
    const body = item.text;
    const all = `${title}\n${body}`;

    const bioTerms = matchTerms(all, scope.bioPharmaTerms.length > 0 ? scope.bioPharmaTerms : DEFAULT_BIOPHARMA_TERMS);
    const bioProducts = matchTerms(all, scope.bioPharmaProducts);
    const securityProducts = matchTerms(all, scope.securityProducts);
    const logSources = matchTerms(`${all}\n${item.platforms.join("\n")}`, scope.logSources);
    const manufacturingOt = item.sectors.some((sector) => MANUFACTURING_SECTORS.test(sector));

    /*
     * A KEV-listed CVE confirms exploitation of this item, except in bulletins
     * that bundle many third-party CVEs (Siemens lists hundreds): there, one
     * KEV entry does not show this product is being attacked.
     */
    const kevHits = item.cves.filter((cve) => kevCves.has(cve));
    const bundle = !item.kevListed && item.cves.length > BUNDLE_LIMIT;
    const kev = item.kevListed || (kevHits.length > 0 && !bundle);
    const exploitation: Exploitation = kev ? "confirmed" : item.exploitationClaim === "reported" ? "reported" : "none";
    const exploited = exploitation !== "none";
    const severe = SEVERE.includes(item.severity);

    const bioPharma = bioTerms.length > 0 || bioProducts.length > 0;
    const reasons: string[] = [];

    if (bioTerms.length > 0) reasons.push(`Bio/Pharma terms: ${bioTerms.join(", ")}`);
    if (bioProducts.length > 0) reasons.push(`Bio/Pharma products in scope: ${bioProducts.join(", ")}`);
    if (securityProducts.length > 0) reasons.push(`security products in scope: ${securityProducts.join(", ")}`);
    if (logSources.length > 0) reasons.push(`log sources in scope: ${logSources.join(", ")}`);
    if (manufacturingOt) reasons.push(`ICS advisory for sectors: ${item.sectors.join(", ")}`);
    reasons.push(
        exploitation === "confirmed"
            ? "exploitation confirmed by CISA KEV"
            : exploitation === "reported"
                ? item.research
                    ? "a research article describes exploitation (unverified: not a vendor or CISA statement)"
                    : item.news
                        ? "a news report describes exploitation (unverified: secondary reporting, not a vendor or CISA statement)"
                        : "the source reports exploitation"
                : "no exploitation evidence",
    );
    if (bundle && kevHits.length > 0) {
        reasons.push(
            `bundles ${item.cves.length} CVEs, ${kevHits.length} of them in CISA KEV; exploitation of this product is not established`,
        );
    }
    reasons.push(`severity: ${item.severity}`);

    let priority: Priority = "ignore";

    if (bioPharma && (exploited || severe)) {
        priority = "P1";
    } else if (exploitation === "confirmed" && (securityProducts.length > 0 || logSources.length > 0 || manufacturingOt)) {
        priority = "P1";
    } else if (securityProducts.length > 0 && (exploited || severe)) {
        priority = "P2";
    } else if (bioPharma) {
        // Industry relevance alone is not enough for P1.
        priority = "P2";
    } else if (manufacturingOt && exploitation === "reported") {
        priority = "P2";
    } else if (logSources.length > 0 && (exploited || severe)) {
        priority = "P3";
    } else if (exploitation === "confirmed") {
        priority = "P3";
    } else if (item.research && item.iocs.length > 0) {
        // Published indicators are directly huntable, whatever the scope lists say.
        priority = "P3";
        reasons.push(`research article publishing ${item.iocs.length} indicators`);
    }

    if (priority === "ignore") {
        reasons.unshift("not in scope, or not severe or exploited enough to act on");
    }

    /* Confidence: how direct the evidence for the match is. */
    const inTitle =
        matchTerms(title, [...bioTerms, ...bioProducts, ...securityProducts, ...logSources]).length > 0 ||
        item.platforms.some((platform) => matchTerms(platform, logSources).length > 0);

    let confidence: Confidence;

    if (priority === "ignore") {
        confidence = "high";
    } else if (exploitation === "confirmed" || inTitle || (manufacturingOt && !bioPharma) || (item.research && item.iocs.length > 0)) {
        confidence = "high";
    } else if (bioPharma || securityProducts.length > 0 || logSources.length > 0) {
        // Matched only in the body text, which may mention the term in passing.
        confidence = "medium";
    } else {
        confidence = "low";
    }

    return {
        priority,
        confidence,
        exploitation,
        reasons,
        matchedBioPharma: [...bioTerms, ...bioProducts],
        matchedSecurityProducts: securityProducts,
        matchedLogSources: logSources,
        products: [...new Set([...item.products, ...bioProducts, ...securityProducts])],
        platforms: [...new Set([...item.platforms, ...logSources])],
    };
}

export const PRIORITY_RANK: Record<Priority, number> = { P1: 1, P2: 2, P3: 3, ignore: 9 };
