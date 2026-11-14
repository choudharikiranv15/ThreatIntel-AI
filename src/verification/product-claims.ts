import type { ProductRow } from "./evidence-cache.js";

/*
 * Checks what an answer says about a named Red Hat product against that
 * product's own rows. One product's status is never inferred from another's,
 * even within the same family.
 */

type ClaimedStatus = "fixed" | "affected" | "not_affected";

/*
 * Single words that unmistakably name a Red Hat product line. Any other word in
 * a product name ("software", "data", "integration", "product") also appears in
 * ordinary sentences, so a product must then be named by its multi-word name.
 * Missing a vague mention is safer than flagging a correct answer.
 */
const BRAND_WORDS = new Set([
    "openshift",
    "jboss",
    "ansible",
    "satellite",
    "quarkus",
    "ceph",
    "gluster",
    "keycloak",
    "openstack",
]);

/* Words that name a product family too loosely to identify one product. */
const GENERIC_WORDS = new Set([
    "red", "hat", "enterprise", "linux", "platform", "for", "on", "the", "and",
    "update", "updates", "services", "service", "support", "extended",
    "advanced", "server", "client", "workstation", "solutions", "telco", "sap",
    "lifecycle", "els", "eus", "aus", "tus", "e4s", "rhel", "of", "with",
]);

function normalize(text: string): string {
    return text
        .toLowerCase()
        .replace(/\brhel\b/g, "enterprise linux")
        .replace(/^red hat\s+/, "")
        .replace(/[^a-z0-9.+ ]+/g, " ")
        .replace(/\s+/g, " ")
        .trim();
}

/** Drops trailing version numbers, so "openshift container platform 4.12" has a family. */
function withoutVersion(name: string): string {
    return name.replace(/(\s+\d[\w.]*)+$/, "").trim();
}

type Phrase = {
    text: string;
    /** True when the phrase names a version, so it points at one product stream. */
    versioned: boolean;
};

function phrasesFor(productName: string): Phrase[] {
    const name = normalize(productName);
    const phrases: Phrase[] = [{ text: name, versioned: /\d/.test(name) }];

    // "enterprise linux 8.2 extended update support" also answers to "enterprise linux 8".
    const majorVersion = name.match(/^(.*?\s\d+)(?:[.\s]|$)/)?.[1];

    if (majorVersion && majorVersion !== name) {
        phrases.push({ text: majorVersion, versioned: true });
    }

    const family = withoutVersion(name.split(/\s\d/)[0] ?? name);

    if (family && family !== name) {
        phrases.push({ text: family, versioned: false });
    }

    // A single brand word, such as "openshift" or "jboss".
    const brand = family.split(" ").find((word) => BRAND_WORDS.has(word));

    if (brand && brand !== family) {
        phrases.push({ text: brand, versioned: false });
    }

    return phrases;
}

function claimedStatus(segment: string): ClaimedStatus | "mixed" | null {
    const lower = segment.toLowerCase();
    const claims = new Set<ClaimedStatus>();

    if (/\b(?:not\s+affected|unaffected|not\s+vulnerable)\b/.test(lower)) {
        claims.add("not_affected");
    }

    const withoutNegated = lower.replace(/\b(?:not\s+affected|unaffected|not\s+vulnerable)\b/g, " ");

    if (/\b(?:affected|vulnerable)\b/.test(withoutNegated)) {
        claims.add("affected");
    }

    if (/\b(?:fixed|patched|fix(?:es)?\s+(?:shipped|available|released)|shipped\s+fix(?:es)?)\b/.test(lower)) {
        claims.add("fixed");
    }

    if (claims.size === 0) {
        return null;
    }

    // Several statuses in one sentence cannot be assigned to products reliably.
    return claims.size === 1 ? [...claims][0] : "mixed";
}

function containsPhrase(segment: string, phrase: string): boolean {
    const escaped = phrase.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

    // The phrase must end at a word boundary that is not a version continuation:
    // "enterprise linux 8" must not match inside "enterprise linux 8.2".
    return new RegExp(`(?:^|[^a-z0-9])${escaped}(?![a-z0-9]|\\.\\d)`).test(segment);
}

const STATUS_WORDS: Record<ClaimedStatus, string> = {
    fixed: "fixed",
    affected: "affected",
    not_affected: "not affected",
};

/**
 * Returns findings for product-specific claims in one sentence.
 *
 * - The claimed status must appear among the named product's rows.
 * - A family name, such as "OpenShift", whose rows disagree is ambiguous: the
 *   answer must name the version rather than assert one status.
 * - A Red Hat product claim with no Red Hat rows at all is unsupported.
 */
export function checkProductClaims(
    target: string,
    segment: string,
    rows: ProductRow[],
    complete: boolean,
): string[] {
    const claim = claimedStatus(segment);

    if (claim === null || claim === "mixed") {
        return [];
    }

    const text = normalize(segment);
    const findings: string[] = [];

    if (rows.length === 0) {
        if (/\b(?:red hat|enterprise linux|openshift|jboss)\b/.test(text)) {
            findings.push(
                `${target}: the answer gives a Red Hat product status, but no Red Hat assessment was retrieved.`,
            );
        }

        return findings;
    }

    /* Which phrases from the evidence does this sentence name? */
    const index = new Map<string, { rows: ProductRow[]; versioned: boolean }>();

    for (const row of rows) {
        for (const phrase of phrasesFor(row.productName)) {
            const existing = index.get(phrase.text) ?? { rows: [], versioned: phrase.versioned };

            existing.rows.push(row);
            index.set(phrase.text, existing);
        }
    }

    // Longest phrases first, so "openshift container platform 4" is not also
    // read as a bare "openshift" claim.
    const named = [...index.entries()]
        .filter(([phrase]) => containsPhrase(text, phrase))
        .sort((a, b) => b[0].length - a[0].length);

    const covered: string[] = [];

    for (const [phrase, match] of named) {
        if (covered.some((longer) => longer.includes(phrase))) {
            continue;
        }

        covered.push(phrase);

        const statuses = new Set(match.rows.map((row) => row.status));
        const label = match.rows[0].productName;

        if (!statuses.has(claim)) {
            findings.push(
                `${target}: the answer says ${phrase} is ${STATUS_WORDS[claim]}, but Red Hat lists ${[...statuses].join(", ")} for it${complete ? "" : " in the rows available"}.`,
            );
            continue;
        }

        if (!match.versioned && statuses.size > 1) {
            findings.push(
                `${target}: "${phrase}" covers products with different statuses (${[...statuses].join(", ")}), so a single status is ambiguous. Name the version, for example ${label}.`,
            );
        }
    }

    return findings;
}
