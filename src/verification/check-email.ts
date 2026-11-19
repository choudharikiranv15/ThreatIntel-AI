import type { HeaderAnalysisPayload } from "../email/analyze.js";
import type { AuthVerdict } from "../email/headers.js";

/*
 * Checks what an answer says about SPF, DKIM, and DMARC against the receiving
 * server's results from the same session's header analysis. Narrow on
 * purpose: a clause naming exactly one mechanism and a pass or fail verdict.
 */

type Mechanism = "spf" | "dkim" | "dmarc";

const MECHANISMS: Record<Mechanism, RegExp> = {
    spf: /\bspf\b/i,
    dkim: /\bdkim\b/i,
    dmarc: /\bdmarc\b/i,
};

const SAID_FAIL = /\b(?:did not|didn't|does not|doesn't|not|never)\s+pass(?:ed|es)?\b|\b(?:fail(?:ed|s|ing|ure)?|soft ?fail(?:ed)?|perm ?error)\b/i;
const SAID_PASS = /\bpass(?:ed|es|ing)?\b|\b(?:verified|aligned and passed|authenticated successfully)\b/i;

const BAD: AuthVerdict[] = ["fail", "softfail", "permerror", "temperror", "none", "neutral", "policy", "unknown"];

function actual(payload: HeaderAnalysisPayload, mechanism: Mechanism): { passed: boolean; label: string } | null {
    const auth = payload.authentication;

    if (!auth) return null;

    if (mechanism === "dkim") {
        if (auth.dkim.length === 0) return { passed: false, label: "not evaluated" };

        const passed = auth.dkim.some((d) => d.result === "pass");

        return { passed, label: auth.dkim.map((d) => d.result).join(", ") };
    }

    const result = auth[mechanism]?.result;

    return result ? { passed: !BAD.includes(result), label: result } : { passed: false, label: "not evaluated" };
}

function clauses(answer: string): string[] {
    return answer
        .split(/\n|(?<=[.!?;])\s+|,\s*|\s+but\s+|\s+while\s+|\s+whereas\s+/i)
        .map((clause) => clause.trim())
        .filter(Boolean);
}

export function checkEmailAnswer(answer: string, analyses: HeaderAnalysisPayload[]): string[] {
    // With several analyses in one session, only the latest is compared.
    const payload = analyses.at(-1);

    if (!payload) return [];

    const findings = new Set<string>();

    for (const clause of clauses(answer)) {
        const named = (Object.keys(MECHANISMS) as Mechanism[]).filter((m) => MECHANISMS[m].test(clause));

        if (named.length !== 1) continue;

        const mechanism = named[0];
        const truth = actual(payload, mechanism);

        if (!truth) continue;

        const saysFail = SAID_FAIL.test(clause);
        const saysPass = !saysFail && SAID_PASS.test(clause);

        if (saysPass && !truth.passed) {
            findings.add(`The answer says ${mechanism.toUpperCase()} passed, but the receiving server's result is ${truth.label}.`);
        } else if (saysFail && truth.passed) {
            findings.add(`The answer says ${mechanism.toUpperCase()} failed, but the receiving server's result is ${truth.label}.`);
        }
    }

    return Array.from(findings);
}

/** A header analysis as the tool returns it, or null. */
export function extractHeaderAnalysis(payload: unknown): HeaderAnalysisPayload | null {
    const candidate = payload as Partial<HeaderAnalysisPayload> | null;

    return candidate?.kind === "email_headers" && Array.isArray(candidate.findings) && typeof candidate.statement === "string"
        ? (candidate as HeaderAnalysisPayload)
        : null;
}
