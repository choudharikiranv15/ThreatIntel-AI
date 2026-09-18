import type {
    Evidence,
    ProviderResult,
    SourceId,
} from "./types.js";

const VALID_PROVIDER_STATUSES = new Set([
    "success",
    "observed_absence",
    "error",
    "timeout",
]);

const VALID_SOURCE_TYPES = new Set([
    "primary",
    "vendor",
    "community",
]);

const VALID_CONFIDENCE = new Set([
    "high",
    "medium",
    "low",
]);

function isRecord(
    value: unknown,
): value is Record<string, unknown> {
    return (
        typeof value === "object" &&
        value !== null &&
        !Array.isArray(value)
    );
}

function isString(value: unknown): value is string {
    return typeof value === "string";
}

function isBoolean(value: unknown): value is boolean {
    return typeof value === "boolean";
}

function validateEvidence(
    evidence: unknown,
    expectedSource: SourceId,
): string[] {
    const errors: string[] = [];

    if (!isRecord(evidence)) {
        return [
            "Evidence must be a non-null object.",
        ];
    }

    if (evidence.source !== expectedSource) {
        errors.push(
            `Evidence source mismatch: expected ${expectedSource}, received ${String(evidence.source)}.`,
        );
    }

    if (!isString(evidence.sourceType)) {
        errors.push(
            "Evidence sourceType must be a string.",
        );
    } else if (!VALID_SOURCE_TYPES.has(evidence.sourceType)) {
        errors.push(
            `Evidence sourceType is invalid: ${evidence.sourceType}.`,
        );
    }

    if (!isString(evidence.retrievedAt)) {
        errors.push(
            "Evidence retrievedAt must be a string.",
        );
    }

    if (!isString(evidence.url)) {
        errors.push(
            "Evidence url must be a string.",
        );
    }

    if (!isString(evidence.title)) {
        errors.push(
            "Evidence title must be a string.",
        );
    }

    if (!isString(evidence.confidence)) {
        errors.push(
            "Evidence confidence must be a string.",
        );
    } else if (!VALID_CONFIDENCE.has(evidence.confidence)) {
        errors.push(
            `Evidence confidence is invalid: ${evidence.confidence}.`,
        );
    }

    if (!isRecord(evidence.facts)) {
        errors.push(
            "Evidence facts must be an object.",
        );
    }

    if (!Array.isArray(evidence.extractedFacts)) {
        errors.push(
            "Evidence extractedFacts must be an array.",
        );
    } else {
        for (
            let index = 0;
            index < evidence.extractedFacts.length;
            index += 1
        ) {
            const fact =
                evidence.extractedFacts[index];

            if (!isRecord(fact)) {
                errors.push(
                    `Evidence extractedFacts[${index}] must be an object.`,
                );
                continue;
            }

            if (!isString(fact.claim)) {
                errors.push(
                    `Evidence extractedFacts[${index}].claim must be a string.`,
                );
            }

            if (
                fact.field !== undefined &&
                !isString(fact.field)
            ) {
                errors.push(
                    `Evidence extractedFacts[${index}].field must be a string when present.`,
                );
            }
        }
    }

    if (!Array.isArray(evidence.references)) {
        errors.push(
            "Evidence references must be an array.",
        );
    } else {
        for (
            let index = 0;
            index < evidence.references.length;
            index += 1
        ) {
            const reference =
                evidence.references[index];

            if (!isRecord(reference)) {
                errors.push(
                    `Evidence references[${index}] must be an object.`,
                );
                continue;
            }

            if (!isString(reference.title)) {
                errors.push(
                    `Evidence references[${index}].title must be a string.`,
                );
            }

            if (!isString(reference.url)) {
                errors.push(
                    `Evidence references[${index}].url must be a string.`,
                );
            }

            if (!isBoolean(reference.retrieved)) {
                errors.push(
                    `Evidence references[${index}].retrieved must be boolean.`,
                );
            }
        }
    }

    return errors;
}

export function validateProviderResult(
    result: unknown,
    expectedProvider: SourceId,
): string[] {
    const errors: string[] = [];

    if (!isRecord(result)) {
        return [
            "Provider result must be a non-null object.",
        ];
    }

    if (result.provider !== expectedProvider) {
        errors.push(
            `Provider mismatch: expected ${expectedProvider}, received ${String(result.provider)}.`,
        );
    }

    if (!isString(result.status)) {
        errors.push(
            "Provider status must be a string.",
        );
    } else if (
        !VALID_PROVIDER_STATUSES.has(result.status)
    ) {
        errors.push(
            `Provider status is invalid: ${result.status}.`,
        );
    }

    if (!isString(result.checkedAt)) {
        errors.push(
            "Provider checkedAt must be a string.",
        );
    }

    if (
        result.error !== null &&
        !isString(result.error)
    ) {
        errors.push(
            "Provider error must be null or a string.",
        );
    }

    const status = result.status;

    /*
     * Provider contract:
     *
     * success
     *   -> evidence MUST exist
     *   -> error MUST be null
     *
     * observed_absence
     *   -> evidence MUST be null
     *   -> error MUST be null
     *
     * error / timeout
     *   -> evidence MUST be null
     *   -> error SHOULD exist
     */

    if (status === "success") {
        if (!result.evidence) {
            errors.push(
                "Provider status is success but evidence is missing.",
            );
        } else {
            errors.push(
                ...validateEvidence(
                    result.evidence,
                    expectedProvider,
                ),
            );
        }

        if (result.error !== null) {
            errors.push(
                "Provider status is success but error is not null.",
            );
        }
    }

    if (status === "observed_absence") {
        if (result.evidence !== null) {
            errors.push(
                "Provider status is observed_absence but evidence is present.",
            );
        }

        if (result.error !== null) {
            errors.push(
                "Provider status is observed_absence but error is not null.",
            );
        }
    }

    if (
        status === "error" ||
        status === "timeout"
    ) {
        if (result.evidence !== null) {
            errors.push(
                `Provider status is ${status} but evidence is present.`,
            );
        }

        if (!isString(result.error)) {
            errors.push(
                `Provider status is ${status} but error is missing.`,
            );
        }
    }

    return errors;
}

export function normalizeInvalidProviderResult(
    result: unknown,
    expectedProvider: SourceId,
): ProviderResult {
    const errors =
        validateProviderResult(
            result,
            expectedProvider,
        );

    if (errors.length === 0) {
        return result as ProviderResult;
    }

    return {
        provider: expectedProvider,
        status: "error",
        evidence: null,
        error:
            `Provider contract violation: ${errors.join(" ")}`,
        checkedAt:
            new Date().toISOString(),
    };
}