
import type {
    InvestigationStatus,
    ProviderStatus,
} from "../types.js";

export const DEFAULT_PRIOR_MAX_AGE_HOURS = 24;

export type PriorDecision =
    | {
        decision: "reuse";
        reason: string;
        ageHours: number;
    }
    | {
        decision: "refresh";
        reason: string;
        ageHours: number | null;
    };

type PriorPolicyInput = {
    status: InvestigationStatus;
    createdAt: string;
    providerResults: unknown[];
    limitations: string[];
    evidenceCount: number;
    evidenceRetrievedAt: string[];
};

type PersistedProviderResult = {
    provider: string;
    status: ProviderStatus;
};

type TimestampAge =
    | {
        valid: true;
        ageHours: number;
    }
    | {
        valid: false;
        reason: "invalid" | "future";
    };

function isProviderResult(
    value: unknown,
): value is PersistedProviderResult {
    if (typeof value !== "object" || value === null) {
        return false;
    }

    const object = value as Record<string, unknown>;

    return (
        typeof object.provider === "string" &&
        (
            object.status === "success" ||
            object.status === "observed_absence" ||
            object.status === "error" ||
            object.status === "timeout"
        )
    );
}

function providerCompleted(
    providerResults: unknown[],
    providerName: string,
): boolean {
    const matchingResults = providerResults.filter(
        (value): value is PersistedProviderResult =>
            isProviderResult(value) &&
            value.provider === providerName,
    );

    // Be conservative if duplicate records disagree: at least one
    // successful completion is required for this provider.
    return matchingResults.some(
        (result) =>
            result.status === "success" ||
            result.status === "observed_absence",
    );
}

function calculateAgeHours(
    timestamp: string,
    now: Date,
): TimestampAge {
    if (typeof timestamp !== "string" || timestamp.trim() === "") {
        return {
            valid: false,
            reason: "invalid",
        };
    }

    const timestampMs = Date.parse(timestamp);

    if (!Number.isFinite(timestampMs)) {
        return {
            valid: false,
            reason: "invalid",
        };
    }

    if (timestampMs > now.getTime()) {
        return {
            valid: false,
            reason: "future",
        };
    }

    return {
        valid: true,
        ageHours:
            (now.getTime() - timestampMs) / (1000 * 60 * 60),
    };
}

function refreshDecision(
    reason: string,
    ageHours: number | null,
): PriorDecision {
    return {
        decision: "refresh",
        reason,
        ageHours,
    };
}

export function evaluatePriorInvestigation(
    input: PriorPolicyInput,
    options: {
        now?: Date;
        maxAgeHours?: number;
    } = {},
): PriorDecision {
    const now = options.now ?? new Date();

    const maxAgeHours =
        options.maxAgeHours ?? DEFAULT_PRIOR_MAX_AGE_HOURS;

    if (
        !(now instanceof Date) ||
        !Number.isFinite(now.getTime())
    ) {
        throw new RangeError(
            "The policy evaluation time must be a valid date.",
        );
    }

    if (
        !Number.isFinite(maxAgeHours) ||
        maxAgeHours < 0
    ) {
        throw new RangeError(
            "maxAgeHours must be a finite, non-negative number.",
        );
    }

    const investigationAge = calculateAgeHours(
        input.createdAt,
        now,
    );

    if (!investigationAge.valid) {
        return refreshDecision(
            investigationAge.reason === "future"
                ? "Prior investigation has a future creation timestamp."
                : "Prior investigation has an invalid creation timestamp.",
            null,
        );
    }

    const ageHours = investigationAge.ageHours;

    if (input.status !== "confirmed") {
        return refreshDecision(
            `Prior investigation status is ${input.status}; only confirmed investigations are eligible for reuse.`,
            ageHours,
        );
    }

    if (ageHours > maxAgeHours) {
        return refreshDecision(
            `Prior investigation is ${ageHours.toFixed(1)} hours old, exceeding the ${maxAgeHours}-hour freshness window.`,
            ageHours,
        );
    }

    if (!Array.isArray(input.limitations) || input.limitations.length > 0) {
        return refreshDecision(
            "Prior investigation contains unresolved limitations or invalid limitation data.",
            ageHours,
        );
    }

    if (
        !Number.isInteger(input.evidenceCount) ||
        input.evidenceCount <= 0
    ) {
        return refreshDecision(
            "Prior investigation contains no valid persisted evidence.",
            ageHours,
        );
    }

    if (
        !Array.isArray(input.evidenceRetrievedAt) ||
        input.evidenceRetrievedAt.length !== input.evidenceCount
    ) {
        return refreshDecision(
            "Evidence retrieval timestamps are missing or incomplete.",
            ageHours,
        );
    }

    const evidenceAges = input.evidenceRetrievedAt.map(
        (timestamp) => calculateAgeHours(timestamp, now),
    );

    const invalidEvidenceTimestamp = evidenceAges.find(
        (result) => !result.valid,
    );

    if (invalidEvidenceTimestamp && !invalidEvidenceTimestamp.valid) {
        return refreshDecision(
            invalidEvidenceTimestamp.reason === "future"
                ? "At least one evidence record has a future retrieval timestamp."
                : "At least one evidence record has an invalid retrieval timestamp.",
            ageHours,
        );
    }

    // All timestamps are valid after the check above.
    const oldestEvidenceAgeHours = Math.max(
        ...evidenceAges.map((result) =>
            result.valid ? result.ageHours : 0,
        ),
    );

    if (oldestEvidenceAgeHours > maxAgeHours) {
        return refreshDecision(
            `Oldest evidence is ${oldestEvidenceAgeHours.toFixed(1)} hours old, exceeding the ${maxAgeHours}-hour freshness window.`,
            ageHours,
        );
    }

    if (
        !Array.isArray(input.providerResults) ||
        !providerCompleted(input.providerResults, "NVD")
    ) {
        return refreshDecision(
            "Prior investigation does not contain a completed NVD check.",
            ageHours,
        );
    }

    if (!providerCompleted(input.providerResults, "CISA_KEV")) {
        return refreshDecision(
            "Prior investigation does not contain a completed CISA KEV check.",
            ageHours,
        );
    }

    return {
        decision: "reuse",
        reason:
            `Prior investigation is confirmed, complete, evidence-backed, and ${ageHours.toFixed(1)} hours old; all evidence is within the freshness window.`,
        ageHours,
    };
}
