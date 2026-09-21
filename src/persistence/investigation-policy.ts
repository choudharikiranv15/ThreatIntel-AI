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
};

type PersistedProviderResult = {
    provider: string;
    status: ProviderStatus;
};

function isProviderResult(
    value: unknown,
): value is PersistedProviderResult {
    if (
        typeof value !== "object" ||
        value === null
    ) {
        return false;
    }

    const object =
        value as Record<string, unknown>;

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
    provider: string,
): boolean {
    const result = providerResults
        .map((value) =>
            isProviderResult(value)
                ? value
                : null,
        )
        .find(
            (value) =>
                value?.provider === provider,
        );

    return (
        result?.status === "success" ||
        result?.status === "observed_absence"
    );
}

function calculateAgeHours(
    createdAt: string,
    now: Date,
): number | null {
    const created =
        new Date(createdAt);

    if (
        Number.isNaN(
            created.getTime(),
        )
    ) {
        return null;
    }

    const ageMs =
        now.getTime() -
        created.getTime();

    if (ageMs < 0) {
        return 0;
    }

    return ageMs / (1000 * 60 * 60);
}

export function evaluatePriorInvestigation(
    input: PriorPolicyInput,
    options: {
        now?: Date;
        maxAgeHours?: number;
    } = {},
): PriorDecision {
    const now =
        options.now ??
        new Date();

    const maxAgeHours =
        options.maxAgeHours ??
        DEFAULT_PRIOR_MAX_AGE_HOURS;

    const ageHours =
        calculateAgeHours(
            input.createdAt,
            now,
        );

    if (ageHours === null) {
        return {
            decision: "refresh",
            reason:
                "Prior investigation has an invalid creation timestamp.",
            ageHours: null,
        };
    }

    if (
        input.status !==
        "confirmed"
    ) {
        return {
            decision: "refresh",
            reason:
                `Prior investigation status is ${input.status}; only confirmed investigations are eligible for reuse.`,
            ageHours,
        };
    }

    if (
        ageHours >
        maxAgeHours
    ) {
        return {
            decision: "refresh",
            reason:
                `Prior investigation is ${ageHours.toFixed(1)} hours old, exceeding the ${maxAgeHours}-hour freshness window.`,
            ageHours,
        };
    }

    if (
        input.limitations.length > 0
    ) {
        return {
            decision: "refresh",
            reason:
                "Prior investigation contains unresolved limitations.",
            ageHours,
        };
    }

    if (
        input.evidenceCount === 0
    ) {
        return {
            decision: "refresh",
            reason:
                "Prior investigation contains no persisted evidence.",
            ageHours,
        };
    }

    if (
        !providerCompleted(
            input.providerResults,
            "NVD",
        )
    ) {
        return {
            decision: "refresh",
            reason:
                "Prior investigation does not contain a completed NVD check.",
            ageHours,
        };
    }

    if (
        !providerCompleted(
            input.providerResults,
            "CISA_KEV",
        )
    ) {
        return {
            decision: "refresh",
            reason:
                "Prior investigation does not contain a completed CISA KEV check.",
            ageHours,
        };
    }

    return {
        decision: "reuse",
        reason:
            `Prior investigation is confirmed, complete, evidence-backed, and ${ageHours.toFixed(1)} hours old.`,
        ageHours,
    };
}