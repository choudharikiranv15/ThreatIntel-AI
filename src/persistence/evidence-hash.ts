import { createHash } from "node:crypto";

function canonicalize(value: unknown): unknown {
    if (Array.isArray(value)) {
        return value.map(canonicalize);
    }

    if (typeof value === "object" && value !== null) {
        const object = value as Record<string, unknown>;

        return Object.fromEntries(
            Object.keys(object)
                .sort()
                .map((key) => [key, canonicalize(object[key])]),
        );
    }

    return value;
}

/**
 * JSONB reorders keys and normalizes whitespace, so the hash covers a canonical
 * form. The same value hashes the same before and after a database round trip.
 */
export function hashPayload(payload: unknown): string {
    const canonical = JSON.stringify(
        canonicalize(JSON.parse(JSON.stringify(payload))),
    );

    return createHash("sha256").update(canonical).digest("hex");
}
