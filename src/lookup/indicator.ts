/*
 * Turns what an analyst pastes into one well-formed indicator, or refuses it.
 * Indicators often arrive defanged ("hxxp://evil[.]com") or inside a URL. Only
 * public indicators are accepted: a private address or internal hostname is
 * never sent to a third-party service, because the lookup itself would
 * disclose it.
 */

export type IndicatorType = "ipv4" | "domain" | "md5" | "sha1" | "sha256";

export type Indicator = { value: string; type: IndicatorType; note?: string };

export type IndicatorRejection = { error: "invalid_indicator" | "not_public" | "unsupported"; message: string };

const MAX_INPUT = 300;

/** Restores a defanged indicator to its plain form. */
export function refang(input: string): string {
    return input
        .trim()
        .replace(/^[`"'<(\[{]+|[`"'>)\]}.,;]+$/g, "")
        .replace(/^hxxp/i, "http")
        .replace(/^fxp/i, "ftp")
        .replace(/\[(\.|dot)\]|\((\.|dot)\)|\{(\.|dot)\}|\s\[dot\]\s/gi, ".")
        .replace(/\[:\]/g, ":")
        .trim();
}

const IPV4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

/* Ranges that are not public internet addresses (RFC 6890 and related). */
const NON_PUBLIC_V4: Array<[string, number]> = [
    ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8],
    ["169.254.0.0", 16], ["172.16.0.0", 12], ["192.0.0.0", 24], ["192.0.2.0", 24],
    ["192.88.99.0", 24], ["192.168.0.0", 16], ["198.18.0.0", 15], ["198.51.100.0", 24],
    ["203.0.113.0", 24], ["224.0.0.0", 4], ["240.0.0.0", 4],
];

function toNumber(ip: string): number {
    return ip.split(".").reduce((n, octet) => n * 256 + Number(octet), 0);
}

export function isPublicIpv4(ip: string): boolean {
    const value = toNumber(ip);

    return !NON_PUBLIC_V4.some(([base, bits]) => {
        const size = 2 ** (32 - bits);

        return value >= toNumber(base) && value < toNumber(base) + size;
    });
}

/* Suffixes that only exist inside networks, or are reserved for tests. */
const INTERNAL_SUFFIX = /\.(local|localhost|internal|intranet|lan|home|corp|private|arpa|test|example|invalid|onion)$/i;
const LABEL = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/;

function domainOf(value: string): string | null {
    const domain = value.toLowerCase().replace(/\.$/, "");

    if (domain.length > 253 || !domain.includes(".")) {
        return null;
    }

    const labels = domain.split(".");

    if (!labels.every((label) => LABEL.test(label)) || !/^(xn--[a-z0-9-]+|[a-z]{2,24})$/.test(labels.at(-1) ?? "")) {
        return null;
    }

    return domain;
}

export function parseIndicator(raw: unknown): Indicator | IndicatorRejection {
    if (typeof raw !== "string" || raw.trim().length === 0 || raw.length > MAX_INPUT) {
        return { error: "invalid_indicator", message: "Give one IPv4 address, domain, or file hash (MD5, SHA-1, or SHA-256)." };
    }

    let value = refang(raw);
    let note: string | undefined;

    // A URL is looked up by its host; the path is never sent anywhere.
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(value)) {
        try {
            value = new URL(value).hostname.replace(/^\[|\]$/g, "");
            note = "Looked up the URL's host only.";
        } catch {
            return { error: "invalid_indicator", message: "That URL could not be read." };
        }
    }

    if (/^[a-f0-9]{64}$/i.test(value)) return { value: value.toLowerCase(), type: "sha256" };
    if (/^[a-f0-9]{40}$/i.test(value)) return { value: value.toLowerCase(), type: "sha1" };
    if (/^[a-f0-9]{32}$/i.test(value)) return { value: value.toLowerCase(), type: "md5" };

    if (IPV4.test(value)) {
        return isPublicIpv4(value)
            ? { value, type: "ipv4", ...(note ? { note } : {}) }
            : { error: "not_public", message: `${value} is a private, reserved, or documentation address. It is not sent to any external service.` };
    }

    if (value.includes(":")) {
        return { error: "unsupported", message: "IPv6 addresses are not supported yet." };
    }

    const domain = domainOf(value);

    if (!domain) {
        return { error: "invalid_indicator", message: "Give one IPv4 address, domain, or file hash (MD5, SHA-1, or SHA-256)." };
    }

    if (INTERNAL_SUFFIX.test(domain)) {
        return { error: "not_public", message: `${domain} is an internal or reserved name. It is not sent to any external service.` };
    }

    return { value: domain, type: "domain", ...(note ? { note } : {}) };
}
