/*
 * Shared shapes for the threat feed. Raw items come from sources unchanged in
 * meaning; evaluation adds priority; selection decides what is posted.
 */

export type FeedSourceId =
    | "cisa-kev"
    | "cisa-advisories"
    | "cisa-ics"
    | "msrc"
    | "paloalto"
    | "fortinet"
    | "cisco"
    | "aws"
    | "gcp"
    | "dfir-report"
    | "unit42"
    | "cybersecuritynews";

export const ALL_FEED_SOURCES: FeedSourceId[] = [
    "cisa-kev",
    "cisa-advisories",
    "cisa-ics",
    "msrc",
    "paloalto",
    "fortinet",
    "cisco",
    "aws",
    "gcp",
    "dfir-report",
    "unit42",
    "cybersecuritynews",
];

/** Research publications: articles about observed attacks, not vendor advisories. */
export const RESEARCH_SOURCES: FeedSourceId[] = ["dfir-report", "unit42"];

/** News sites: secondary reporting of other people's findings. Never read for indicators. */
export const NEWS_SOURCES: FeedSourceId[] = ["cybersecuritynews"];

export type Severity = "critical" | "high" | "medium" | "low" | "unknown";

/**
 * confirmed: listed in CISA KEV. reported: the source itself says it has been
 * exploited. none: no exploitation evidence, which is not proof of safety.
 */
export type Exploitation = "confirmed" | "reported" | "none";

export type Priority = "P1" | "P2" | "P3" | "ignore";
export type Confidence = "high" | "medium" | "low";

export type IocType = "ipv4" | "domain" | "url" | "sha256" | "sha1" | "md5" | "filename";

export type Ioc = {
    type: IocType;
    /** Exactly as the source wrote it, including any defanging. */
    value: string;
    /** The page the indicator was taken from. */
    source: string;
    /** The source's own caution about using it, or a note that the list was capped. */
    note?: string;
};

export type RawItem = {
    source: FeedSourceId;
    /** Source family plus the source's own id, so one advisory has one key across feeds. */
    itemKey: string;
    title: string;
    url: string;
    publishedAt: string | null;
    /** Plain text used for matching, capped. */
    text: string;
    cves: string[];
    severity: Severity;
    /** What the source's own text says about exploitation. */
    exploitationClaim: "reported" | "denied" | null;
    /** Products named by structured fields or the advisory title. */
    products: string[];
    /** Platforms implied by the source itself, such as AWS for an AWS bulletin. */
    platforms: string[];
    /** CISA ICS deployment sectors, when given. */
    sectors: string[];
    iocs: Ioc[];
    /** True for KEV catalog entries. */
    kevListed: boolean;
    /** True for research articles, whose claims are not vendor or CISA statements. */
    research?: boolean;
    /** True for news reports, which retell other people's findings: unverified like research. */
    news?: boolean;
};

export type Evaluation = {
    priority: Priority;
    confidence: Confidence;
    exploitation: Exploitation;
    /** Why this priority, in plain words. */
    reasons: string[];
    matchedBioPharma: string[];
    matchedSecurityProducts: string[];
    matchedLogSources: string[];
    products: string[];
    platforms: string[];
};

export type EvaluatedItem = RawItem & Evaluation;

export type ProviderOutcome = {
    source: FeedSourceId;
    status: "success" | "failed";
    items: number;
    error: string | null;
    durationMs: number;
};
