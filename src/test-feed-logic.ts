/*
 * Threat feed rules, offline and deterministic: parsing real recorded feeds,
 * priority, deduplication, updates, limits, IOC extraction, and formatting.
 * Database behaviour (persistence, restarts, leases, delivery) is tested in
 * persistence/test-feed.ts.
 */
import fs from "node:fs";
import path from "node:path";

import { BUNDLE_LIMIT, evaluate, type ScopeConfig } from "./feed/classify.js";
import { CONCEPTS } from "./feed/concepts.js";
import { formatFeedPost, formatQuietNotice, NO_IOCS, POST_DIVIDER } from "./feed/format.js";
import { extractIocs, extractIocsFromIndicatorFile, indicatorFileLinks, MAX_IOCS } from "./feed/iocs.js";
import { HOW_TO_READ, summarizeFeed } from "./feed/tools.js";
import { parseFeed } from "./feed/rss.js";
import {
    DEFAULT_SELECTION,
    sameThreat,
    selectForPublication,
    titleSimilarity,
    type Candidate,
    type RecentPost,
    type RecentCve,
    type SelectionConfig,
} from "./feed/select.js";
import { createSourceFetcher, enrichResearchItem, exploitationClaimIn, parseKev, parseSource, severityIn, withinWindow } from "./feed/sources.js";
import type { EvaluatedItem, RawItem } from "./feed/types.js";

function assert(condition: unknown, message: string): asserts condition {
    if (!condition) {
        throw new Error(`Assertion failed: ${message}`);
    }
}

const FIXTURES = path.join(process.cwd(), "test-fixtures", "feed");
const fixture = (name: string) => fs.readFileSync(path.join(FIXTURES, name), "utf8");

const EMPTY: ScopeConfig = { bioPharmaTerms: [], bioPharmaProducts: [], securityProducts: [], logSources: [] };

const SCOPE: ScopeConfig = {
    bioPharmaTerms: [],
    bioPharmaProducts: ["LabWare LIMS", "DeltaV"],
    securityProducts: ["FortiGate", "CrowdStrike Falcon", "Splunk"],
    logSources: ["Microsoft 365", "Entra ID", "AWS"],
};

const NOW = new Date("2026-11-14T12:00:00.000Z");

function raw(overrides: Partial<RawItem> = {}): RawItem {
    return {
        source: "cisa-advisories",
        itemKey: `test:${Math.random().toString(36).slice(2)}`,
        title: "Generic advisory",
        url: "https://example.test/advisory",
        publishedAt: "2026-11-14T00:00:00.000Z",
        text: "",
        cves: [],
        severity: "unknown",
        exploitationClaim: null,
        products: [],
        platforms: [],
        sectors: [],
        iocs: [],
        kevListed: false,
        ...overrides,
    };
}

function evaluated(overrides: Partial<RawItem> = {}, scope = SCOPE, kev: string[] = []): EvaluatedItem {
    const item = raw(overrides);

    return { ...item, ...evaluate(item, scope, new Set(kev)) };
}

/* ------------------------------- 0. Parsing ------------------------------- */

function testParsing(): void {
    const sources = {
        "cisa-advisories": "cisa-all.xml",
        "cisa-ics": "cisa-ics.xml",
        msrc: "msrc.xml",
        paloalto: "paloalto.xml",
        fortinet: "fortinet.xml",
        cisco: "cisco.xml",
        aws: "aws.xml",
        gcp: "gcp.xml",
    } as const;

    const keys = new Map<string, string>();

    for (const [source, file] of Object.entries(sources)) {
        const items = parseSource(source as keyof typeof sources, fixture(file));

        assert(items.length > 0, `${source} must parse its recorded feed`);

        for (const item of items) {
            assert(/^https:\/\//.test(item.url), `${source} items keep the original https link: ${item.url}`);
            assert(item.publishedAt && !Number.isNaN(Date.parse(item.publishedAt)), `${source} items keep the publication time`);
            assert(item.itemKey.includes(":") && item.title.length > 0, `${source} items have a key and a title`);

            if (keys.has(item.itemKey) && keys.get(item.itemKey) !== source) {
                // The same advisory through two CISA feeds must share one key.
                assert(item.itemKey.startsWith("cisa:"), `only CISA's two feeds overlap: ${item.itemKey}`);
            }

            keys.set(item.itemKey, source);
        }
    }

    /* Source details that drive priority */
    const ics = parseSource("cisa-ics", fixture("cisa-ics.xml"));

    assert(ics.every((item) => item.severity === "critical"), `ICS severity comes from the CVSS table, not a vector's "3.1": ${ics.map((item) => item.severity)}`);
    assert(ics.every((item) => item.sectors.length > 0), "ICS advisories keep their deployment sectors");

    const msrc = parseSource("msrc", fixture("msrc.xml"));

    assert(msrc.length === 2, "MSRC revisions are skipped; only first publications are items");

    const aws = parseSource("aws", fixture("aws.xml"));

    assert(aws.every((item) => !item.url.includes("/rss/")), "AWS items link to the bulletin, not the RSS redirect");

    const cisco = parseSource("cisco", fixture("cisco.xml"));

    assert(cisco.every((item) => !item.url.includes("vs_f=")), "tracking parameters are removed from links");

    const gcp = parseSource("gcp", fixture("gcp.xml"));

    assert(gcp.some((item) => item.severity !== "unknown"), "Google Cloud severity is read from its table");

    /* The KEV catalog: only recent additions, all confirmed exploitation. */
    const kev = parseKev(JSON.parse(fixture("kev.json")), new Date("2000-01-01"));

    assert(kev.length === 6 && kev.every((item) => item.kevListed && item.cves.length === 1), "KEV entries are items of their own");
    assert(parseKev(JSON.parse(fixture("kev.json")), new Date("2099-01-01")).length === 0, "old KEV additions are not new intelligence");

    /* A window drops old items, so MSRC's years of history never reach the database. */
    assert(withinWindow([raw({ publishedAt: "2020-01-01T00:00:00Z" }), raw()], new Date("2026-11-10")).length === 1, "items outside the window are dropped");

    /* A bot-check page is not a feed. */
    assert(parseFeed("<!doctype html><html><title>Microsoft</title></html>").length === 0, "an HTML page yields no items");

    console.log("✓ Every source's recorded feed parses with links, dates, keys, severity, and sectors");
}

/* -------------------------- Exploitation evidence ------------------------- */

function testExploitationEvidence(): void {
    const cases: Array<[string, "reported" | "denied" | null]> = [
        ["These vulnerabilities were found during internal testing and are not known to be actively exploited.", "denied"],
        ["No known public exploitation specifically targeting these vulnerabilities has been reported to CISA at this time.", "denied"],
        ["The Cisco PSIRT is not aware of any public announcements or malicious use of the vulnerability.", "denied"],
        ["An attacker could exploit this vulnerability by sending a crafted request.", null],
        ["A successful exploit could allow the attacker to execute code.", null],
        ["Two of them are known to be actively exploited.", "reported"],
        ["Fortinet is aware of an instance of this vulnerability being exploited in the wild.", "reported"],
        ["Microsoft is aware of limited, targeted attacks.", "reported"],
    ];

    for (const [text, expected] of cases) {
        assert(exploitationClaimIn(text) === expected, `"${text}" should be ${expected}, got ${exploitationClaimIn(text)}`);
    }

    /* Reported is not confirmed; only KEV confirms. */
    const reported = evaluated({ exploitationClaim: "reported", products: ["FortiGate"] });
    const confirmed = evaluated({ cves: ["CVE-2026-0001"], products: ["FortiGate"] }, SCOPE, ["CVE-2026-0001"]);

    assert(reported.exploitation === "reported" && confirmed.exploitation === "confirmed", "a source's claim is reported; KEV confirms");

    /* A bundle with one KEV CVE among many does not confirm exploitation of the product. */
    const bundleCves = Array.from({ length: BUNDLE_LIMIT + 1 }, (_, index) => `CVE-2026-${1000 + index}`);
    const bundle = evaluated({ cves: bundleCves, sectors: ["Critical Manufacturing"] }, EMPTY, [bundleCves[0]]);

    assert(bundle.exploitation === "none" && bundle.priority === "ignore", `a bundled third-party KEV CVE does not make a P1: ${bundle.priority}`);
    assert(bundle.reasons.some((reason) => reason.includes("not established")), "the reason says why");

    assert(severityIn("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") === "unknown", "a vector string's version is not a score");
    assert(severityIn("CVSS v3.1 Base Score: 9.8") === "critical", "a stated base score is read");
    assert(severityIn("CVE-2026-0325 PAN-OS: Bypass (Severity: HIGH)") === "high", "a severity label is read");

    console.log("✓ Exploitation is evidence-based: denials win, capability wording is not exploitation, and only KEV confirms");
}

/* ---------------------- 1-4. Priority by category ---------------------- */

function testPriorities(): void {
    /* 1. Bio/Pharma */
    const pharma = evaluated({ title: "Ransomware campaign targets pharmaceutical manufacturers", severity: "high" });

    assert(pharma.priority === "P1", `Bio/Pharma with high severity is P1: ${pharma.priority}`);

    const lims = evaluated({ title: "LabWare LIMS authentication bypass", exploitationClaim: "reported" });

    assert(lims.priority === "P1" && lims.confidence === "high", "an in-scope Bio/Pharma product, exploited, is P1 with high confidence");

    const pharmaLow = evaluated({ title: "Clinical trial portal information disclosure", severity: "medium" });

    assert(pharmaLow.priority === "P2", "industry relevance alone does not make P1");

    const healthcare = evaluated({ title: "Hospital patient portal flaw in healthcare software", severity: "critical" }, EMPTY);

    assert(healthcare.priority === "ignore", "a healthcare mention alone is not Bio/Pharma relevance");

    const exploitedOt = evaluated({ title: "Siemens SIMATIC", cves: ["CVE-2026-0002"], sectors: ["Critical Manufacturing"] }, EMPTY, ["CVE-2026-0002"]);

    assert(exploitedOt.priority === "P1", "confirmed exploitation of manufacturing OT is P1");

    const unexploitedOt = evaluated({ title: "Siemens SIMATIC", severity: "critical", sectors: ["Critical Manufacturing", "Healthcare and Public Health"] }, EMPTY);

    assert(unexploitedOt.priority === "ignore", "an unexploited OT advisory without a configured product does not post");

    /* 2. Security products */
    const fortigate = evaluated({ title: "FortiGate SSL-VPN heap overflow", severity: "critical" });

    assert(fortigate.priority === "P2" && fortigate.matchedSecurityProducts.includes("FortiGate"), "a severe flaw in an in-scope security product is P2");

    const fortigateExploited = evaluated({ title: "FortiGate SSL-VPN heap overflow", cves: ["CVE-2026-0003"] }, SCOPE, ["CVE-2026-0003"]);

    assert(fortigateExploited.priority === "P1", "confirmed exploitation of an in-scope product is P1");

    /* 3. Log sources */
    const entra = evaluated({ title: "Entra ID token validation flaw", severity: "high" });

    assert(entra.priority === "P3" && entra.matchedLogSources.includes("Entra ID"), "a severe flaw in an in-scope log source is P3");

    const awsPlatform = evaluated({ title: "Template injection in a workbench", platforms: ["AWS"], severity: "high" });

    assert(awsPlatform.priority === "P3", "a platform named by the source counts as a log source match");

    /* 4. Unrelated */
    const unrelated = evaluated({ title: "Printer firmware update", severity: "medium" });

    assert(unrelated.priority === "ignore", "unrelated, unexploited items are filtered out");

    const lowInScope = evaluated({ title: "Splunk dashboard cosmetic issue", severity: "low" });

    assert(lowInScope.priority === "ignore", "a low-severity, unexploited in-scope item is filtered out");

    const kevUnscoped = evaluated({ title: "UnrealIRCd flaw", cves: ["CVE-2026-0004"], kevListed: true }, EMPTY);

    assert(kevUnscoped.priority === "P3", "confirmed exploitation outside scope is still P3");

    /* Matching is by whole word or phrase. */
    const partial = evaluated({ title: "AWSome Tool flaw", severity: "high" });

    assert(partial.priority === "ignore", "a scope term inside another word does not match");

    console.log("✓ Bio/Pharma is P1, security products P2, log sources P3, and unrelated items are filtered");
}

/* ----------------------- 5-9. Selection behaviour ----------------------- */

const candidate = (item: EvaluatedItem, published: Candidate["published"] = null): Candidate => ({ item, published });

function decide(
    candidates: Candidate[],
    config: Partial<SelectionConfig> = {},
    recent = new Map<string, RecentCve>(),
    posts: RecentPost[] = [],
) {
    return selectForPublication(candidates, recent, { ...DEFAULT_SELECTION, ...config }, NOW, posts);
}

function testSelection(): void {
    const p1 = evaluated({ itemKey: "a:p1", title: "pharmaceutical research data theft", severity: "high" });
    const p2 = evaluated({ itemKey: "a:p2", title: "FortiGate flaw", severity: "critical" });
    const p3 = evaluated({ itemKey: "a:p3", title: "Entra ID flaw", severity: "critical" });
    const ignored = evaluated({ itemKey: "a:ig", title: "Printer flaw" });

    /* 5. P1 outranks P2 and P3 when the limit is reached. */
    const limited = decide([candidate(p3), candidate(p2), candidate(p1)], { maxPostsPerCycle: 1, urgentBypass: false });

    assert(limited.get("a:p1")?.kind === "publish", "P1 is posted first");
    assert(limited.get("a:p2")?.kind === "defer" && limited.get("a:p3")?.kind === "defer", "lower priorities wait for a later cycle");

    const two = decide([candidate(p3), candidate(p2), candidate(p1)], { maxPostsPerCycle: 2, urgentBypass: false });

    assert(two.get("a:p1")?.kind === "publish" && two.get("a:p2")?.kind === "publish" && two.get("a:p3")?.kind === "defer", "P2 comes before P3");

    /* 6. Duplicates: a CVE posted recently is not posted again through another advisory. */
    const kevItem = evaluated({ itemKey: "kev:CVE-2026-0100", title: "FortiGate exploited", cves: ["CVE-2026-0100"], kevListed: true });
    const vendorItem = evaluated({ itemKey: "fortinet:FG-1", title: "FortiGate advisory", cves: ["CVE-2026-0100"], severity: "critical" }, SCOPE, ["CVE-2026-0100"]);

    const sameCycle = decide([candidate(kevItem), candidate(vendorItem)]);
    const kinds = [sameCycle.get(kevItem.itemKey)?.kind, sameCycle.get(vendorItem.itemKey)?.kind].sort();

    assert(kinds[0] === "publish" && kinds[1] === "suppress", `one underlying threat is posted once per cycle: ${kinds}`);

    const recent = new Map<string, RecentCve>([
        ["CVE-2026-0100", { itemKey: "kev:CVE-2026-0100", publishedAt: "2026-11-13T00:00:00.000Z", exploitation: "confirmed", iocCount: 0 }],
    ]);

    assert(decide([candidate(vendorItem)], {}, recent).get(vendorItem.itemKey)?.kind === "suppress", "a CVE posted yesterday is suppressed in another advisory");

    const withIocs = { ...vendorItem, iocs: [{ type: "ipv4" as const, value: "203.0.113[.]5", source: "x" }] };

    assert(decide([candidate(withIocs)], {}, recent).get(vendorItem.itemKey)?.kind === "publish", "an advisory adding indicators is worth posting");

    const partlyCovered = { ...vendorItem, cves: ["CVE-2026-0100", "CVE-2026-0101"] };

    assert(decide([candidate(partlyCovered)], {}, recent).get(vendorItem.itemKey)?.kind === "publish", "an advisory with uncovered CVEs is not a duplicate");

    const old = new Map([[...recent][0]].map(([cve, entry]) => [cve, { ...entry, publishedAt: "2026-10-01T00:00:00.000Z" }]));

    assert(decide([candidate(vendorItem)], {}, old).get(vendorItem.itemKey)?.kind === "publish", "outside the dedupe window a CVE may be posted again");

    /* Already posted, same content: never posted again. */
    const published = { lastPublishedAt: "2026-11-10T00:00:00.000Z", exploitation: "none" as const, iocCount: 0 };

    assert(decide([candidate(p2, published)]).get(p2.itemKey)?.kind === "keep", "an unchanged posted item is not reposted");

    /* 7. A material update is reconsidered and posted as an update. */
    const nowExploited = { ...p2, exploitation: "confirmed" as const, priority: "P1" as const };
    const update = decide([candidate(nowExploited, published)]).get(p2.itemKey);

    assert(update?.kind === "publish" && update.updated, "newly confirmed exploitation is posted as an update");

    const recentPost = { ...published, lastPublishedAt: "2026-11-14T06:00:00.000Z" };
    const newIocs = { ...p2, iocs: [{ type: "domain" as const, value: "evil[.]example", source: "x" }] };

    assert(decide([candidate(newIocs, recentPost)]).get(p2.itemKey)?.kind === "defer", "a non-urgent update within the cooldown waits");
    assert(decide([candidate(newIocs, published)]).get(p2.itemKey)?.kind === "publish", "after the cooldown, new indicators are posted");

    const urgentUpdate = decide([candidate({ ...nowExploited, matchedBioPharma: ["x"] }, recentPost)]).get(p2.itemKey);

    assert(urgentUpdate?.kind === "publish", "newly confirmed P1 exploitation skips the cooldown");

    /* 8. The per-cycle limit, with the urgent exception. */
    const many = Array.from({ length: 6 }, (_, index) =>
        evaluated({ itemKey: `m:${index}`, title: `FortiGate flaw ${index}`, severity: "critical", cves: [`CVE-2026-02${index}0`] }),
    );
    const capped = decide(many.map((item) => candidate(item)), { maxPostsPerCycle: 3 });

    assert([...capped.values()].filter((d) => d.kind === "publish").length === 3, "no more than the limit is posted");
    assert([...capped.values()].filter((d) => d.kind === "defer").length === 3, "the rest are kept, not discarded");

    const urgent = evaluated({ itemKey: "u:1", title: "FortiGate exploited", cves: ["CVE-2026-0300"] }, SCOPE, ["CVE-2026-0300"]);
    const withUrgent = decide([...many, urgent].map((item) => candidate(item)), { maxPostsPerCycle: 1 });

    assert(withUrgent.get("u:1")?.kind === "publish", "confirmed P1 exploitation is posted first");

    const urgentOverflow = decide(
        [urgent, { ...urgent, itemKey: "u:2", cves: ["CVE-2026-0301"] }, { ...urgent, itemKey: "u:3", cves: ["CVE-2026-0302"] }].map((item) => candidate(item)),
        { maxPostsPerCycle: 1, urgentMaxPerCycle: 1 },
    );

    assert(
        [...urgentOverflow.values()].filter((d) => d.kind === "publish").length === 2 &&
        [...urgentOverflow.values()].some((d) => d.kind === "publish" && d.urgent),
        "one urgent post may exceed the limit, and no more",
    );

    assert(
        [...decide([urgent, { ...urgent, itemKey: "u:2", cves: ["CVE-2026-0301"] }].map((item) => candidate(item)), { maxPostsPerCycle: 1, urgentBypass: false }).values()]
            .filter((d) => d.kind === "publish").length === 1,
        "with the urgent exception off, the limit holds",
    );

    /* Minimum priority and age */
    assert(decide([candidate(p3)], { minPriority: "P2" }).get(p3.itemKey)?.kind === "ignore", "items below the minimum priority are not posted");

    const stale = evaluated({ title: "FortiGate flaw", severity: "critical", publishedAt: "2026-10-01T00:00:00.000Z" });

    assert(decide([candidate(stale)]).get(stale.itemKey)?.kind === "expire", "outdated items are not posted for the first time");

    /* 9. An empty cycle posts nothing. */
    assert(decide([]).size === 0, "no candidates, no decisions");
    assert(
        [...decide([candidate(ignored)]).values()].every((d) => d.kind !== "publish"),
        "nothing meeting the threshold means nothing is posted",
    );

    console.log("✓ Selection ranks P1 first, suppresses duplicates, reconsiders real updates, and respects limits and empty cycles");
}

/* --------------------------- 10-11. Indicators --------------------------- */

const ADVISORY_HTML = `
<h2>Technical Details</h2>
<p>For example, an attacker may contact example.com or 192.0.2.1 in a lab setup.</p>
<p>Version 10.2.1.4 fixes this. See https://vendor.example/advisory for details.</p>
<h2>Indicators of Compromise</h2>
<p>The following indicators were observed:</p>
<table>
<tr><td>203.0.113[.]45</td><td>C2 server</td></tr>
<tr><td>198.51.100.7</td><td>Staging</td></tr>
<tr><td>update-check[.]example[.]net</td><td>Domain</td></tr>
<tr><td>hxxps://cdn.bad-host[.]example/payload.bin</td><td>Download URL</td></tr>
<tr><td>e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855</td><td>SHA256</td></tr>
<tr><td>D41D8CD98F00B204E9800998ECF8427E</td><td>MD5</td></tr>
<tr><td>svchost_update.exe</td><td>Dropper</td></tr>
</table>
<h2>Mitigations</h2>
<p>Block evil[.]example.org and 203.0.113.99 is our sinkhole recommendation.</p>
`;

function testIocs(): void {
    const iocs = extractIocs(ADVISORY_HTML, "https://example.test/aa26-001a");
    const values = iocs.map((ioc) => `${ioc.type}=${ioc.value}`);

    const expected = [
        "ipv4=203.0.113[.]45",
        "ipv4=198.51.100.7",
        "domain=update-check[.]example[.]net",
        "url=hxxps://cdn.bad-host[.]example/payload.bin",
        "sha256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "md5=D41D8CD98F00B204E9800998ECF8427E",
        "filename=svchost_update.exe",
    ];

    for (const value of expected) {
        assert(values.includes(value), `indicator kept exactly as published: ${value} (got ${values.join(", ")})`);
    }

    assert(values.length === expected.length, `nothing else is extracted: ${values.join(", ")}`);
    assert(!values.some((value) => /example\.com|192\.0\.2\.1|10\.2\.1\.4|vendor\.example|evil\[\.\]example\.org|203\.0\.113\.99/.test(value)), "text outside the indicator section is never an indicator");
    assert(iocs.every((ioc) => ioc.source === "https://example.test/aa26-001a"), "each indicator records its source");

    /* 10. No indicator section: no indicators, and the post says so. */
    assert(extractIocs("<p>Patch now. Contact 203.0.113[.]1 for support.</p>", "x").length === 0, "without an indicator section, nothing is extracted");

    const post = formatFeedPost(evaluated({ title: "FortiGate flaw", severity: "critical" }));

    assert(post.trimEnd().endsWith(NO_IOCS), "a post without indicators says so explicitly");

    /* 11. The post keeps exact values, in code spans so Discord makes no links. */
    const withIocs = formatFeedPost({ ...evaluated({ title: "Campaign X" }), iocs });

    for (const ioc of iocs) {
        assert(withIocs.includes(`\`${ioc.value}\``), `the post shows ${ioc.value} exactly, unlinked`);
    }

    console.log("✓ Indicators come only from the indicator section, exactly as published; missing ones are stated");
}

/* ------------------------------- Formatting ------------------------------- */

function testFormat(): void {
    const item = evaluated({
        title: "CVE-2026-0325 PAN-OS: GlobalProtect Bypass (Severity: HIGH)",
        products: ["PAN-OS"],
        platforms: ["AWS"],
        url: "https://security.paloaltonetworks.com/CVE-2026-0325",
    });
    const post = formatFeedPost(item);
    const lines = post.split("\n");

    assert(lines[0] === POST_DIVIDER, "each post starts with a divider, so grouped Discord messages stay apart");
    assert(
        lines[1] === "**Threat Name:**" && lines[2] === "CVE-2026-0325 PAN-OS: GlobalProtect Bypass",
        `the threat name has its own heading: ${lines.slice(1, 3)}`,
    );

    const headings = lines.filter((line) => line.startsWith("**"));

    assert(
        JSON.stringify(headings) === JSON.stringify(["**Threat Name:**", "**Affected Tools / Products:**", "**Affected Platforms:**", "**Article:**", "**IOCs to Hunt:**"]),
        `exactly the five sections, in order: ${headings}`,
    );
    assert(post.includes("<https://security.paloaltonetworks.com/CVE-2026-0325>"), "the original link is kept");
    assert(!/summary|remediation|recommend/i.test(post), "no summaries or remediation text");

    /* Hostile source text */
    const hostile = formatFeedPost(evaluated({ title: "@everyone urgent <@123>", products: ["**bold** [link](https://x)"] }));

    assert(!hostile.includes("@everyone") && !hostile.includes("<@123>"), "mentions in source text cannot ping");
    assert(!hostile.includes("[link](https://x)"), "markdown links in source text are neutralised");

    const badLink = formatFeedPost(evaluated({ url: "javascript:alert(1)" }));

    assert(!badLink.includes("javascript:"), "only http and https links are posted");

    /* Length */
    const huge = formatFeedPost({
        ...evaluated({ title: "Campaign" }),
        iocs: Array.from({ length: 300 }, (_, index) => ({ type: "sha256" as const, value: "a".repeat(63) + (index % 10), source: "x" })),
    });

    assert(huge.length <= 2000 && /and \d+ more in the article/.test(huge), "long indicator lists are cut to fit one message and say how many are left");

    const gcp = formatFeedPost(evaluated({ title: "GCP-2026-079", cves: ["CVE-2026-1", "CVE-2026-2"] }));

    assert(gcp.split("\n")[2] === "GCP-2026-079: CVE-2026-1, CVE-2026-2", "a bare bulletin id is named by its CVEs");

    console.log("✓ Posts follow the required format exactly and are safe against hostile source text");
}

/* ---------------------------- Status summary ---------------------------- */

function testStatusSummary(): void {
    const posts = [
        { title: "CVE-2026-123039 Check Point flaw", selectedAt: "2026-11-14T10:57:57.000Z", deliveryStatus: "sent" },
        { title: "CVE-2026-114713 UnrealIRCd flaw", selectedAt: "2026-11-14T10:57:57.500Z", deliveryStatus: "sent" },
        { title: "Siemens Desigo", selectedAt: "2026-11-14T07:53:48.000Z", deliveryStatus: "sent" },
    ];
    const run = { startedAt: "2026-11-16T06:07:48.000Z", status: "success", discovered: 74, newItems: 0, selected: 0, deferred: 0, error: null };

    /* The live misreading: a quiet run must read as normal, and sent posts as already delivered. */
    const quiet = summarizeFeed({ enabled: true, nextRunAt: "2026-11-16T09:07:54.000Z", lastRun: run, posts, sentTotal: 6 });

    assert(/0 of them new, and 0 were posted/.test(quiet), `the quiet run is stated plainly: ${quiet}`);
    assert(/normal when the sources publish nothing new/.test(quiet), "a quiet run is explained as normal");
    assert(/next cycle is due at 2026-11-16T09:07:54/.test(quiet), "the next cycle is given");
    assert(
        quiet.includes("Check Point") && quiet.includes("UnrealIRCd") && !quiet.includes("Siemens"),
        `the most recent batch is named by title, and only that batch: ${quiet}`,
    );
    assert(/already in the feed channel/.test(quiet), "delivered posts are said to be in the channel");

    const failed = summarizeFeed({ enabled: true, nextRunAt: null, lastRun: { ...run, status: "failed", error: "every source failed" }, posts, sentTotal: 6 });

    assert(/failed and collected nothing: every source failed/.test(failed), "a failed run is never an empty success");

    const limited = summarizeFeed({ enabled: true, nextRunAt: null, lastRun: { ...run, selected: 3, deferred: 2 }, posts, sentTotal: 6 });

    assert(/2 qualifying items wait for a later cycle/.test(limited), "deferral is explained only when it happened");

    assert(/disabled/.test(summarizeFeed({ enabled: false, nextRunAt: null, lastRun: null, posts: [], sentTotal: 0 })), "a disabled feed says so");
    assert(/Nothing has been posted yet/.test(summarizeFeed({ enabled: true, nextRunAt: null, lastRun: null, posts: [], sentTotal: 0 })), "no posts says so");

    assert(HOW_TO_READ.some((rule) => /never posted again/.test(rule)), "the reading rules state that posts are not repeated");

    console.log("✓ Feed status starts with a plain summary that cannot be read as pending posts or a failure");
}

/* ------------------------------ Quiet notice ------------------------------ */

function testQuietNotice(): void {
    /* The concept list: vetted, short, and uniform. */
    assert(CONCEPTS.length >= 40, `enough concepts that repeats are rare: ${CONCEPTS.length}`);
    assert(new Set(CONCEPTS.map((concept) => concept.question.toLowerCase())).size === CONCEPTS.length, "no concept repeats");

    for (const concept of CONCEPTS) {
        assert(/^What is .+\?$/.test(concept.question), `every question starts with "What is": ${concept.question}`);
        assert(concept.answer.length >= 60 && concept.answer.length <= 320, `answers are one or two lines: ${concept.question} (${concept.answer.length})`);
        assert((concept.answer.match(/[.!?](\s|$)/g) ?? []).length <= 3, `answers are at most a few sentences: ${concept.question}`);
        assert(!/@|<|\*\*|\]\(/.test(concept.answer + concept.question), `no mentions or markdown in a concept: ${concept.question}`);
    }

    const notice = formatQuietNotice(3, CONCEPTS[0]);
    const lines = notice.split("\n");

    assert(lines[0] === POST_DIVIDER, "the notice starts with the divider, like every feed message");
    assert(lines[1] === "There's no latest feed in the last 3 hours.", `the notice says so plainly: ${lines[1]}`);
    assert(lines[3] === "**What is NVD?**" && lines[4] === CONCEPTS[0].answer, "the concept follows as a question and a short answer");
    assert(lines.length === 5 && notice.length < 600, "the notice stays short");

    assert(formatQuietNotice(1, CONCEPTS[0]).includes("in the last hour."), "the wording follows the configured interval");

    const partial = formatQuietNotice(3, CONCEPTS[0], { failed: 2, total: 9 });

    assert(/2 of 9 sources could not be checked/.test(partial), "a notice after a partial cycle says which coverage was missing");

    console.log("✓ The quiet notice is short, honest about coverage, and carries a vetted concept");
}

/* --------------------------- Research articles --------------------------- */

const DFIR_URL = "https://thedfirreport.com/2026/06/29/example/";

async function testResearch(): Promise<void> {
    /* Feeds: title and summary only, marked as research. */
    for (const [source, file] of [["dfir-report", "dfir-report.xml"], ["unit42", "unit42.xml"]] as const) {
        const items = parseSource(source, fixture(file));

        assert(items.length === 4, `${source} parses its recorded feed`);
        assert(
            items.every((item) => item.research && item.itemKey.startsWith(`${source}:`) && /^https:\/\//.test(item.url) && item.publishedAt && item.iocs.length === 0),
            `${source} items are research items with a key, link, and date; indicators come from the article`,
        );
    }

    /* The DFIR Report "Indicators" section: exact values, including plain IPs. */
    const dfir = extractIocs(fixture("dfir-report-article-indicators.html"), DFIR_URL);
    const count = (type: string, list = dfir) => list.filter((ioc) => ioc.type === type).length;

    assert(count("domain") === 15 && count("ipv4") === 8 && count("sha256") === 3 && count("sha1") === 3 && count("md5") === 3, `the indicator section is read in full: ${dfir.length}`);
    assert(dfir.some((ioc) => ioc.value === "opmanager[.]pro") && dfir.some((ioc) => ioc.value === "192.121.22.94"), "values are kept exactly as published");
    assert(dfir[0].type === "ipv4" && dfir.at(-1)?.type === "md5", "the most huntable types come first");

    /* A section at the end of the page stops at the page furniture, and keeps the source's caution. */
    const footer = extractIocs(fixture("dfir-report-article-footer.html"), DFIR_URL);

    assert(count("url", footer) === 11 && footer.every((ioc) => !ioc.value.includes("thedfirreport.com")), `the site's own links are never indicators: ${footer.filter((ioc) => ioc.type === "url").map((ioc) => ioc.value).join(" ")}`);
    assert(footer.every((ioc) => /shared SaaS infrastructure/.test(ioc.note ?? "")), "the source's caution about its indicators is kept");
    assert(/-# Source note: .*shared SaaS infrastructure/.test(formatFeedPost({ ...evaluated({ title: "Flash Alert" }), iocs: footer })), "and shown in the post");

    /* Unit 42: defanged domains and hashes. */
    const unit42 = extractIocs(fixture("unit42-article.html"), "https://unit42.paloaltonetworks.com/x/");

    assert(count("domain", unit42) === 5 && count("sha256", unit42) === 21 && unit42.some((ioc) => ioc.value === "fonts.chrorne[.]com"), "Unit 42 indicator sections are read");

    /* An indicator section that only links to the source's GitHub dataset. */
    const github = fixture("dfir-report-article-github.html");

    assert(extractIocs(github, DFIR_URL).length === 0, "a link to GitHub is a reference, not an indicator");

    const links = indicatorFileLinks(github);

    assert(
        links.length === 1 && links[0].startsWith("https://raw.githubusercontent.com/The-DFIR-Report/DFIR-Report-Indicators/main/"),
        `the source's own indicator file is followed: ${links}`,
    );
    assert(indicatorFileLinks('<h2>Indicators</h2><p>https://github.com/someone-else/iocs/blob/main/list.md</p>').length === 0, "only trusted indicator repositories are followed");

    const file = extractIocsFromIndicatorFile(fixture("dfir-report-indicators.md"), links[0]);

    assert(file.length === 179 && file.every((ioc) => ioc.type === "domain" && ioc.source === links[0]), `the indicator file is read line by line, with its own URL as the source: ${file.length}`);
    assert(file.some((ioc) => ioc.value === "stats.us3.org"), "plain domains count inside a dedicated indicator file");
    assert(extractIocsFromIndicatorFile("# Notes\nexample.com\n203.0.113.9\n", "x").length === 0, "values outside code blocks are never indicators");

    /* Section boundaries and reference links, on a page built to contain each trap. */
    const traps = extractIocs(
        [
            "<h2>Indicators</h2>",
            "<p>hxxps://evil[.]example/payload and https://thedfirreport.com/services/ for more.</p>",
            "<p>Rules: https://github.com/example/rules and https://www.virustotal.com/gui/file/abc</p>",
            "<h5>Share this entry</h5><p>share-site[.]example</p>",
            "<footer><p>footer-host[.]example</p></footer>",
        ].join("\n"),
        DFIR_URL,
    ).map((ioc) => ioc.value);

    assert(JSON.stringify(traps) === JSON.stringify(["hxxps://evil[.]example/payload"]), `only the real indicator survives: ${traps.join(", ")}`);

    const afterFooter = extractIocs("<h2>Indicators of Compromise</h2><p>bad[.]example</p><footer><p>footer-host[.]example</p></footer>", DFIR_URL).map((ioc) => ioc.value);

    assert(JSON.stringify(afterFooter) === JSON.stringify(["bad[.]example"]), `the page footer is never part of the section: ${afterFooter.join(", ")}`);

    const ownSite = extractIocs("<h2>Indicators</h2><p>https://thedfirreport.com/contact/ https://cdn.thedfirreport.com/x hxxp://c2[.]example/a</p>", DFIR_URL).map((ioc) => ioc.value);

    assert(JSON.stringify(ownSite) === JSON.stringify(["hxxp://c2[.]example/a"]), `links to the article's own site are not indicators: ${ownSite.join(", ")}`);

    const huge = extractIocsFromIndicatorFile("```\n" + Array.from({ length: MAX_IOCS + 100 }, (_, index) => `host${index}.example.org`).join("\n") + "\n```\n", "x");

    assert(huge.length === MAX_IOCS && huge.every((ioc) => new RegExp(`lists ${MAX_IOCS + 100} indicators`).test(ioc.note ?? "")), "a very long list is capped, and says how many the source lists");

    /* Enrichment: the article and its indicator file together. */
    const [first] = parseSource("dfir-report", fixture("dfir-report.xml"));
    const enriched = await enrichResearchItem(first, async (url) =>
        url.includes("raw.githubusercontent.com") ? fixture("dfir-report-indicators.md") : github,
    );

    assert(enriched.iocs.length === 179 && enriched.url === first.url, "an article's indicators include its linked dataset");

    /* Priority: indicators make a research article worth posting; without them it is not. */
    const withIocs = evaluated({ title: "Intrusion report", research: true, iocs: dfir }, EMPTY);
    const without = evaluated({ title: "Opinion piece on AI", research: true }, EMPTY);

    assert(withIocs.priority === "P3" && withIocs.confidence === "high" && withIocs.reasons.some((reason) => /publishing 32 indicators/.test(reason)), `a research article with indicators is P3: ${withIocs.priority}`);
    assert(without.priority === "ignore", "a research article without indicators or scope is not posted");

    const claimed = evaluated({ title: "FortiGate intrusion", research: true, exploitationClaim: "reported", iocs: dfir });

    assert(claimed.reasons.some((reason) => /unverified/.test(reason)), "a research article's exploitation claim is labelled unverified");
    assert(evaluated({ title: "pharmaceutical firm breached", research: true, exploitationClaim: "reported", iocs: dfir }).priority === "P1", "scope rules still raise research items");

    /* Same threat through another article: nothing new to hunt, so no second post. */
    const posted: RecentPost[] = [{
        itemKey: "dfir-report:akira",
        title: "From Bing Search to Ransomware: Bumblebee and AdaptixC2 Deliver Akira",
        publishedAt: "2026-11-13T00:00:00.000Z",
        iocValues: new Set(dfir.map((ioc) => ioc.value.toLowerCase())),
    }];

    const repeat = evaluated({ itemKey: "unit42:akira", title: "Akira ransomware via Bumblebee", research: true, iocs: dfir.slice(0, 20) }, EMPTY);

    assert(sameThreat(repeat, posted, NOW, DEFAULT_SELECTION)?.itemKey === "dfir-report:akira", "an article whose indicators were already posted is the same threat");
    assert(decide([candidate(repeat)], {}, new Map(), posted).get("unit42:akira")?.kind === "suppress", "and is not posted again");

    const fresh = { ...repeat, iocs: [...dfir.slice(0, 5), ...unit42] };

    assert(decide([candidate(fresh)], {}, new Map(), posted).get("unit42:akira")?.kind === "publish", "new indicators are new hunting value");

    const sameTitle = evaluated({ itemKey: "x:1", title: "Bumblebee and AdaptixC2 Deliver Akira: From Bing Search to Ransomware", severity: "critical", products: ["FortiGate"] });

    assert(decide([candidate(sameTitle)], {}, new Map(), posted).get("x:1")?.kind === "suppress", "without a CVE or indicators, a near-identical title is the same threat");
    assert(titleSimilarity("BengalSEO Part 1: Anatomy of the Operation", "BengalSEO Part 2: Following the Money") < 0.7, "a series' next part is not a duplicate");
    assert(titleSimilarity("FortiGate SSL-VPN heap overflow", "Entra ID token validation flaw") === 0, "unrelated titles do not match");

    const old = [{ ...posted[0], publishedAt: "2026-10-01T00:00:00.000Z" }];

    assert(decide([candidate(repeat)], {}, new Map(), old).get("unit42:akira")?.kind === "publish", "outside the dedupe window, the threat may be posted again");

    /* Two research articles in one cycle with the same indicators: one post. */
    const twin = { ...repeat, itemKey: "dfir-report:twin", iocs: dfir };
    const both = decide([candidate(twin), candidate(repeat)]);

    assert([...both.values()].filter((d) => d.kind === "publish").length === 1 && [...both.values()].some((d) => d.kind === "suppress"), "one threat, one post, even within a cycle");

    /* An article page that cannot be read: the item waits, it is not posted without indicators. */
    const realFetch = globalThis.fetch;
    const feed = fixture("dfir-report.xml").replace(/<pubDate>[^<]*<\/pubDate>/g, `<pubDate>${new Date().toUTCString()}</pubDate>`);
    let failing = 1;

    globalThis.fetch = (async (input: string | URL | Request) => {
        const url = String(input);

        if (url.endsWith("/feed/")) return new Response(feed, { status: 200 });
        if (url.includes("raw.githubusercontent.com")) return new Response(fixture("dfir-report-indicators.md"), { status: 200 });

        failing -= 1;

        return failing >= 0 ? new Response("down", { status: 503 }) : new Response(fixture("dfir-report-article-indicators.html"), { status: 200 });
    }) as typeof fetch;

    try {
        const options = { timeoutMs: 2000, retry: { attempts: 1, maxDelayMs: 1, budgetMs: 1 }, since: () => new Date(Date.now() - 86_400_000), kevCatalog: async () => ({ catalog: {} }) };
        const partial = await createSourceFetcher(options)("dfir-report");

        assert(partial.length === 3 && partial.every((item) => item.iocs.length > 0), `an unreadable article is left out and the rest are read: ${partial.length}`);

        failing = 99;

        let threw = false;

        try {
            await createSourceFetcher(options)("dfir-report");
        } catch {
            threw = true;
        }

        assert(threw, "when no article can be read, the source counts as failed");
    } finally {
        globalThis.fetch = realFetch;
    }

    console.log("✓ Research articles add real indicators, keep source cautions, and are posted once per threat");
}

async function main(): Promise<void> {
    await testResearch();
    testQuietNotice();
    testStatusSummary();
    testParsing();
    testExploitationEvidence();
    testPriorities();
    testSelection();
    testIocs();
    testFormat();

    console.log("Threat feed logic tests PASSED");
}

main().catch((error) => {
    console.error("Threat feed logic tests FAILED");
    console.error(error);
    process.exitCode = 1;
});
