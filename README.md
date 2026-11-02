# ThreatIntel AI Engine v0.4

A CVE investigation engine for ThreatIntel AI. Retrieves authoritative evidence from external intelligence sources and structures it for LLM-assisted SOC analysis.

## What it does

Given a CVE identifier, the engine:

- Retrieves the NVD CVE record (CVSS, CWE, affected configurations, references)
- Checks CISA Known Exploited Vulnerabilities (KEV) catalog status
- Retrieves Red Hat vendor impact, including shipped fixes
- Retrieves ecosystem package fixes from reviewed OSV advisories
- Compares sources and classifies each disagreement, without choosing a winner
- Builds an assessment in which each statement cites its facts, provider checks, or evidence
- Compares investigations over time, separating real changes from outages and engine changes
- Validates every provider response against a strict contract before accepting it
- Generates human-readable confirmed facts backed by traceable evidence
- Produces conservative analytical inferences with explicit supporting fact references
- Returns explicit limitations when a source is unavailable or returns no data

It deliberately does **not** invent MITRE ATT&CK mappings, detection claims, or facts not present in retrieved evidence.

## Build

```powershell
npm install
npm run build
```

## Validate

```powershell
npm run validate
```

## Tests

```powershell
# Build, then run everything that needs no network or database
npm test

# Needs PostgreSQL with the schema and migrations applied
npm run test:database

# Calls the live NVD, CISA, and Red Hat APIs
npm run test:live
```

CI runs `npm test` and `npm run test:database` against a real PostgreSQL service on every push and pull request.

The primary regression case is `CVE-2024-3094`. Expected outcome: `confirmed` status, CVSS 10 CRITICAL, KEV `not-listed`.

## Install into OpenClaw

```powershell
openclaw plugins install --link .
openclaw plugins enable threatintel-ai-engine
openclaw gateway restart
```

Then verify:

```powershell
openclaw plugins inspect threatintel-ai-engine --runtime --json
```

The answer gate reads the model's final answer, so OpenClaw only runs it after you allow conversation access for this plugin:

```powershell
openclaw config set plugins.entries.threatintel-ai-engine.hooks.allowConversationAccess true
openclaw gateway restart
```

## Database

For a new database, apply `db/schema.sql`, then every file in `db/migrations/` in order. For an existing database, including Supabase, apply only the migrations you have not run yet, using the Supabase SQL editor or `psql`.

**Apply `db/migrations/001_evidence_integrity.sql` before deploying v0.3.** Until then, saving investigations fails, and tool results report `persisted: false`.

Migration 001 also enables row-level security with no policies. That blocks Supabase's `anon` and `authenticated` Data API roles, while the table owner the plugin connects as keeps access.

Remote connections use TLS by default, without verifying the server certificate. To verify it, set `THREATINTEL_DB_SSL=verify-full` and `THREATINTEL_DB_SSL_CA` to the path of your provider's CA file. `THREATINTEL_DB_SSL=disable` turns TLS off.

To check that a saved investigation still matches its evidence, with no network access:

```powershell
npm run replay -- <investigation-id>
```

Replay re-derives the investigation from stored provider results and checks each evidence record against its SHA-256 hash. Investigations saved before migration 001 report `not_hashed`, and can differ if the extraction logic has changed since.

## Source correlation

`summary.correlations` compares what independent sources say, keeping every source's value:

| Classification | Meaning | Example |
|---|---|---|
| `agreement` | Sources say the same thing | CISA KEV and NVD record the same KEV date |
| `conflict` | Sources disagree about the same thing | Different scores for identical CVSS metrics; NVD records a KEV entry the catalog lacks |
| `explained_difference` | Sources are answering different questions | NVD 10.0 and Red Hat 9.8 because they rate `S` differently |
| `incomplete` | A comparison could not be completed, which is neither agreement nor conflict | The KEV check failed; a package or product could not be confidently matched |

Comparisons are deliberately narrow. CVSS v3 and v4 are never compared. Red Hat products are matched to NVD by CPE product and major version, and records with no match are counted as not compared. Fixed versions are compared only when a package's name and namespace match one NVD vendor's product, because `log4j` and `log4j-core` are different artifacts, and so are `python:requests` and `org.fork:requests`. A mismatch is called a conflict only when the package is firmly tied to that vendor. Otherwise it is reported as not comparable.

Red Hat's rating scale is separate from CVSS severity, so they are never reported as agreeing. Treating "Important" as similar to HIGH is this engine's approximate interpretation, and it is labelled as one.

## Sources

| Source | Provides | If it has no record |
|---|---|---|
| NVD | CVSS, CWE, affected products, references | `not-found` or `partial` |
| CISA KEV | Known exploitation | `not-listed`, which does not establish that exploitation has not occurred |
| Red Hat | Vendor impact and shipped fixes | No vendor assessment |
| OSV | Ecosystem package names and fixed versions | Normal for closed-source products |

OSV's `CVE-*` records hold only upstream git ranges, so the engine follows up to two aliased GHSA advisories and reports any it did not use. Unreviewed and withdrawn advisories are not treated as fix evidence, and distribution records are not followed.

If only OSV fails, the investigation stays `confirmed` and can be reused for one hour with the gap shown, then OSV is retried. NVD, CISA KEV, and Red Hat failures still prevent reuse.

## Changes over time

A refreshed investigation includes `changesSincePrior`, and `threatintel_compare_investigations` compares the two most recent saved investigations. The baseline is first re-derived from its stored evidence through the current engine, so each difference has one meaning:

- `intelligence_change`: a source that answered both times now says something else.
- `collection_difference`: a source was unavailable or not checked in one of them.
- `processing_difference`: the stored evidence gives a different result under the current engine.

Comparison never writes to stored investigations. `baseline.recorded` and `recordedBefore` hold what was originally saved, labelled apart from the re-derived values. `noIntelligenceChange` is `null` when either record is unreliable.

Integrity is reported in two parts, because hashes cover evidence payloads only:

- `evidenceRows`: `verified`, `tampered`, `missing`, `inconsistent`, `not_hashed`, or `none`.
- `recordConsistency`: whether the record matches what its evidence re-derives. Across engine versions this is `unverifiable`.

`fullyVerified` is true only when evidence rows verify and the record is consistent, so missing, empty, or inconsistent evidence is never reported as verified.

## Tool output and answer checking

- Tool results stay under 16,000 characters, the lowest default OpenClaw cap, so truncation cannot remove sections. They are compact JSON, because formatting whitespace would only displace intelligence. Fresh and reused investigations share one schema. Raw source payloads stay in PostgreSQL, and capped lists report `total` and `omitted`. The limit is enforced on the complete response; if abnormal data would exceed it, the result is shortened and marked `_reducedToFit`.
- Before a final answer is accepted, a deterministic gate compares its CVE IDs, CVSS score, severity, KEV state, and version numbers with the investigation results from that session. A mismatch triggers one revision pass. If a delivered message still conflicts with the evidence, it is sent with a visible warning listing the conflict. The gate also asks for a revision when an answer says data was just retrieved but no provider was queried in that turn, claims sources agree when the comparisons do not establish it, or makes a claim about all Red Hat products that the status counts contradict. It skips sentences that reject a claim, such as "the claimed 9.8 is incorrect". The gate is a floor against fabrication, not a check that the reasoning is correct.

`npm run build; npm run test:contract` runs the real plugin entry offline, faking only the network and database socket.

## Design rules

- The LLM is the **reasoning layer**, not the source of truth.
- Every confirmed fact must trace back to a retrieved evidence document.
- Every inference must reference the facts that support it.
- Provider failures are surfaced as explicit limitations, never silently dropped.
- `observed_absence` (source checked, CVE not found) is never conflated with an error or a positive result.
