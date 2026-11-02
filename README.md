# ThreatIntel AI Engine v0.3

A CVE investigation engine for ThreatIntel AI. Retrieves authoritative evidence from external intelligence sources and structures it for LLM-assisted SOC analysis.

## What it does

Given a CVE identifier, the engine:

- Retrieves the NVD CVE record (CVSS, CWE, affected configurations, references)
- Checks CISA Known Exploited Vulnerabilities (KEV) catalog status
- Retrieves Red Hat vendor impact, including shipped fixes, and reports CVSS disagreements between sources
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

## Tool output and answer checking

- Tool results stay under 16,000 characters, the lowest default OpenClaw cap, so truncation cannot remove sections. Fresh and reused investigations share one schema. Raw source payloads stay in PostgreSQL, and capped lists report `total` and `omitted`.
- Before a final answer is accepted, a deterministic gate compares its CVE IDs, CVSS score, severity, KEV state, and version numbers with the investigation results from that session. A mismatch triggers one revision pass. If the answer is still wrong, or the hook times out, the original answer is delivered and the mismatch is only logged. The gate is a floor against fabrication, not a check that the reasoning is correct.

`npm run build; npm run test:contract` runs the real plugin entry offline, faking only the network and database socket.

## Design rules

- The LLM is the **reasoning layer**, not the source of truth.
- Every confirmed fact must trace back to a retrieved evidence document.
- Every inference must reference the facts that support it.
- Provider failures are surfaced as explicit limitations, never silently dropped.
- `observed_absence` (source checked, CVE not found) is never conflated with an error or a positive result.
