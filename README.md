# ThreatIntel AI Engine v0.2

A CVE investigation engine for ThreatIntel AI. Retrieves authoritative evidence from external intelligence sources and structures it for LLM-assisted SOC analysis.

## What it does

Given a CVE identifier, the engine:

- Retrieves the NVD CVE record (CVSS, CWE, affected configurations, references)
- Checks CISA Known Exploited Vulnerabilities (KEV) catalog status
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
# Integration test against live NVD and CISA APIs
npm run test:cve

# Fault-injection tests (provider timeouts, errors, absences)
npm run test:faults

# Provider contract validation tests
npm run test:validation

# Provenance graph integrity tests
npm run test:provenance
```

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
