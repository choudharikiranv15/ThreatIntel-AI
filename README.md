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
openclaw plugins install --link . --force
openclaw plugins enable threatintel-ai-engine
openclaw gateway restart
```

Then verify:

```powershell
openclaw plugins inspect threatintel-ai-engine --runtime --json
```

## Design rules

- The LLM is the **reasoning layer**, not the source of truth.
- Every confirmed fact must trace back to a retrieved evidence document.
- Every inference must reference the facts that support it.
- Provider failures are surfaced as explicit limitations, never silently dropped.
- `observed_absence` (source checked, CVE not found) is never conflated with an error or a positive result.
