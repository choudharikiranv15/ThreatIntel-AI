# ThreatIntel AI Engine v0.1

The first engine module for ThreatIntel AI.

## Goal

Turn ThreatIntel AI from:

Discord -> LLM -> answer

into:

Discord -> OpenClaw -> investigation tool -> authoritative evidence -> LLM reasoning -> SOC report

## v0.1 scope

The first tool is:

`threatintel_investigate`

It currently supports CVE investigations and retrieves:

- NVD CVE record
- CISA Known Exploited Vulnerabilities (KEV) status
- CVSS information when present
- CWE/weakness information when present
- affected-configuration presence
- authoritative/reference URLs
- explicit limitations

It deliberately does **not** invent MITRE ATT&CK mappings or detection claims.

## Build

PowerShell:

```powershell
npm install
npm run build
openclaw plugins validate --entry .\dist\index.js
```

## Local install into OpenClaw

From this directory:

```powershell
openclaw plugins install --link . --force
openclaw plugins enable threatintel-ai-engine
openclaw gateway restart
```

Then verify:

```powershell
openclaw plugins inspect threatintel-ai-engine --runtime --json
```

You should see the `threatintel_investigate` tool registered.

## Golden test

```powershell
npm run test:cve
```

Use `CVE-2024-3094` as the first regression case.

The expected behavior is evidence-first: the model should use the tool output rather than relying on memory for affected versions, CVSS, KEV status, or the technical description.

## Next engine modules

1. Vendor advisory collector
2. MITRE ATT&CK lookup
3. IOC classifier + normalizer
4. VirusTotal / AbuseIPDB / OTX enrichment
5. Evidence correlation
6. confidence scoring
7. investigation planner
8. internal SOC RAG
9. golden-case regression suite

## Design rule

The LLM is the reasoning layer, not the source of truth.
