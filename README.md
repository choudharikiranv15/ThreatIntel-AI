# ThreatIntel AI Engine v0.5

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
- Watches selected CVEs on a schedule and posts a Discord alert when their intelligence changes

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

# Calls the live NVD, CISA, Red Hat, and OSV APIs
npm run test:live
```

`npm test` includes an OpenClaw delivery contract test. It fails if the installed OpenClaw is not the pinned 2026.7.1-2, or if OpenClaw's delivery stops honouring `skipQueue`, which the watchlist relies on to avoid duplicate alerts. Run it before upgrading OpenClaw.

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

**Apply `db/migrations/002_watchlist.sql` before using the watchlist in v0.5.** It only adds the `watchlist` and `watch_events` tables, so investigations keep working without it.

Migrations 001 and 002 also enable row-level security with no policies. That blocks Supabase's `anon` and `authenticated` Data API roles, while the table owner the plugin connects as keeps access.

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

The gate also checks statements about a named Red Hat product, such as "OpenShift 4.12 is fixed", against that product's own rows. A family name such as "OpenShift" whose products have different statuses is reported as ambiguous. Only full product names and a short list of brand words (OpenShift, JBoss, Ansible, and similar) count as naming a product, so ordinary words like "software" or "product" are never read as product claims.

`npm run build; npm run test:contract` runs the real plugin entry offline, faking only the network and database socket.

## Watchlist

The watchlist re-investigates chosen CVEs on a schedule and posts one Discord message when the intelligence changes.

### Tools

| Tool | Purpose |
|---|---|
| `threatintel_watch_add` | Watch a CVE. Records a baseline immediately. |
| `threatintel_watch_remove` | Stop watching. Past alerts are kept. |
| `threatintel_watch_list` | List watched CVEs with their last result and next check. |
| `threatintel_watch_set` | Change a CVE's check interval (6 to 168 hours) or pause it. |
| `threatintel_watch_status` | Delivery counts, recent alerts and message IDs; can re-queue failed alerts. |

All five tools, including the read-only ones, are restricted to OpenClaw owners. Everyone else gets `owner_only`. OpenClaw treats a sender as an owner only when they are listed in `commands.ownerAllowFrom`. Until that is set, the tools refuse everyone:

```powershell
openclaw config set commands.ownerAllowFrom '["discord:<your-user-id>"]'
```

### Configuration

Set these under `plugins.entries.threatintel-ai-engine.config`:

| Field | Default | Meaning |
|---|---|---|
| `watchEnabled` | `false` | Runs scheduled checks and delivery in the gateway. |
| `watchNotifyTarget` | none | Where alerts go, for example `channel:<discord-channel-id>`. Without it, changes are recorded but not sent. |
| `watchTickMinutes` | `5` | How often the gateway looks for due checks and pending alerts (1 to 60). |
| `watchDefaultIntervalHours` | `24` | Default time between checks of one CVE (6 to 168). |
| `watchMaxEntries` | `100` | The most CVEs the watchlist may hold (1 to 500). |
| `watchDeliveryMode` | `direct` | `direct` or `openclaw_queue`. See below. |

### What triggers an alert

Each check is compared with the CVE's baseline using the same comparison as `threatintel_compare_investigations`. Only an `intelligence_change` in these fields alerts:

- KEV listing added or removed. A move to or from `unknown` does not alert.
- CVSS score or vector.
- NVD affected versions.
- New package fixed versions.
- A Red Hat product moving to `affected` or `fixed`, or from `affected` to `not_affected`.

Nothing alerts, and the baseline does not move, when:

- NVD or CISA KEV could not be checked. The check counts as failed and is retried with backoff.
- A difference is only a `collection_difference` or `processing_difference`, such as a Red Hat outage or an engine upgrade.

A baseline that fails its integrity check (tampered, missing, or inconsistent evidence, or a deleted baseline row) produces an `integrity_warning` alert instead of a silent re-baseline. A baseline that only cannot be verified, for example after an engine upgrade, is replaced quietly and recorded as `baseline_reset`. The baseline moves forward only when every source answered.

After three failed checks in a row, one `monitor_failure` alert is sent, and one `monitor_recovered` alert follows when checks succeed again.

### Delivery and retries

Alerts are saved in `watch_events` before they are sent, so a crash or restart never loses one. Each alert is stored once per comparison, so a retried check never repeats it. A change that reverses and then happens again, such as a KEV listing that is removed and later restored, alerts each time.

In `direct` mode, the default, PostgreSQL is the only retry owner. Each send uses OpenClaw's `deliverOutboundPayloads` with `skipQueue: true`, so OpenClaw never keeps its own copy to retry. A failed send is retried with backoff for up to six attempts, then marked `failed`. `threatintel_watch_status` with `retryFailedDeliveries` puts failed alerts back in the queue.

`openclaw_queue` is a fallback in case direct delivery stops working. Once OpenClaw has queued an alert, it is marked `handed_off`, and the watchlist never sends it again. Only a failure before OpenClaw queues the alert stays with the watchlist's own retries. One alert is never owned by both retry systems.

Delivery is at least once. If the gateway stops after Discord accepts a message but before the result is saved, the alert is sent again after restart, labelled as a possible repeat.

### Scheduling and recovery

Due checks and pending alerts live in PostgreSQL, not in memory. A gateway restart or host reboot resumes where it stopped: overdue checks run on the first cycle, about 30 seconds after the service starts, and unsent alerts are delivered.

Checks and deliveries are claimed with database leases that expire (15 minutes for a check, 2 minutes for a delivery). Two gateways pointed at one database never run the same check or send the same alert. A lease left by a crashed gateway is picked up after it expires.

Monitoring makes at most ten checks per cycle, two seconds apart, with longer source retries than interactive use. The CISA KEV catalog is downloaded at most once an hour and shared across checks, and its `checkedAt` is the download time.

## Production

The Windows gateway used for development is not a production host. For 24/7 monitoring:

- **Host.** Run the gateway on an always-on Linux host or VM, as a systemd service with `Restart=always` and `WantedBy=multi-user.target`, or as a container with `restart: unless-stopped`. Either one restarts it after a crash and a reboot. The first start after an install can take about two minutes.
- **One instance.** Run a single gateway with `watchEnabled: true`. Leases make a second one safe, but it adds nothing.
- **Clock.** Keep NTP enabled. Schedules and leases use the database clock, while log timestamps use the host clock.
- **Database.** Check which backups your Supabase plan includes: daily backups and point-in-time recovery depend on the plan. Independently, take a regular `pg_dump` of the plugin's tables: `investigations`, `evidence`, `facts`, `inferences`, `watchlist`, and `watch_events`. After a restore, replay a recent investigation to confirm that its evidence still verifies.
- **Monitoring.** `monitor_failure` alerts report sources that stay down. `threatintel_watch_status` shows failed and pending deliveries. Alerts cannot report a stopped gateway, so add an external uptime check on the gateway host or process.
- **Logs.** Keep the gateway logs with rotation. A failed check or delivery cycle is logged. Each CVE's last check error and each alert's last delivery error are stored in PostgreSQL and shown by `threatintel_watch_list` and `threatintel_watch_status`.
- **Upgrades.** Keep OpenClaw on the pinned version until the delivery contract test passes on the new version.

## Design rules

- The LLM is the **reasoning layer**, not the source of truth.
- Every confirmed fact must trace back to a retrieved evidence document.
- Every inference must reference the facts that support it.
- Provider failures are surfaced as explicit limitations, never silently dropped.
- `observed_absence` (source checked, CVE not found) is never conflated with an error or a positive result.
