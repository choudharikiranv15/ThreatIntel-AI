# Moving the gateway to a Google Cloud e2-micro

This runs the OpenClaw gateway, with this plugin, around the clock on Google Cloud's free-tier VM. The watchlist and threat feed keep their state in Supabase, so nothing is lost in the move: due checks and pending posts resume on the VM.

The gateway uses about 350 MB of memory, so the e2-micro's 1 GB plus 2 GB of swap is enough. OpenClaw's own GCP guide builds OpenClaw from source in Docker, which runs out of memory on an e2-micro; these scripts install the prebuilt npm package instead.

Expect about 10 minutes of downtime: the Windows gateway stops before the VM's starts, because two gateways with one bot token would answer every chat message twice.

## 1. Create the VM (on your PC)

Install the [gcloud CLI](https://cloud.google.com/sdk/docs/install) and sign in with `gcloud init`. Then:

```powershell
gcloud compute instances create threatintel-gateway `
  --zone=us-central1-a `
  --machine-type=e2-micro `
  --image-family=ubuntu-2404-lts-amd64 --image-project=ubuntu-os-cloud `
  --boot-disk-size=30GB --boot-disk-type=pd-standard
```

The free tier covers one e2-micro only in `us-west1`, `us-central1`, or `us-east1`, with a standard (not SSD) disk of up to 30 GB. Check the current terms on [cloud.google.com/free](https://cloud.google.com/free), and set a small budget alert under **Billing > Budgets & alerts** so any unexpected charge, such as for the external IP address, is reported to you.

No inbound ports are needed: Discord, Supabase, and the advisory feeds are all outbound connections. Allow SSH only through Google's Identity-Aware Proxy, so it is never open to the internet, and remove the default rules that open SSH and RDP to everyone:

```powershell
gcloud services enable iap.googleapis.com
gcloud compute firewall-rules create allow-ssh-from-iap --network=default --direction=INGRESS --action=ALLOW --rules=tcp:22 --source-ranges=35.235.240.0/20
# Confirm SSH through IAP works before removing the open rules.
gcloud compute ssh threatintel-gateway --zone=us-central1-a --tunnel-through-iap --command="echo ok"
gcloud compute firewall-rules delete default-allow-ssh default-allow-rdp
```

Every `gcloud compute ssh` and `scp` below then needs `--tunnel-through-iap`.

## 2. Prepare the VM

```powershell
gcloud compute ssh threatintel-gateway --zone=us-central1-a --tunnel-through-iap
```

On the VM:

```bash
curl -fsSL https://raw.githubusercontent.com/choudharikiranv15/ThreatIntel-AI/main/deploy/gcp/setup-vm.sh -o setup-vm.sh
bash setup-vm.sh
source ~/.profile
```

This adds swap, turns on automatic security updates, caps log size, installs Node 24 and OpenClaw 2026.7.1-2 (pinned), and clones and builds this repository. It is safe to run again.

## 3. Export the state (on your PC)

From the repository folder in PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File deploy\gcp\export-state.ps1
gcloud compute scp "$env:USERPROFILE\openclaw-state.tgz" threatintel-gateway:openclaw-state.tgz --zone=us-central1-a --tunnel-through-iap
Remove-Item "$env:USERPROFILE\openclaw-state.tgz"
```

The script stops the Windows gateway, disables its scheduled task so it does not return after a reboot, and packs `~/.openclaw` with your `THREATINTEL_DB_*` settings added to its `.env`. It leaves out the Discord plugin's Windows-built packages, which the VM reinstalls, and logs and backups.

The archive holds the Discord token, API keys, and database password. Copy it only over SSH, as above, and delete it afterwards.

## 4. Start the gateway (on the VM)

Optionally create a free check at [healthchecks.io](https://healthchecks.io) with a 5-minute period and copy its ping URL. Then:

```bash
bash ~/ThreatIntel-AI/deploy/gcp/finish-vm.sh ~/openclaw-state.tgz https://hc-ping.com/<your-uuid>
rm ~/openclaw-state.tgz
```

This restores the state, points the two Windows paths in the config (the workspace and the plugin path) at the VM, reinstalls the Discord plugin, checks that the database and Discord settings are present without printing them, and installs the gateway as a systemd user service with lingering. The service restarts within 5 seconds after a crash and starts at boot. With a ping URL, the VM pings it every 5 minutes while the gateway runs, and healthchecks.io emails you when the pings stop.

## 5. Verify

```bash
openclaw gateway status
journalctl --user -u openclaw-gateway.service -f
```

Then, in Discord:

- Ask the bot to investigate a CVE.
- Ask it for the threat feed status; the next cycle time should be unchanged.
- Ask it for the watchlist status.

Reboot once to prove recovery: `sudo reboot`, wait two minutes, and ask the bot something.

## Hard spending cap (optional)

Budgets in Google Cloud only send alerts. [budget-cap](budget-cap/main.py) turns one into a hard stop: the budget publishes its spend to a Pub/Sub topic, and the function unlinks billing from the project once spend reaches the budget, which stops the VM and every other paid service in the project. Relink billing in the console to resume. Budget data lags by hours, so spend can pass the cap slightly before it acts. If billing stays off, Google may eventually delete the VM's disk; the watchlist and feed state are in Supabase, and these scripts rebuild the VM.

Setup, with `$p` your project id and `$budget` the budget's full name from `gcloud billing budgets list`:

```powershell
gcloud services enable pubsub.googleapis.com run.googleapis.com cloudfunctions.googleapis.com cloudbuild.googleapis.com artifactregistry.googleapis.com eventarc.googleapis.com cloudresourcemanager.googleapis.com iam.googleapis.com billingbudgets.googleapis.com --project=$p
gcloud pubsub topics create budget-cap --project=$p

# The function's identity may only unlink billing from this project.
gcloud iam service-accounts create budget-cap --project=$p
gcloud projects add-iam-policy-binding $p --member="serviceAccount:budget-cap@$p.iam.gserviceaccount.com" --role=roles/billing.projectManager --condition=None
gcloud projects add-iam-policy-binding $p --member="serviceAccount:budget-cap@$p.iam.gserviceaccount.com" --role=roles/serviceusage.serviceUsageConsumer --condition=None
gcloud projects add-iam-policy-binding $p --member="serviceAccount:budget-cap@$p.iam.gserviceaccount.com" --role=roles/run.invoker --condition=None

# A separate build identity, so the VM's default account gains nothing.
gcloud iam service-accounts create budget-cap-build --project=$p
gcloud projects add-iam-policy-binding $p --member="serviceAccount:budget-cap-build@$p.iam.gserviceaccount.com" --role=roles/cloudbuild.builds.builder --condition=None

gcloud functions deploy budget-cap --gen2 --region=us-central1 --runtime=python312 --source=deploy/gcp/budget-cap --entry-point=stop_billing --trigger-topic=budget-cap --service-account=budget-cap@$p.iam.gserviceaccount.com --trigger-service-account=budget-cap@$p.iam.gserviceaccount.com --build-service-account=projects/$p/serviceAccounts/budget-cap-build@$p.iam.gserviceaccount.com --set-env-vars=TARGET_PROJECT_ID=$p --memory=256Mi --max-instances=1 --project=$p

gcloud billing budgets update $budget --notifications-rule-pubsub-topic=projects/$p/topics/budget-cap --billing-project=$p
```

Test it without shutting anything down: a message with `"dryRun": true` is evaluated and logged but never acted on.

```powershell
gcloud pubsub topics publish budget-cap --project=$p --message='{\"costAmount\":150,\"budgetAmount\":100,\"currencyCode\":\"INR\",\"dryRun\":true}'
gcloud functions logs read budget-cap --gen2 --region=us-central1 --project=$p --limit=5
```

The log should say `DRY RUN: spend 150.0 reached budget 100.0; would disable billing`.

## Security settings

The gateway is reachable by everyone in your Discord server, and OpenClaw's defaults are designed for a single trusted user. Apply these settings after the install; `openclaw security audit` should then report no runtime or file-system tools exposed.

```bash
# Deny by default: only this plugin's tools and web fetch/search.
openclaw config set tools.profile '"minimal"' --strict-json
openclaw config set tools.alsoAllow '["threatintel-ai-engine","web_fetch","web_search"]' --strict-json
openclaw config set tools.deny '["group:runtime","group:fs","group:sessions","group:automation","group:nodes","group:ui","skill_workshop","cron"]' --strict-json
openclaw config set tools.exec '{"security":"deny","ask":"off"}' --strict-json
openclaw config set gateway.controlUi.allowInsecureAuth false --strict-json
# Chat commands and directives (/model, /verbose, /reasoning, /reset...) from the owner only.
openclaw config set commands.allowFrom '{"discord":["user:<your Discord user ID>"]}' --strict-json
openclaw config set commands.restart false --strict-json
openclaw gateway restart
```

Replace the agent's workspace files with the ones in [deploy/workspace](../workspace): OpenClaw's starter files describe the operator and the host, and everything in them is part of the model's context. Back up the old ones first:

```bash
W=~/.openclaw/workspace
tar -czf ~/.openclaw/workspace-backup.tgz -C "$W" . && chmod 600 ~/.openclaw/workspace-backup.tgz
install -m 600 ~/ThreatIntel-AI/deploy/workspace/*.md "$W"/
```

The plugin also adds confidentiality rules to the system prompt and checks every outgoing message: anything naming a secret, an internal path or host, an administrative command, a settings key, the model, or the instruction files is replaced before it reaches Discord (`src/verification/disclosure-guard.ts`). Leave `plugins.entries.threatintel-ai-engine.hooks.allowPromptInjection` unset so the rules are added, and keep `channels.discord.streaming.mode` at `off` so no draft text is shown before the check.

Connect to the database as the least-privilege role from `db/migrations/004_app_role.sql`, not Supabase's `postgres` role, and harden SSH with a drop-in such as `/etc/ssh/sshd_config.d/60-hardening.conf` (`PermitRootLogin no`, `X11Forwarding no`, `MaxAuthTries 3`), checked with `sudo sshd -t` before `sudo systemctl reload ssh`.

To replace a secret without it appearing on screen or in shell history: `bash ~/ThreatIntel-AI/deploy/gcp/rotate-secret.sh discord|nvd|abuseipdb|greynoise|otx|db|openrouter`. Never configure a key through the bot.

## Everyday operations

| Task | Command (on the VM) |
|---|---|
| Logs | `journalctl --user -u openclaw-gateway.service -f` |
| Restart | `openclaw gateway restart` |
| Deploy a new version of the plugin | `cd ~/ThreatIntel-AI && git pull --ff-only && npm ci && npm run build && openclaw gateway restart` |
| Change plugin config | `openclaw config set plugins.entries.threatintel-ai-engine.config.<field> <value>`, then restart |

Run `npm test` before deploying a version that changes the OpenClaw version: its delivery contract test must pass first.

## Moving back to the PC

Stop the VM's gateway first (`systemctl --user disable --now openclaw-gateway.service`), then on the PC: `Enable-ScheduledTask -TaskName 'OpenClaw Gateway'; openclaw gateway restart`.
