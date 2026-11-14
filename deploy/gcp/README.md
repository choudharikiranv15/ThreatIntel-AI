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

No inbound ports are needed: Discord, Supabase, and the advisory feeds are all outbound connections. Leave only SSH open.

## 2. Prepare the VM

```powershell
gcloud compute ssh threatintel-gateway --zone=us-central1-a
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
gcloud compute scp "$env:USERPROFILE\openclaw-state.tgz" threatintel-gateway:~/ --zone=us-central1-a
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
