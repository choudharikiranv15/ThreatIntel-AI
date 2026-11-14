#!/usr/bin/env bash
# Restores the OpenClaw state exported from Windows and starts the gateway as a
# service that survives crashes and reboots. Run on the VM after setup-vm.sh:
#   bash finish-vm.sh ~/openclaw-state.tgz [healthchecks-ping-url]
# Make sure the Windows gateway is stopped first (export-state.ps1 does that).
set -euo pipefail

ARCHIVE="${1:?usage: finish-vm.sh <openclaw-state.tgz> [healthchecks-ping-url]}"
HC_URL="${2:-}"
REPO_DIR="$HOME/ThreatIntel-AI"
STATE="$HOME/.openclaw"

export PATH="$HOME/.npm-global/bin:$PATH"
export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"

step() { printf '\n==> %s\n' "$*"; }

[ -f "$ARCHIVE" ] || { echo "No archive at $ARCHIVE" >&2; exit 1; }
[ -f "$REPO_DIR/dist/index.js" ] || { echo "Run setup-vm.sh first: $REPO_DIR/dist/index.js is missing." >&2; exit 1; }

step "Restoring state into $STATE"
if [ -e "$STATE" ]; then
    backup="$STATE.before-restore.$(date +%Y%m%d%H%M%S)"
    mv "$STATE" "$backup"
    echo "existing state moved to $backup"
fi
tar -xzf "$ARCHIVE" -C "$HOME"
chmod 700 "$STATE"
chmod 600 "$STATE/.env" "$STATE/openclaw.json"

step "Pointing Windows paths at this machine"
openclaw config set agents.defaults.workspace "$STATE/workspace"
openclaw config set plugins.load.paths "[\"$REPO_DIR\"]" --strict-json

step "Repairing plugins (reinstalls the Discord plugin for Linux)"
openclaw doctor --fix --non-interactive

step "Checking the database settings are present (values are not printed)"
for name in THREATINTEL_DB_HOST THREATINTEL_DB_PORT THREATINTEL_DB_NAME THREATINTEL_DB_USER THREATINTEL_DB_PASSWORD DISCORD_BOT_TOKEN; do
    if grep -q "^${name}=." "$STATE/.env"; then echo "$name=present"; else echo "$name=MISSING" >&2; exit 1; fi
done

step "Installing the gateway as a systemd user service"
# Lingering keeps the user's services running without a login session and
# starts them at boot. Enabled first, so the user service manager is up.
sudo loginctl enable-linger "$USER"
openclaw gateway install --force
systemctl --user daemon-reload
systemctl --user enable --now openclaw-gateway.service

if [ -n "$HC_URL" ]; then
    step "Health ping every 5 minutes while the gateway is running"
    line="*/5 * * * * XDG_RUNTIME_DIR=/run/user/$(id -u) systemctl --user is-active --quiet openclaw-gateway.service && curl -fsS -m 10 --retry 3 '$HC_URL' >/dev/null"
    ( crontab -l 2>/dev/null | grep -v 'openclaw-gateway.service' ; echo "$line" ) | crontab -
    echo "installed; the check alerts you if pings stop"
fi

step "Status"
sleep 5
systemctl --user --no-pager status openclaw-gateway.service | head -5 || true
cat <<EOF

The gateway is starting; the first start can take about two minutes.
Follow it with:   journalctl --user -u openclaw-gateway.service -f
Check it with:    openclaw gateway status

Then delete the archive from this VM:   rm $ARCHIVE
EOF
