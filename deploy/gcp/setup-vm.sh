#!/usr/bin/env bash
# Prepares a fresh Ubuntu 24.04 / Debian 12 VM (e2-micro) for the gateway.
# Run once, as the normal user that will run the gateway (not root):
#   bash setup-vm.sh
# Safe to re-run: every step checks before it changes anything.
set -euo pipefail

OPENCLAW_VERSION="2026.7.1-2"   # pinned: the watchlist's delivery contract is verified on this version
REPO_URL="https://github.com/choudharikiranv15/ThreatIntel-AI.git"
REPO_DIR="$HOME/ThreatIntel-AI"
SWAP_SIZE="2G"                  # e2-micro has 1 GB of RAM; npm installs need headroom

if [ "$(id -u)" -eq 0 ]; then
    echo "Run this as your normal user, not root. It uses sudo where needed." >&2
    exit 1
fi

step() { printf '\n==> %s\n' "$*"; }

step "Swap (${SWAP_SIZE})"
if swapon --show | grep -q '/swapfile'; then
    echo "swap already enabled"
else
    sudo fallocate -l "$SWAP_SIZE" /swapfile
    sudo chmod 600 /swapfile
    sudo mkswap /swapfile >/dev/null
    sudo swapon /swapfile
    grep -q '^/swapfile ' /etc/fstab || echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab >/dev/null
    # Prefer RAM; use swap only under pressure.
    echo 'vm.swappiness=10' | sudo tee /etc/sysctl.d/99-swappiness.conf >/dev/null
    sudo sysctl -q -p /etc/sysctl.d/99-swappiness.conf
fi

step "System packages and security updates"
sudo apt-get update -qq
sudo apt-get install -y -qq git curl ca-certificates unattended-upgrades >/dev/null
# Security patches install automatically; the VM is not rebooted automatically.
sudo dpkg-reconfigure -f noninteractive unattended-upgrades

step "Log size limit"
sudo mkdir -p /etc/systemd/journald.conf.d
printf '[Journal]\nSystemMaxUse=200M\n' | sudo tee /etc/systemd/journald.conf.d/size.conf >/dev/null
sudo systemctl restart systemd-journald

step "Node.js 24"
if command -v node >/dev/null && node -e 'const [a,b]=process.versions.node.split(".").map(Number); process.exit(a>24||(a===24&&b>=15)?0:1)'; then
    echo "node $(node --version) already installed"
else
    curl -fsSL https://deb.nodesource.com/setup_24.x | sudo -E bash - >/dev/null
    sudo apt-get install -y -qq nodejs >/dev/null
    echo "node $(node --version)"
fi

step "npm global prefix in your home directory (no sudo for npm -g)"
mkdir -p "$HOME/.npm-global"
npm config set prefix "$HOME/.npm-global"
grep -q 'npm-global/bin' "$HOME/.profile" 2>/dev/null || echo 'export PATH="$HOME/.npm-global/bin:$PATH"' >> "$HOME/.profile"
export PATH="$HOME/.npm-global/bin:$PATH"

step "OpenClaw ${OPENCLAW_VERSION} (pinned)"
if [ "$(openclaw --version 2>/dev/null | grep -oE '[0-9]{4}\.[0-9]+\.[0-9]+(-[0-9]+)?' | head -1)" = "$OPENCLAW_VERSION" ]; then
    echo "openclaw ${OPENCLAW_VERSION} already installed"
else
    npm install -g "openclaw@${OPENCLAW_VERSION}" --no-fund --no-audit
fi
openclaw --version

step "ThreatIntel AI plugin"
if [ -d "$REPO_DIR/.git" ]; then
    git -C "$REPO_DIR" pull --ff-only
else
    git clone "$REPO_URL" "$REPO_DIR"
fi
cd "$REPO_DIR"
npm ci --no-fund --no-audit
npm run build

step "Done"
cat <<EOF
The VM is ready. Next:
  1. On your Windows PC, run deploy/gcp/export-state.ps1. It stops the Windows gateway.
  2. Copy the archive it creates to this VM (see deploy/gcp/README.md).
  3. Here, run: bash $REPO_DIR/deploy/gcp/finish-vm.sh ~/openclaw-state.tgz

Log out and back in (or run: source ~/.profile) so 'openclaw' is on your PATH.
EOF
