#!/usr/bin/env bash
# Replaces one secret on the gateway VM without it appearing on screen, in
# shell history, or in the process list. Every file that holds the secret is
# updated, backups are kept, and the gateway is restarted.
#
#   bash rotate-secret.sh discord      # new Discord bot token
#   bash rotate-secret.sh nvd          # new NVD API key
#   bash rotate-secret.sh db           # new password for the plugin's database role
#   bash rotate-secret.sh openrouter   # new OpenRouter key (OpenClaw's own prompt)
set -euo pipefail
umask 077
export PATH="$HOME/.npm-global/bin:$PATH"
export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
S="$HOME/.openclaw"
stamp=$(date -u +%Y%m%d%H%M%S)

backup() {
    for f in "$@"; do
        [ -f "$f" ] && cp -p "$f" "$f.before-rotate-$stamp"
    done
}

ask() {
    local value
    read -rsp "$1: " value
    echo >&2
    [ -n "$value" ] || { echo "Nothing entered; nothing changed." >&2; exit 1; }
    printf '%s' "$value"
}

restart() {
    systemctl --user restart --no-block openclaw-gateway.service
    echo "Gateway restarting. Check it with: journalctl --user -u openclaw-gateway.service -f"
}

# Sets KEY=value in an env file, keeping every other line. The value arrives on stdin.
set_env() {
    node -e '
const fs = require("fs");
const [file, key] = process.argv.slice(1);
const value = fs.readFileSync(0, "utf8");
if (!fs.existsSync(file)) process.exit(0);
let found = false;
const lines = fs.readFileSync(file, "utf8").split("\n").map((line) => {
    if (line.startsWith(key + "=")) { found = true; return `${key}=${value}`; }
    return line;
});
if (!found) lines.splice(lines.length && lines[lines.length - 1] === "" ? lines.length - 1 : lines.length, 0, `${key}=${value}`);
fs.writeFileSync(file, lines.join("\n"), { mode: 0o600 });
' "$1" "$2"
}

case "${1:-}" in
    discord)
        backup "$S/.env" "$S/gateway.systemd.env" "$S/openclaw.json"
        token=$(ask "New Discord bot token")
        printf '%s' "$token" | set_env "$S/.env" DISCORD_BOT_TOKEN
        printf '%s' "$token" | set_env "$S/gateway.systemd.env" DISCORD_BOT_TOKEN
        printf '%s' "$token" | node -e '
const fs = require("fs");
const file = process.argv[1];
const config = JSON.parse(fs.readFileSync(file, "utf8"));
if (config.channels?.discord && "token" in config.channels.discord) {
    config.channels.discord.token = fs.readFileSync(0, "utf8");
    fs.writeFileSync(file, JSON.stringify(config, null, 2) + "\n", { mode: 0o600 });
}
' "$S/openclaw.json"
        unset token
        restart
        ;;
    nvd)
        backup "$S/openclaw.json"
        ask "New NVD API key" | node -e '
const fs = require("fs");
const file = process.argv[1];
const config = JSON.parse(fs.readFileSync(file, "utf8"));
config.plugins.entries["threatintel-ai-engine"].config.nvdApiKey = fs.readFileSync(0, "utf8");
fs.writeFileSync(file, JSON.stringify(config, null, 2) + "\n", { mode: 0o600 });
' "$S/openclaw.json"
        restart
        ;;
    db)
        echo "First set the new password for the plugin's role in the Supabase SQL editor:"
        echo "  ALTER ROLE threatintel_app WITH PASSWORD '<new password>';"
        backup "$S/.env" "$S/gateway.systemd.env"
        password=$(ask "The same new password")
        printf '%s' "$password" | set_env "$S/.env" THREATINTEL_DB_PASSWORD
        printf '%s' "$password" | set_env "$S/gateway.systemd.env" THREATINTEL_DB_PASSWORD
        unset password
        restart
        ;;
    openrouter)
        openclaw models auth paste-api-key --provider openrouter
        restart
        ;;
    *)
        sed -n '2,9p' "$0"
        exit 1
        ;;
esac

echo "Backups: $S/*.before-rotate-$stamp. Delete them once the gateway works: they hold the old value."
