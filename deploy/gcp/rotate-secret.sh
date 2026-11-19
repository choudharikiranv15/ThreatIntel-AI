#!/usr/bin/env bash
# Replaces one secret on the gateway VM without it appearing on screen, in
# shell history, or in the process list. Every file that holds the secret is
# updated, backups are kept, and the gateway is restarted.
#
#   bash rotate-secret.sh discord      # new Discord bot token
#   bash rotate-secret.sh nvd          # new NVD API key
#   bash rotate-secret.sh abuseipdb    # AbuseIPDB key for indicator lookups (also greynoise, otx, virustotal)
#   bash rotate-secret.sh db           # new password for the plugin's database role
#   bash rotate-secret.sh openrouter   # new OpenRouter key (OpenClaw's own prompt)
#
# A key can also come from a file instead of the prompt (delete the file after):
#   bash rotate-secret.sh abuseipdb < ~/key.txt
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
    local value=""
    # A value read from a file may lack a final newline: read then returns 1
    # with the value already set, which must not end the script silently.
    IFS= read -rsp "$1: " value || true
    value="${value%$'\r'}"
    echo >&2
    [ -n "${value//[[:space:]]/}" ] || { echo "Nothing entered (a paste may not have arrived); nothing changed." >&2; exit 1; }
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
    nvd|abuseipdb|greynoise|otx|virustotal)
        field=$(case "$1" in nvd) echo nvdApiKey;; abuseipdb) echo abuseipdbApiKey;; greynoise) echo greynoiseApiKey;; otx) echo otxApiKey;; virustotal) echo virustotalApiKey;; esac)
        backup "$S/openclaw.json"
        # The key is trimmed, checked against the service, and saved only if it was not rejected.
        if ! ask "New $1 API key" | node -e '
const fs = require("fs");
const [file, field, service] = process.argv.slice(1);
const value = fs.readFileSync(0, "utf8").trim();
if (!value) process.exit(1); // The prompt has already said why.
const formats = { abuseipdb: /^[0-9a-f]{80}$/i, otx: /^[0-9a-f]{64}$/i, virustotal: /^[0-9a-f]{64}$/i, nvd: /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i };
if (value.length < 16 || /\s/.test(value)) {
    console.error("That is not a key: the paste may not have arrived (right-click or Ctrl+Shift+V to paste). Nothing changed.");
    process.exit(1);
}
if (formats[service] && !formats[service].test(value)) {
    console.error(`Note: this does not have the usual ${service} key format; checking it with ${service} anyway.`);
}
const checks = {
    abuseipdb: ["https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8", { Key: value, Accept: "application/json" }],
    otx: ["https://otx.alienvault.com/api/v1/user/me", { "X-OTX-API-KEY": value }],
    virustotal: ["https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8", { "x-apikey": value }],
    greynoise: ["https://api.greynoise.io/v3/community/8.8.8.8", { key: value }],
    nvd: ["https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228", { apiKey: value }],
};
(async () => {
    const [url, headers] = checks[service];
    const status = await fetch(url, { headers, signal: AbortSignal.timeout(20000) }).then((r) => r.status, () => 0);
    if (status === 401 || status === 403) {
        console.error(`${service} rejected this key (HTTP ${status}). Nothing changed.`);
        process.exitCode = 1;
        return;
    }
    console.error(status === 200 ? `${service} accepted the key.` : `Could not confirm the key with ${service} (HTTP ${status}); saving it anyway.`);
    const config = JSON.parse(fs.readFileSync(file, "utf8"));
    config.plugins.entries["threatintel-ai-engine"].config[field] = value;
    fs.writeFileSync(file, JSON.stringify(config, null, 2) + "\n", { mode: 0o600 });
})();
' "$S/openclaw.json" "$field" "$1"; then
            # Nothing was saved, so the backup is identical and only adds a copy of the secrets.
            rm -f "$S/openclaw.json.before-rotate-$stamp"
            exit 1
        fi
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
        sed -n '2,10p' "$0"
        exit 1
        ;;
esac

echo "Backups: $S/*.before-rotate-$stamp. Delete them once the gateway works: they hold the old value."
