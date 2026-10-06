#!/usr/bin/env bash
# sync-url.sh — capture the current DSH GUI tunnel URL into the launcher page.
#
# ngrok (free, unnamed tunnel) rotates its public URL on every restart, so the
# static launcher goes stale. Run this after restarting the tunnel.
#
#   ./sync-url.sh              # update files locally
#   ./sync-url.sh --push       # update, commit and push (Pages redeploys)
#
# The URL is AES-256-GCM encrypted before it is written into index.html. The
# committed page therefore holds only ciphertext, which is what makes it safe to
# publish from a public repository. The passphrase is never committed.
#
# Passphrase resolution order:
#   1. $DSH_LAUNCHER_PASSPHRASE
#   2. macOS Keychain (service "dsh-launcher")
#   3. newly generated, then stored in the Keychain (or .passphrase, gitignored)

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
URL_JSON="$REPO_DIR/url.json"          # plaintext, LOCAL ONLY (gitignored)
INDEX="$REPO_DIR/index.html"
PASS_FILE="$REPO_DIR/.passphrase"      # fallback store, gitignored
KEYCHAIN_SERVICE="dsh-launcher"
NGROK_API="http://127.0.0.1:4040/api/tunnels"
NGROK_LOG="/tmp/ngrok-harness.log"

die() { printf 'error: %s\n' "$1" >&2; exit 1; }

# --- passphrase -------------------------------------------------------------
generate_passphrase() {
  # Five dictionary words + a 3-digit suffix: typeable, and stretched 600k times
  # by PBKDF2 before it becomes an AES key.
  local words=() w
  if [ -r /usr/share/dict/words ]; then
    while [ "${#words[@]}" -lt 5 ]; do
      w="$(grep -E '^[a-z]{5,8}$' /usr/share/dict/words | awk 'NR==r{print; exit}' r=$((RANDOM % 5000 + 1)))"
      [ -n "$w" ] && words+=("$w")
    done
  else
    for _ in 1 2 3 4 5; do
      words+=("$(LC_ALL=C tr -dc 'a-z' </dev/urandom | head -c 6)")
    done
  fi
  printf '%s-%s' "$(IFS=-; echo "${words[*]}")" "$((RANDOM % 900 + 100))"
}

get_passphrase() {
  if [ -n "${DSH_LAUNCHER_PASSPHRASE:-}" ]; then
    printf '%s' "$DSH_LAUNCHER_PASSPHRASE"; return 0
  fi
  local from_keychain=""
  if command -v security >/dev/null 2>&1; then
    from_keychain="$(security find-generic-password -s "$KEYCHAIN_SERVICE" -w 2>/dev/null || true)"
  fi
  if [ -n "$from_keychain" ]; then
    printf '%s' "$from_keychain"; return 0
  fi
  if [ -r "$PASS_FILE" ]; then
    printf '%s' "$(cat "$PASS_FILE")"; return 0
  fi

  # First run: mint one and persist it outside the repo.
  local fresh; fresh="$(generate_passphrase)"
  if command -v security >/dev/null 2>&1 &&
     security add-generic-password -a "$USER" -s "$KEYCHAIN_SERVICE" -w "$fresh" -U >/dev/null 2>&1; then
    printf '\n  New launcher passphrase generated and stored in your login Keychain.\n' >&2
    printf '  Enter this once per device at the Pages URL:\n\n    %s\n\n' "$fresh" >&2
  else
    umask 077; printf '%s' "$fresh" > "$PASS_FILE"
    printf '\n  New launcher passphrase generated and stored in %s (mode 600).\n' "$PASS_FILE" >&2
    printf '  Enter this once per device at the Pages URL:\n\n    %s\n\n' "$fresh" >&2
  fi
  printf '%s' "$fresh"
}

# --- discover the URL -------------------------------------------------------
discover() {
  local json
  if json="$(curl -s --max-time 5 "$NGROK_API" 2>/dev/null)" && [ -n "$json" ]; then
    printf '%s' "$json" | python3 -c '
import json, sys
try:
    tunnels = json.load(sys.stdin).get("tunnels", [])
except Exception:
    sys.exit(1)
for t in tunnels:
    addr = (t.get("config") or {}).get("addr", "")
    if "3080" in addr and t.get("public_url", "").startswith("https://"):
        print(t["public_url"]); break
else:
    sys.exit(1)
' && return 0
  fi
  if [ -f "$NGROK_LOG" ]; then
    python3 - "$NGROK_LOG" <<'PY' && return 0
import json, sys
url = None
for line in open(sys.argv[1], errors="ignore"):
    line = line.strip()
    if not line.startswith("{"):
        continue
    try:
        rec = json.loads(line)
    except Exception:
        continue
    u = rec.get("url") or rec.get("public_url")
    if isinstance(u, str) and u.startswith("https://"):
        url = u
if url:
    print(url)
else:
    sys.exit(1)
PY
  fi
  return 1
}

URL="$(discover || true)"
[ -n "${URL:-}" ] || die "could not discover a tunnel URL (is 'ngrok http 3080' running?)"
case "$URL" in https://*) ;; *) die "refusing non-https URL: $URL" ;; esac
STAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "tunnel: $URL"

PASS="$(get_passphrase)"
[ -n "$PASS" ] || die "empty passphrase"

# --- encrypt (WebCrypto-compatible: PBKDF2-SHA256 + AES-256-GCM) ------------
PAYLOAD="$(DSH_PASS="$PASS" DSH_URL="$URL" DSH_STAMP="$STAMP" node -e '
const { webcrypto } = require("node:crypto");
const subtle = webcrypto.subtle;
const enc = new TextEncoder();
(async () => {
  const salt = webcrypto.getRandomValues(new Uint8Array(16));
  const iv = webcrypto.getRandomValues(new Uint8Array(12));
  const iter = 600000;
  const material = await subtle.importKey("raw", enc.encode(process.env.DSH_PASS), "PBKDF2", false, ["deriveKey"]);
  const key = await subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: iter, hash: "SHA-256" },
    material, { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
  const ct = await subtle.encrypt({ name: "AES-GCM", iv }, key,
    enc.encode(JSON.stringify({ url: process.env.DSH_URL, updated: process.env.DSH_STAMP })));
  const b64 = (b) => Buffer.from(new Uint8Array(b)).toString("base64");
  process.stdout.write(JSON.stringify(
    { v: 1, iter, salt: b64(salt), iv: b64(iv), ct: b64(ct), updated: process.env.DSH_STAMP }));
})().catch((e) => { console.error(e); process.exit(1); });
')" || die "encryption failed"

# --- inject the ciphertext into index.html ----------------------------------
python3 - "$INDEX" "$PAYLOAD" <<'PY'
import re, sys
path, payload = sys.argv[1], sys.argv[2]
src = open(path).read()
new, n = re.subn(
    r'<script id="dsh-secret" type="application/json">.*?</script>',
    lambda m: '<script id="dsh-secret" type="application/json">%s</script>' % payload,
    src, count=1, flags=re.S)
if n != 1:
    sys.exit("could not find the dsh-secret script tag in index.html")
open(path, "w").write(new)
PY

# --- local plaintext record (gitignored) ------------------------------------
python3 - "$URL_JSON" "$URL" "$STAMP" <<'PY'
import json, sys
path, url, stamp = sys.argv[1:4]
json.dump({"url": url, "updated": stamp}, open(path, "w"), indent=2)
open(path, "a").write("\n")
PY

echo "updated index.html (ciphertext) and url.json (local only)"

# --- guards -----------------------------------------------------------------
# 1. no credential-shaped values
# 2. no plaintext tunnel URL in any tracked file
guard() {
  local hits
  local pattern
  pattern='(authtoken[[:space:]]*[:=][[:space:]]*[^[:space:]]+'
  pattern+='|gh[opsu]_[A-Za-z0-9]{20,}'
  pattern+='|github_pat_[A-Za-z0-9_]{20,}'
  pattern+='|[A-Za-z0-9]{20,}_[A-Za-z0-9]{20,}'
  pattern+='|[?&]token=[A-Za-z0-9._-]{16,})'
  hits="$(grep -RIlE "$pattern" --exclude-dir=.git \
            --exclude='url.json' --exclude='.passphrase' "$REPO_DIR" 2>/dev/null || true)"
  [ -z "$hits" ] || die "credential-shaped content found, refusing: $hits"

  # The passphrase is not credential-*shaped*, so it needs its own check —
  # a stray test page or backup would otherwise publish it verbatim.
  hits="$(grep -RIlF "$PASS" --exclude-dir=.git \
            --exclude='.passphrase' "$REPO_DIR" 2>/dev/null || true)"
  [ -z "$hits" ] || die "passphrase appears in a repo file, refusing: $hits"

  if git -C "$REPO_DIR" rev-parse --git-dir >/dev/null 2>&1; then
    if git -C "$REPO_DIR" grep -qF "$URL" -- . 2>/dev/null; then
      die "plaintext tunnel URL appears in a tracked file — refusing to publish"
    fi
    if git -C "$REPO_DIR" grep -qF "$PASS" -- . 2>/dev/null; then
      die "passphrase appears in a tracked file — refusing to publish"
    fi
  fi
}
guard

# --- optionally publish -----------------------------------------------------
if [ "${1:-}" = "--push" ]; then
  cd "$REPO_DIR"
  git add -A
  if git diff --cached --quiet; then
    echo "no change to publish"
  else
    git -c user.name="${GIT_AUTHOR_NAME:-dsh-launcher}" \
        -c user.email="${GIT_AUTHOR_EMAIL:-dsh-launcher@users.noreply.github.com}" \
        commit -q -m "sync tunnel URL ($STAMP)"
    git push -q
    echo "pushed; GitHub Pages will redeploy shortly"
  fi
fi
