# DSH Harness Launcher

A one-page launcher for this machine's DeepSeek Harness GUI, reachable from anywhere
through an ngrok tunnel. Published as a static GitHub Pages site.

## Why this is a static page

GitHub Pages serves files only — it cannot run the harness. `dsh web` is a Node
server listening on `127.0.0.1:3080`; ngrok exposes it. This repo holds only the
launcher that points at whatever public URL the tunnel currently has.

## Why the repo is public but the URL is not

GitHub Pages for a **private** repository requires a paid plan, so this repo is
public. Nothing sensitive is published, because the tunnel URL is stored in
`index.html` as **AES-256-GCM ciphertext**:

- Key derivation: PBKDF2-HMAC-SHA-256, 600,000 iterations, random 16-byte salt.
- Encryption: AES-256-GCM with a random 12-byte IV, fresh on every sync.
- The passphrase is **never** committed; the page prompts for it and remembers it
  in that browser's `localStorage` only.

Opening the page without the passphrase reveals nothing — the URL is not present
in the DOM, only its ciphertext.

This matters because the tunnel also serves `/interviewhelper/`, which bypasses the
GUI token gate and returns 200 with no credentials at all. Publishing the tunnel
URL in the clear would expose that endpoint.

## Files

| File | Published? | Purpose |
| --- | --- | --- |
| `index.html` | yes | The launcher, with the encrypted payload inline |
| `sync-url.sh` | yes | Captures the current URL and re-encrypts it |
| `README.md` | yes | This file |
| `url.json` | **no** (gitignored) | Plaintext URL, local record only |
| `.passphrase` | **no** (gitignored) | Passphrase, mode 600, when the Keychain is unavailable |

## Keeping the URL fresh

ngrok's free tier assigns a random domain that **changes on every restart**, so the
page goes stale. After restarting the tunnel:

```sh
./sync-url.sh          # update index.html (ciphertext) + url.json locally
./sync-url.sh --push   # update, commit and push (Pages redeploys in ~1 min)
```

The script reads the live URL from ngrok's local API (`127.0.0.1:4040/api/tunnels`),
falling back to `/tmp/ngrok-harness.log`, then refuses to write if any of these is
true:

1. a credential-shaped value appears anywhere in the repo;
2. the **passphrase** appears anywhere in the repo;
3. the plaintext **tunnel URL** appears in any tracked file.

Passphrase resolution order: `$DSH_LAUNCHER_PASSPHRASE` → macOS Keychain (service
`dsh-launcher`) → newly generated and stored in the Keychain, or in `.passphrase`
if the Keychain is unavailable.

## Using it

1. Open the Pages URL.
2. Enter the passphrase once — this device remembers it.
3. Optionally paste the GUI access token, also remembered per device.
4. Click **Open harness**. The server sets a 30-day cookie, after which the token
   is not needed again.

`Lock launcher` forgets the passphrase on that device.
