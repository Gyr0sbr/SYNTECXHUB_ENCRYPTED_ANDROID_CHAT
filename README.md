# SecureChat (Python): encrypted android chat

Client/server chat where every message is encrypted with **AES-256-GCM on the client**.
The relay server only ever sees ciphertext. Tkinter GUI + terminal client.

## Run
```bash
pip install -r requirements.txt
python -m securechat.server --port 8765                 # terminal 1: relay (logs show ciphertext only)
python -m securechat.app --user alice                   # terminal 2: GUI
python -m securechat.app --user bob                     # terminal 3: second user
#   add --cli for a terminal UI, --no-keyring to force the password-protected key file
```
First launch asks for a room name and shared passphrase (same on both clients). After that the key
is loaded from the vault automatically. Test it: `python -m unittest discover -s tests -v`

GUI menu: **Show ciphertext**, **Reconnect**, **Clear history**, **Delete key and history**.
CLI commands: `/cipher /clear /reset /quit`.

## How it works
| File | Role |
|---|---|
| `crypto_engine.py` | AES-256-GCM, PBKDF2-SHA256 (210k iters, per-room salt). Envelope `v1:base64(nonce‖ct‖tag)`. AAD = `room|sender|id|ts`. |
| `keystore.py` | Secure key storage (below). |
| `storage.py` | SQLite history; stores **envelopes only**, decrypts on read. Duplicate ids ignored. |
| `server.py` | asyncio relay: joins rooms, forwards JSON lines, validates shape, caps line size. |
| `client.py` | Encrypt → send → persist; receive → persist → decrypt. Per-message errors, auto-reconnect on send. |
| `app.py` | GUI/CLI. Failed decrypt = red "cannot decrypt" line; failed send = error dialog, text kept. |

## Secure key storage
```
passphrase ─PBKDF2→ chat key ─AES-GCM(master key)→ wrapped blob → vault.json (chmod 600)
master key = OS keyring (Keychain / Credential Locker / Secret Service)
             else scrypt(local unlock password)
```
The plaintext chat key is never written to disk. If the vault can't be unlocked, the app says so,
clears it and asks you to set up again.

## Risks and limitations
- **Shared symmetric key**: anyone with the passphrase reads everything; no per-user identity or
  sender authentication. Use X25519 key agreement / Signal or MLS for real deployments.
- **Weak passphrase**: PBKDF2 slows offline guessing but can't save a short one. Prefer random keys
  exchanged out-of-band (QR) or Argon2id.
- **No forward secrecy / rekeying**: one key leak exposes all messages. Random 96-bit nonces also
  limit a key to about 2³² messages.
- **Key in process memory**: Python can't reliably zero secrets (immutable `str`/`bytes`, GC copies);
  a memory dump or malware running as your user can recover it. The OS keyring protects at rest,
  not against code running as you. Unlike Android's hardware-backed Keystore, a desktop keyring is software-only.
- **Password-mode fallback** is only as strong as the unlock password (scrypt n=2¹⁵).
- **No transport encryption or auth to the server**: the server sees metadata (room, sender, time,
  size) and could drop, delay or replay messages. Add TLS and signed sequence numbers.
- **Not audited**: learning prototype. Use a vetted protocol/library for production.

## Android
The Python code runs on desktop. To ship it on Android you'd package the client with Kivy/Buildozer
and reach the Android Keystore via pyjnius. The native Kotlin version from earlier already does this
properly with the hardware-backed Keystore.
