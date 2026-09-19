"""Secure storage of the chat key at rest.

    passphrase --PBKDF2--> chat key --AES-GCM(master key)--> wrapped blob --> vault.json (0600)

The master key comes from, in order of preference:
  1. the OS keyring (Keychain / Credential Locker / Secret Service)   -> "keyring" mode
  2. a local unlock password stretched with scrypt                     -> "password" mode
The plaintext chat key is never written to disk.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
from typing import Callable, Optional, Tuple

from .crypto_engine import CryptoError, open_, seal

SERVICE = "securechat-py"


class VaultError(Exception):
    pass


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _scrypt(password: str, salt: bytes) -> bytes:
    return hashlib.scrypt(password.encode(), salt=salt, n=2**15, r=8, p=1, maxmem=64 * 1024 * 1024, dklen=32)


class KeyVault:
    def __init__(self, path: Path, use_keyring: bool = True):
        self.path = Path(path)
        self.use_keyring = use_keyring
        self._account = str(self.path.resolve())

    # -- OS keyring master key -------------------------------------------------
    def _keyring_master(self, create: bool) -> Optional[bytes]:
        if not self.use_keyring:
            return None
        try:
            import keyring
            v = keyring.get_password(SERVICE, self._account)
            if v is None and create:
                v = _b64e(os.urandom(32))
                keyring.set_password(SERVICE, self._account, v)
            return base64.b64decode(v) if v else None
        except Exception:      # no backend (headless Linux), locked, not installed...
            return None

    @staticmethod
    def _aad(room: str) -> bytes:
        return f"chat-key|{room}".encode()

    # -- public API -------------------------------------------------------------
    def exists(self) -> bool:
        return self.path.exists()

    def save(self, room: str, key: bytes, ask_master: Callable[[], str]) -> None:
        mode, salt = "keyring", b""
        master = self._keyring_master(create=True)
        if master is None:
            mode, salt = "password", os.urandom(16)
            pw = ask_master()
            if not pw:
                raise VaultError("An unlock password is required (no OS keyring available).")
            master = _scrypt(pw, salt)
        doc = {"v": 1, "room": room, "mode": mode, "salt": _b64e(salt),
               "wrapped": _b64e(seal(master, key, self._aad(room)))}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(doc, f)
        os.replace(tmp, self.path)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    def load(self, ask_master: Callable[[], str]) -> Optional[Tuple[str, bytes]]:
        if not self.exists():
            return None
        try:
            doc = json.loads(self.path.read_text())
            room, wrapped = doc["room"], base64.b64decode(doc["wrapped"])
            if doc["mode"] == "keyring":
                master = self._keyring_master(create=False)
                if master is None:
                    raise VaultError("OS keyring entry is unavailable")
            else:
                master = _scrypt(ask_master(), base64.b64decode(doc["salt"]))
            return room, open_(master, wrapped, self._aad(room))
        except VaultError:
            raise
        except CryptoError as e:
            raise VaultError("Could not unlock the saved key (wrong password or key changed)") from e
        except (KeyError, ValueError, OSError) as e:
            raise VaultError(f"Vault file is corrupt: {e}") from e

    def delete(self) -> None:
        try:
            self.path.unlink(missing_ok=True)
        except OSError:
            pass
        try:
            import keyring
            keyring.delete_password(SERVICE, self._account)
        except Exception:
            pass
