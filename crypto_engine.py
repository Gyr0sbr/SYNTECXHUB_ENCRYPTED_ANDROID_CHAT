"""AES-256-GCM helpers.

Envelope format:  v1:<base64( nonce[12] || ciphertext || tag[16] )>

* GCM = confidentiality + integrity: wrong key / modified data raises CryptoError.
* A fresh random 96-bit nonce per message (os.urandom); never reused with the same key.
* AAD binds ciphertext to its metadata (room, sender, id, timestamp).
"""
import base64
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

VERSION = "v1"
NONCE_LEN = 12
TAG_LEN = 16
KEY_LEN = 32
PBKDF2_ITERATIONS = 210_000


class CryptoError(Exception):
    """Any encryption/decryption failure. Messages are safe to show to the user."""


def new_key() -> bytes:
    return AESGCM.generate_key(bit_length=256)


def derive_key(passphrase: str, salt: bytes) -> bytes:
    """Stretch a shared passphrase into a 256-bit key (slow on purpose)."""
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=KEY_LEN, salt=salt, iterations=PBKDF2_ITERATIONS)
    return kdf.derive(passphrase.encode("utf-8"))


def room_salt(room: str) -> bytes:
    """Per-room salt so the same passphrase yields different keys in different rooms."""
    digest = hashes.Hash(hashes.SHA256())
    digest.update(f"securechat-v1|{room}".encode())
    return digest.finalize()


def message_aad(room: str, sender: str, msg_id: str, ts: int) -> bytes:
    return f"{room}|{sender}|{msg_id}|{ts}".encode("utf-8")


def seal(key: bytes, plaintext: bytes, aad: bytes) -> bytes:
    try:
        nonce = os.urandom(NONCE_LEN)
        return nonce + AESGCM(key).encrypt(nonce, plaintext, aad)
    except ValueError as e:
        raise CryptoError(f"Encryption failed: {e}") from e


def open_(key: bytes, blob: bytes, aad: bytes) -> bytes:
    if len(blob) < NONCE_LEN + TAG_LEN:
        raise CryptoError("Ciphertext is too short")
    try:
        return AESGCM(key).decrypt(blob[:NONCE_LEN], blob[NONCE_LEN:], aad)
    except InvalidTag as e:
        raise CryptoError("Authentication failed: wrong key or message was modified") from e
    except ValueError as e:
        raise CryptoError(f"Decryption failed: {e}") from e


def encrypt(text: str, key: bytes, aad: bytes) -> str:
    return f"{VERSION}:" + base64.b64encode(seal(key, text.encode("utf-8"), aad)).decode("ascii")


def decrypt(envelope: str, key: bytes, aad: bytes) -> str:
    if not isinstance(envelope, str):
        raise CryptoError("Malformed message")
    parts = envelope.split(":")
    if len(parts) != 2 or parts[0] != VERSION:
        raise CryptoError("Malformed or unsupported message format")
    try:
        blob = base64.b64decode(parts[1], validate=True)
    except ValueError as e:
        raise CryptoError("Corrupt message encoding") from e
    try:
        return open_(key, blob, aad).decode("utf-8")
    except UnicodeDecodeError as e:
        raise CryptoError("Decrypted data is not valid text") from e
