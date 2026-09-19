"""Chat client core (no UI). Encrypts before sending, decrypts after receiving."""
import json
import socket
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Callable, Optional

from .crypto_engine import CryptoError, decrypt, encrypt, message_aad
from .server import MAX_LINE
from .storage import MessageDb


class SendError(Exception):
    pass


@dataclass
class Message:
    id: str
    sender: str
    mine: bool
    ts: int
    text: Optional[str]      # None when decryption failed
    error: Optional[str]
    envelope: str


class ChatClient:
    def __init__(self, host: str, port: int, room: str, user: str, key: bytes, db: MessageDb,
                 on_message: Callable[[Message], None] = lambda m: None,
                 on_status: Callable[[str], None] = lambda s: None):
        self.host, self.port, self.room, self.user = host, port, room, user
        self._key, self._db = key, db
        self.on_message, self.on_status = on_message, on_status
        self._sock: Optional[socket.socket] = None
        self._lock = threading.Lock()

    # -- connection --------------------------------------------------------------
    @property
    def connected(self) -> bool:
        return self._sock is not None

    def connect(self) -> None:
        try:
            s = socket.create_connection((self.host, self.port), timeout=5)
        except OSError as e:
            raise SendError(f"Cannot reach server {self.host}:{self.port}: {e}") from e
        s.settimeout(None)
        s.sendall((json.dumps({"join": self.room}) + "\n").encode())
        self._sock = s
        threading.Thread(target=self._reader, args=(s,), daemon=True).start()
        self.on_status("connected")

    def close(self) -> None:
        s, self._sock = self._sock, None
        if s:
            try:
                s.close()
            except OSError:
                pass

    def _reader(self, s: socket.socket) -> None:
        try:
            f = s.makefile("rb")
            while True:
                line = f.readline(MAX_LINE)
                if not line:
                    break
                try:
                    m = json.loads(line)
                    ok = (m["room"] == self.room and all(isinstance(m[k], str) for k in ("id", "sender", "envelope"))
                          and isinstance(m["ts"], int))
                except (ValueError, KeyError, TypeError):
                    continue                                 # ignore junk from the network
                if ok and self._db.insert(m):
                    self.on_message(self.decode(m))
        except OSError:
            pass
        finally:
            if self._sock is s:
                self._sock = None
                self.on_status("disconnected")

    # -- messaging ---------------------------------------------------------------
    def send(self, text: str) -> Message:
        text = text.strip()
        if not text:
            raise SendError("Message is empty")
        msg_id, ts = uuid.uuid4().hex, int(time.time() * 1000)
        try:
            env = encrypt(text, self._key, message_aad(self.room, self.user, msg_id, ts))   # local encryption
        except CryptoError as e:
            raise SendError(str(e)) from e
        wire = {"id": msg_id, "room": self.room, "sender": self.user, "ts": ts, "envelope": env}
        with self._lock:
            if not self.connected:
                self.connect()                               # one automatic reconnect attempt
            try:
                self._sock.sendall((json.dumps(wire) + "\n").encode())   # only ciphertext leaves
            except (OSError, AttributeError) as e:
                self.close()
                self.on_status("disconnected")
                raise SendError(f"Not sent: connection lost ({e})") from e
        self._db.insert(wire)
        return self.decode(wire)

    def decode(self, m: dict) -> Message:
        try:
            text, err = decrypt(m["envelope"], self._key, message_aad(m["room"], m["sender"], m["id"], m["ts"])), None
        except CryptoError as e:
            text, err = None, str(e)
        return Message(m["id"], m["sender"], m["sender"] == self.user, m["ts"], text, err, m["envelope"])

    def history(self):
        return [self.decode(m) for m in self._db.all(self.room)]
