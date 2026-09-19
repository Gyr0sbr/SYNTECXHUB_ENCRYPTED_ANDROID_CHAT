"""Relay server. It forwards JSON lines between clients in the same room and only ever sees
ciphertext envelopes (see the log output). Run:  python -m securechat.server --port 8765
"""
import argparse
import asyncio
import json
import logging
import threading

MAX_LINE = 64 * 1024
log = logging.getLogger("relay")


class RelayServer:
    def __init__(self, host: str = "127.0.0.1", port: int = 8765):
        self.host, self.port = host, port
        self.rooms: dict = {}
        self._loop = None
        self._server = None

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        room = None
        try:
            while True:
                try:
                    line = await reader.readline()
                except ValueError:                       # line longer than MAX_LINE
                    log.warning("oversized line, dropping client")
                    break
                if not line:
                    break
                try:
                    msg = json.loads(line)
                    if not isinstance(msg, dict):
                        raise ValueError
                except ValueError:
                    continue
                if "join" in msg and isinstance(msg["join"], str):
                    room = msg["join"]
                    self.rooms.setdefault(room, set()).add(writer)
                    continue
                if room is None or msg.get("room") != room:
                    continue
                if not all(isinstance(msg.get(k), str) for k in ("id", "sender", "envelope")):
                    continue
                log.info("relay %s@%s: %s...", msg["sender"], room, msg["envelope"][:48])
                for w in list(self.rooms.get(room, ())):
                    if w is writer:
                        continue
                    try:
                        w.write(line if line.endswith(b"\n") else line + b"\n")
                        await w.drain()
                    except (ConnectionError, OSError):
                        self.rooms[room].discard(w)
        finally:
            if room:
                self.rooms.get(room, set()).discard(writer)
            writer.close()

    async def _start(self):
        self._server = await asyncio.start_server(self._handle, self.host, self.port, limit=MAX_LINE)
        self.port = self._server.sockets[0].getsockname()[1]
        log.info("listening on %s:%s", self.host, self.port)

    async def serve_forever(self):
        await self._start()
        async with self._server:
            await self._server.serve_forever()

    def start_in_thread(self) -> int:
        """For tests / embedding. Returns the bound port."""
        ready = threading.Event()

        def run():
            self._loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._loop)
            self._loop.run_until_complete(self._start())
            ready.set()
            self._loop.run_forever()

        threading.Thread(target=run, daemon=True).start()
        ready.wait(5)
        return self.port

    def stop(self):
        if self._loop:
            self._loop.call_soon_threadsafe(self._loop.stop)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8765)
    a = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    try:
        asyncio.run(RelayServer(a.host, a.port).serve_forever())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
