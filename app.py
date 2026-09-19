"""Entry point.   python -m securechat.app --user alice            (GUI)
                  python -m securechat.app --user alice --cli      (terminal)
Each --user gets its own data dir, so you can run two clients on one machine."""
import argparse
import getpass
import queue
import sys
import time
from pathlib import Path

from .client import ChatClient, Message, SendError
from .crypto_engine import CryptoError, derive_key, room_salt
from .keystore import KeyVault, VaultError
from .storage import MessageDb


def fmt_time(ts: int) -> str:
    return time.strftime("%H:%M", time.localtime(ts / 1000))


def open_session(args, ask_room, ask_passphrase, ask_master, warn):
    """Load the wrapped key from the vault, or derive a new one from room + passphrase."""
    data = Path(args.data_dir or Path.home() / ".securechat_py" / args.user)
    vault = KeyVault(data / "vault.json", use_keyring=not args.no_keyring)
    try:
        loaded = vault.load(ask_master)
    except VaultError as e:
        warn(f"Saved key could not be unlocked: {e}\nSet up the chat again.")
        vault.delete()
        loaded = None
    if loaded is None:
        room = (ask_room() or "").strip()
        pw = ask_passphrase()
        if not room or not pw or len(pw) < 8:
            raise SystemExit("Room name required and passphrase must be at least 8 characters.")
        key = derive_key(pw, room_salt(room))
        vault.save(room, key, ask_master)
    else:
        room, key = loaded
    data.mkdir(parents=True, exist_ok=True)
    return vault, MessageDb(data / "messages.db"), room, key


# --------------------------------------------------------------------------- CLI
def run_cli(args):
    vault, db, room, key = open_session(
        args,
        ask_room=lambda: input("Room name: "),
        ask_passphrase=lambda: getpass.getpass("Shared passphrase (8+ chars): "),
        ask_master=lambda: getpass.getpass("Local unlock password: "),
        warn=lambda m: print("!", m, file=sys.stderr))
    show_cipher = False

    def render(m: Message):
        who = "me" if m.mine else m.sender
        line = f"[{fmt_time(m.ts)}] {who}: " + (m.text if m.text is not None else f"<cannot decrypt: {m.error}>")
        print("\r" + line + ("\n      " + m.envelope[:70] + "..." if show_cipher else ""))

    client = ChatClient(args.host, args.port, room, args.user, key, db, on_message=render,
                        on_status=lambda s: print(f"* {s}"))
    for m in client.history():
        render(m)
    try:
        client.connect()
    except SendError as e:
        print("!", e)
    print("Commands: /cipher  /clear  /reset  /quit")
    try:
        while True:
            line = input()
            if line == "/quit":
                break
            elif line == "/cipher":
                show_cipher = not show_cipher
            elif line == "/clear":
                db.clear()
            elif line == "/reset":
                db.clear(); vault.delete(); print("Key and history deleted."); break
            elif line.strip():
                try:
                    render(client.send(line))
                except SendError as e:
                    print("!", e)
    except (EOFError, KeyboardInterrupt):
        pass
    finally:
        client.close()


# --------------------------------------------------------------------------- GUI
def run_gui(args):
    import tkinter as tk
    from tkinter import messagebox, simpledialog

    root = tk.Tk()
    root.title(f"SecureChat: {args.user}")
    root.geometry("460x560")
    root.withdraw()
    vault, db, room, key = open_session(
        args,
        ask_room=lambda: simpledialog.askstring("Set up", "Room name:", parent=root),
        ask_passphrase=lambda: simpledialog.askstring("Set up", "Shared passphrase (8+ chars):", show="*", parent=root),
        ask_master=lambda: simpledialog.askstring("Unlock", "Local unlock password:", show="*", parent=root),
        warn=lambda m: messagebox.showwarning("Key problem", m, parent=root))
    root.deiconify()

    events: "queue.Queue" = queue.Queue()
    client = ChatClient(args.host, args.port, room, args.user, key, db,
                        on_message=lambda m: events.put(("msg", m)),
                        on_status=lambda s: events.put(("status", s)))
    show_cipher = tk.BooleanVar(value=False)
    status = tk.StringVar(value="connecting...")

    top = tk.Frame(root); top.pack(fill="x")
    tk.Label(top, text=f"Room: {room}   (AES-256-GCM, encrypted on this device)", anchor="w").pack(side="left", padx=6)
    tk.Label(root, textvariable=status, anchor="w", fg="gray30").pack(fill="x", padx=6)

    text = tk.Text(root, state="disabled", wrap="word", padx=6, pady=6)
    text.pack(fill="both", expand=True)
    text.tag_config("me", foreground="#0b5394")
    text.tag_config("them", foreground="#222222")
    text.tag_config("err", foreground="#b00020")
    text.tag_config("cipher", foreground="#888888", font=("Courier", 8))

    def render_all():
        text.config(state="normal"); text.delete("1.0", "end")
        for m in client.history():
            who = "me" if m.mine else m.sender
            if m.text is None:
                text.insert("end", f"[{fmt_time(m.ts)}] {who}: cannot decrypt ({m.error})\n", "err")
            else:
                text.insert("end", f"[{fmt_time(m.ts)}] {who}: {m.text}\n", "me" if m.mine else "them")
            if show_cipher.get():
                text.insert("end", "    " + m.envelope[:72] + "...\n", "cipher")
        text.config(state="disabled"); text.see("end")

    entry = tk.Entry(root)
    entry.pack(side="left", fill="x", expand=True, padx=6, pady=6)

    def do_send(_evt=None):
        body = entry.get()
        if not body.strip():
            return
        try:
            client.send(body)
            entry.delete(0, "end")
            render_all()
        except SendError as e:
            status.set("disconnected")
            messagebox.showerror("Message not sent", f"{e}\n\nYour text is still in the box.", parent=root)

    tk.Button(root, text="Send", command=do_send).pack(side="right", padx=6, pady=6)
    entry.bind("<Return>", do_send)

    def reconnect():
        try:
            client.close(); client.connect()
        except SendError as e:
            messagebox.showerror("Connection", str(e), parent=root)

    def clear_history():
        db.clear(); render_all()

    def reset_key():
        if messagebox.askyesno("Delete key", "Delete the saved key and all history?", parent=root):
            client.close(); db.clear(); vault.delete(); root.destroy()

    menu = tk.Menu(root); m = tk.Menu(menu, tearoff=0)
    m.add_checkbutton(label="Show ciphertext", variable=show_cipher, command=render_all)
    m.add_command(label="Reconnect", command=reconnect)
    m.add_command(label="Clear history", command=clear_history)
    m.add_command(label="Delete key and history", command=reset_key)
    menu.add_cascade(label="Chat", menu=m); root.config(menu=menu)

    def pump():
        dirty = False
        while True:
            try:
                kind, val = events.get_nowait()
            except queue.Empty:
                break
            if kind == "status":
                status.set(val)
            else:
                dirty = True
        if dirty:
            render_all()
        root.after(100, pump)

    render_all()
    try:
        client.connect()
    except SendError as e:
        status.set("disconnected"); messagebox.showwarning("Connection", str(e), parent=root)
    root.after(100, pump)
    root.protocol("WM_DELETE_WINDOW", lambda: (client.close(), root.destroy()))
    root.mainloop()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--user", required=True)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--data-dir")
    ap.add_argument("--cli", action="store_true", help="terminal UI instead of Tkinter")
    ap.add_argument("--no-keyring", action="store_true", help="force password-protected key file")
    args = ap.parse_args()
    (run_cli if args.cli else run_gui)(args)


if __name__ == "__main__":
    main()
