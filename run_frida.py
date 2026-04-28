"""
run_frida.py
------------
Attach frida_hook.js to Pikmin Bloom via TCP (bypasses macOS simmy crash).

Usage:
  # 1. Make sure frida-server is running on the emulator:
  #    adb root
  #    adb shell /data/local/tmp/frida-server &
  #    adb shell setenforce 0
  #
  # 2. Forward the port:
  #    adb forward tcp:27042 tcp:27042
  #
  # 3. Run this script:
  #    python run_frida.py            # attach mode (app already running)
  #    python run_frida.py --spawn    # spawn mode (kills + restarts app, bypasses anti-tamper)
  #    python run_frida.py --list     # list processes

pip install frida
"""

import frida
import sys
import os
import argparse
import time
import threading

SCRIPT_PATH = os.path.join(os.path.dirname(__file__), "frida_hook.js")
DEFAULT_HOST = "127.0.0.1:27042"
DEFAULT_NAME = "Pikmin Bloom"
PIKMIN_PACKAGES = [
    "com.nianticlabs.pikminbloom",
    "Pikmin Bloom",
    "pikmin",
]


DUMP_DIR = os.path.join(os.path.dirname(__file__), "decrypted_dumps")
os.makedirs(DUMP_DIR, exist_ok=True)


def on_message(message, data):
    if message["type"] == "error":
        print(f"[error] {message['stack']}")
        return

    if message["type"] != "send":
        return

    payload = message.get("payload", {})

    # Binary buffer sent from hook
    if isinstance(payload, dict) and payload.get("type") == "buffer" and data:
        idx   = payload.get("index", 0)
        label = payload.get("label", "buf")
        alg   = payload.get("alg", "?")
        size  = len(data)
        fname = f"{idx:03d}_{label.replace('/', '_')}_{size}.bin"
        fpath = os.path.join(DUMP_DIR, fname)
        with open(fpath, "wb") as f:
            f.write(data)
        print(f"\n[+] Saved {size:,} bytes → {fpath}")
        print(f"    alg={alg}  preview={data[:24].hex()}")
        # Quick FlatBuffers check
        if len(data) >= 4:
            u32 = int.from_bytes(data[:4], "little")
            if 0 < u32 < 500:
                print(f"    ** FlatBuffers root_off={u32} — run: python decode_rpc2.py \"{fpath}\"")
    else:
        print(f"[hook] {payload}")


def find_pikmin_process(device):
    procs = device.enumerate_processes()
    # exact package match first
    for proc in procs:
        if any(pkg.lower() == proc.name.lower() for pkg in PIKMIN_PACKAGES):
            return proc
    # partial match
    for proc in procs:
        if any(pkg.lower() in proc.name.lower() for pkg in PIKMIN_PACKAGES):
            return proc
    return None


def main():
    parser = argparse.ArgumentParser(description="Attach frida_hook.js to Pikmin Bloom")
    parser.add_argument("--host", default=DEFAULT_HOST, help="frida-server host:port")
    parser.add_argument("--name", default=None, help="Process name (auto-detect if omitted)")
    parser.add_argument("--pid", type=int, default=None, help="Process PID")
    parser.add_argument("--spawn", action="store_true",
                        help="Spawn app fresh instead of attaching (bypasses anti-tamper)")
    parser.add_argument("--list", action="store_true", help="List processes and exit")
    args = parser.parse_args()

    print(f"[*] Connecting to frida-server at {args.host} ...")
    try:
        dm = frida.get_device_manager()
        device = dm.add_remote_device(args.host)
        print(f"[+] Connected: {device.name}")
    except Exception as e:
        print(f"[-] Connection failed: {e}")
        print("    Make sure frida-server is running on the emulator and port is forwarded:")
        print("      adb shell su -c '/data/local/tmp/frida-server &'")
        print("      adb forward tcp:27042 tcp:27042")
        sys.exit(1)

    # List processes
    procs = device.enumerate_processes()
    if args.list:
        print(f"\n{'PID':>7}  Name")
        print("-" * 50)
        for p in sorted(procs, key=lambda x: x.name.lower()):
            print(f"{p.pid:>7}  {p.name}")
        return

    # Spawn mode: kill existing instance and launch fresh
    if args.spawn:
        pkg = "com.nianticlabs.pikminbloom"
        print(f"[*] Spawn mode: killing existing '{pkg}' if running ...")
        try:
            for p in procs:
                if "pikmin" in p.name.lower():
                    device.kill(p.pid)
                    print(f"    Killed PID {p.pid}")
                    time.sleep(1)
        except Exception:
            pass
        print(f"[*] Spawning '{pkg}' ...")
        try:
            pid = device.spawn([pkg])
            name = pkg
        except Exception as e:
            print(f"[-] Spawn failed: {e}")
            sys.exit(1)
        print(f"[+] Spawned PID={pid}")
        print(f"[*] Attaching before app initialises ...")
        try:
            session = device.attach(pid)
        except Exception as e:
            print(f"[-] Attach failed: {e}")
            sys.exit(1)
    else:
        # Attach mode: find running process
        if args.pid:
            pid = args.pid
            name = f"PID {pid}"
        elif args.name:
            match = next((p for p in procs if args.name.lower() in p.name.lower()), None)
            if not match:
                print(f"[-] Process '{args.name}' not found. Running processes:")
                for p in sorted(procs, key=lambda x: x.name.lower()):
                    print(f"  {p.pid:>7}  {p.name}")
                sys.exit(1)
            pid, name = match.pid, match.name
        else:
            match = find_pikmin_process(device)
            if not match:
                print("[-] Pikmin Bloom not found. All processes:")
                for p in sorted(procs, key=lambda x: x.name.lower()):
                    print(f"  {p.pid:>7}  {p.name}")
                sys.exit(1)
            pid, name = match.pid, match.name

        print(f"[*] Attaching to '{name}' (PID={pid}) ...")
        try:
            session = device.attach(pid)
        except Exception as e:
            print(f"[-] Attach failed: {e}")
            print("    Tip: try --spawn mode to inject before anti-tamper runs:")
            print("         python run_frida.py --spawn")
            sys.exit(1)

    print(f"[+] Attached!")

    # Load the hook script
    if not os.path.exists(SCRIPT_PATH):
        print(f"[-] Script not found: {SCRIPT_PATH}")
        sys.exit(1)

    with open(SCRIPT_PATH, "r") as f:
        source = f.read()

    script = session.create_script(source)
    script.on("message", on_message)

    try:
        script.load()
    except Exception as e:
        print(f"[-] Script load failed: {e}")
        sys.exit(1)

    print(f"[+] frida_hook.js loaded and running.")

    # In spawn mode, resume the app now that the script is injected
    if args.spawn:
        device.resume(pid)
        print(f"[+] App resumed — Pikmin Bloom is now starting with hooks active")
    print(f"[*] Decrypted buffers will be saved to /sdcard/pikmin_decrypted/")
    print(f"[*] Now open the game / trigger rpc2 (force-stop + restart).")
    print(f"[*] Press Ctrl-C to stop.\n")

    detached = threading.Event()

    def on_detached(reason):
        print(f"\n[!] Session detached: {reason}")
        detached.set()

    session.on("detached", on_detached)

    # Simple REPL — runs in a background thread so on_message still fires
    def repl():
        print("[REPL] Commands: scan_fb()  eval(<js>)  quit")
        while not detached.is_set():
            try:
                line = input("js> ").strip()
            except (EOFError, KeyboardInterrupt):
                break
            # strip accidental prompt prefix if user copy-pasted "js> ..."
            if line.startswith("js>"):
                line = line[3:].strip()
            if not line:
                continue
            if line in ("quit", "exit", "q"):
                break
            try:
                if line == "scan_fb()":
                    script.exports_sync.scan_fb()
                elif line.startswith("scan_plaintext"):
                    import re as _re
                    m = _re.search(r'\((\d*)\)', line)
                    sz = int(m.group(1)) if m and m.group(1) else None
                    script.exports_sync.scan_plaintext(sz)
                else:
                    result = script.exports_sync.eval_js(line)
                    if result is not None:
                        print(f"  => {result}")
            except Exception as e:
                print(f"  [err] {e}")
        detached.set()

    t = threading.Thread(target=repl, daemon=True)
    t.start()

    try:
        while not detached.is_set():
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass

    print("\n[*] Detaching...")
    try:
        session.detach()
    except Exception:
        pass


if __name__ == "__main__":
    main()
