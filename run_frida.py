"""
run_frida.py
------------
Attach frida_hook.js to Pikmin Bloom via TCP (bypasses macOS simmy crash).

Usage:
  # 1. Make sure frida-server is running on the emulator:
  #    adb shell su -c "/data/local/tmp/frida-server &"
  #
  # 2. Forward the port:
  #    adb forward tcp:27042 tcp:27042
  #
  # 3. Run this script:
  #    python run_frida.py
  #    python run_frida.py --host 127.0.0.1:27042 --name "Pikmin Bloom"

pip install frida
"""

import frida
import sys
import os
import argparse
import time

SCRIPT_PATH = os.path.join(os.path.dirname(__file__), "frida_hook.js")
DEFAULT_HOST = "127.0.0.1:27042"
DEFAULT_NAME = "Pikmin Bloom"
PIKMIN_PACKAGES = [
    "com.nianticlabs.pikminbloom",
    "Pikmin Bloom",
    "pikmin",
]


def on_message(message, data):
    if message["type"] == "send":
        print(f"[hook] {message['payload']}")
    elif message["type"] == "error":
        print(f"[error] {message['stack']}")
    else:
        print(f"[msg] {message}")


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

    # Find target process
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
    print(f"[*] Decrypted buffers will be saved to /sdcard/pikmin_decrypted/")
    print(f"[*] Now open the game / trigger rpc2 (force-stop + restart).")
    print(f"[*] Press Ctrl-C to stop.\n")

    def on_detached(reason):
        print(f"\n[!] Session detached: {reason}")

    session.on("detached", on_detached)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Detaching...")
        session.detach()


if __name__ == "__main__":
    main()
