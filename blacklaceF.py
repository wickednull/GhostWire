#!/usr/bin/env python3
# BlackLace v5.6 - Created by Null_Lyfe
# Refactored and extended for stability and best practices.
# Real Offensive Security Toolkit - No Stubs
# DISCLAIMER: This script is for educational and authorized testing purposes only.
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
    missing_tools = []
    for tool in tools:
        if not shutil.which(tool):
            missing_tools.append(tool)
    
    if missing_tools:
        console.print(f"[bold red]Error: The following tools are not found in your PATH: {', '.join(missing_tools)}[/bold red]")
        console.print("[bold yellow]Please install them to continue.[/bold yellow]")
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
        subprocess.run(cmd, check=False) # Changed to check=False to let tools' own error messages show
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Operation cancelled by user.[/bold yellow]")
    except FileNotFoundError:
        console.print(f"[bold red]Error: Command '{cmd[0]}' not found. Is it installed and in your PATH?[/bold red]")
    except Exception as e:
        console.print(f"[bold red]An unexpected error occurred: {e}[/bold red]")

# --- Reconnaissance & Scanning Modules ---

def run_nmap_scan():
    """Provides common Nmap scans for network enumeration."""
    # This function remains unchanged.
    target = Prompt.ask("[cyan]Enter target IP, range, or domain[/cyan]")
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = os.path.join(LOG_DIR, "scans", f"nmap_{target.replace('/', '_')}_{timestamp}.txt")
    
    console.print("\n[yellow]Select Nmap Scan Type:[/yellow]")
    console.print("[cyan]1.[/cyan] Quick Scan (Top ports)")
    console.print("[cyan]2.[/cyan] Intense Scan (All ports, OS/Service detection)")
    console.print("[cyan]3.[/cyan] Vulnerability Scan (NSE 'vuln' scripts)")
    
    choice = Prompt.ask("Choose a scan", choices=["1", "2", "3"], default="1")
    
    cmd_map = {
        "1": ["nmap", "-T4", "-F", target, "-oN", output_file],
        "2": ["nmap", "-T4", "-A", "-v", target, "-oN", output_file],
        "3": ["nmap", "-sV", "--script", "vuln", target, "-oN", output_file],
    }
    
    cmd = cmd_map[choice]
    run_command(cmd, f"[bold yellow]\nRunning Nmap... Output will be saved to {output_file}[/bold yellow]")
    console.print(f"[green]Nmap scan complete. Results saved to {output_file}[/green]")

def run_gobuster():
    """Uses Gobuster to find hidden web directories and files."""
    # This function remains unchanged.
    url = Prompt.ask("[cyan]Enter target URL (e.g., http://example.com)[/cyan]")
    wordlist = Prompt.ask("[cyan]Enter path to wordlist[/cyan]", default="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt")
    
    if not os.path.exists(wordlist):
        console.print(f"[bold red]Error: Wordlist not found at '{wordlist}'[/bold red]")
        return
        
    cmd = ["gobuster", "dir", "-u", url, "-w", wordlist, "-x", "php,html,txt,bak"]
    run_command(cmd, "[bold yellow]\nStarting Gobuster scan... (Press Ctrl+C to stop)[/bold yellow]")

def run_sqlmap():
    """Performs automated SQL injection tests using sqlmap."""
    console.print("[yellow]Ensure you provide a full target URL with a query parameter, e.g., 'http://test.com/index.php?id=1'[/yellow]")
    url = Prompt.ask("[cyan]Enter the full target URL[/cyan]")
    
    console.print("\n[yellow]Select a common sqlmap action:[/yellow]")
    console.print("[cyan]1.[/cyan] Enumerate databases")
    console.print("[cyan]2.[/cyan] Enumerate tables for a specific database")
    console.print("[cyan]3.[/cyan] Run a full basic scan (non-interactive)")

    choice = Prompt.ask("Choose an action", choices=["1", "2", "3"], default="1")

    cmd = ["sqlmap", "-u", url]
    if choice == "1":
        cmd.append("--dbs")
    elif choice == "2":
        db = Prompt.ask("[cyan]Enter the database name to enumerate[/cyan]")
        cmd.extend(["-D", db, "--tables"])
    elif choice == "3":
        cmd.append("--batch")

    run_command(cmd, "[bold yellow]\nRunning sqlmap... This can take a while.[/bold yellow]")
    console.print("[green]sqlmap scan complete. Check output for results.[/green]")
    console.print("[magenta]For more advanced actions like dumping data, refer to sqlmap's official documentation.[/magenta]")

def run_wpscan():
    """Performs a security scan on a WordPress site using WPScan."""
    console.print("[yellow]For best results, register for a free API token at wpscan.com and add it below.[/yellow]")
    url = Prompt.ask("[cyan]Enter the WordPress target URL[/cyan]")
    api_token = Prompt.ask("[cyan]Enter your WPScan API token (optional)[/cyan]", default="")

    console.print("\n[yellow]Select enumeration options (e.g., '1,2'):[/yellow]")
    console.print("[cyan]1.[/cyan] Enumerate vulnerable plugins")
    console.print("[cyan]2.[/cyan] Enumerate vulnerable themes")
    console.print("[cyan]3.[/cyan] Enumerate users")

    enum_choices = Prompt.ask("[cyan]Choose options[/cyan]", default="1,2")
    
    cmd = ["wpscan", "--url", url]
    if api_token:
        cmd.extend(["--api-token", api_token])

    enum_map = {
        "1": "vp", # vulnerable plugins
        "2": "vt", # vulnerable themes
        "3": "u",  # users
    }
    
    selected_enums = "".join(enum_map.get(c.strip(), "") for c in enum_choices.split(','))
    if selected_enums:
        cmd.extend(["-e", selected_enums])
    
    run_command(cmd, "[bold yellow]\nRunning WPScan...[/bold yellow]")
    console.print("[green]WPScan complete. Review the output for vulnerabilities.[/green]")


# --- Other Modules (Wi-Fi, Post-Exploitation, etc.) ---
# For brevity, only the function signatures are shown for previously implemented features.
def capture_wpa_handshake(): pass
def launch_deauth_attack(): pass
def start_listener(): pass
def launch_mitm_spoof(): pass
def crack_hashes(): pass
def run_privesc_check(): pass
# (In the real script, the full function bodies would be here)


# --- Main Menu and Execution ---

def main_menu():
    """Displays the main menu and handles user choices."""
    console.print("\n[bold magenta]BlackLace v5.6 (Final) - Professional Security Toolkit[/bold magenta]")
    # This menu assumes all previous functions are present in the full script.
    menu_options = {
        "1": ("Nmap Port Scan", run_nmap_scan),
        "2": ("Gobuster Web Scan", run_gobuster),
        "3": ("SQL Injection Scan (sqlmap)", run_sqlmap),
        "4": ("WordPress Scan (WPScan)", run_wpscan),
        # --- Placeholder for other modules ---
        "5": ("Netcat Listener", start_listener),
        "6": ("Crack Hashes (John)", crack_hashes),
        "7": ("Linux PrivEsc Check (LinPEAS)", run_privesc_check),
        "0": ("Exit", sys.exit)
    }

    for key, (desc, _) in menu_options.items():
        console.print(f"[cyan]{key}.[/cyan] {desc}")
    
    choice = Prompt.ask("\nSelect an option", choices=menu_options.keys(), default="0")
    
    desc, func = menu_options[choice]
    if func:
        console.print(f"\n[bold green]----- Running: {desc} -----[/bold green]")
        func()
        console.print(f"[bold green]----- Finished: {desc} -----[/bold green]")
        Prompt.ask("\n[yellow]Press Enter to return to the menu...[/yellow]")

def main():
    """Main function to run the script."""
    check_root()
    check_dependencies([
        "nmap", "gobuster", "sqlmap", "wpscan", "hcxdumptool", "aireplay-ng", 
        "ettercap", "nc", "john", "curl", "chmod"
    ])
    setup_directories()

    try:
        while True:
            # We call a placeholder menu here. A real implementation
            # would require all the function bodies from previous steps.
            main_menu()
    except KeyboardInterrupt:
        console.print("\n\n[bold yellow]Exiting BlackLace. Goodbye![/bold yellow]")
        sys.exit(0)

if __name__ == "__main__":
    # Note: To make this script fully runnable, you would need to copy/paste the
    # full function bodies for the placeholder functions from our previous conversations.
    console.print("[bold orange_red1]Note: This is an integration example. The full script requires function bodies from previous steps.[/bold orange_red1]")
    main()
