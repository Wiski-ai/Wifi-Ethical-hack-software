#!/usr/bin/env python3

import os
import sys
import csv
import subprocess
import signal
import time
import urllib.request
from datetime import datetime
from pathlib import Path
import re
from typing import Dict, Set, Optional
import logging

# Configuration du logging
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)


class WiFiAutoScanner:
    """Scanner WiFi automatisé avec détection de réseaux et information vendeur."""

    # Constantes
    SCAN_INTERVAL = 7  # secondes
    SLEEP_INTERVAL = 1  # secondes
    VENDOR_API_TIMEOUT = 2  # secondes
    CSV_HEADERS = [
        "Heure", "ESSID", "BSSID", "Vendor", "Sécurité", 
        "Signal", "Canal", "Clients"
    ]

    def __init__(self):
        """Initialise le scanner WiFi."""
        self.csv_file = Path.cwd() / "wifi_scan_results.csv"
        self.temp_csv = Path.cwd() / "temp_scan"

        self.interface: Optional[str] = None
        self.monitor_interface: Optional[str] = None
        self.airodump_process: Optional[subprocess.Popen] = None

        self.known_networks: Set[str] = set()
        self.vendor_cache: Dict[str, str] = {}

        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

    def signal_handler(self, sig, frame):
        """Gère l'interruption du programme."""
        logger.info("Arrêt demandé.")
        self.cleanup()
        sys.exit(0)

    def check_root(self) -> None:
        """Vérifie que le script est exécuté en tant que root."""
        if os.geteuid() != 0:
            logger.error("Lancer avec sudo.")
            sys.exit(1)

    def run_command(self, cmd: list, silent: bool = True) -> subprocess.CompletedProcess:
        """Exécute une commande système."""
        kwargs = {
            "stdout": subprocess.DEVNULL if silent else None,
            "stderr": subprocess.DEVNULL if silent else None
        }
        return subprocess.run(cmd, **kwargs)

    def kill_conflicts(self) -> None:
        """Supprime les processus conflictuels."""
        logger.info("Suppression des processus gênants...")
        self.run_command(["airmon-ng", "check", "kill"])

    # -------------------------
    # DETECTION INTERFACE WIFI
    # -------------------------

    def find_wireless_interface(self) -> bool:
        """Détecte et sélectionne une interface WiFi."""
        result = subprocess.run(["iw", "dev"], capture_output=True, text=True)

        interfaces = [
            line.split()[1] 
            for line in result.stdout.split("\n")
            if line.strip().startswith("Interface")
        ]

        if not interfaces:
            logger.error("Aucune interface WiFi détectée.")
            return False

        logger.info("Interfaces WiFi détectées :")
        for i, iface in enumerate(interfaces):
            print(f"  {i} : {iface}")

        try:
            choice = int(input("Sélectionne l'interface : "))
            self.interface = interfaces[choice]
            logger.info(f"Interface choisie : {self.interface}")
            return True
        except (ValueError, IndexError):
            logger.error("Choix invalide.")
            return False

    # -------------------------
    # CHECK MONITOR MODE
    # -------------------------

    def get_monitor_interface(self) -> Optional[str]:
        """Récupère l'interface en mode monitor."""
        result = subprocess.run(["iwconfig"], capture_output=True, text=True)

        for line in result.stdout.split("\n"):
            if "Mode:Monitor" in line:
                return line.split()[0]
        return None

    def is_monitor_mode(self) -> bool:
        """Vérifie si une interface est en mode monitor."""
        self.monitor_interface = self.get_monitor_interface()
        return self.monitor_interface is not None

    # -------------------------
    # ACTIVER MONITOR MODE
    # -------------------------

    def setup_monitor_mode(self) -> bool:
        """Active le mode monitor sur l'interface."""
        if self.is_monitor_mode():
            logger.info(f"Interface déjà en monitor : {self.monitor_interface}")
            return True

        logger.info(f"Activation monitor sur {self.interface}...")
        self.run_command(["airmon-ng", "start", self.interface])

        self.monitor_interface = self.get_monitor_interface()
        if self.monitor_interface:
            logger.info(f"Interface monitor : {self.monitor_interface}")
            return True

        logger.error("Impossible d'activer le monitor.")
        return False

    # -------------------------
    # MAC VALIDATION
    # -------------------------

    @staticmethod
    def is_valid_mac(mac: str) -> bool:
        """Valide le format d'une adresse MAC."""
        return re.match(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', mac) is not None

    # -------------------------
    # VENDOR LOOKUP
    # -------------------------

    def get_vendor(self, mac: str) -> str:
        """Récupère le vendeur de l'adresse MAC."""
        prefix = mac.upper()[:8]

        if prefix in self.vendor_cache:
            return self.vendor_cache[prefix]

        try:
            url = f"https://api.macvendors.com/{mac}"
            vendor = urllib.request.urlopen(url, timeout=self.VENDOR_API_TIMEOUT).read().decode()
        except Exception as e:
            vendor = "Unknown"
            logger.debug(f"Erreur lors du lookup vendeur pour {mac}: {e}")

        self.vendor_cache[prefix] = vendor
        return vendor

    # -------------------------
    # CSV INIT
    # -------------------------

    def init_csv(self) -> None:
        """Initialise le fichier CSV avec les en-têtes."""
        with open(self.csv_file, "w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(self.CSV_HEADERS)
        logger.info(f"CSV prêt : {self.csv_file}")

    # -------------------------
    # PARSER AIRODUMP
    # -------------------------

    def parse_airodump_csv(self) -> Dict[str, Dict]:
        """Parse le fichier CSV d'airodump-ng."""
        result = {}
        path = str(self.temp_csv) + "-01.csv"

        if not os.path.exists(path):
            return result

        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                rows = list(csv.reader(f))
        except Exception as e:
            logger.error(f"Erreur lors de la lecture du CSV: {e}")
            return result

        in_stations = False

        for row in rows:
            if not row:
                continue

            if row[0].strip() == "Station MAC":
                in_stations = True
                continue

            if not in_stations:
                # Parsing des réseaux
                if len(row) < 14:
                    continue

                bssid = row[0].strip()
                if not self.is_valid_mac(bssid):
                    continue

                essid = row[13].strip() or "<Hidden>"
                result[bssid] = {
                    "essid": essid,
                    "privacy": row[5].strip(),
                    "cipher": row[6].strip(),
                    "auth": row[7].strip(),
                    "channel": row[3].strip(),
                    "signal": row[8].strip(),
                    "clients": 0
                }
            else:
                # Parsing des stations
                if len(row) < 6:
                    continue

                station = row[0].strip()
                net = row[5].strip()

                if self.is_valid_mac(station) and net in result:
                    result[net]["clients"] += 1

        return result

    # -------------------------
    # CSV UPDATE
    # -------------------------

    def update_csv(self, networks: Dict[str, Dict]) -> None:
        """Met à jour le fichier CSV avec les nouveaux réseaux."""
        for bssid, data in networks.items():
            if bssid in self.known_networks:
                continue

            self.known_networks.add(bssid)

            now = datetime.now().strftime("%H:%M:%S")
            essid = data["essid"]
            vendor = self.get_vendor(bssid)
            sec = f"{data['privacy']} {data['cipher']} {data['auth']}".strip()

            with open(self.csv_file, "a", newline="", encoding="utf-8") as f:
                csv.writer(f).writerow([
                    now, essid, bssid, vendor, sec,
                    data["signal"], data["channel"], data["clients"]
                ])

            logger.info(f"[{now}] Nouveau réseau : {essid:30s} | {vendor}")

    # -------------------------
    # SCAN
    # -------------------------

    def scan(self) -> None:
        """Lance le scan WiFi continu."""
        logger.info("Scan WiFi lancé (Ctrl+C pour arrêter)\n")
        self.init_csv()

        while True:
            try:
                self.airodump_process = subprocess.Popen([
                    "airodump-ng",
                    "--band", "abg",
                    "--output-format", "csv",
                    "--write", str(self.temp_csv),
                    "--write-interval", "5",
                    self.monitor_interface
                ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

                self.airodump_process.wait(timeout=self.SCAN_INTERVAL)

            except subprocess.TimeoutExpired:
                self.airodump_process.terminate()

            networks = self.parse_airodump_csv()
            if networks:
                self.update_csv(networks)

            time.sleep(self.SLEEP_INTERVAL)

    # -------------------------
    # CLEANUP
    # -------------------------

    def cleanup(self) -> None:
        """Nettoie les ressources et restaure le système."""
        logger.info("Nettoyage...")

        # Arrête le processus airodump
        if self.airodump_process:
            try:
                self.airodump_process.kill()
            except Exception:
                pass

        # Supprime les fichiers temporaires
        for f in Path.cwd().glob("temp_scan*"):
            try:
                f.unlink(missing_ok=True)
            except Exception as e:
                logger.debug(f"Erreur lors de la suppression de {f}: {e}")

        # Désactive le mode monitor
        if self.monitor_interface:
            self.run_command(["airmon-ng", "stop", self.monitor_interface])
            self.run_command(["systemctl", "restart", "NetworkManager"])

        logger.info("Terminé.")


def main() -> None:
    """Fonction principale."""
    scanner = WiFiAutoScanner()

    scanner.check_root()
    scanner.kill_conflicts()

    if not scanner.find_wireless_interface():
        return

    if not scanner.setup_monitor_mode():
        return

    scanner.scan()


if __name__ == "__main__":
    main()