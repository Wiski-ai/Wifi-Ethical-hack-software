#!/usr/bin/env python3

import os
import sys
import csv
import subprocess
import signal
import time
from datetime import datetime
from pathlib import Path
import re
from typing import Dict, Set, Optional
import logging
import glob

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)


class WiFiAutoScanner:

    SLEEP_INTERVAL = 1

    CSV_HEADERS = [
        "Heure", "ESSID", "BSSID", "Vendor", "Sécurité",
        "Signal", "Canal", "Clients"
    ]

    def __init__(self):
        self.csv_file = Path.cwd() / "wifi_scan_results.csv"
        self.temp_csv = Path.cwd() / "temp_scan"

        self.interface: Optional[str] = None
        self.monitor_interface: Optional[str] = None
        self.airodump_process: Optional[subprocess.Popen] = None

        self.known_networks: Set[str] = set()
        self.vendor_db: Dict[str, str] = {}

        signal.signal(signal.SIGINT, self.cleanup)



    def run_command(self, cmd):
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def kill_conflicts(self):
        self.run_command(["airmon-ng", "check", "kill"])

    def check_root(self):
        if os.geteuid() != 0:
            print("sudo requis")
            sys.exit(1)



    def find_wireless_interface(self):
        result = subprocess.run(["iw", "dev"], capture_output=True, text=True)

        interfaces = [
            line.split()[1]
            for line in result.stdout.split("\n")
            if line.strip().startswith("Interface")
        ]

        if not interfaces:
            return False

        for i, iface in enumerate(interfaces):
            print(f"{i} : {iface}")

        try:
            choice = int(input("Choix : "))
            self.interface = interfaces[choice]
        except (ValueError, IndexError):
            logger.error("Choix invalide")
            return False

        return True

    def get_monitor_interface(self):
        # Première tentative: iw dev (plus fiable pour type monitor)
        result = subprocess.run(["iw", "dev"], capture_output=True, text=True)
        lines = result.stdout.splitlines()
        for i, line in enumerate(lines):
            line_strip = line.strip()
            if line_strip.startswith("Interface"):
                parts = line_strip.split()
                if len(parts) >= 2:
                    iface = parts[1]
                    # Chercher 'type monitor' dans les lignes indentées suivantes
                    j = i + 1
                    while j < len(lines) and lines[j].startswith("\t"):
                        if "type monitor" in lines[j]:
                            return iface
                        j += 1

        # Fallback: iwconfig (ancien format)
        result2 = subprocess.run(["iwconfig"], capture_output=True, text=True)
        for line in result2.stdout.split("\n"):
            if "Mode:Monitor" in line:
                return line.split()[0]

        return None

    def setup_monitor_mode(self):
        self.run_command(["airmon-ng", "start", self.interface])

        # petit délai pour que l'interface soit créée/renommée
        time.sleep(1)

        self.monitor_interface = self.get_monitor_interface()

        return self.monitor_interface is not None


    def load_vendor_database(self):
        """Charge MACVendors.txt (format IEEE brut)"""

        self.vendor_db = {}

        try:
            with open("MACVendors.txt", "r", encoding="utf-8", errors="ignore") as f:

                current_mac = None

                for line in f:
                    line = line.strip()

                    # Ligne HEX (format principal)
                    if "(hex)" in line:
                        parts = line.split("(hex)")
                        mac = parts[0].strip().upper().replace("-", ":")
                        vendor = parts[1].strip()

                        mac = ":".join(mac.split(":")[:3])

                        self.vendor_db[mac] = vendor
                        current_mac = mac

                    # Fallback base 16 (rarement utile mais on garde)
                    elif "(base 16)" in line and current_mac:
                        continue

            logger.info(f"{len(self.vendor_db)} vendors chargés")

        except Exception as e:
            logger.error(f"Erreur MACVendors: {e}")

    def get_vendor(self, mac: str) -> str:
        # Normaliser et prendre les 3 premiers octets pour la recherche
        if not mac:
            return "Unknown"
        normalized = mac.upper().replace("-", ":")
        normalized = ":".join(normalized.split(":")[:3])
        return self.vendor_db.get(normalized, "Unknown")



    def init_csv(self):
        with open(self.csv_file, "w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(self.CSV_HEADERS)

    def cleanup_temp_files(self):
        """
        Supprime les fichiers temporaires produits par airodump-ng du précédent run,
        pour éviter de relire d'anciens CSV quand on relance le scan.
        Exemples de fichiers: temp_scan-01.csv, temp_scan-01.kismet.csv, temp_scan-01.cap, ...
        """
        base = self.temp_csv.name  # 'temp_scan'
        cwd = Path.cwd()
        patterns = [f"{base}-*", f"{base}*"]
        removed = 0
        for patt in patterns:
            for p in cwd.glob(patt):
                # Sécurité: n'effacer que les fichiers commençant par base
                if p.name.startswith(base):
                    try:
                        if p.is_file():
                            p.unlink()
                            removed += 1
                        else:
                            # pour dossiers éventuels (rare)
                            try:
                                if p.is_dir():
                                    for sub in p.iterdir():
                                        if sub.is_file():
                                            sub.unlink()
                                    p.rmdir()
                                    removed += 1
                            except Exception:
                                pass
                    except Exception as e:
                        logger.debug(f"Impossible de supprimer {p}: {e}")
        if removed:
            logger.info(f"Suppression de {removed} anciens fichiers temporaires '{base}*'")

    def parse_airodump_csv(self) -> Dict[str, Dict]:
        result = {}
        path = str(self.temp_csv) + "-01.csv"

        if not os.path.exists(path) or os.path.getsize(path) == 0:
            return result

        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                rows = list(csv.reader(f))
        except:
            return result

        in_stations = False

        for row in rows:
            if not row:
                continue

            if row[0].strip() == "Station MAC":
                in_stations = True
                continue

            if not in_stations:
                # la section réseaux (BSS)
                if len(row) < 14:
                    continue

                bssid = row[0].strip()

                if not re.match(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', bssid):
                    continue

                result[bssid] = {
                    "essid": row[13].strip() or "<Hidden>",
                    "privacy": row[5].strip(),
                    "cipher": row[6].strip(),
                    "auth": row[7].strip(),
                    "channel": row[3].strip(),
                    "signal": row[8].strip(),
                    "clients": 0
                }

        return result



    def update_csv(self, networks):
        for bssid, data in networks.items():

            if bssid in self.known_networks:
                continue

            self.known_networks.add(bssid)

            now = datetime.now().strftime("%H:%M:%S")
            vendor = self.get_vendor(bssid)

            with open(self.csv_file, "a", newline="", encoding="utf-8") as f:
                csv.writer(f).writerow([
                    now,
                    data["essid"],
                    bssid,
                    vendor,
                    f"{data['privacy']} {data['cipher']} {data['auth']}",
                    data["signal"],
                    data["channel"],
                    data["clients"]
                ])

            print(f"{now} | {data['essid']} | {vendor}")



    def scan(self):

        # réinitialise le csv d'export (écrase l'ancien wifi_scan_results.csv)
        self.init_csv()

        # supprime d'anciens fichiers temporaires pour éviter de relire du vieux CSV
        self.cleanup_temp_files()

        # Lancer airodump-ng
        self.airodump_process = subprocess.Popen([
            "airodump-ng",
            "--band", "abg",
            "--output-format", "csv",
            "--write", str(self.temp_csv),
            self.monitor_interface
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        try:
            while True:
                networks = self.parse_airodump_csv()

                if networks:
                    self.update_csv(networks)

                time.sleep(self.SLEEP_INTERVAL)

        except KeyboardInterrupt:
            pass

        finally:
            self.cleanup()



    def cleanup(self, *args):
        print("\nNettoyage...")

        if self.airodump_process:
            try:
                self.airodump_process.terminate()
                # optionnel : attendre un peu et forcer kill si nécessaire
                time.sleep(0.5)
                if self.airodump_process.poll() is None:
                    self.airodump_process.kill()
            except Exception:
                pass

        if self.monitor_interface:
            self.run_command(["airmon-ng", "stop", self.monitor_interface])

        sys.exit(0)


def main():
    scanner = WiFiAutoScanner()

    scanner.check_root()
    scanner.kill_conflicts()

    if not scanner.find_wireless_interface():
        return

    if not scanner.setup_monitor_mode():
        return

    scanner.load_vendor_database()

    scanner.scan()


if __name__ == "__main__":
    main()
