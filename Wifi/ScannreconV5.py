#!/usr/bin/env python3
import os
import sys
import csv
import subprocess
import signal
import time
from datetime import datetime
from pathlib import Path

class WiFiAutoScanner:
    def __init__(self):
        self.csv_file = Path.cwd() / 'wifi_scan_results.csv'
        self.temp_csv = Path.cwd() / 'temp_scan'
        self.interface = None
        self.monitor_interface = None
        self.airodump_process = None
        self.known_networks = set()
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
    
    def signal_handler(self, sig, frame):
        print("\n[*] Arrêt du scan demandé par Ctrl+C.")
        self.cleanup()
        sys.exit(0)

    def check_root(self):
        if os.geteuid() != 0:
            print("[!] Ce script doit être lancé en root (sudo).")
            sys.exit(1)

    def kill_conflicts(self):
        print("[*] Suppression des processus gênants (NetworkManager, wpa_supplicant)...")
        subprocess.run(['airmon-ng', 'check', 'kill'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def find_wireless_interface(self):
        result = subprocess.run(['iwconfig'], capture_output=True, text=True)
        for line in result.stdout.split('\n'):
            if 'IEEE 802.11' in line:
                self.interface = line.split()[0]
                print(f"[+] Interface détectée : {self.interface}")
                return True
        print("[!] Aucune interface WiFi détectée.")
        return False

    def setup_monitor_mode(self):
        print(f"[*] Activation du mode monitor sur {self.interface}...")
        subprocess.run(['airmon-ng', 'start', self.interface], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        result = subprocess.run(['iwconfig'], capture_output=True, text=True)
        for line in result.stdout.split('\n'):
            if "Mode:Monitor" in line:
                self.monitor_interface = line.split()[0]
                print(f"[+] Interface monitor : {self.monitor_interface}")
                return True
        possible = [f"{self.interface}mon", f"{self.interface}0"]
        for cand in possible:
            result = subprocess.run(['iwconfig', cand], capture_output=True, text=True)
            if "Monitor" in result.stdout:
                self.monitor_interface = cand
                print(f"[+] Interface monitor : {self.monitor_interface}")
                return True
        print("[!] Échec de l'activation du mode monitor.")
        return False

    def cleanup(self):
        print("[*] Nettoyage et retour en mode normal...")
        try:
            if self.airodump_process:
                try:
                    self.airodump_process.terminate()
                    self.airodump_process.wait(timeout=2)
                except Exception:
                    self.airodump_process.kill()
        except Exception:
            pass
        try:
            for f in Path.cwd().glob('temp_scan*'):
                f.unlink(missing_ok=True)
        except Exception:
            pass
        if self.monitor_interface:
            subprocess.run(['airmon-ng', 'stop', self.monitor_interface], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print(f"[+] {self.monitor_interface} revenu en mode normal.")
            # >>> Ajout demandé : restart NetworkManager
            subprocess.run(['systemctl', 'restart', 'NetworkManager'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print("[+] NetworkManager relancé.")
        print("[+] Scan terminé.")

    def init_csv(self):
        with open(self.csv_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                'Heure',
                'ESSID',
                'BSSID',
                'Sécurité',
                'Signal',
                'Canal',
                'Clients'
            ])
        print(f"[+] Fichier CSV prêt : {self.csv_file}")

    def is_valid_mac(self, mac):
        import re
        return re.match(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', mac) is not None

    def parse_airodump_csv(self):
        result = {}
        path = str(self.temp_csv) + '-01.csv'

        if not os.path.exists(path):
            return result

        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                reader = csv.reader(f)
                rows = list(reader)
        except Exception:
            return result

        in_stations = False

        for row in rows:
            if not row:
                continue
            if row[0].strip() == "Station MAC":
                in_stations = True
                continue
            if not in_stations:
                if row[0].strip() == "BSSID":
                    continue
                if len(row) < 14:
                    continue
                bssid = row[0].strip()
                if not self.is_valid_mac(bssid):
                    continue
                channel = row[3].strip()
                privacy = row[5].strip()
                cipher = row[6].strip()
                auth = row[7].strip()
                signal = row[8].strip()
                essid = row[13].strip() if len(row) > 13 else ""
                if not essid:
                    essid = "<Hidden>"
                result[bssid] = {
                    "essid": essid,
                    "privacy": privacy,
                    "cipher": cipher,
                    "auth": auth,
                    "channel": channel,
                    "signal": signal,
                    "clients": 0
                }
            else:
                if len(row) < 6:
                    continue
                station_mac = row[0].strip()
                net_bssid = row[5].strip()
                if self.is_valid_mac(station_mac) and net_bssid in result:
                    result[net_bssid]['clients'] += 1
        return result

    def update_csv(self, networks):
        for bssid, data in networks.items():
            now = datetime.now().strftime('%H:%M:%S')
            essid = data['essid']
            sec = f"{data['privacy']} {data['cipher']} {data['auth']}".strip()
            signal = data['signal']
            channel = data['channel']
            clients = data['clients']
            if bssid not in self.known_networks:
                self.known_networks.add(bssid)
                with open(self.csv_file, 'a', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow([now, essid, bssid, sec, signal, channel, clients])
                print(f"[{now}] Nouveau réseau : {essid:35s} / {bssid}")
            else:
                self.update_clients_csv(bssid, clients, now)

    def update_clients_csv(self, bssid, clients, now_time):
        try:
            with open(self.csv_file, 'r', encoding='utf-8') as f:
                rows = list(csv.reader(f))
            for i in range(len(rows)-1, 0, -1):
                if len(rows[i]) >= 7 and rows[i][2] == bssid:
                    rows[i][6] = str(clients)
                    rows[i][0] = now_time
                    break
            with open(self.csv_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerows(rows)
        except Exception:
            pass

    def scan(self):
        print("\n[*] Scan WiFi lancé (Ctrl+C pour arrêter)...")
        print(f"[*] Résultats : {self.csv_file}\n")
        self.init_csv()
        try:
            while True:
                try:
                    self.airodump_process = subprocess.Popen([
                        'airodump-ng',
                        '--output-format', 'csv',
                        '--write', str(self.temp_csv),
                        '--write-interval', '5',
                        self.monitor_interface
                    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    self.airodump_process.wait(timeout=7)
                except subprocess.TimeoutExpired:
                    try:
                        self.airodump_process.terminate()
                    except:
                        pass
                except Exception:
                    pass
                networks = self.parse_airodump_csv()
                if networks:
                    self.update_csv(networks)
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        except Exception:
            pass
        finally:
            self.cleanup()


def main():
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