#!/usr/bin/env python3
import subprocess
import re
import time
import os
from datetime import datetime
from collections import defaultdict

class WifiScanner:
    def __init__(self):
        self.networks = defaultdict(dict)
        self.interface = None
        self.is_monitoring = False
        
    def print_banner(self):
        # Couleurs ANSI
        RED = '\033[91m'
        RESET = '\033[0m'
        
        banner_red = f"""{RED}
    ____                          
   / __/______ ____  ___  ___ ____
  _\ \/ __/ _ `/ _ \/ _ \/ -_) __/
 /___/\__/\_,_/_//_/_//_/\__/_/
                    
            Scann Tool by H8Laws
{RESET}"""
        print(banner_red)
    
    def clear_screen(self):
        os.system('clear' if os.name == 'posix' else 'cls')
    
    def get_wifi_interfaces(self):
        try:
            result = subprocess.run(['iwconfig'], capture_output=True, text=True)
            interfaces = re.findall(r'(\w+)\s+IEEE 802.11', result.stdout)
            return interfaces
        except Exception as e:
            print(f"[!] Erreur: {e}")
            return []
    
    def enable_monitor_mode(self, interface):
        try:
            print(f"[*] Activation du mode moniteur sur {interface}...")
            subprocess.run(['ip', 'link', 'set', interface, 'down'], check=True)
            subprocess.run(['iw', 'dev', interface, 'set', 'type', 'monitor'], check=True)
            subprocess.run(['ip', 'link', 'set', interface, 'up'], check=True)
            print(f"[+] Mode moniteur activé sur {interface}")
            self.is_monitoring = True
            return True
        except Exception as e:
            print(f"[!] Erreur lors de l'activation du mode moniteur: {e}")
            return False
    
    def disable_monitor_mode(self, interface):
        try:
            print(f"[*] Désactivation du mode moniteur sur {interface}...")
            subprocess.run(['ip', 'link', 'set', interface, 'down'], check=True)
            subprocess.run(['iw', 'dev', interface, 'set', 'type', 'managed'], check=True)
            subprocess.run(['ip', 'link', 'set', interface, 'up'], check=True)
            print(f"[+] Mode moniteur désactivé")
            self.is_monitoring = False
        except Exception as e:
            print(f"[!] Erreur: {e}")
    
    def scan_networks(self, interface, duration=10):
        try:
            print(f"\n[*] Scan en cours pendant {duration} secondes...")
            result = subprocess.run(
                ['timeout', str(duration), 'airodump-ng', interface],
                capture_output=True,
                text=True,
                timeout=duration + 5
            )
            return result.stdout
        except subprocess.TimeoutExpired:
            print("[!] Timeout du scan")
            return ""
        except Exception as e:
            print(f"[!] Erreur lors du scan: {e}")
            return ""
    
    def parse_networks(self, output):
        networks = []
        lines = output.split('\n')
        in_stations = False
        
        for line in lines:
            if 'BSSID' in line:
                in_stations = False
                continue
            if 'Station MAC' in line:
                in_stations = True
                continue
            if in_stations:
                continue
            
            line = line.strip()
            if not line or line.startswith('('):
                continue
            
            parts = re.split(r'\s+', line)
            if len(parts) >= 7 and re.match(r'([0-9A-Fa-f]{2}:){5}([0-9A-Fa-f]{2})', parts[0]):
                try:
                    bssid = parts[0]
                    power = parts[1]
                    beacons = parts[2]
                    channel = parts[3]
                    encryption = ' '.join(parts[5:7]) if len(parts) > 6 else 'Unknown'
                    essid = ' '.join(parts[8:]) if len(parts) > 8 else '(Hidden)'
                    
                    networks.append({
                        'bssid': bssid,
                        'power': power,
                        'beacons': beacons,
                        'channel': channel,
                        'encryption': encryption,
                        'essid': essid
                    })
                except:
                    continue
        
        return networks
    
    def display_networks(self, networks):
        self.clear_screen()
        self.print_banner()
        
        print(f"\n[*] Mise à jour: {datetime.now().strftime('%H:%M:%S')}")
        print(f"[*] Réseaux détectés: {len(networks)}\n")
        
        header = f"{'BSSID':<18} {'PWR':<6} {'Canal':<8} {'Chiffrement':<20} {'SSID':<30}"
        print("╔" + "═" * (len(header) - 2) + "╗")
        print("║ " + header + " ║")
        print("╠" + "═" * (len(header) - 2) + "╣")
        
        for net in sorted(networks, key=lambda x: int(x['power']), reverse=True):
            bssid = net['bssid']
            power = net['power']
            channel = net['channel']
            encryption = net['encryption'][:18]
            essid = net['essid'][:28]
            
            row = f"{bssid:<18} {power:<6} {channel:<8} {encryption:<20} {essid:<30}"
            print("║ " + row + " ║")
        
        print("╚" + "═" * (len(header) - 2) + "╝")
        print("\n[*] Appuyez sur Ctrl+C pour quitter")
    
    def run_realtime_scan(self, interface, scan_interval=15):
        if not self.enable_monitor_mode(interface):
            return
        
        try:
            while True:
                output = self.scan_networks(interface, duration=scan_interval)
                networks = self.parse_networks(output)
                self.display_networks(networks)
                time.sleep(2)
        
        except KeyboardInterrupt:
            print("\n\n[*] Arrêt du scan...")
            self.disable_monitor_mode(interface)
            print("[+] Scan terminé")
        except Exception as e:
            print(f"[!] Erreur: {e}")
            self.disable_monitor_mode(interface)

def main():
    if os.geteuid() != 0:
        print("[!] Ce script doit être exécuté avec les privilèges root (sudo)")
        exit(1)
    
    scanner = WifiScanner()
    scanner.print_banner()
    
    interfaces = scanner.get_wifi_interfaces()
    
    if not interfaces:
        print("[!] Aucune interface WiFi détectée")
        exit(1)
    
    print(f"\n[*] Interfaces WiFi détectées: {', '.join(interfaces)}\n")
    
    for i, iface in enumerate(interfaces, 1):
        print(f"  {i}. {iface}")
    
    try:
        choice = int(input("\n[?] Choisissez une interface (numéro): ")) - 1
        if 0 <= choice < len(interfaces):
            interface = interfaces[choice]
            scanner.run_realtime_scan(interface, scan_interval=15)
        else:
            print("[!] Choix invalide")
    except ValueError:
        print("[!] Entrée invalide")
    except KeyboardInterrupt:
        print("\n[*] Annulation")

if __name__ == "__main__":
    main()