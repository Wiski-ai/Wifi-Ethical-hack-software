# Improved Interface Detection in ScannreconV5.py

import subprocess
import sys

class Scannrecon:
    def __init__(self):
        self.interfaces = self.get_interfaces()

    def get_interfaces(self):
        interfaces = []
        try:
            # Using nmcli to get the network interfaces
            result = subprocess.run(['nmcli', '-t', '-f', 'INTERFACE', 'device', 'status'], 
                                    capture_output=True, text=True, check=True)
            interfaces = result.stdout.splitlines()
        except subprocess.CalledProcessError as e:
            print(f"Error retrieving interfaces: {e}")
            sys.exit(1)

        if not interfaces:
            print("No interfaces found.")
            sys.exit(1)
        return interfaces

    def interface_details(self, interface):
        try:
            # Improved error handling with iw
            subprocess.run(['iw', interface, 'info'], check=True)
            print(f"{interface} is active.")
        except subprocess.CalledProcessError as e:
            print(f"Error checking interface {interface}: {e}")

    def scan(self):
        for interface in self.interfaces:
            self.interface_details(interface)
            # You can add alternative scanning methods here.

if __name__ == '__main__':
    scanner = Scannrecon()
    scanner.scan()