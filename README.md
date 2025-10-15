# README.md

# WiLabAttack (Example)

**IMPORTANT — AUTHORIZED USE ONLY**

This repository contains tools and scripts intended **only** for legitimate security auditing, research, and educational use in isolated lab environments. You **must** have explicit, written permission from the network or system owner before running any tools in this repository.

The authors and maintainers of this repository **are not liable** for any misuse of the code. By using any code in this repository you agree to assume full responsibility for your actions.

---

## Table of Contents

* [Purpose](#purpose)
* [Disclaimer / Authorization](#disclaimer--authorization)
* [Quick Start (Lab Only)](#quick-start-lab-only)
* [Usage Examples](#usage-examples)
* [Safety & Built-in Protections](#safety--built-in-protections)
* [Installation (Recommended)](#installation-recommended)
* [Testing Environment (HostAPD / VM guidance)](#testing-environment-hostapd--vm-guidance)
* [Contributing](#contributing)
* [Reporting Security Issues](#reporting-security-issues)
* [License](#license)

---

## Purpose

This project provides a toolkit to study Wi‑Fi security techniques and defensive countermeasures. It is intended to be used in controlled, isolated labs (for example with a disposable AP and a dedicated Kali VM). The code may implement scanning, handshake capture, and simulated attack techniques for educational and research use only.

---

## Disclaimer / Authorization

You MUST obtain **explicit written authorization** from the owner of any network or system before testing. Unauthorized testing against networks you do not own or have permission to test is illegal in many jurisdictions.

To reduce risk, tools or commands that can cause disruptions are disabled by default or require explicit flags. See `AUTHORIZATION_TEMPLATE.md` for a simple permission form you can use to document authorization.

---

## Quick Start (Lab only)

1. Create an **isolated lab**: a dedicated VM (Kali), an isolated virtual network or physical disposable AP, and a snapshot before testing.

2. Always begin with a dry-run to see what would happen without sending any frames:

   ```bash
   python wilab.py --dry-run
   ```

3. To run intrusive actions you must specify BOTH flags:

   ```bash
   python wilab.py --i-have-written-permission --target-lab
   ```

   The tool will then prompt you to type a confirmation phrase (e.g. `I HAVE PERMISSION`) before continuing.

4. Keep logs local and do not enable any remote log uploads unless you have explicit consent.

---

## Usage Examples

* `--dry-run` : simulate actions only (no network frames sent).
* `--capture-handshake` : capture WPA/WPA2/3 handshake to local file (requires monitor mode and appropriate permissions).
* `--deauth [--force]` : send deauthentication frames. Requires `--i-have-written-permission` and interactive confirmation; disabled in default builds or in public releases unless `--force` and explicit permission flags present.

*Examples may vary by script. See the tool's in-file `--help` output for full flags.*

---

## Safety & Built-in Protections

To minimize misuse the repository includes the following protections and recommendations:

* **Dry-run mode**: Simulates operations without sending packets.
* **Interactive confirmation**: Requires typing a human confirmation phrase before any disruptive action.
* **Explicit permission flags**: `--i-have-written-permission` and `--target-lab` are required to enable risky operations.
* **No automatic remote logging**: Tools do not phone-home or upload logs by default.
* **Rate limiting for broadcast frames**: When enabled, burst attacks are slowed to minimize collateral impact.
* **Environment checks**: Basic heuristics to detect if the machine is connected to a non-isolated network; if detected, disruptive actions are blocked.

These protections are not a substitute for legal authorization. They are intended to reduce accidental misuse and to document responsible use patterns.

---

## Installation (Recommended)

See `INSTALL.md` for a step-by-step guide to set up a safe, isolated Kali VM and a disposable test access point (hostapd). Always test in an isolated environment.

---

## Testing Environment (HostAPD / VM guidance)

We strongly recommend the following baseline lab setup:

* Host machine (Linux preferred) with virtualization (VirtualBox / VMware / QEMU).
* Create a Kali Linux VM and take a snapshot before any test.
* Use a separate USB Wi‑Fi adapter that supports monitor mode and packet injection for testing. Do not use the host's primary Wi‑Fi adapter in managed mode for attacks.
* Create a disposable AP using `hostapd` or use a cheap physical router set to factory defaults.
* Use host-only/NAT or a dedicated VLAN to ensure no traffic leaks to production networks.

---

## Contributing

Contributions are welcome but must follow these rules:

* All contributions must be designed for lab use only.
* Do not submit exploits, 0‑day code, or instructions to attack production services.
* Avoid including real IPs, SSIDs, credentials, or PII in commits or screenshots.
* Submit a PR with a clear description and include tests demonstrating safe behavior (use `--dry-run`).

See `CONTRIBUTING.md` for more details.

---

## Reporting Security Issues

If you find a vulnerability in this repository, please responsibly disclose it following `SECURITY.md`.

---

## License

This repository uses the MIT license. See `LICENSE` for full text.

---

# SECURITY.md

# Security Policy

## Reporting a Vulnerability

If you discover a security issue, please send an email to [your-email@example.com](mailto:your-email@example.com) with the subject `Security issue: WiLabAttack`. Include:

* A clear description of the issue
* Steps to reproduce (use `--dry-run` if needed)
* Impact assessment and suggested mitigations

We will aim to acknowledge receipt within 48 hours and work with you to remediate.

## Disclosure Policy

* Please do not publish vulnerabilities publicly before a fix is available or without prior coordination.
* We follow a 90-day disclosure timeline by default unless the reporter requests otherwise.

## Safe Reporting

* Do not attach captured material that contains personally identifiable information (PII) or unauthorized handshake captures from third‑party networks.

---

# AUTHORIZATION_TEMPLATE.md

# Authorization for Penetration Testing

I, ___________________ (Owner/Representative), hereby authorize _________________ (Tester) to perform penetration testing and security assessment on the network described below.

* **Network / SSID / Identifier**: ___________________
* **Scope (allowed targets, channels, IP ranges)**: ___________________
* **Date(s) of testing**: ___________________
* **Restrictions**: ___________________
* **Emergency contact / Owner contact**: ___________________

Owner signature: ______________________    Date: _______________

Tester signature: ______________________    Date: _______________

Notes:

* Keep a signed copy of this form before running any offensive tests.
* If possible, include a copy of this form on-site or accessible via an internal ticketing system.

---

# INSTALL.md

# Installation & Lab Setup Guide (Recommended)

This guide walks through a minimal safe lab setup to run the tools in this repository.

## System prerequisites

* Host OS: Linux (recommended) or Windows/macOS with virtualization.
* Virtualization: VirtualBox, VMware, or QEMU.
* Kali Linux VM (latest stable).
* USB Wi‑Fi adapter that supports monitor mode and injection (chipsets: Atheros, Ralink, Realtek variants known to support monitor/injection).

## Steps

1. **Prepare the host**

   * Install your virtualization platform (VirtualBox/VMware/QEMU).
   * Ensure USB passthrough works for your Wi‑Fi adapter.

2. **Create Kali VM**

   * Download Kali ISO from official site.
   * Create a VM with at least 2 vCPUs, 4GB RAM, and a dedicated virtual disk.
   * Add the USB Wi‑Fi adapter to the VM (USB passthrough).
   * Take a snapshot named `clean-base` before installing/testing.

3. **Install dependencies inside Kali**

   ```bash
   sudo apt update && sudo apt install -y python3 python3-pip aircrack-ng hostapd iw
   pip3 install -r requirements.txt  # if a requirements file exists
   ```

4. **Set up a disposable test AP (hostapd)**

   * Create a minimal `hostapd.conf`:

     ```ini
     interface=wlan1
     driver=nl80211
     ssid=WiLabTestAP
     channel=6
     hw_mode=g
     wpa=2
     wpa_passphrase=TestPass123
     ```

   * Start hostapd in a controlled network namespace or a separate test machine.

5. **Test monitor mode**

   ```bash
   sudo ip link set wlan1 down
   sudo iw wlan1 set monitor control
   sudo ip link set wlan1 up
   airodump-ng wlan1
   ```

6. **Run the tool in dry‑run**

   ```bash
   python wilab.py --dry-run
   ```

7. **Run with explicit permission**

   ```bash
   python wilab.py --i-have-written-permission --target-lab
   # tool will prompt for confirmation phrase
   ```

## Cleanup

* Restore the VM snapshot or revert the VM after testing.
* Remove any captured handshake files from shared drives if they contain third‑party network data.

---

# CONTRIBUTING.md

# Contributing Guidelines

Thanks for considering contributing! To keep this project safe and focused on education, please follow these rules:

1. **Lab-only commits**: All new features or tests must support `--dry-run` mode and be safe to review.
2. **No production exploits**: Do not add code or instructions for attacking production infrastructure.
3. **No sensitive data**: Remove any IPs, SSIDs, credentials, or PII before committing.
4. **Testing**: Where applicable, include tests or example outputs using `--dry-run`.
5. **Pull Requests**: Explain the purpose, security considerations, and how the change can be tested in a lab.

---

# CODE_OF_CONDUCT.md

# Contributor Covenant Code of Conduct

All contributors must adhere to the Contributor Covenant. Be respectful, do not harass, and avoid content that encourages illegal activity.

(Include a link to the full contributor covenant or paste the full text here.)

---

# LICENSE

MIT License

Copyright (c) YEAR YourName

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
