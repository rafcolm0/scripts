#!/usr/bin/env python3
"""
wifi_passive_audit.py

Runs airodump-ng AND wash in passive mode and generates a unified table:

- BSSID
- ESSID
- Channel
- PWR
- Encryption
- Cipher
- Auth
- WPS version
- Locked (Yes/No)
- Status (PENDING / TESTED / FIXED / IGNORE)

NO ACTIVE ATTACKS.

Usage:
    sudo python3 wifi_passive_audit.py -i wlan0mon -d 120 -o scan

Requires:
    - airodump-ng
    - wash (from reaver)
    - python3
"""

import argparse
import csv
import subprocess
import time
import os
from dataclasses import dataclass, field
from typing import Dict, List


# ---------------------------------------------------------
# Data Classes
# ---------------------------------------------------------

@dataclass
class AccessPoint:
    bssid: str
    pwr: int
    channel: str
    essid: str
    privacy: str
    cipher: str
    auth: str
    wps: str = "?"
    locked: str = "?"
    status: str = "PENDING"


# ---------------------------------------------------------
# Helpers
# ---------------------------------------------------------

def run_airodump(interface: str, duration: int, prefix: str) -> str:
    """Run airodump-ng for `duration` sec and save CSV."""
    csv_path = f"{prefix}-01.csv"

    print(f"[+] Running airodump-ng for {duration} seconds...")
    proc = subprocess.Popen(
        ["sudo", "timeout", str(duration),
         "airodump-ng", "--write", prefix, "--output-format", "csv", interface],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    # progress bar
    start = time.time()
    bar_width = 30
    while proc.poll() is None:
        elapsed = int(time.time() - start)
        progress = min(elapsed / duration, 1)
        filled = int(bar_width * progress)
        bar = "#" * filled + "-" * (bar_width - filled)
        print(f"\r[SCAN] |{bar}| {elapsed}/{duration} sec", end="", flush=True)
        if elapsed >= duration:
            break
        time.sleep(1)

    print("\n[+] Finished airodump scan.")
    return csv_path


def parse_airodump_csv(csv_file: str) -> Dict[str, AccessPoint]:
    """Parse APs from airodump CSV."""
    aps = {}

    with open(csv_file, newline="", encoding="utf-8", errors="ignore") as f:
        reader = csv.reader(f)
        in_ap_section = False

        for row in reader:
            if not row:
                continue

            if row[0] == "BSSID":
                in_ap_section = True
                continue

            if in_ap_section:
                if len(row) < 14:
                    continue

                try:
                    bssid = row[0].strip()
                    channel = row[3].strip()
                    privacy = row[5].strip()
                    cipher = row[6].strip()
                    auth = row[7].strip()
                    pwr = row[8].strip()
                    essid = row[13].strip()
                except:
                    continue

                if not bssid or bssid == "Station MAC":
                    break

                pwr = int(pwr) if pwr not in ("", "NA") else -999

                aps[bssid] = AccessPoint(
                    bssid=bssid,
                    pwr=pwr,
                    channel=channel,
                    essid=essid,
                    privacy=privacy,
                    cipher=cipher,
                    auth=auth,
                )

    return aps


def run_wash(interface: str) -> Dict[str, Dict[str, str]]:
    """Run wash and collect WPS + Locked data."""
    print("[+] Running wash (passive WPS scan)...")

    try:
        output = subprocess.check_output(
            ["wash", "-i", interface],
            stderr=subprocess.DEVNULL
        ).decode()
    except:
        print("[!] wash failed or interface busy.")
        return {}

    wps_data = {}

    for line in output.splitlines():
        if ":" not in line or "BSSID" in line:
            continue

        parts = line.split()
        if len(parts) < 6:
            continue

        bssid = parts[0]
        wps_ver = parts[3]
        locked = parts[4]

        wps_data[bssid] = {
            "wps": wps_ver,
            "locked": locked,
        }

    return wps_data


def print_table(aps: List[AccessPoint]):
    """Pretty table."""
    headers = [
        ("#", 3), ("PWR", 4), ("CH", 3),
        ("BSSID", 17), ("ESSID", 20),
        ("ENC", 7), ("CIPH", 6), ("AUTH", 6),
        ("WPS", 5), ("LOCK", 5), ("STATUS", 10),
    ]

    print("\n=== WiFi Passive Audit Table ===")
    print("(sorted by strongest signal)\n")

    # header
    line = "  " + "  ".join(h[0].ljust(h[1]) for h in headers)
    print(line)
    print("  " + "  ".join("-" * h[1] for h in headers))

    for i, ap in enumerate(aps, 1):
        row = [
            str(i).ljust(3),
            str(ap.pwr).ljust(4),
            ap.channel.ljust(3),
            ap.bssid.ljust(17),
            ap.essid[:20].ljust(20),
            ap.privacy.ljust(7),
            ap.cipher.ljust(6),
            ap.auth.ljust(6),
            ap.wps.ljust(5),
            ap.locked.ljust(5),
            ap.status.ljust(10),
        ]
        print("  " + "  ".join(row))


# ---------------------------------------------------------
# Main
# ---------------------------------------------------------

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", required=True)
    parser.add_argument("-d", "--duration", type=int, default=120)
    parser.add_argument("-o", "--output-prefix", default="scan")
    args = parser.parse_args()

    csv_file = run_airodump(args.interface, args.duration, args.output_prefix)
    aps = parse_airodump_csv(csv_file)
    wps_info = run_wash(args.interface)

    # merge WPS + Locked
    for bssid, ap in aps.items():
        if bssid in wps_info:
            ap.wps = wps_info[bssid]["wps"]
            ap.locked = wps_info[bssid]["locked"]

    # Sort strongest first (PWR closer to 0)
    sorted_aps = sorted(aps.values(), key=lambda x: x.pwr, reverse=True)

    print_table(sorted_aps)


if __name__ == "__main__":
    main()
