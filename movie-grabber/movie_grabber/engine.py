"""Ties everything together: search, add to qBittorrent, import, notify."""

from __future__ import annotations

import contextlib
import fcntl
import logging
import re
import signal
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator, Optional

from . import library
from .config import parse_duration, search_interval
from .notify import Notifier
from .qbit import ERROR_STATES, QbitClient, QbitError, is_complete
from .releases import Evaluation, SearchResult, WantedMovie, parse_wanted_line, rank
from .sources import Source, build_sources, make_session
from .state import COMPLETED, DOWNLOADING, GAVE_UP, WANTED, State, now_iso, parse_iso

log = logging.getLogger(__name__)

_MAGNET_HASH_RE = re.compile(r"urn:btih:([0-9a-fA-F]{40})")


def human_size(n: Optional[int]) -> str:
    if not n:
        return "unknown size"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024
    return str(n)


def read_movies_file(path: str) -> list[WantedMovie]:
    p = Path(path)
    if not p.exists():
        log.warning("Movies file %s does not exist", p)
        return []
    movies = []
    for line in p.read_text(encoding="utf-8").splitlines():
        m = parse_wanted_line(line)
        if m:
            movies.append(m)
    return movies


class Engine:
    def __init__(self, cfg: dict[str, Any], state: Optional[State] = None,
                 qbit: Optional[QbitClient] = None, sources: Optional[list[Source]] = None,
                 notifier: Optional[Notifier] = None):
        self.cfg = cfg
        self.state = state or State(cfg["state_db"])
        self.qbit = qbit or QbitClient(cfg["qbittorrent"], timeout=float(cfg["http"]["timeout"]))
        self.sources = sources if sources is not None else build_sources(cfg)
        self.notifier = notifier or Notifier(cfg["email"])
        self.http = make_session(cfg["http"])
        self._stop = False

    # ------------------------------------------------------------- locking
    @contextlib.contextmanager
    def locked(self) -> Iterator[None]:
        """Serialize runs (daemon, cron and the qBittorrent hook may overlap)."""
        with open(self.cfg["state_db"] + ".lock", "w") as fh:
            fcntl.flock(fh, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(fh, fcntl.LOCK_UN)

    # ------------------------------------------------------------ searching
    def sync_movies(self) -> list[sqlite3.Row]:
        rows = []
        for m in read_movies_file(self.cfg["movies_file"]):
            if m.library not in self.cfg["library"]["roots"]:
                log.warning("%s: unknown library %r, using 'default'", m.display, m.library)
                m.library = "default"
            rows.append(self.state.upsert_wanted(m.key, m.title, m.year, m.library))
        return rows

    def search_title(self, movie: WantedMovie, rejected: set[str] = frozenset()) -> list[Evaluation]:
        results: list[SearchResult] = []
        for src in self.sources:
            try:
                found = src.search(movie)
                log.debug("%s: %d results from %s", movie.display, len(found), src.name)
                results.extend(found)
            except Exception as e:  # one broken site must not stop the others
                log.warning("Source %s failed for %s: %s", src.name, movie.display, e)
        return rank(results, movie, self.cfg["quality"], rejected)

    def search_run(self) -> None:
        sched = self.cfg["schedule"]
        max_attempts = int(sched["max_search_attempts"])
        delay = parse_duration(sched["delay_between_searches"])
        lib_cfg = self.cfg["library"]

        wanted = [r for r in self.sync_movies() if r["status"] == WANTED]
        log.info("Search run: %d title(s) wanted", len(wanted))
        for i, row in enumerate(wanted):
            if self._stop:
                break
            movie = WantedMovie(row["title"], row["year"], row["library"])

            if lib_cfg["skip_if_in_library"] and movie.year:
                existing = library.already_in_library(lib_cfg["roots"][movie.library], movie.title, movie.year)
                if existing:
                    log.info("%s is already in the library (%s), skipping", movie.display, existing)
                    self.state.update(row["id"], status=COMPLETED, dest_path=str(existing),
                                      completed_at=now_iso(), error=None)
                    continue

            if max_attempts and row["attempts"] >= max_attempts:
                log.info("%s: giving up after %d searches", movie.display, row["attempts"])
                self.state.update(row["id"], status=GAVE_UP)
                continue

            if i:
                time.sleep(delay)
            evals = self.search_title(movie, State.rejected_names(row))
            self.state.update(row["id"], attempts=row["attempts"] + 1, last_search=now_iso())

            best = evals[0] if evals and evals[0].accepted else None
            if not best:
                reasons = {}
                for e in evals:
                    reasons[e.reason] = reasons.get(e.reason, 0) + 1
                summary = "; ".join(f"{n}x {r}" for r, n in sorted(reasons.items(), key=lambda kv: -kv[1])[:4])
                log.info("%s: no acceptable release (%d candidates%s)", movie.display, len(evals),
                         f": {summary}" if summary else "")
                continue

            if not row["year"] and best.parsed.year:
                # Title listed without a year: take it from the release for "Title (Year)" naming.
                self.state.update(row["id"], year=best.parsed.year)
                movie.year = best.parsed.year
            try:
                self._grab(row, movie, best.result)
            except Exception as e:
                log.error("%s: failed to add %r to qBittorrent: %s", movie.display, best.result.name, e)
                self.state.update(row["id"], error=f"add failed: {e}")

        self.state.set_meta("last_search_run", now_iso())

    def _grab(self, row: sqlite3.Row, movie: WantedMovie, res: SearchResult) -> None:
        tag = f"mg-{row['id']}"
        tags = [t for t in (self.cfg["qbittorrent"].get("tag"), tag) if t]
        info_hash = res.info_hash

        try:
            if res.magnet:
                self.qbit.add(url=res.magnet, tags=tags)
            else:
                magnet, data = self._fetch_torrent(res.torrent_url)
                if magnet:
                    m = _MAGNET_HASH_RE.search(magnet)
                    info_hash = info_hash or (m.group(1).lower() if m else None)
                    self.qbit.add(url=magnet, tags=tags)
                else:
                    self.qbit.add(torrent_bytes=data, tags=tags, name=f"{tag}.torrent")
        except QbitError:
            # Maybe it's already in qBittorrent (added by hand): adopt it.
            existing = self.qbit.find(info_hash=info_hash) if info_hash else None
            if not existing:
                raise
            self.qbit.add_tags(existing["hash"], tags)

        log.info("%s: added %r from %s (%d seeders, %s)", movie.display, res.name,
                 res.source_name, res.seeders, human_size(res.size))
        self.state.update(row["id"], status=DOWNLOADING, release_name=res.name, source=res.source_name,
                          size=res.size or None, info_hash=info_hash, added_at=now_iso(), error=None)

        if self.cfg["email"].get("notify_on_added"):
            self.notifier.send(
                f"Downloading: {movie.display}",
                f"Started downloading {movie.display}.\n\nRelease: {res.name}\nSource:  {res.source_name}\n"
                f"Seeders: {res.seeders}\nSize:    {human_size(res.size)}\n",
            )

    def _fetch_torrent(self, url: str) -> tuple[Optional[str], Optional[bytes]]:
        """Download a .torrent ourselves; Jackett/Prowlarr links sometimes redirect to a magnet."""
        for _ in range(5):
            r = self.http.get(url, allow_redirects=False, timeout=float(self.cfg["http"]["timeout"]))
            if r.is_redirect or r.status_code in (301, 302, 303, 307, 308):
                url = r.headers.get("Location", "")
                if url.startswith("magnet:"):
                    return url, None
                continue
            r.raise_for_status()
            return None, r.content
        raise RuntimeError("Too many redirects fetching torrent")

    # ---------------------------------------------------------- downloading
    def check_downloads(self) -> None:
        rows = self.state.by_status(DOWNLOADING)
        if not rows:
            return
        stalled_after = parse_duration(self.cfg["schedule"]["stalled_after"])
        now = datetime.now(timezone.utc)

        for row in rows:
            name = f"{row['title']} ({row['year']})" if row["year"] else row["title"]
            added = parse_iso(row["added_at"]) or now
            try:
                t = self.qbit.find(info_hash=row["info_hash"], tag=f"mg-{row['id']}")
            except (QbitError, OSError) as e:
                log.error("Cannot reach qBittorrent: %s", e)
                return

            if not t:
                if now - added > timedelta(hours=1):
                    log.warning("%s: torrent is gone from qBittorrent, searching again", name)
                    self.state.update(row["id"], status=WANTED, error="torrent removed from qBittorrent")
                continue

            if not row["info_hash"]:
                self.state.update(row["id"], info_hash=t["hash"])

            if t.get("state") in ERROR_STATES:
                self._drop(row, t, name, f"qBittorrent reports state '{t['state']}'")
            elif is_complete(t):
                self._import(row, t, name)
            elif stalled_after and now - added > timedelta(seconds=stalled_after):
                pct = float(t.get("progress", 0)) * 100
                self._drop(row, t, name, f"not finished after {self.cfg['schedule']['stalled_after']} ({pct:.0f}% done)")

    def _drop(self, row: sqlite3.Row, t: dict[str, Any], name: str, why: str) -> None:
        log.warning("%s: dropping %r: %s; will look for another release", name, row["release_name"], why)
        try:
            self.qbit.delete(t["hash"], delete_files=True)
        except QbitError as e:
            log.warning("Could not delete torrent: %s", e)
        self.state.reject_release(row["id"], row["release_name"])
        self.state.update(row["id"], status=WANTED, info_hash=None, error=why)
        if self.cfg["email"].get("notify_on_failure"):
            self.notifier.send(f"Download dropped: {name}",
                               f"Dropped release {row['release_name']}\nReason: {why}\n\n"
                               "It has been blacklisted and another release will be searched for.\n")

    def _import(self, row: sqlite3.Row, t: dict[str, Any], name: str) -> None:
        lib_cfg = self.cfg["library"]
        root = lib_cfg["roots"].get(row["library"]) or lib_cfg["roots"]["default"]
        save_path = Path(self.qbit.local_path(t["save_path"]))
        files = [save_path / f["name"] for f in self.qbit.files(t["hash"]) if f.get("priority", 1) != 0]

        try:
            if lib_cfg["transfer"] == "move":
                self.qbit.stop(t["hash"])  # don't yank files out from under a seeding torrent
            result = library.import_files(files, root, row["title"], row["year"], lib_cfg)
        except Exception as e:
            msg = f"import failed: {e}"
            log.error("%s: %s", name, msg)
            if row["error"] != msg and self.cfg["email"].get("notify_on_failure"):
                self.notifier.send(f"Import failed: {name}",
                                   f"{name} finished downloading but could not be moved into Plex.\n\n"
                                   f"Error: {e}\nFiles: {save_path}\n\nIt will be retried automatically.\n")
            self.state.update(row["id"], error=msg)
            return

        self.state.update(row["id"], status=COMPLETED, completed_at=now_iso(),
                          dest_path=str(result.video), error=None)
        log.info("%s: imported to %s", name, result.video)

        if lib_cfg["transfer"] == "move" or lib_cfg["remove_torrent"]:
            try:
                self.qbit.delete(t["hash"], delete_files=True)
            except QbitError as e:
                log.warning("%s: could not remove torrent from qBittorrent: %s", name, e)

        try:
            library.refresh_plex(self.cfg["plex"])
        except Exception as e:
            log.warning("Plex refresh failed: %s", e)

        added = parse_iso(row["added_at"])
        took = f"{(datetime.now(timezone.utc) - added).total_seconds() / 3600:.1f} h" if added else "?"
        extras = "\n".join(f"  {p.name}" for p in result.extras) or "  (none)"
        self.notifier.send(
            f"Downloaded: {name}",
            f"{name} has been downloaded and added to your Plex library.\n\n"
            f"Release:  {row['release_name']}\n"
            f"Source:   {row['source']}\n"
            f"Size:     {human_size(result.video.stat().st_size)}\n"
            f"Location: {result.video}\n"
            f"Subtitles:\n{extras}\n"
            f"Download time: {took}\n",
        )

    # --------------------------------------------------------------- daemon
    def run_once(self) -> None:
        with self.locked():
            self.check_downloads()
            self.search_run()

    def run_forever(self) -> None:
        interval = search_interval(self.cfg)
        check_every = parse_duration(self.cfg["schedule"]["check_downloads_every"])

        def _stop(signum, _frame):
            log.info("Received signal %s, shutting down", signum)
            self._stop = True

        signal.signal(signal.SIGTERM, _stop)
        signal.signal(signal.SIGINT, _stop)

        last = parse_iso(self.state.get_meta("last_search_run"))
        next_search = last.timestamp() + interval if last else time.time()
        next_check = time.time()
        log.info("Daemon started: searching every %s, checking downloads every %s",
                 timedelta(seconds=int(interval)), timedelta(seconds=int(check_every)))
        try:
            self.qbit.ensure_category()
        except Exception as e:
            log.warning("Could not create qBittorrent category: %s", e)

        while not self._stop:
            now = time.time()
            if now >= next_check:
                try:
                    with self.locked():
                        self.check_downloads()
                except Exception:
                    log.exception("Error while checking downloads; will retry")
                next_check = time.time() + check_every
            if now >= next_search and not self._stop:
                try:
                    with self.locked():
                        self.search_run()
                except Exception:
                    log.exception("Error during search run; will retry next run")
                next_search = time.time() + interval
                log.info("Next search at %s", datetime.fromtimestamp(next_search).strftime("%Y-%m-%d %H:%M"))
            # Sleep in short slices so SIGTERM is handled promptly.
            wake = min(next_check, next_search)
            while not self._stop and time.time() < wake:
                time.sleep(min(5, max(0.0, wake - time.time())))
        log.info("Stopped")
