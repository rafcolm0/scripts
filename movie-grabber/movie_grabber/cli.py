"""Command-line interface.

    movie-grabber run            # daemon: search on schedule, poll downloads
    movie-grabber once           # one check + one search pass (for cron)
    movie-grabber check          # only import finished downloads (qBittorrent hook)
    movie-grabber search "Heat (1995)"   # dry-run: show ranked candidates
    movie-grabber status         # show all titles and their state
    movie-grabber reset "Heat (1995)"    # mark a title as wanted again
    movie-grabber test           # test qBittorrent, sources and email
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from logging.handlers import RotatingFileHandler

from .config import ConfigError, load_config
from .engine import Engine, human_size
from .releases import WantedMovie, parse_wanted_line
from .state import WANTED

DEFAULT_CONFIG = os.environ.get("MOVIE_GRABBER_CONFIG", "~/.config/movie-grabber/config.yaml")


def setup_logging(cfg: dict, verbose: bool) -> None:
    handlers: list[logging.Handler] = [logging.StreamHandler()]
    if cfg.get("log_file"):
        handlers.append(RotatingFileHandler(cfg["log_file"], maxBytes=5_000_000, backupCount=3))
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        handlers=handlers,
    )
    logging.getLogger("urllib3").setLevel(logging.WARNING)


def _parse_title(text: str) -> WantedMovie:
    m = parse_wanted_line(text)
    if not m:
        raise SystemExit(f"Could not parse title: {text!r}")
    return m


def cmd_search(engine: Engine, args) -> int:
    movie = _parse_title(args.title)
    evals = engine.search_title(movie)
    if not evals:
        print("No results from any source.")
        return 1
    shown = [e for e in evals if e.accepted] + ([e for e in evals if not e.accepted] if args.all else [])
    for e in shown[: args.limit]:
        mark = "OK " if e.accepted else "-- "
        print(f"{mark}[{e.result.source_name}] {e.result.name}")
        print(f"     seeders={e.result.seeders} size={human_size(e.result.size)} "
              f"source={e.parsed.source} res={e.parsed.resolution} -> {e.reason}")
    accepted = sum(e.accepted for e in evals)
    print(f"\n{accepted} acceptable of {len(evals)} results."
          + ("" if args.all else " Use --all to see rejected ones."))
    if accepted:
        print(f"Would download: {evals[0].result.name}")
    return 0


def cmd_status(engine: Engine, _args) -> int:
    engine.sync_movies()
    rows = engine.state.all()
    if not rows:
        print("No titles yet. Add some to", engine.cfg["movies_file"])
        return 0
    for r in rows:
        name = f"{r['title']} ({r['year']})" if r["year"] else r["title"]
        detail = r["release_name"] or ""
        if r["status"] == "completed" and r["dest_path"]:
            detail = r["dest_path"]
        if r["error"]:
            detail += f"  [!] {r['error']}"
        print(f"{r['status']:<12} {name:<45} tries={r['attempts']:<3} {detail}")
    last = engine.state.get_meta("last_search_run")
    print(f"\nLast search run: {last or 'never'}")
    return 0


def cmd_reset(engine: Engine, args) -> int:
    movie = _parse_title(args.title)
    row = engine.state.get_by_key(movie.key)
    if not row:
        print(f"{movie.display} is not tracked yet.")
        return 1
    engine.state.update(row["id"], status=WANTED, attempts=0, error=None, info_hash=None,
                        **({"rejected": "[]"} if args.clear_blacklist else {}))
    print(f"{movie.display} is wanted again.")
    return 0


def cmd_test(engine: Engine, args) -> int:
    ok = True
    try:
        print(f"qBittorrent: OK (version {engine.qbit.version()})")
        engine.qbit.ensure_category()
    except Exception as e:
        ok = False
        print(f"qBittorrent: FAILED - {e}")

    probe = WantedMovie("The Matrix", 1999)
    for src in engine.sources:
        try:
            n = len(src.search(probe))
            print(f"Source {src.name}: OK ({n} results for '{probe.display}')")
        except Exception as e:
            ok = False
            print(f"Source {src.name}: FAILED - {e}")

    for name, root in engine.cfg["library"]["roots"].items():
        writable = os.path.isdir(root) and os.access(root, os.W_OK)
        ok &= writable
        print(f"Library '{name}' {root}: {'OK' if writable else 'MISSING or NOT WRITABLE'}")

    if engine.notifier.enabled and not args.no_email:
        sent = engine.notifier.send("movie-grabber test email", "If you can read this, email works.\n")
        ok &= sent
        print(f"Email: {'sent' if sent else 'FAILED (see log)'}")
    return 0 if ok else 1


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="movie-grabber", description="Automatic movie downloader for Plex.")
    p.add_argument("-c", "--config", default=DEFAULT_CONFIG, help=f"config file (default {DEFAULT_CONFIG})")
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="cmd")
    sub.add_parser("run", help="run as a daemon (default)")
    sub.add_parser("once", help="check downloads and search once, then exit")
    sub.add_parser("check", help="only import finished downloads")
    s = sub.add_parser("search", help="dry-run search for one title")
    s.add_argument("title", help='e.g. "The Matrix (1999)"')
    s.add_argument("--all", action="store_true", help="also show rejected results")
    s.add_argument("--limit", type=int, default=25)
    sub.add_parser("status", help="list tracked titles")
    r = sub.add_parser("reset", help="mark a title as wanted again")
    r.add_argument("title")
    r.add_argument("--clear-blacklist", action="store_true")
    t = sub.add_parser("test", help="test qBittorrent, sources, library dirs and email")
    t.add_argument("--no-email", action="store_true")
    args = p.parse_args(argv)

    try:
        cfg = load_config(os.path.expanduser(args.config))
    except ConfigError as e:
        print(f"Config error: {e}", file=sys.stderr)
        return 2
    setup_logging(cfg, args.verbose)
    engine = Engine(cfg)

    cmd = args.cmd or "run"
    if cmd == "run":
        engine.run_forever()
    elif cmd == "once":
        engine.run_once()
    elif cmd == "check":
        with engine.locked():
            engine.check_downloads()
    elif cmd == "search":
        return cmd_search(engine, args)
    elif cmd == "status":
        return cmd_status(engine, args)
    elif cmd == "reset":
        return cmd_reset(engine, args)
    elif cmd == "test":
        return cmd_test(engine, args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
