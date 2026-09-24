"""Configuration loading, defaults and validation."""

from __future__ import annotations

import copy
import os
import re
from pathlib import Path
from typing import Any

import yaml

DEFAULTS: dict[str, Any] = {
    "movies_file": "movies.txt",
    "state_db": "movie-grabber.db",
    "log_file": None,
    "schedule": {
        # "Trigger X times every Y": runs=4, every=1d -> search every 6 hours.
        "runs": 4,
        "every": "1d",
        # How often to poll qBittorrent for finished downloads (daemon mode).
        "check_downloads_every": "5m",
        # Give up on a title after this many unsuccessful searches (0 = never).
        "max_search_attempts": 0,
        # Pause between titles so we don't hammer the sites.
        "delay_between_searches": "3s",
        # A download with no completion after this long is dropped, its release
        # blacklisted, and the title goes back to "wanted" (0 = never).
        "stalled_after": "3d",
    },
    "quality": {
        "resolutions": ["1080p"],
        # Order = preference. "bluray" covers BluRay/BRRip/BDRip,
        # "web" covers WEB-DL/WEBRip/VOD rips (AMZN, NF, iTunes, ...).
        "sources": ["bluray", "web"],
        # Order = preference. Matched as whole words anywhere in the release tags.
        "preferred_groups": ["YTS", "YIFY"],
        "require_preferred_group": True,
        # Preferred-group releases that don't say BluRay/WEB are still accepted
        # (e.g. "Movie (2020) [1080p] [YTS.MX]").
        "accept_untagged_source_from_preferred_groups": True,
        "exclude_keywords": [
            "cam", "hdcam", "camrip", "ts", "hdts", "telesync", "tc", "telecine",
            "scr", "screener", "dvdscr", "r5", "workprint", "hc", "hardcoded",
            "3d", "sample", "trailer",
        ],
        "preferred_codec": None,  # e.g. "x264" or "x265" (tie-breaker only)
        "min_seeders": 3,
        "min_size_gb": 0.4,
        "max_size_gb": 20,
    },
    "sources": [
        {"type": "yts", "name": "YTS", "enabled": True, "base_url": "https://yts.mx"},
    ],
    "qbittorrent": {
        "url": "http://localhost:8080",
        "username": "admin",
        "password": "",
        "category": "movie-grabber",
        "tag": "movie-grabber",
        "save_path": None,  # None = qBittorrent default
        # Map qBittorrent paths to paths on this machine (for Docker setups).
        "path_map": {},
        "verify_ssl": True,
    },
    "library": {
        # Named Plex library roots. Titles go to "default" unless the movies
        # file line ends with "@<name>".
        "roots": {"default": "/srv/media/Movies"},
        "transfer": "move",  # move | copy | hardlink
        # Remove the torrent from qBittorrent after import. Always true for "move".
        "remove_torrent": True,
        "skip_if_in_library": True,
        "file_mode": None,  # e.g. "0664"
        "dir_mode": None,   # e.g. "0775"
    },
    "plex": {
        "url": None,    # e.g. http://localhost:32400 ; enables library refresh
        "token": None,
        "section_ids": [],  # empty = refresh all sections
    },
    "email": {
        "enabled": True,
        "smtp_host": "smtp.gmail.com",
        "smtp_port": 587,
        "security": "starttls",  # starttls | ssl | none
        "username": "",
        "password": "",
        "from": "",
        "to": [],
        "notify_on_added": False,
        "notify_on_failure": True,
    },
    "http": {
        "timeout": 30,
        "user_agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64) movie-grabber/1.0",
    },
}

_DURATION_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*([smhdw]?)\s*$", re.I)
_UNITS = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}


class ConfigError(Exception):
    pass


def parse_duration(value: Any) -> float:
    """Parse "30s", "15m", "6h", "2d", "1w" or a number of seconds."""
    if isinstance(value, (int, float)):
        return float(value)
    m = _DURATION_RE.match(str(value))
    if not m:
        raise ConfigError(f"Invalid duration: {value!r} (use e.g. 30m, 6h, 2d)")
    return float(m.group(1)) * _UNITS[m.group(2).lower()]


def _deep_merge(base: dict, override: dict) -> dict:
    out = copy.deepcopy(base)
    for key, val in (override or {}).items():
        if isinstance(val, dict) and isinstance(out.get(key), dict) and key != "path_map" and key != "roots":
            out[key] = _deep_merge(out[key], val)
        else:
            out[key] = val
    return out


def _expand_env(obj: Any) -> Any:
    """Expand ${VAR} / $VAR in all string values so secrets can live in the environment."""
    if isinstance(obj, str):
        return os.path.expandvars(obj)
    if isinstance(obj, list):
        return [_expand_env(v) for v in obj]
    if isinstance(obj, dict):
        return {k: _expand_env(v) for k, v in obj.items()}
    return obj


def load_config(path: str | os.PathLike) -> dict[str, Any]:
    path = Path(path).expanduser().resolve()
    if not path.exists():
        raise ConfigError(f"Config file not found: {path}")
    with open(path, encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}
    if not isinstance(raw, dict):
        raise ConfigError("Config file must be a YAML mapping")

    cfg = _expand_env(_deep_merge(DEFAULTS, raw))

    # Relative paths are relative to the config file's directory.
    base = path.parent
    for key in ("movies_file", "state_db", "log_file"):
        if cfg.get(key):
            p = Path(cfg[key]).expanduser()
            cfg[key] = str(p if p.is_absolute() else base / p)

    _validate(cfg)
    return cfg


def _validate(cfg: dict[str, Any]) -> None:
    sched = cfg["schedule"]
    if int(sched["runs"]) < 1:
        raise ConfigError("schedule.runs must be >= 1")
    for key in ("every", "check_downloads_every", "delay_between_searches", "stalled_after"):
        parse_duration(sched[key])

    q = cfg["quality"]
    bad = set(q["sources"]) - {"bluray", "web"}
    if bad:
        raise ConfigError(f"quality.sources may only contain 'bluray' and 'web', got {sorted(bad)}")

    lib = cfg["library"]
    if lib["transfer"] not in ("move", "copy", "hardlink"):
        raise ConfigError("library.transfer must be move, copy or hardlink")
    if "default" not in lib["roots"]:
        raise ConfigError("library.roots must define a 'default' library")

    email = cfg["email"]
    if email["enabled"]:
        if isinstance(email["to"], str):
            email["to"] = [email["to"]]
        if not email["to"]:
            raise ConfigError("email.to is required when email is enabled")
        if email["security"] not in ("starttls", "ssl", "none"):
            raise ConfigError("email.security must be starttls, ssl or none")

    for src in cfg["sources"]:
        if src.get("type") not in ("yts", "apibay", "torznab"):
            raise ConfigError(f"Unknown source type: {src.get('type')!r}")
        if src["type"] == "torznab" and not src.get("url"):
            raise ConfigError(f"torznab source {src.get('name')!r} needs a url")


def search_interval(cfg: dict[str, Any]) -> float:
    """Seconds between search runs: `every` divided by `runs`."""
    sched = cfg["schedule"]
    return parse_duration(sched["every"]) / int(sched["runs"])
