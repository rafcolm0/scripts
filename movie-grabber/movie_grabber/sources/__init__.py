"""Torrent search sources."""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import quote

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from ..releases import SearchResult, WantedMovie

log = logging.getLogger(__name__)

PUBLIC_TRACKERS = [
    "udp://tracker.opentrackr.org:1337/announce",
    "udp://open.stealth.si:80/announce",
    "udp://tracker.torrent.eu.org:451/announce",
    "udp://exodus.desync.com:6969/announce",
    "udp://tracker.openbittorrent.com:6969/announce",
    "udp://open.demonii.com:1337/announce",
    "udp://explodie.org:6969/announce",
]


def make_magnet(info_hash: str, name: str, trackers: list[str] | None = None) -> str:
    parts = [f"magnet:?xt=urn:btih:{info_hash}", f"dn={quote(name)}"]
    parts += [f"tr={quote(t, safe='')}" for t in (trackers or PUBLIC_TRACKERS)]
    return "&".join(parts)


def make_session(http_cfg: dict[str, Any]) -> requests.Session:
    s = requests.Session()
    s.headers["User-Agent"] = http_cfg["user_agent"]
    # urllib3's default retryable methods already cover GET, the only method these sessions use.
    retry = Retry(total=3, backoff_factor=2, status_forcelist=(429, 500, 502, 503, 504))
    s.mount("http://", HTTPAdapter(max_retries=retry))
    s.mount("https://", HTTPAdapter(max_retries=retry))
    return s


class Source:
    type = "base"

    def __init__(self, cfg: dict[str, Any], session: requests.Session, timeout: float):
        self.cfg = cfg
        self.name = cfg.get("name") or self.type
        self.session = session
        self.timeout = timeout

    def search(self, movie: WantedMovie) -> list[SearchResult]:
        raise NotImplementedError


def build_sources(cfg: dict[str, Any]) -> list[Source]:
    from .apibay import ApibaySource
    from .torznab import TorznabSource
    from .yts import YtsSource

    types = {"yts": YtsSource, "apibay": ApibaySource, "torznab": TorznabSource}
    session = make_session(cfg["http"])
    timeout = float(cfg["http"]["timeout"])
    return [types[s["type"]](s, session, timeout) for s in cfg["sources"] if s.get("enabled", True)]
