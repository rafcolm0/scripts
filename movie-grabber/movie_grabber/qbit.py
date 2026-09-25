"""Minimal qBittorrent WebUI API (v2) client."""

from __future__ import annotations

import logging
from pathlib import PurePosixPath
from typing import Any, Optional

import requests

log = logging.getLogger(__name__)

# States where the torrent's data is fully on disk.
COMPLETE_STATES = {"uploading", "stalledUP", "pausedUP", "stoppedUP", "queuedUP", "forcedUP"}
ERROR_STATES = {"error", "missingFiles"}


class QbitError(Exception):
    pass


class QbitClient:
    def __init__(self, cfg: dict[str, Any], timeout: float = 30):
        self.cfg = cfg
        self.base = cfg["url"].rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = cfg.get("verify_ssl", True)
        # qBittorrent's CSRF protection wants a matching Referer/Origin.
        self.session.headers.update({"Referer": self.base, "Origin": self.base})
        self._logged_in = False

    # ------------------------------------------------------------------ core
    def login(self) -> None:
        r = self.session.post(
            f"{self.base}/api/v2/auth/login",
            data={"username": self.cfg["username"], "password": self.cfg["password"]},
            timeout=self.timeout,
        )
        if r.status_code != 200 or r.text.strip() == "Fails.":
            raise QbitError(f"qBittorrent login failed (HTTP {r.status_code}: {r.text.strip()[:100]})")
        self._logged_in = True

    def _request(self, method: str, path: str, **kw) -> requests.Response:
        if not self._logged_in:
            self.login()
        url = f"{self.base}/api/v2/{path}"
        r = self.session.request(method, url, timeout=self.timeout, **kw)
        if r.status_code == 403:  # session expired
            self.login()
            r = self.session.request(method, url, timeout=self.timeout, **kw)
        if r.status_code >= 400:
            raise QbitError(f"{method} {path} -> HTTP {r.status_code}: {r.text.strip()[:200]}")
        return r

    def version(self) -> str:
        return self._request("GET", "app/version").text.strip()

    # ------------------------------------------------------------ torrents
    def ensure_category(self) -> None:
        cat = self.cfg.get("category")
        if not cat:
            return
        existing = self._request("GET", "torrents/categories").json()
        if cat not in existing:
            data = {"category": cat}
            if self.cfg.get("save_path"):
                data["savePath"] = self.cfg["save_path"]
            self._request("POST", "torrents/createCategory", data=data)

    def add(self, *, url: Optional[str] = None, torrent_bytes: Optional[bytes] = None,
            tags: list[str], name: str = "movie.torrent") -> None:
        data: dict[str, Any] = {"tags": ",".join(tags), "paused": "false", "stopped": "false"}
        if self.cfg.get("category"):
            data["category"] = self.cfg["category"]
        if self.cfg.get("save_path"):
            data["savepath"] = self.cfg["save_path"]
        files = None
        if torrent_bytes is not None:
            files = {"torrents": (name, torrent_bytes, "application/x-bittorrent")}
        elif url:
            data["urls"] = url
        else:
            raise ValueError("add() needs url or torrent_bytes")
        r = self._request("POST", "torrents/add", data=data, files=files)
        if r.text.strip() == "Fails.":
            raise QbitError("qBittorrent refused the torrent (duplicate or invalid)")

    def torrents(self, **filters) -> list[dict[str, Any]]:
        return self._request("GET", "torrents/info", params=filters).json()

    def find(self, *, info_hash: Optional[str] = None, tag: Optional[str] = None) -> Optional[dict[str, Any]]:
        if info_hash:
            found = self.torrents(hashes=info_hash.lower())
            if found:
                return found[0]
        if tag:
            # Filter client-side: works on qBittorrent versions without ?tag=.
            filters = {"category": self.cfg["category"]} if self.cfg.get("category") else {}
            for t in self.torrents(**filters):
                if tag in [x.strip() for x in (t.get("tags") or "").split(",")]:
                    return t
        return None

    def add_tags(self, info_hash: str, tags: list[str]) -> None:
        self._request("POST", "torrents/addTags", data={"hashes": info_hash, "tags": ",".join(tags)})

    def files(self, info_hash: str) -> list[dict[str, Any]]:
        return self._request("GET", "torrents/files", params={"hash": info_hash}).json()

    def stop(self, info_hash: str) -> None:
        # qBittorrent 5 renamed pause -> stop.
        try:
            self._request("POST", "torrents/stop", data={"hashes": info_hash})
        except QbitError:
            self._request("POST", "torrents/pause", data={"hashes": info_hash})

    def delete(self, info_hash: str, delete_files: bool) -> None:
        self._request("POST", "torrents/delete",
                      data={"hashes": info_hash, "deleteFiles": "true" if delete_files else "false"})

    # --------------------------------------------------------------- paths
    def local_path(self, remote: str) -> str:
        """Translate a path as qBittorrent sees it into a path on this machine."""
        remote_p = PurePosixPath(remote)
        for src, dst in sorted((self.cfg.get("path_map") or {}).items(), key=lambda kv: -len(kv[0])):
            try:
                rel = remote_p.relative_to(src)
            except ValueError:
                continue
            return str(PurePosixPath(dst) / rel)
        return remote


def is_complete(t: dict[str, Any]) -> bool:
    return float(t.get("progress", 0)) >= 1.0 and t.get("state") in COMPLETE_STATES
