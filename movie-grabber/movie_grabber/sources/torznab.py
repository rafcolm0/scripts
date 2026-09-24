"""Torznab (Jackett / Prowlarr): gives access to hundreds of torrent sites through one API."""

from __future__ import annotations

import xml.etree.ElementTree as ET

from ..releases import SearchResult, WantedMovie
from . import Source

_TORZNAB_NS = "http://torznab.com/schemas/2015/feed"


class TorznabSource(Source):
    type = "torznab"

    def search(self, movie: WantedMovie) -> list[SearchResult]:
        query = f"{movie.title} {movie.year}" if movie.year else movie.title
        params = {"t": "search", "q": query}
        if self.cfg.get("api_key"):
            params["apikey"] = self.cfg["api_key"]
        cats = self.cfg.get("categories", [2000])
        if cats:
            params["cat"] = ",".join(str(c) for c in cats)

        resp = self.session.get(self.cfg["url"], params=params, timeout=self.timeout)
        resp.raise_for_status()
        return parse_torznab(resp.content, self.name)


def parse_torznab(xml_bytes: bytes, source_name: str) -> list[SearchResult]:
    root = ET.fromstring(xml_bytes)
    if root.tag == "error":
        raise RuntimeError(f"Torznab error {root.get('code')}: {root.get('description')}")

    results = []
    for item in root.iter("item"):
        attrs = {a.get("name"): a.get("value") for a in item.iter(f"{{{_TORZNAB_NS}}}attr")}
        title = (item.findtext("title") or "").strip()
        link = (item.findtext("link") or "").strip()
        enclosure = item.find("enclosure")
        if not link and enclosure is not None:
            link = enclosure.get("url", "")

        size = item.findtext("size") or attrs.get("size") or (enclosure.get("length") if enclosure is not None else 0)
        magnet = attrs.get("magneturl") or (link if link.startswith("magnet:") else None)
        torrent_url = link if link and not link.startswith("magnet:") else None

        results.append(SearchResult(
            name=title,
            source_name=source_name,
            seeders=int(attrs.get("seeders") or 0),
            size=int(size or 0),
            magnet=magnet,
            torrent_url=torrent_url,
            info_hash=(attrs.get("infohash") or "").lower() or None,
        ))
    return results
