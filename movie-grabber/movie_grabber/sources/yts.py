"""YTS / YIFY via its public JSON API."""

from __future__ import annotations

from ..releases import SearchResult, WantedMovie
from . import Source, make_magnet

_TYPE_LABELS = {"bluray": "BluRay", "web": "WEBRip"}


class YtsSource(Source):
    type = "yts"

    def search(self, movie: WantedMovie) -> list[SearchResult]:
        base = self.cfg.get("base_url", "https://yts.mx").rstrip("/")
        resp = self.session.get(
            f"{base}/api/v2/list_movies.json",
            params={"query_term": movie.title, "limit": 50},
            timeout=self.timeout,
        )
        resp.raise_for_status()
        data = resp.json().get("data") or {}

        results = []
        for m in data.get("movies") or []:
            title = m.get("title_english") or m.get("title") or ""
            year = m.get("year")
            for t in m.get("torrents") or []:
                if not t.get("hash"):
                    continue
                # Build a scene-style name so the same filters apply to every source.
                src = _TYPE_LABELS.get((t.get("type") or "").lower(), t.get("type") or "")
                name = f"{title} ({year}) [{t.get('quality')}] [{src}] [{t.get('video_codec') or ''}] [YTS]"
                results.append(SearchResult(
                    name=name,
                    source_name=self.name,
                    seeders=int(t.get("seeds") or 0),
                    size=int(t.get("size_bytes") or 0),
                    magnet=make_magnet(t["hash"], name),
                    info_hash=t["hash"].lower(),
                ))
        return results
