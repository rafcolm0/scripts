"""The Pirate Bay's JSON API (apibay)."""

from __future__ import annotations

from ..releases import SearchResult, WantedMovie
from . import Source, make_magnet

# 207 = Video > HD Movies
_DEFAULT_CATEGORY = 207


class ApibaySource(Source):
    type = "apibay"

    def search(self, movie: WantedMovie) -> list[SearchResult]:
        base = self.cfg.get("base_url", "https://apibay.org").rstrip("/")
        resp = self.session.get(
            f"{base}/q.php",
            params={"q": movie.query, "cat": self.cfg.get("category", _DEFAULT_CATEGORY)},
            timeout=self.timeout,
        )
        resp.raise_for_status()

        results = []
        for item in resp.json() or []:
            info_hash = item.get("info_hash") or ""
            if item.get("id") in (None, "0") or info_hash.strip("0") == "":
                continue  # "No results returned" placeholder
            results.append(SearchResult(
                name=item.get("name", ""),
                source_name=self.name,
                seeders=int(item.get("seeders") or 0),
                size=int(item.get("size") or 0),
                magnet=make_magnet(info_hash, item.get("name", "")),
                info_hash=info_hash.lower(),
            ))
        return results
