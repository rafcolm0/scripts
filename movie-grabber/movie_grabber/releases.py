"""Parsing torrent release names and deciding which one to grab."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Optional

_YEAR_RE = re.compile(r"(?<!\d)(19\d{2}|20\d{2})(?!\d)")
_RESOLUTIONS = ("2160p", "1080p", "720p", "576p", "480p")

# Tokens that mark the end of the title part of a release name.
_MARKER_RE = re.compile(
    r"\b(2160p|1080p|720p|576p|480p|4k|uhd|bluray|blu ray|brrip|bdrip|web ?dl|web ?rip|"
    r"hdrip|dvdrip|x264|x265|h264|h265|hevc|remux|yts|yify)\b"
)

_BLURAY_PHRASES = ("bluray", "blu ray", "brrip", "br rip", "bdrip", "bd rip", "bdremux", "bd25", "bd50")
_WEB_PHRASES = (
    "web dl", "webdl", "web rip", "webrip", "web", "vod", "vodrip", "amzn", "nf", "dsnp",
    "hmax", "atvp", "itunes", "pcok", "hulu",
)
# Sources we recognise but never want.
_OTHER_PHRASES = ("hdtv", "pdtv", "sdtv", "tvrip", "hdrip", "dvdrip", "dvd", "dvd5", "dvd9", "satrip", "dvdscr", "ppvrip")
_CODECS = {
    "x264": ("x264", "h264", "avc"),
    "x265": ("x265", "h265", "hevc"),
}


def normalize(text: str) -> str:
    """Lower-case, '&' -> 'and', drop apostrophes, everything else non-alnum -> single space."""
    text = text.lower().replace("&", " and ")
    text = re.sub(r"['’`]", "", text)
    text = re.sub(r"[^a-z0-9]+", " ", text)
    return text.strip()


def has_phrase(haystack_norm: str, phrase: str) -> bool:
    """Whole-word phrase match on already-normalized text."""
    phrase = normalize(phrase)
    return bool(phrase) and f" {phrase} " in f" {haystack_norm} "


@dataclass
class ParsedRelease:
    raw: str
    title: str             # normalized title part
    year: Optional[int]
    tags: str              # normalized text after the title/year
    resolution: Optional[str]
    source: Optional[str]  # "bluray" | "web" | "other" | None
    codec: Optional[str]


def parse_release(name: str) -> ParsedRelease:
    norm = normalize(name)

    marker = _MARKER_RE.search(norm)
    cutoff = marker.start() if marker else len(norm)

    # The release year is the last year-looking number before the quality
    # markers that is not at the very start ("1917 2019 1080p" -> 2019,
    # "Blade Runner 2049 2017 1080p" -> 2017).
    year_match = None
    for m in _YEAR_RE.finditer(norm):
        if 0 < m.start() < cutoff:
            year_match = m
    if year_match:
        title = norm[: year_match.start()].strip()
        tags = norm[year_match.end():].strip()
        year = int(year_match.group(1))
    else:
        title = norm[:cutoff].strip()
        tags = norm[cutoff:].strip()
        year = None

    resolution = next((r for r in _RESOLUTIONS if has_phrase(tags, r)), None)
    if resolution is None and (has_phrase(tags, "4k") or has_phrase(tags, "uhd")):
        resolution = "2160p"

    if any(has_phrase(tags, p) for p in _BLURAY_PHRASES):
        source = "bluray"
    elif any(has_phrase(tags, p) for p in _WEB_PHRASES):
        source = "web"
    elif any(has_phrase(tags, p) for p in _OTHER_PHRASES):
        source = "other"
    else:
        source = None

    codec = next((c for c, aliases in _CODECS.items() if any(has_phrase(tags, a) for a in aliases)), None)

    return ParsedRelease(name, title, year, tags, resolution, source, codec)


@dataclass
class SearchResult:
    """A torrent found by a source."""
    name: str
    source_name: str
    seeders: int = 0
    size: int = 0                      # bytes, 0 if unknown
    magnet: Optional[str] = None
    torrent_url: Optional[str] = None
    info_hash: Optional[str] = None    # lower-case hex, if known

    @property
    def download_ref(self) -> Optional[str]:
        return self.magnet or self.torrent_url


@dataclass
class Evaluation:
    result: SearchResult
    parsed: ParsedRelease
    accepted: bool
    reason: str = ""
    sort_key: tuple = ()


def display_name(title: str, year: Optional[int]) -> str:
    """Format as "Title (Year)", or just the title when the year is unknown."""
    return f"{title} ({year})" if year else title


@dataclass
class WantedMovie:
    title: str
    year: Optional[int] = None
    library: str = "default"

    @property
    def key(self) -> str:
        return f"{normalize(self.title)}|{self.year or ''}"

    @property
    def display(self) -> str:
        return display_name(self.title, self.year)

    @property
    def query(self) -> str:
        """Search string for the torrent sites: "Title Year"."""
        return f"{self.title} {self.year}" if self.year else self.title


_LINE_RE = re.compile(r"^(?P<title>.+?)\s*(?:[(\[](?P<year>(?:19|20)\d{2})[)\]])?\s*(?:@(?P<lib>[\w-]+))?\s*$")


def parse_wanted_line(line: str) -> Optional[WantedMovie]:
    """Parse a movies-file line: ``Title (Year) @library``; year and library are optional."""
    line = line.strip()
    if line.startswith("#"):
        return None
    line = line.split(" #", 1)[0].strip()  # inline comments
    if not line:
        return None
    m = _LINE_RE.match(line)
    if not m:
        return None
    title = m.group("title").strip()
    year = int(m.group("year")) if m.group("year") else None
    return WantedMovie(title=title, year=year, library=m.group("lib") or "default")


def title_matches(wanted: WantedMovie, parsed: ParsedRelease) -> bool:
    def strip_article(t: str) -> str:
        return t[4:] if t.startswith("the ") else t

    # "The Matrix" and "Matrix" are treated as the same title.
    if strip_article(normalize(wanted.title)) != strip_article(parsed.title):
        return False
    # A wanted year must match exactly; a release without a year can't be verified.
    return not wanted.year or parsed.year == wanted.year


def evaluate(result: SearchResult, wanted: WantedMovie, quality: dict[str, Any],
             rejected_names: set[str] = frozenset()) -> Evaluation:
    parsed = parse_release(result.name)

    def reject(reason: str) -> Evaluation:
        return Evaluation(result, parsed, False, reason)

    if result.name in rejected_names:
        return reject("previously failed/blacklisted")
    if not result.download_ref:
        return reject("no magnet or torrent link")
    if not title_matches(wanted, parsed):
        return reject(f"title/year mismatch (parsed {parsed.title!r} {parsed.year})")

    resolutions = [r.lower() for r in quality["resolutions"]]
    if parsed.resolution not in resolutions:
        return reject(f"resolution {parsed.resolution or 'unknown'} not in {resolutions}")

    for kw in quality["exclude_keywords"]:
        if has_phrase(parsed.tags, kw):
            return reject(f"excluded keyword {kw!r}")

    groups = list(quality["preferred_groups"])
    group_idx = next((i for i, g in enumerate(groups) if has_phrase(parsed.tags, g)), None)
    if quality["require_preferred_group"] and group_idx is None:
        return reject("not from a preferred group")

    sources = list(quality["sources"])
    if parsed.source in sources:
        source_rank = len(sources) - sources.index(parsed.source)
    elif parsed.source is None and group_idx is not None and quality["accept_untagged_source_from_preferred_groups"]:
        source_rank = 0
    else:
        return reject(f"source {parsed.source or 'unknown'} not in {sources}")

    if result.seeders < int(quality["min_seeders"]):
        return reject(f"only {result.seeders} seeders")

    if result.size:
        gb = result.size / 1024 ** 3
        if gb < float(quality["min_size_gb"]) or gb > float(quality["max_size_gb"]):
            return reject(f"size {gb:.2f} GB out of range")

    group_rank = len(groups) - group_idx if group_idx is not None else 0
    codec_rank = 1 if quality.get("preferred_codec") and parsed.codec == quality["preferred_codec"] else 0
    sort_key = (group_rank, source_rank, codec_rank, result.seeders)
    return Evaluation(result, parsed, True, "ok", sort_key)


def rank(results: list[SearchResult], wanted: WantedMovie, quality: dict[str, Any],
         rejected_names: set[str] = frozenset()) -> list[Evaluation]:
    """Evaluate all results; accepted ones first, best first."""
    evals = [evaluate(r, wanted, quality, rejected_names) for r in results]
    accepted = sorted((e for e in evals if e.accepted), key=lambda e: e.sort_key, reverse=True)
    rejected = [e for e in evals if not e.accepted]
    return accepted + rejected
