"""Put finished downloads into the Plex library using Plex's naming convention:

    <library root>/Movie Title (Year)/Movie Title (Year).mkv
    <library root>/Movie Title (Year)/Movie Title (Year).en.srt
"""

from __future__ import annotations

import errno
import logging
import os
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import requests

from .releases import display_name

log = logging.getLogger(__name__)

VIDEO_EXTS = {".mkv", ".mp4", ".avi", ".m4v", ".mov", ".wmv", ".mpg", ".mpeg", ".webm"}
SUB_EXTS = {".srt", ".ass", ".ssa", ".vtt", ".sub", ".idx"}

_LANGS = {
    "english": "en", "eng": "en", "spanish": "es", "spa": "es", "french": "fr", "fre": "fr",
    "german": "de", "ger": "de", "italian": "it", "ita": "it", "portuguese": "pt", "por": "pt",
    "brazilian": "pt-BR", "dutch": "nl", "russian": "ru", "japanese": "ja", "chinese": "zh",
    "korean": "ko", "arabic": "ar", "swedish": "sv", "danish": "da", "norwegian": "no",
    "finnish": "fi", "polish": "pl", "greek": "el", "turkish": "tr", "hebrew": "he",
}
_ISO2 = {v for v in _LANGS.values() if len(v) == 2}


def safe_name(text: str) -> str:
    text = text.replace(":", " -").replace("/", "-").replace("\\", "-")
    text = re.sub(r'[<>"|?*\x00-\x1f]', "", text)
    return re.sub(r"\s+", " ", text).strip(" .")


def folder_name(title: str, year: Optional[int]) -> str:
    return safe_name(display_name(title, year))


def _sub_language(path: Path) -> Optional[str]:
    for token in reversed(re.split(r"[._\-\s]+", path.stem.lower())):
        if token in _LANGS:
            return _LANGS[token]
        if token in _ISO2:
            return token
    return None


@dataclass
class ImportResult:
    dest_dir: Path
    video: Path
    extras: list[Path] = field(default_factory=list)


def already_in_library(root: str, title: str, year: Optional[int]) -> Optional[Path]:
    d = Path(root) / folder_name(title, year)
    if d.is_dir() and any(p.suffix.lower() in VIDEO_EXTS for p in d.iterdir()):
        return d
    return None


def _transfer(src: Path, dst: Path, mode: str) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    if dst.exists():
        dst.unlink()
    if mode == "move":
        shutil.move(str(src), str(dst))
    elif mode == "copy":
        shutil.copy2(src, dst)
    elif mode == "hardlink":
        try:
            os.link(src, dst)
        except OSError as e:
            if e.errno not in (errno.EXDEV, errno.EPERM):
                raise
            log.warning("Hardlink not possible (%s), copying %s instead", e.strerror, src.name)
            shutil.copy2(src, dst)
    else:
        raise ValueError(mode)


def import_files(files: list[Path], root: str, title: str, year: Optional[int],
                 lib_cfg: dict[str, Any]) -> ImportResult:
    """Pick the main video (largest, non-sample) plus subtitles and place them in the library."""
    videos = [f for f in files if f.suffix.lower() in VIDEO_EXTS and "sample" not in f.name.lower()]
    if not videos:
        raise FileNotFoundError("No video file found in download")
    video = max(videos, key=lambda p: p.stat().st_size)

    base = folder_name(title, year)
    dest_dir = Path(root) / base
    mode = lib_cfg["transfer"]

    dest_video = dest_dir / f"{base}{video.suffix.lower()}"
    _transfer(video, dest_video, mode)
    result = ImportResult(dest_dir=dest_dir, video=dest_video)

    used: set[str] = set()
    for sub in sorted(f for f in files if f.suffix.lower() in SUB_EXTS):
        lang = _sub_language(sub)
        stem = f"{base}.{lang}" if lang else base
        candidate, n = f"{stem}{sub.suffix.lower()}", 1
        while candidate in used:
            n += 1
            candidate = f"{stem}.{n}{sub.suffix.lower()}"
        used.add(candidate)
        dest = dest_dir / candidate
        try:
            _transfer(sub, dest, mode)
            result.extras.append(dest)
        except OSError as e:
            log.warning("Could not import subtitle %s: %s", sub, e)

    _apply_modes(dest_dir, [result.video, *result.extras], lib_cfg)
    return result


def _apply_modes(dest_dir: Path, files: list[Path], lib_cfg: dict[str, Any]) -> None:
    try:
        if lib_cfg.get("dir_mode"):
            os.chmod(dest_dir, int(str(lib_cfg["dir_mode"]), 8))
        if lib_cfg.get("file_mode"):
            for f in files:
                os.chmod(f, int(str(lib_cfg["file_mode"]), 8))
    except OSError as e:
        log.warning("chmod failed: %s", e)


def refresh_plex(plex_cfg: dict[str, Any], timeout: float = 30) -> None:
    if not plex_cfg.get("url") or not plex_cfg.get("token"):
        return
    base = plex_cfg["url"].rstrip("/")
    sections = plex_cfg.get("section_ids") or ["all"]
    for sid in sections:
        # Token goes in a header, not the query string, so it never shows up in logged error URLs.
        r = requests.get(f"{base}/library/sections/{sid}/refresh",
                         headers={"X-Plex-Token": plex_cfg["token"]}, timeout=timeout)
        r.raise_for_status()
    log.info("Asked Plex to refresh library section(s): %s", ", ".join(map(str, sections)))
