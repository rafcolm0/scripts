"""End-to-end flow with a fake qBittorrent and a fake source (no network)."""

import copy
import os
import tempfile
import unittest
from pathlib import Path

from movie_grabber.config import DEFAULTS
from movie_grabber.engine import Engine
from movie_grabber.qbit import QbitClient
from movie_grabber.releases import SearchResult
from movie_grabber.state import State
from movie_grabber.sources.torznab import parse_torznab

HASH = "0123456789abcdef0123456789abcdef01234567"


class FakeSource:
    name = "fake"

    def __init__(self, results):
        self.results = results
        self.calls = 0

    def search(self, movie):
        self.calls += 1
        return list(self.results)


class FakeQbit(QbitClient):
    def __init__(self, cfg, download_dir):
        super().__init__(cfg)
        self.download_dir = Path(download_dir)
        self.torrents_ = {}
        self.deleted = []

    def ensure_category(self):
        pass

    def add(self, *, url=None, torrent_bytes=None, tags, name="x"):
        self.torrents_[HASH] = {"hash": HASH, "tags": ", ".join(tags), "progress": 0.1, "state": "downloading",
                                "save_path": "/downloads", "name": "Heat.1995.1080p.BluRay.x264-YIFY"}

    def find(self, *, info_hash=None, tag=None):
        return self.torrents_.get(HASH)

    def files(self, info_hash):
        root = self.download_dir / "Heat.1995.1080p.BluRay.x264-YIFY"
        return [{"name": str(p.relative_to(self.download_dir)), "priority": 1}
                for p in root.rglob("*") if p.is_file()]

    def stop(self, info_hash):
        pass

    def delete(self, info_hash, delete_files):
        self.deleted.append((info_hash, delete_files))
        self.torrents_.pop(info_hash, None)


class FakeNotifier:
    enabled = True

    def __init__(self):
        self.sent = []

    def send(self, subject, body):
        self.sent.append((subject, body))
        return True


class EngineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = Path(self.tmp.name)
        self.downloads, self.plex = t / "dl", t / "plex"
        self.downloads.mkdir()
        self.plex.mkdir()
        (t / "movies.txt").write_text("# my list\nHeat (1995)\n")

        cfg = copy.deepcopy(DEFAULTS)
        cfg["movies_file"] = str(t / "movies.txt")
        cfg["state_db"] = str(t / "state.db")
        cfg["schedule"]["delay_between_searches"] = "0s"
        cfg["library"]["roots"] = {"default": str(self.plex)}
        cfg["qbittorrent"]["path_map"] = {"/downloads": str(self.downloads)}
        cfg["email"]["to"] = ["me@example.com"]
        self.cfg = cfg

        self.source = FakeSource([
            SearchResult("Heat.1995.1080p.BluRay.x264-YIFY", "fake", 80, 2 * 1024 ** 3,
                         magnet=f"magnet:?xt=urn:btih:{HASH}", info_hash=HASH),
            SearchResult("Heat.1995.1080p.HDCAM-YIFY", "fake", 999, 2 * 1024 ** 3, magnet="magnet:?x"),
        ])
        self.qbit = FakeQbit(cfg["qbittorrent"], self.downloads)
        self.notifier = FakeNotifier()
        self.engine = Engine(cfg, State(cfg["state_db"]), self.qbit, [self.source], self.notifier)

    def tearDown(self):
        self.engine.state.close()
        self.tmp.cleanup()

    def _finish_download(self):
        rel = self.downloads / "Heat.1995.1080p.BluRay.x264-YIFY"
        (rel / "Subs").mkdir(parents=True)
        (rel / "Heat.1995.1080p.BluRay.x264-YIFY.mp4").write_bytes(b"v" * 5000)
        (rel / "sample.mp4").write_bytes(b"s" * 10)
        (rel / "Subs" / "2_English.srt").write_text("1\n")
        (rel / "Subs" / "3_Spanish.srt").write_text("1\n")
        (rel / "YTSProxies.com.txt").write_text("junk")
        self.qbit.torrents_[HASH].update(progress=1.0, state="stalledUP")

    def test_full_flow(self):
        self.engine.run_once()
        row = self.engine.state.all()[0]
        self.assertEqual(row["status"], "downloading")
        self.assertEqual(row["release_name"], "Heat.1995.1080p.BluRay.x264-YIFY")

        # Still downloading: nothing happens, and no new search while downloading.
        self.engine.run_once()
        self.assertEqual(self.source.calls, 1)
        self.assertEqual(self.engine.state.all()[0]["status"], "downloading")

        self._finish_download()
        self.engine.check_downloads()

        movie_dir = self.plex / "Heat (1995)"
        self.assertEqual(sorted(p.name for p in movie_dir.iterdir()),
                         ["Heat (1995).en.srt", "Heat (1995).es.srt", "Heat (1995).mp4"])
        self.assertEqual(self.engine.state.all()[0]["status"], "completed")
        self.assertEqual(self.qbit.deleted, [(HASH, True)])
        self.assertEqual(len(self.notifier.sent), 1)
        subject, body = self.notifier.sent[0]
        self.assertEqual(subject, "Downloaded: Heat (1995)")
        self.assertIn(str(movie_dir / "Heat (1995).mp4"), body)

        # Completed titles are not searched again.
        self.engine.run_once()
        self.assertEqual(self.source.calls, 1)

    def test_hardlink_keeps_torrent_seeding(self):
        self.cfg["library"].update(transfer="hardlink", remove_torrent=False)
        self.engine.run_once()
        self._finish_download()
        self.engine.check_downloads()
        src = self.downloads / "Heat.1995.1080p.BluRay.x264-YIFY" / "Heat.1995.1080p.BluRay.x264-YIFY.mp4"
        dst = self.plex / "Heat (1995)" / "Heat (1995).mp4"
        self.assertTrue(src.exists() and dst.exists())
        self.assertEqual(os.stat(src).st_ino, os.stat(dst).st_ino)
        self.assertEqual(self.qbit.deleted, [])

    def test_stalled_download_is_blacklisted(self):
        self.cfg["schedule"]["stalled_after"] = "2d"
        self.engine.run_once()
        row_id = self.engine.state.all()[0]["id"]
        self.engine.state.update(row_id, added_at="2020-01-01T00:00:00+00:00")
        self.engine.check_downloads()
        row = self.engine.state.all()[0]
        self.assertEqual(row["status"], "wanted")
        self.assertIn("Heat.1995.1080p.BluRay.x264-YIFY", State.rejected_names(row))
        # Next search finds nothing acceptable (only the blacklisted one and a CAM).
        self.engine.search_run()
        self.assertEqual(self.engine.state.all()[0]["status"], "wanted")

    def test_skips_movies_already_in_library(self):
        (self.plex / "Heat (1995)").mkdir()
        (self.plex / "Heat (1995)" / "Heat (1995).mkv").write_bytes(b"x")
        self.engine.run_once()
        self.assertEqual(self.engine.state.all()[0]["status"], "completed")
        self.assertEqual(self.source.calls, 0)


class TorznabParseTests(unittest.TestCase):
    def test_parse(self):
        xml = b"""<?xml version="1.0"?>
<rss xmlns:torznab="http://torznab.com/schemas/2015/feed"><channel>
<item><title>Heat.1995.1080p.BluRay.x264-YIFY</title><size>2147483648</size>
<link>http://localhost:9117/dl/abc</link>
<torznab:attr name="seeders" value="42"/><torznab:attr name="infohash" value="ABCDEF"/></item>
<item><title>Heat 1995 1080p WEBRip</title><link>magnet:?xt=urn:btih:123</link></item>
</channel></rss>"""
        a, b = parse_torznab(xml, "jackett")
        self.assertEqual((a.seeders, a.size, a.torrent_url, a.magnet, a.info_hash),
                         (42, 2147483648, "http://localhost:9117/dl/abc", None, "abcdef"))
        self.assertEqual((b.magnet, b.torrent_url), ("magnet:?xt=urn:btih:123", None))


if __name__ == "__main__":
    unittest.main()
