import unittest

from movie_grabber.config import DEFAULTS
from movie_grabber.releases import (SearchResult, WantedMovie, evaluate, parse_release,
                                    parse_wanted_line, rank)

Q = dict(DEFAULTS["quality"], preferred_groups=["YTS", "YIFY", "RARBG"])
GB = 1024 ** 3


def res(name, seeders=50, size=2 * GB):
    return SearchResult(name=name, source_name="test", seeders=seeders, size=size, magnet="magnet:?xt=urn:btih:" + "a" * 40)


class ParseReleaseTests(unittest.TestCase):
    def test_scene_name(self):
        p = parse_release("The.Matrix.1999.1080p.BluRay.x264-YIFY")
        self.assertEqual((p.title, p.year, p.resolution, p.source, p.codec),
                         ("the matrix", 1999, "1080p", "bluray", "x264"))

    def test_yts_style_name(self):
        p = parse_release("Dune: Part Two (2024) [1080p] [WEBRip] [5.1] [YTS.MX]")
        self.assertEqual((p.title, p.year, p.resolution, p.source), ("dune part two", 2024, "1080p", "web"))

    def test_numeric_titles(self):
        self.assertEqual(parse_release("1917.2019.1080p.BluRay.x264-YTS").title, "1917")
        p = parse_release("Blade.Runner.2049.2017.1080p.BRRip.x264-RARBG")
        self.assertEqual((p.title, p.year, p.source), ("blade runner 2049", 2017, "bluray"))

    def test_web_variants(self):
        for n in ("Heat 1995 1080p AMZN WEB-DL DDP5.1 H.264-YTS", "Heat.1995.1080p.WEBRip.x265-RARBG",
                  "Heat (1995) 1080p VODRip YIFY"):
            self.assertEqual(parse_release(n).source, "web", n)

    def test_title_words_do_not_count_as_tags(self):
        p = parse_release("Charlottes.Web.1973.1080p.BluRay.x264-YTS")
        self.assertEqual((p.title, p.source), ("charlottes web", "bluray"))


class WantedLineTests(unittest.TestCase):
    def test_variants(self):
        self.assertEqual(parse_wanted_line("The Matrix (1999)"), WantedMovie("The Matrix", 1999))
        self.assertEqual(parse_wanted_line("Frozen [2013] @kids"), WantedMovie("Frozen", 2013, "kids"))
        self.assertEqual(parse_wanted_line("Heat"), WantedMovie("Heat", None))
        self.assertEqual(parse_wanted_line("Heat (1995)  # Michael Mann"), WantedMovie("Heat", 1995))
        self.assertIsNone(parse_wanted_line("# comment"))
        self.assertIsNone(parse_wanted_line("   "))


class EvaluateTests(unittest.TestCase):
    movie = WantedMovie("The Matrix", 1999)

    def check(self, name, accepted, **kw):
        e = evaluate(res(name, **kw), self.movie, Q)
        self.assertEqual(e.accepted, accepted, f"{name}: {e.reason}")
        return e

    def test_accepts_good_releases(self):
        self.check("The.Matrix.1999.1080p.BluRay.x264-YIFY", True)
        self.check("The Matrix (1999) [1080p] [YTS.MX]", True)  # untagged source from preferred group
        self.check("Matrix.1999.1080p.BrRip.x264-YIFY", True)

    def test_rejects(self):
        self.assertIn("resolution", self.check("The.Matrix.1999.720p.BluRay.x264-YIFY", False).reason)
        self.assertIn("resolution", self.check("The.Matrix.1999.2160p.BluRay.x265-YTS", False).reason)
        self.assertIn("preferred group", self.check("The.Matrix.1999.1080p.BluRay.x264-SPARKS", False).reason)
        self.assertIn("excluded", self.check("The.Matrix.1999.1080p.HDCAM.x264-YIFY", False).reason)
        self.assertIn("mismatch", self.check("The.Matrix.Reloaded.2003.1080p.BluRay.x264-YIFY", False).reason)
        self.assertIn("mismatch", self.check("The.Matrix.2021.1080p.BluRay.x264-YIFY", False).reason)
        self.assertIn("seeders", self.check("The.Matrix.1999.1080p.BluRay.x264-YIFY", False, seeders=0).reason)
        self.assertIn("size", self.check("The.Matrix.1999.1080p.BluRay.x264-YIFY", False, size=60 * GB).reason)
        self.assertIn("source", self.check("The.Matrix.1999.1080p.HDTV.x264-YIFY", False).reason)

    def test_dts_audio_is_not_telesync(self):
        self.check("The.Matrix.1999.1080p.BluRay.DTS.x264-YIFY", True)

    def test_blacklist(self):
        name = "The.Matrix.1999.1080p.BluRay.x264-YIFY"
        self.assertFalse(evaluate(res(name), self.movie, Q, {name}).accepted)

    def test_ranking_prefers_group_then_source_then_seeders(self):
        ranked = rank([
            res("The.Matrix.1999.1080p.WEBRip.x264-RARBG", seeders=900),
            res("The.Matrix.1999.1080p.WEBRip.x264-YTS", seeders=10),
            res("The.Matrix.1999.1080p.BluRay.x264-YTS", seeders=5),
            res("The.Matrix.1999.1080p.BluRay.x264-YTS", seeders=40),
            res("The.Matrix.1999.720p.BluRay.x264-YTS", seeders=999),
        ], self.movie, Q)
        self.assertEqual([(e.result.name, e.result.seeders) for e in ranked[:4]], [
            ("The.Matrix.1999.1080p.BluRay.x264-YTS", 40),
            ("The.Matrix.1999.1080p.BluRay.x264-YTS", 5),
            ("The.Matrix.1999.1080p.WEBRip.x264-YTS", 10),
            ("The.Matrix.1999.1080p.WEBRip.x264-RARBG", 900),
        ])
        self.assertFalse(ranked[4].accepted)


if __name__ == "__main__":
    unittest.main()
