import unittest
from unittest import mock

from movie_grabber.library import folder_name, refresh_plex


class FolderNameTests(unittest.TestCase):
    def test_plex_naming(self):
        self.assertEqual(folder_name("Dune: Part Two", 2024), "Dune - Part Two (2024)")
        self.assertEqual(folder_name("Heat", None), "Heat")


class RefreshPlexTests(unittest.TestCase):
    @mock.patch("movie_grabber.library.requests.get")
    def test_token_is_sent_as_header_not_in_url(self, get):
        refresh_plex({"url": "http://plex:32400/", "token": "secret", "section_ids": [1]})
        get.assert_called_once_with("http://plex:32400/library/sections/1/refresh",
                                    headers={"X-Plex-Token": "secret"}, timeout=30)

    @mock.patch("movie_grabber.library.requests.get")
    def test_skipped_without_url_or_token(self, get):
        refresh_plex({"url": None, "token": "secret"})
        refresh_plex({"url": "http://plex:32400", "token": None})
        get.assert_not_called()


if __name__ == "__main__":
    unittest.main()
