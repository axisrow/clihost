"""Tests for render_menu_page — dashboard title and hapi menu item gating (issue #63)."""
import unittest

from ttydproxy.views import DEFAULT_TITLE, render_menu_page


HAPI_URL = "https://app.hapi.run/?token=abc123"


class TestMenuViews(unittest.TestCase):
    def test_hapi_item_rendered_when_url_present(self):
        page = render_menu_page("hapi", HAPI_URL)
        self.assertIn("HAPI Server", page)
        self.assertIn("href=", page)
        self.assertIn(HAPI_URL, page)

    def test_hapi_item_absent_when_url_missing(self):
        # Without a relay URL the whole menu item must disappear — no link AND no
        # disabled "(not available)" placeholder (regression on the removed stub).
        page = render_menu_page("hapi", None)
        self.assertNotIn("HAPI Server", page)
        self.assertNotIn("not available", page)

    def test_neutral_title_both_branches(self):
        for hapi_url in (HAPI_URL, None):
            with self.subTest(hapi_url=hapi_url):
                page = render_menu_page("hapi", hapi_url)
                self.assertIn(f"<title>{DEFAULT_TITLE}", page)
                self.assertIn(f"<h1>{DEFAULT_TITLE}", page)
                self.assertNotIn("HAPI Dashboard", page)

    def test_username_is_escaped(self):
        page = render_menu_page("<script>alert(1)</script>", None)
        self.assertNotIn("<script>alert(1)</script>", page)
        self.assertIn("&lt;script&gt;", page)


if __name__ == "__main__":
    unittest.main()
