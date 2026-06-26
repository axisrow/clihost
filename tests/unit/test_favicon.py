"""Tests for favicon assets and template links."""
import unittest

from ttydproxy import assets
from ttydproxy.app import FAVICON_ROUTES
from ttydproxy.views import render_login_page, render_menu_page, render_terminal_page


FAVICON_LINKS = (
    '<link rel="icon" href="/favicon.ico" sizes="any">',
    '<link rel="icon" type="image/png" sizes="16x16" href="/favicon-16x16.png">',
    '<link rel="icon" type="image/png" sizes="32x32" href="/favicon-32x32.png">',
    '<link rel="apple-touch-icon" href="/apple-touch-icon.png">',
)


class TestFavicon(unittest.TestCase):
    def test_favicon_assets_are_loaded(self):
        # The aliases degrade to None when a file is missing (B18); assert they
        # actually loaded first, so a missing asset reads as a clear failure
        # rather than an AttributeError on the .startswith below.
        for name in ("FAVICON_ICO", "FAVICON_16_PNG", "FAVICON_32_PNG", "APPLE_TOUCH_ICON_PNG"):
            self.assertIsNotNone(getattr(assets, name), f"{name} failed to load")
        self.assertTrue(assets.FAVICON_ICO.startswith(b"\x00\x00\x01\x00"))
        self.assertTrue(assets.FAVICON_16_PNG.startswith(b"\x89PNG\r\n\x1a\n"))
        self.assertTrue(assets.FAVICON_32_PNG.startswith(b"\x89PNG\r\n\x1a\n"))
        self.assertTrue(assets.APPLE_TOUCH_ICON_PNG.startswith(b"\x89PNG\r\n\x1a\n"))

    def test_favicon_routes_are_available(self):
        self.assertEqual(FAVICON_ROUTES["/favicon.ico"][0], "image/x-icon")
        self.assertEqual(FAVICON_ROUTES["/favicon-16x16.png"][0], "image/png")
        self.assertEqual(FAVICON_ROUTES["/favicon-32x32.png"][0], "image/png")
        self.assertEqual(FAVICON_ROUTES["/apple-touch-icon.png"][0], "image/png")

    def test_templates_include_favicon_links(self):
        pages = (
            render_login_page("csrf"),
            render_menu_page("hapi", None),
            render_terminal_page(1, "hapi", False),
        )

        for page in pages:
            for link in FAVICON_LINKS:
                with self.subTest(link=link):
                    self.assertIn(link, page)


if __name__ == "__main__":
    unittest.main()
