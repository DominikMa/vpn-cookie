from __future__ import annotations

from vpn_cookie.browser import PASSWORD_SELECTORS, SUBMIT_SELECTORS, USERNAME_SELECTORS, _click_first, _fill_first


class FakeLocator:
    def __init__(self, page, selector: str):
        self.page = page
        self.selector = selector
        self.first = self

    def count(self):
        return 1 if self.selector in self.page.available_selectors else 0

    def fill(self, value: str):
        self.page.fills.append((self.selector, value))

    def click(self):
        self.page.clicks.append(self.selector)


class FakePage:
    def __init__(self, available_selectors: set[str]):
        self.available_selectors = available_selectors
        self.fills = []
        self.clicks = []

    def locator(self, selector: str):
        return FakeLocator(self, selector)


def test_fill_first_skips_empty_values():
    page = FakePage({USERNAME_SELECTORS[0]})

    assert not _fill_first(page, USERNAME_SELECTORS, "")
    assert not _fill_first(page, PASSWORD_SELECTORS, None)
    assert page.fills == []


def test_submit_only_when_password_was_filled_pattern():
    page = FakePage({USERNAME_SELECTORS[0], PASSWORD_SELECTORS[0], SUBMIT_SELECTORS[0]})

    _fill_first(page, USERNAME_SELECTORS, "alice")
    password_filled = _fill_first(page, PASSWORD_SELECTORS, "secret")
    if password_filled:
        _click_first(page, SUBMIT_SELECTORS)

    assert page.fills == [(USERNAME_SELECTORS[0], "alice"), (PASSWORD_SELECTORS[0], "secret")]
    assert page.clicks == [SUBMIT_SELECTORS[0]]


def test_no_submit_when_password_missing_pattern():
    page = FakePage({USERNAME_SELECTORS[0], PASSWORD_SELECTORS[0], SUBMIT_SELECTORS[0]})

    _fill_first(page, USERNAME_SELECTORS, "alice")
    password_filled = _fill_first(page, PASSWORD_SELECTORS, None)
    if password_filled:
        _click_first(page, SUBMIT_SELECTORS)

    assert page.fills == [(USERNAME_SELECTORS[0], "alice")]
    assert page.clicks == []
