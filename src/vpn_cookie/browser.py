from __future__ import annotations

import time
from tempfile import TemporaryDirectory
from urllib.parse import urlparse

from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
from playwright.sync_api import sync_playwright

from vpn_cookie.config import AppConfig
from vpn_cookie.errors import BrowserError

USERNAME_SELECTORS = [
    'input[name="username"]',
    'input[name="user"]',
    'input#username',
    'input[type="text"]',
]
PASSWORD_SELECTORS = [
    'input[name="password"]',
    'input#password',
    'input[type="password"]',
]
SUBMIT_SELECTORS = [
    'input[type="submit"]',
    'button[type="submit"]',
    'button:has-text("Login")',
    'button:has-text("Log in")',
    'button:has-text("Anmelden")',
]


def cookie_value(cookies: list[dict], cookie_name: str) -> str | None:
    for cookie in cookies:
        if cookie.get("name") == cookie_name and cookie.get("value"):
            return cookie["value"]
    return None


def _fill_first(page, selectors: list[str], value: str | None) -> bool:
    if not value:
        return False
    for selector in selectors:
        locator = page.locator(selector).first
        try:
            if locator.count():
                locator.fill(value)
                return True
        except PlaywrightTimeoutError:
            continue
    return False


def _click_first(page, selectors: list[str]) -> bool:
    for selector in selectors:
        locator = page.locator(selector).first
        try:
            if locator.count():
                locator.click()
                return True
        except PlaywrightTimeoutError:
            continue
    return False


def login_and_extract_cookie(config: AppConfig, password: str | None = None, timeout_seconds: int = 300) -> str:
    context = None
    try:
        with sync_playwright() as playwright, TemporaryDirectory(prefix="vpn-cookie-chromium-") as user_data_dir:
            launch_args = {
                "headless": False,
                "viewport": {"width": config.browser.width, "height": config.browser.height},
                "user_agent": config.browser.useragent,
                "args": [
                    f"--app={config.vpn_url}",
                    "--window-size=%d,%d" % (config.browser.width, config.browser.height),
                ],
            }
            if not config.browser.useragent:
                launch_args.pop("user_agent")
            if config.browser.executable_path:
                launch_args["executable_path"] = config.browser.executable_path
            context = playwright.chromium.launch_persistent_context(user_data_dir, **launch_args)
            page = context.pages[0] if context.pages else context.new_page()
            if page.url == "about:blank":
                page.goto(config.vpn_url, wait_until="domcontentloaded")
            else:
                page.wait_for_load_state("domcontentloaded")
            _fill_first(page, USERNAME_SELECTORS, config.username)
            password_filled = _fill_first(page, PASSWORD_SELECTORS, password)
            if password_filled:
                _click_first(page, SUBMIT_SELECTORS)

            parsed = urlparse(config.vpn_url)
            urls = [f"{parsed.scheme}://{parsed.netloc}"]
            deadline = time.monotonic() + timeout_seconds
            while time.monotonic() < deadline:
                value = cookie_value(context.cookies(urls), config.cookie_name)
                if value:
                    return value
                page.wait_for_timeout(1000)
            raise BrowserError(
                f"Timed out after {timeout_seconds}s waiting for cookie {config.cookie_name!r} from {parsed.netloc}. "
                "Finish the VPN login in the browser, or increase --timeout."
            )
    except BrowserError:
        raise
    except PlaywrightError as error:
        message = str(error)
        if "closed" in message.lower() or "target page" in message.lower():
            raise BrowserError(
                "Browser was closed before the VPN cookie was available. "
                "Keep the login window open until the cookie has been extracted."
            ) from error
        raise BrowserError(f"Browser automation failed while logging in to {config.vpn_url}: {message}") from error
    finally:
        if context is not None:
            try:
                context.close()
            except PlaywrightError:
                pass
