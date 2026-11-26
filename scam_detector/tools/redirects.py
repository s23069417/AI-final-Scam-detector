"""Following a short link to the address it really leads to.

Owner: Ulzhan.

Rule 6 of CLAUDE.md: HEAD requests only. A HEAD request asks the server for the
headers of a page without its body, so we never download or open the page. We
only read the "Location" header of a redirect (HTTP 301, 302, 303, 307, 308) and
follow it, at most MAX_HOPS times.

Any network problem gives None: the inspector then reports only that the link is
short, and the rest of the verdict still works.
"""

from __future__ import annotations

import http.client
from typing import Callable
from urllib.parse import urljoin, urlsplit

MAX_HOPS = 5
TIMEOUT_SECONDS = 3.0
USER_AGENT = "AI-Scam-Detector/1.0 (student project; HEAD requests only)"
REDIRECT_CODES = {301, 302, 303, 307, 308}

# head(url, timeout) -> (status code, Location header or None)
HeadFunction = Callable[[str, float], "tuple[int, str | None]"]


def head(url: str, timeout: float) -> tuple[int, str | None]:
    """Send one HEAD request and return the status code and the Location header."""
    parts = urlsplit(url)
    if parts.scheme == "https":
        connection = http.client.HTTPSConnection(parts.netloc, timeout=timeout)
    else:
        connection = http.client.HTTPConnection(parts.netloc, timeout=timeout)
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    try:
        connection.request("HEAD", path, headers={"User-Agent": USER_AGENT})
        response = connection.getresponse()
        return response.status, response.getheader("Location")
    finally:
        connection.close()


def resolve(
    url: str,
    *,
    head_function: HeadFunction = head,
    max_hops: int = MAX_HOPS,
    timeout: float = TIMEOUT_SECONDS,
) -> str | None:
    """Follow redirects from `url`. Returns the final URL, or None on any failure.

    `head_function` is a parameter so that tests can pass a fake one and never
    touch the network.
    """
    if "://" not in url:
        url = "http://" + url
    for _ in range(max_hops + 1):
        if urlsplit(url).scheme not in ("http", "https"):
            return None  # e.g. "tg://" or "javascript:"; not something we follow
        try:
            status, location = head_function(url, timeout)
        except (OSError, http.client.HTTPException, ValueError):
            return None  # no connection, timeout, broken answer, bad URL
        if status not in REDIRECT_CODES:
            return url  # not a redirect: this is where the link leads
        if not location:
            return None
        url = urljoin(url, location)  # Location may be relative, e.g. "/login"
    return None  # too many redirects
