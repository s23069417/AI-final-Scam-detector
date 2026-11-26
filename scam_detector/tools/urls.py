"""Finding links in a message (part of the link inspector, no network).

Owner: Ulzhan.

Every link is returned together with its exact position, so a signal can always
point at the link text the user really saw.

A link is one of:
- a full URL:      "https://kaspi.kz/pay", "http://185.23.4.10/x";
- a www address:   "www.halykbank.kz";
- a bare domain:   "kaspi-bonus.kz/prize", "bit.ly/3abc" (only with a known top-level
                   domain, so "т.е." or "4.5" are not taken for links).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit

# Top-level domains we accept for bare domains written without "http://".
# Full URLs ("https://...") are accepted with any top-level domain.
BARE_TLDS = (
    "kz", "ru", "com", "net", "org", "info", "biz", "pro", "su", "uz", "kg",
    "io", "co", "me", "cc", "ly", "gl", "gd", "to", "at", "id",
    "xyz", "top", "click", "online", "site", "icu", "buzz", "live", "shop", "store",
    "link", "vip", "fun", "space", "website", "work", "rest", "cfd", "sbs", "app",
)

# Letters allowed inside a domain label. Cyrillic and Kazakh letters are included on
# purpose: "kаspi.kz" with a Cyrillic "а" is a classic look-alike trick.
_LABEL_CHARS = r"a-z0-9а-яёәғқңөұүһі"
_LABEL = rf"[{_LABEL_CHARS}](?:[{_LABEL_CHARS}-]*[{_LABEL_CHARS}])?"
# Characters a URL can contain after the domain (stops at spaces, quotes, brackets).
_URL_CHAR = r"[^\s<>\"'«»()\[\]]"
_TAIL = _URL_CHAR + "*"

LINK_PATTERN = re.compile(
    r"https?://" + _URL_CHAR + "+"  # full URL with a scheme
    + r"|\bwww\." + _URL_CHAR + "+"  # www.something
    # bare domain: not glued to an e-mail ("info@kaspi.kz") or to another word
    + rf"|(?<![@\w.-])(?:{_LABEL}\.)+(?:{'|'.join(BARE_TLDS)})\b(?:/{_TAIL})?",
    re.IGNORECASE,
)

# Punctuation that usually ends the sentence, not the link: "зайдите на kaspi.kz."
_TRAILING = ".,!?;:'\"»)]}…"


@dataclass(frozen=True)
class Link:
    text: str  # the link exactly as written in the message
    host: str  # lower-case host name, e.g. "kaspi.kz"
    start: int  # character offsets in the original message
    end: int


def host_of(link_text: str) -> str:
    """The lower-case host of a link, with or without "http://" in front."""
    if not re.match(r"https?://", link_text, re.IGNORECASE):
        link_text = "http://" + link_text
    try:
        host = urlsplit(link_text).hostname or ""
    except ValueError:  # e.g. a broken IPv6 address
        return ""
    return host.rstrip(".")


def find_links(message: str) -> list[Link]:
    """Return every link in the message, in order of appearance."""
    links = []
    for m in LINK_PATTERN.finditer(message):
        start, end = m.start(), m.end()
        while end > start and message[end - 1] in _TRAILING:
            end -= 1
        text = message[start:end]
        host = host_of(text)
        if host:
            links.append(Link(text=text, host=host, start=start, end=end))
    return links
