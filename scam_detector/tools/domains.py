"""Checks on a single host name (part of the link inspector, no network).

Owner: Ulzhan.

The questions we ask about a host such as "kaspi-bonus.kz":
- is it an official bank or government domain?          is_official()
- does it pretend to be one?                              looks_like_official()
- is it a URL shortener that hides the real address?      is_shortener()
- is it a bare IP address instead of a name?              is_ip_address()
- does it use a top-level domain popular with scammers?   has_risky_tld()
"""

from __future__ import annotations

import ipaddress
from pathlib import Path

OFFICIAL_DOMAINS_FILE = Path(__file__).with_name("official_domains.txt")


def load_official_domains(path: Path = OFFICIAL_DOMAINS_FILE) -> tuple[str, ...]:
    """Read the list of official domains, skipping comments and empty lines."""
    domains = []
    for line in path.read_text(encoding="utf-8").splitlines():
        domain = line.split("#", 1)[0].strip().lower()
        if domain:
            domains.append(domain)
    return tuple(domains)


OFFICIAL_DOMAINS = load_official_domains()

# Brand names that scammers put into fake domains: "kaspi-bonus.kz", "halyk-prize.top".
# Cyrillic spellings are included because domains can be written in Cyrillic.
BRAND_WORDS = (
    "kaspi", "halyk", "homebank", "jusan", "forte", "bereke", "eubank", "otbasy",
    "homecredit", "egov", "каспи", "халык", "халық",
)

# Cyrillic letters that look exactly like Latin ones: "kаspi.kz" with a Cyrillic "а".
HOMOGLYPHS = str.maketrans("аеорсухкіј", "aeopcyxkij")

# Well-known URL shorteners. A short link hides where it really leads.
SHORTENERS = {
    "bit.ly", "tinyurl.com", "clck.ru", "goo.su", "cutt.ly", "t.ly", "is.gd", "u.to",
    "ow.ly", "rebrand.ly", "shorturl.at", "tiny.cc", "rb.gy", "vk.cc", "s.id", "t.co",
}

# Cheap top-level domains often used for one-day scam sites. Informational only.
RISKY_TLDS = {
    "xyz", "top", "click", "online", "site", "icu", "buzz", "live", "shop", "store",
    "link", "vip", "fun", "space", "website", "work", "rest", "cfd", "sbs",
}


def _without_www(host: str) -> str:
    return host[4:] if host.startswith("www.") else host


def is_official(host: str, official: tuple[str, ...] = OFFICIAL_DOMAINS) -> bool:
    """True for an official domain or one of its subdomains."""
    return any(host == d or host.endswith("." + d) for d in official)


def is_ip_address(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def is_shortener(host: str) -> bool:
    return _without_www(host) in SHORTENERS


def has_risky_tld(host: str) -> bool:
    return host.rsplit(".", 1)[-1] in RISKY_TLDS


def site_name(host: str) -> str:
    """The name part of the registered domain: "online.kaspi.kz" -> "kaspi".

    Simplification: we take the label before the last dot. This is right for
    ".kz", ".com", ".top" and similar, which is what we meet in our messages.
    """
    labels = host.split(".")
    return labels[-2] if len(labels) >= 2 else host


def edit_distance(a: str, b: str) -> int:
    """Levenshtein distance: how many single-letter edits turn a into b."""
    previous = list(range(len(b) + 1))
    for i, char_a in enumerate(a, start=1):
        current = [i]
        for j, char_b in enumerate(b, start=1):
            current.append(
                min(
                    previous[j] + 1,  # delete char_a
                    current[j - 1] + 1,  # insert char_b
                    previous[j - 1] + (char_a != char_b),  # replace
                )
            )
        previous = current
    return previous[-1]


def looks_like_official(host: str, official: tuple[str, ...] = OFFICIAL_DOMAINS) -> bool:
    """True if the host pretends to be an official domain but is not one.

    Three tricks are caught:
    1. look-alike letters:   "kаspi.kz" (Cyrillic "а");
    2. a brand in the name:  "kaspi-bonus.kz", "halykbank.kz.secure-login.top";
    3. a typo of the name:   "kaspl.kz", "halykbnk.kz".
    """
    if is_official(host, official) or is_ip_address(host):
        return False

    latin = host.translate(HOMOGLYPHS)
    if latin != host and is_official(latin, official):
        return True  # trick 1

    # Check both spellings: "kаspi-bonus" needs the Latin one, "каспи-бонус" the original.
    if any(brand in latin or brand in host for brand in BRAND_WORDS):
        return True  # trick 2

    name = site_name(latin)
    for domain in official:
        official_name = site_name(domain)
        if len(official_name) < 4:
            continue  # "bcc", "gov": too short, almost any 3-letter name would match
        allowed = 1 if len(official_name) <= 6 else 2
        if 0 < edit_distance(name, official_name) <= allowed:
            return True  # trick 3
    return False
