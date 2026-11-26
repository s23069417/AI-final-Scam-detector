"""Link and domain inspector: the `inspect_links` tool.

Owner: Ulzhan.

For every link in the message (see urls.py) the inspector reports:

| id               | severity | meaning                                                  |
|------------------|----------|----------------------------------------------------------|
| lookalike_domain | high     | pretends to be a bank or government site but is not one  |
| short_link       | medium   | a URL shortener hides where the link really leads        |
| ip_link          | medium   | a bare IP address instead of a site name                 |
| risky_tld        | low      | a cheap top-level domain popular with scam sites (info)  |

Official domains (kaspi.kz, halykbank.kz, egov.kz, ...) give no signal, so a
real bank SMS with a link to the bank's site is not flagged.

Network use: only for short links, and only HEAD requests (redirects.py). The
short link is followed to its final address and that address is checked too.
Setting the environment variable SCAM_LINKS_OFFLINE=1 turns the network off
(used by the tests and for reproducible evaluation runs).
"""

from __future__ import annotations

import os
from typing import Callable

from scam_detector.signals import NO_ARGUMENTS, Signal, Tool
from scam_detector.tools import redirects
from scam_detector.tools.domains import (
    has_risky_tld,
    is_ip_address,
    is_shortener,
    looks_like_official,
)
from scam_detector.tools.urls import Link, find_links, host_of

TOOL_NAME = "inspect_links"

SEVERITY = {
    "lookalike_domain": "high",
    "short_link": "medium",
    "ip_link": "medium",
    "risky_tld": "low",
}

# resolve(url) -> final URL or None
ResolveFunction = Callable[[str], "str | None"]


def network_allowed() -> bool:
    return os.environ.get("SCAM_LINKS_OFFLINE", "") not in ("1", "true", "yes")


def _host_signal_ids(host: str) -> list[str]:
    """Signal ids for one host, without any network."""
    ids = []
    if looks_like_official(host):
        ids.append("lookalike_domain")
    if is_ip_address(host):
        ids.append("ip_link")
    if has_risky_tld(host):
        ids.append("risky_tld")
    return ids


def _link_signal_ids(link: Link, resolve: ResolveFunction | None) -> list[str]:
    """Signal ids for one link. `resolve` is None when the network is off."""
    ids = _host_signal_ids(link.host)
    if is_shortener(link.host):
        ids.append("short_link")
        final_url = resolve(link.text) if resolve is not None else None
        if final_url is not None:
            # Where the short link really leads: "bit.ly/x" -> "kaspi-bonus.kz".
            ids += _host_signal_ids(host_of(final_url))
    return list(dict.fromkeys(ids))  # drop repeats, keep order


def inspect_links(
    message: str, *, resolve: ResolveFunction | None = redirects.resolve
) -> list[Signal]:
    """Return link signals for the message. Pass resolve=None to stay offline."""
    signals = []
    for link in find_links(message):
        for signal_id in _link_signal_ids(link, resolve):
            signals.append(
                Signal(
                    id=signal_id,
                    tool=TOOL_NAME,
                    severity=SEVERITY[signal_id],
                    evidence=link.text,  # always the link as the user saw it
                    start=link.start,
                    end=link.end,
                )
            )
    return signals


def _run(message: str, _tool_input: dict) -> list[Signal]:
    return inspect_links(message, resolve=redirects.resolve if network_allowed() else None)


TOOL = Tool(
    name=TOOL_NAME,
    description=(
        "Checks every link in the message under analysis. Reports lookalike_domain when a "
        "domain pretends to be a Kazakhstan bank or government site but is not on the "
        "official list (e.g. 'kaspi-bonus.kz', 'kаspi.kz' with a Cyrillic letter), "
        "short_link for URL shorteners such as bit.ly (they are followed with HEAD requests "
        "and the final address is checked too), ip_link for a bare IP address, and risky_tld "
        "(informational) for cheap domains like .xyz or .top. Links to official domains such "
        "as kaspi.kz give no signal. Takes no arguments. Returns a JSON list of signals with "
        "the exact link text as evidence."
    ),
    input_schema=NO_ARGUMENTS,
    run=_run,
)
