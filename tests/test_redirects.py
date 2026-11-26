"""Tests for following short links. They never touch the network: a fake
head function plays the role of the servers."""

import socket

from scam_detector.tools.redirects import resolve


def fake_web(routes):
    """A fake head function. `routes` maps a URL to (status, Location)."""
    calls = []

    def head_function(url, timeout):
        calls.append(url)
        if url not in routes:
            raise socket.timeout("no such server in the test")
        return routes[url]

    head_function.calls = calls
    return head_function


def test_follows_redirects_to_the_final_page():
    web = fake_web(
        {
            "https://bit.ly/abc": (301, "https://step.example/x"),
            "https://step.example/x": (302, "https://kaspi-bonus.kz/login"),
            "https://kaspi-bonus.kz/login": (200, None),
        }
    )
    assert resolve("https://bit.ly/abc", head_function=web) == "https://kaspi-bonus.kz/login"
    assert web.calls == [
        "https://bit.ly/abc",
        "https://step.example/x",
        "https://kaspi-bonus.kz/login",
    ]


def test_adds_http_to_a_bare_link():
    web = fake_web({"http://bit.ly/abc": (200, None)})
    assert resolve("bit.ly/abc", head_function=web) == "http://bit.ly/abc"


def test_relative_location():
    web = fake_web(
        {"https://short.example/a": (302, "/login"), "https://short.example/login": (200, None)}
    )
    assert resolve("https://short.example/a", head_function=web) == "https://short.example/login"


def test_network_error_gives_none():
    assert resolve("https://bit.ly/abc", head_function=fake_web({})) is None


def test_redirect_without_location_gives_none():
    web = fake_web({"https://bit.ly/abc": (302, None)})
    assert resolve("https://bit.ly/abc", head_function=web) is None


def test_redirect_loop_stops_after_max_hops():
    web = fake_web({"https://a.example/": (302, "https://a.example/")})
    assert resolve("https://a.example/", head_function=web, max_hops=3) is None
    assert len(web.calls) == 4  # the first request + 3 redirects


def test_does_not_follow_non_web_schemes():
    web = fake_web({"https://bit.ly/abc": (302, "tg://resolve?domain=x")})
    assert resolve("https://bit.ly/abc", head_function=web) is None
    assert web.calls == ["https://bit.ly/abc"]
