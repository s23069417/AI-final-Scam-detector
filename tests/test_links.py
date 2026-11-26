"""Tests for the inspect_links tool. All links are invented; no test touches the network."""

import pytest

from scam_detector.agent import default_tools
from scam_detector.tools import links
from scam_detector.tools.links import TOOL, inspect_links
from scam_detector.verdict import rule_floor


def offline(message):
    return {s.id for s in inspect_links(message, resolve=None)}


def with_fake_resolver(message, destinations):
    """Run the inspector with a fake resolver: short link -> final URL."""
    return {s.id for s in inspect_links(message, resolve=destinations.get)}


@pytest.mark.parametrize(
    "message",
    [
        "Kaspi: оплата 5 000 тг принята. Чек: https://kaspi.kz/receipt/123",
        "Halyk: вход в Homebank. Если это не вы, позвоните 7111. homebank.kz",
        "Ваша заявка принята на egov.kz",
        "Ертең сабақ болмайды, кесте: https://narxoz.kz/schedule",
        "Привет! Без ссылок, просто сообщение.",
    ],
)
def test_official_and_ordinary_links_give_no_signal(message):
    assert offline(message) == set()


@pytest.mark.parametrize(
    "message, expected",
    [
        ("Сіздің бонусыңыз: kaspi-bonus.kz/get", {"lookalike_domain"}),
        ("Вход: https://kаspi.kz/login", {"lookalike_domain"}),
        ("Приз: http://halyk-prize.top", {"lookalike_domain", "risky_tld"}),
        ("Оплата: http://185.23.4.10/pay", {"ip_link"}),
        ("Посылка задержана: bit.ly/3abc", {"short_link"}),
        ("Розыгрыш: http://super-prize.xyz", {"risky_tld"}),
    ],
)
def test_suspicious_links(message, expected):
    assert offline(message) == expected


def test_short_link_is_followed_to_a_fake_bank():
    message = "Подтвердите: https://bit.ly/3abc"
    found = with_fake_resolver(message, {"https://bit.ly/3abc": "https://kaspi-bonus.top/in"})
    assert found == {"short_link", "lookalike_domain", "risky_tld"}


def test_short_link_to_an_official_site_is_only_short():
    message = "Kaspi: https://bit.ly/kaspi-app"
    found = with_fake_resolver(message, {"https://bit.ly/kaspi-app": "https://kaspi.kz/app"})
    assert found == {"short_link"}


def test_unreachable_short_link_is_only_short():
    assert with_fake_resolver("bit.ly/3abc", {}) == {"short_link"}


def test_evidence_is_the_link_as_written():
    message = "Срочно! Зайдите на kaspi-bonus.kz/get."
    [signal] = inspect_links(message, resolve=None)
    assert signal.id == "lookalike_domain"
    assert signal.severity == "high"
    assert signal.tool == "inspect_links"
    assert signal.evidence == "kaspi-bonus.kz/get"
    assert message[signal.start:signal.end] == signal.evidence


def test_each_link_gets_its_own_signals():
    message = "Банк: kaspi.kz. Приз: kaspi-bonus.kz. Ещё: bit.ly/x"
    signals = inspect_links(message, resolve=None)
    assert [(s.id, s.evidence) for s in signals] == [
        ("lookalike_domain", "kaspi-bonus.kz"),
        ("short_link", "bit.ly/x"),
    ]


def test_tool_respects_offline_switch(monkeypatch):
    def must_not_be_called(url):
        raise AssertionError("network used while SCAM_LINKS_OFFLINE=1")

    monkeypatch.setattr(links.redirects, "resolve", must_not_be_called)
    monkeypatch.setenv("SCAM_LINKS_OFFLINE", "1")
    assert [s.id for s in TOOL.run("bit.ly/3abc", {})] == ["short_link"]


def test_tool_uses_network_when_allowed(monkeypatch):
    monkeypatch.setattr(links.redirects, "resolve", lambda url: "https://halyk-bonus.kz/")
    monkeypatch.delenv("SCAM_LINKS_OFFLINE", raising=False)
    assert {s.id for s in TOOL.run("bit.ly/3abc", {})} == {"short_link", "lookalike_domain"}


def test_tool_is_registered_in_the_agent():
    assert "inspect_links" in {t.name for t in default_tools()}


# How link signals work together with Gulmira's safety floor (verdict.py).


def test_fake_bank_link_alone_is_at_least_suspicious():
    assert rule_floor(inspect_links("kaspi-bonus.kz", resolve=None)) == "suspicious"


def test_risky_tld_alone_does_not_raise_the_floor():
    assert rule_floor(inspect_links("http://super-prize.xyz", resolve=None)) == "legitimate"
