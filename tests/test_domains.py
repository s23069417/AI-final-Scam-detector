"""Tests for the host checks of the link inspector. All domains are invented examples."""

import pytest

from scam_detector.tools.domains import (
    OFFICIAL_DOMAINS,
    edit_distance,
    has_risky_tld,
    is_ip_address,
    is_official,
    is_shortener,
    load_official_domains,
    looks_like_official,
    site_name,
)


def test_official_list_is_loaded_without_comments():
    assert "kaspi.kz" in OFFICIAL_DOMAINS
    assert all("#" not in d and " " not in d and d == d.lower() for d in OFFICIAL_DOMAINS)


def test_load_official_domains_from_a_file(tmp_path):
    path = tmp_path / "domains.txt"
    path.write_text("# comment\n\nExample.KZ   # note\nbank.com\n", encoding="utf-8")
    assert load_official_domains(path) == ("example.kz", "bank.com")


@pytest.mark.parametrize(
    "host",
    [
        "kaspi.kz", "online.kaspi.kz", "www.halykbank.kz", "homebank.kz", "egov.kz",
        # checked by hand on 2026-11-26
        "bank.forte.kz", "berekebank.kz", "bankffin.kz", "online.hcsbk.kz", "otbasybank.kz",
    ],
)
def test_official_hosts(host):
    assert is_official(host)
    assert not looks_like_official(host)


@pytest.mark.parametrize(
    "host",
    [
        "kаspi.kz",  # Cyrillic "а"
        "kaspi-bonus.kz",
        "kaspi.kz.secure-login.top",  # official name at the start, real site at the end
        "halyk-prize.top",
        "my-homebank.online",
        "egov-kz.site",
        "каспи-бонус.kz",
        "kaspl.kz",  # typo
        "halykbnk.kz",  # typo
        "jusam.kz",  # typo
    ],
)
def test_look_alike_hosts(host):
    assert not is_official(host)
    assert looks_like_official(host)


@pytest.mark.parametrize(
    "host", ["example.com", "narxoz.kz", "wildberries.ru", "185.23.4.10", "bit.ly", "bcd.kz"]
)
def test_unrelated_hosts_are_not_look_alikes(host):
    assert not looks_like_official(host)


def test_official_list_can_be_passed_in():
    assert looks_like_official("mybank-bonus.kz", official=("mybank.kz",)) is False
    assert looks_like_official("mybnk.kz", official=("mybank.kz",)) is True


def test_shorteners():
    assert is_shortener("bit.ly")
    assert is_shortener("www.clck.ru")
    assert not is_shortener("kaspi.kz")


def test_ip_addresses():
    assert is_ip_address("185.23.4.10")
    assert is_ip_address("::1")
    assert not is_ip_address("kaspi.kz")


def test_risky_tlds():
    assert has_risky_tld("halyk-prize.top")
    assert not has_risky_tld("kaspi.kz")


def test_site_name():
    assert site_name("online.kaspi.kz") == "kaspi"
    assert site_name("kaspi.kz.secure-login.top") == "secure-login"
    assert site_name("localhost") == "localhost"


@pytest.mark.parametrize(
    "a, b, distance",
    [("kaspi", "kaspi", 0), ("kaspi", "kaspl", 1), ("halykbank", "halykbnk", 1), ("", "abc", 3)],
)
def test_edit_distance(a, b, distance):
    assert edit_distance(a, b) == distance
