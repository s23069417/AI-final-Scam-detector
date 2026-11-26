"""Tests for finding links in a message. All texts and links are invented."""

import pytest

from scam_detector.tools.urls import find_links, host_of

# ---------------------------------------------------------------- finding links


@pytest.mark.parametrize(
    "message, expected_text, expected_host",
    [
        ("Оплатите тут: https://kaspi.kz/pay?id=1", "https://kaspi.kz/pay?id=1", "kaspi.kz"),
        ("Go to http://185.23.4.10/pay now", "http://185.23.4.10/pay", "185.23.4.10"),
        ("Сайт: www.halykbank.kz", "www.halykbank.kz", "www.halykbank.kz"),
        ("Сыйлықты алыңыз kaspi-bonus.kz/prize", "kaspi-bonus.kz/prize", "kaspi-bonus.kz"),
        ("Перейдите bit.ly/3abcXY", "bit.ly/3abcXY", "bit.ly"),
        # Cyrillic "а" inside a Latin-looking domain
        ("Вход: kаspi.kz", "kаspi.kz", "kаspi.kz"),
        ("HTTPS://KASPI.KZ", "HTTPS://KASPI.KZ", "kaspi.kz"),
    ],
)
def test_finds_link_text_and_host(message, expected_text, expected_host):
    [link] = find_links(message)
    assert link.text == expected_text
    assert link.host == expected_host
    assert message[link.start:link.end] == expected_text


@pytest.mark.parametrize(
    "message, expected_text",
    [
        ("Зайдите на kaspi.kz.", "kaspi.kz"),
        ("Подробнее (https://bit.ly/x1)!", "https://bit.ly/x1"),
        ("Сілтеме: «halykbank.kz»", "halykbank.kz"),
        ("Check https://example.com/a, then reply", "https://example.com/a"),
    ],
)
def test_sentence_punctuation_is_not_part_of_the_link(message, expected_text):
    [link] = find_links(message)
    assert link.text == expected_text


def test_finds_several_links_in_order():
    message = "Банк: halykbank.kz, а приз тут: http://halyk-prize.top/get"
    assert [l.host for l in find_links(message)] == ["halykbank.kz", "halyk-prize.top"]


@pytest.mark.parametrize(
    "message",
    [
        "Покупка 4 590.50 тг, MAGNUM, карта *1234.",
        "Код подтверждения: 4821. Никому не сообщайте.",
        "Встретимся завтра, т.е. в субботу.",
        "Пишите на info@kaspi.kz",  # an e-mail address is not a link
        "Сабақ ертең сағат 9.30-да басталады.",
        "",
    ],
)
def test_text_without_links(message):
    assert find_links(message) == []


def test_host_of_works_with_and_without_scheme():
    assert host_of("https://Kaspi.KZ/pay") == "kaspi.kz"
    assert host_of("kaspi.kz/pay") == "kaspi.kz"
    assert host_of("kaspi.kz.") == "kaspi.kz"
