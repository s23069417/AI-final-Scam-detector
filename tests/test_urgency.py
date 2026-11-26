"""Tests for the urgency detector. All texts are invented."""

import pytest

from scam_detector.detectors.urgency import TOOL, detect_urgency


def ids(message: str) -> set[str]:
    return {s.id for s in detect_urgency(message)}


@pytest.mark.parametrize(
    "message",
    [
        "Срочно перезвоните в службу безопасности!",
        "Подтвердите данные в течение 30 минут.",
        "Акция только сегодня, успейте забрать приз!",
        "Осталось 2 часа до окончания розыгрыша.",
        "URGENT: verify your account immediately.",
        "Confirm within 24 hours to keep your prize.",
        "Your offer expires today, act now!",
        "Шұғыл түрде банкке хабарласыңыз.",
        "24 сағат ішінде растаңыз.",
        # from Ulzhan's review
        "Тек бүгін!",
        "Бір сағат ішінде растаңыз.",
        "Подтвердите в течение часа.",
        "Please confirm within an hour.",
    ],
)
def test_finds_time_pressure(message):
    assert "urgency_time_pressure" in ids(message)


@pytest.mark.parametrize(
    "message",
    [
        "Ваша карта будет заблокирована, если вы не подтвердите личность.",
        "Подтвердите операцию, иначе счёт будет закрыт.",
        "Последнее предупреждение: против вас возбуждено уголовное дело.",
        "Your account will be suspended unless you verify your details.",
        "Pay the fine, otherwise you will face legal action.",
        "FINAL NOTICE about your parcel.",
        "Сіздің картаңыз бұғатталады.",
        "Растаңыз, әйтпесе шотыңыз бұғатталады.",
        # from Ulzhan's review
        "Картаңыз блокталады.",
        "Сізге қатысты қылмыстық іс қозғалды.",
        "Растаңыз, болмаса шотыңыз жабылады.",
        # "a loan is being taken out in your name"
        "Сіздің атыңызға несие рәсімделуде.",
        "На ваше имя оформляют кредит, срочно свяжитесь с нами.",
        "Someone is applying for a loan in your name.",
    ],
)
def test_finds_threats(message):
    assert "urgency_threat" in ids(message)


@pytest.mark.parametrize(
    "message",
    [
        "Покупка 4 590 тг, MAGNUM, карта *1234.",
        "Код подтверждения: 4821. Никому не сообщайте.",
        "Привет! Встретимся завтра в 10 у входа в университет?",
        "Your order has been shipped and will arrive on Friday.",
        "Сабақ ертең сағат 9-да басталады.",
        # "жедел жәрдем" is the ambulance (false alarm found in Ulzhan's review)
        "Әжем ауырып қалды, жедел жәрдем шақырдық.",
        "",
    ],
)
def test_calm_messages_have_no_urgency(message):
    assert ids(message) == set()


def test_one_message_can_have_both_signals():
    message = "Срочно! Ваш счёт будет заблокирован в течение 2 часов."
    assert ids(message) == {"urgency_time_pressure", "urgency_threat"}


def test_signals_are_medium_and_carry_exact_evidence():
    message = "Внимание. Срочно позвоните."
    [signal] = detect_urgency(message)
    assert signal.severity == "medium"
    assert signal.evidence == "Срочно"
    assert message[signal.start:signal.end] == "Срочно"


def test_tool_wrapper():
    assert [s.id for s in TOOL.run("act now", {})] == ["urgency_time_pressure"]
