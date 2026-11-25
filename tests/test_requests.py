"""Tests for the code / card data / transfer request detector.

All numbers, names and links below are invented.
"""

import pytest

from scam_detector.detectors.requests import TOOL, detect_requests


def ids(message: str) -> set[str]:
    return {s.id for s in detect_requests(message)}


@pytest.mark.parametrize(
    "message",
    [
        # Russian
        "Здравствуйте, служба безопасности банка. Продиктуйте код из СМС для отмены операции.",
        "Пришлите, пожалуйста, код, который сейчас придёт вам на телефон.",
        "Чтобы не потерять деньги, сообщите код подтверждения оператору.",
        "Код из смс скиньте мне сюда, это для розыгрыша",
        # English
        "Hi, this is your bank. Please send us the verification code we just texted you.",
        "Reply with the OTP to confirm your parcel delivery.",
        # Kazakh
        "Сәлеметсіз бе, банк қызметі. SMS-тегі кодты айтыңыз.",
        "Құпия сөзді осы нөмірге жіберіңіз.",
    ],
)
def test_finds_code_requests(message):
    assert "code_request" in ids(message)


@pytest.mark.parametrize(
    "message",
    [
        "Для получения выплаты укажите номер вашей карты и срок действия.",
        "Для зачисления приза нужен CVV код с обратной стороны карты.",
        "To receive the refund, provide your card number and expiry date.",
        "Ұтысты алу үшін карта нөмірін жазыңыз.",
    ],
)
def test_finds_card_data_requests(message):
    assert "card_data_request" in ids(message)


@pytest.mark.parametrize(
    "message",
    [
        "Срочно переведите деньги на безопасный счёт, иначе их украдут.",
        "Вы выиграли iPhone! Оплатите комиссию 2 500 тг за доставку.",
        "Мама, переведите 15000 тенге на этот номер, потом объясню",
        "Your account is at risk. Transfer your funds to a safe account now.",
        "To claim your prize, pay a small fee of $5.",
        "Сыйлықты алу үшін 3000 теңге аударыңыз.",
        "Ақшаңызды қауіпсіз шотқа аударыңыз.",
    ],
)
def test_finds_transfer_requests(message):
    assert "transfer_request" in ids(message)


@pytest.mark.parametrize(
    "message",
    [
        # Real-looking bank notifications: a code plus a warning not to share it.
        "Код подтверждения: 4821. Никому не сообщайте этот код, даже сотрудникам банка.",
        "Ваш код для входа 5530. Не сообщайте его никому.",
        "Your verification code is 739201. Never share this code with anyone.",
        "Do not share your PIN or CVV with anyone, including bank staff.",
        "Растау коды: 6612. Кодты ешкімге айтпаңыз.",
        # Ordinary transaction notices.
        "Покупка 4 590 тг, MAGNUM, карта *1234. Доступно 120 000 тг.",
        "Your transfer of 5000 KZT was received. Thank you.",
        "Введите код 3391 на сайте, чтобы завершить вход.",
        # Everyday messages.
        "Привет! Во сколько завтра пара по статистике?",
        "Мама, я дома, всё хорошо.",
        "",
    ],
)
def test_legitimate_messages_have_no_request_signals(message):
    assert ids(message) == set()


def test_evidence_is_exact_text_from_the_message():
    message = "Добрый день. ПРОДИКТУЙТЕ КОД из смс, пожалуйста."
    [signal] = detect_requests(message)
    assert signal.id == "code_request"
    assert signal.evidence == message[signal.start:signal.end]
    assert signal.evidence.startswith("ПРОДИКТУЙТЕ")
    assert signal.severity == "high"
    assert signal.tool == "detect_requests"


def test_one_message_can_raise_several_signals():
    message = "Сообщите код из СМС и переведите деньги на резервный счёт."
    assert ids(message) == {"code_request", "transfer_request"}


def test_tool_wrapper_ignores_arguments_and_returns_signals():
    signals = TOOL.run("Продиктуйте код из СМС", {})
    assert [s.id for s in signals] == ["code_request"]
    assert TOOL.api_definition()["input_schema"]["properties"] == {}
