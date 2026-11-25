"""Detector of requests for codes, card data and money transfers.

Owner: Gulmira. Languages: Russian, Kazakh, English.

The detector looks for a *request* addressed to the reader ("продиктуйте код"),
not for the mere presence of a code. Real bank notifications often contain a
code together with a warning ("Ваш код 4821. Никому не сообщайте"), and those
must not raise a signal; see `is_negated` in `_match.py`.
"""

from __future__ import annotations

from scam_detector.detectors._match import SEP, compile_all, find_signals, gap
from scam_detector.signals import NO_ARGUMENTS, Signal, Tool

TOOL_NAME = "detect_requests"

# --- verbs ------------------------------------------------------------------
# Russian polite imperatives: "tell / dictate / send me ...".
# "введите" (enter) is left out on purpose: "введите код на сайте" is how
# legitimate one-time-password messages are worded.
RU_SHARE = (
    r"\b(?:сообщите|назовите|продиктуйте|скажите|отправьте|пришлите|перешлите|"
    r"скиньте|напишите|укажите|подтвердите|отправить|сообщить|назвать|продиктовать)\b"
)
EN_SHARE = (
    r"\b(?:send|share|tell|give|provide|forward|text|read\s+out|reply\s+with|"
    r"confirm|verify|tell\s+us)\b"
)
# Kazakh imperatives come after the object: "кодты айтыңыз".
# Negative forms ("айтпаңыз", "жібермеңіз") do not match these stems.
KK_SHARE = (
    r"(?:айтыңыз|атаңыз|айтып\s+жіберіңіз|жіберіңіз|жіберсеңіз|хабарлаңыз|беріңіз|"
    r"жазыңыз|көрсетіңіз|растаңыз|айтасыз\s+ба)"
)

# --- objects ----------------------------------------------------------------
RU_CODE = r"(?:код\w*|пароль\w*|пин-?код\w*|\bпин\b|cvv2?|cvc2?|смс-?код\w*)"
EN_CODE = (
    r"(?:\bcode\b|\bcodes\b|\botp\b|\bpin\b|password|passcode|cvv2?|cvc2?|"
    r"verification\s+code|one-time\s+code)"
)
KK_CODE = r"(?:код\w*|құпия\s*сөз\w*|пин-?код\w*|cvv2?|cvc2?)"

RU_CARD = (
    r"(?:номер\w*\s+(?:вашей\s+|своей\s+)?карт\w*|данн\w+\s+(?:вашей\s+|своей\s+)?карт\w*|"
    r"реквизит\w*\s+карт\w*|срок\w*\s+действия|три\s+цифры|cvv2?|cvc2?)"
)
EN_CARD = (
    r"(?:card\s+number|card\s+details|card\s+data|expiry\s+date|expiration\s+date|"
    r"security\s+code|cvv2?|cvc2?|three\s+digits|3\s+digits)"
)
# "карт\w*" covers both "карта" and the colloquial "карточка" ("карточкаңыздың нөмірін").
KK_CARD = (
    r"(?:карт\w*\s+нөмір\w*|карт\w*\s+дерект\w*|карт\w*\s+мәлімет\w*|"
    r"жарамдылық\s+мерзім\w*|үш\s+сан\w*|cvv2?|cvc2?)"
)

RU_PAY = (
    r"\b(?:переведите|перечислите|отправьте|внесите|оплатите|пополните|скиньте|"
    r"перевести|оплатить|внести)\b"
)
RU_MONEY = (
    r"(?:деньг\w*|средств\w*|сумм\w*|комисси\w*|пошлин\w*|налог\w*|предоплат\w*|"
    r"взнос\w*|\d[\d\s]*(?:тг|тенге|₸|руб\w*|\$|долл\w*))"
)
EN_PAY = r"\b(?:transfer|send|wire|pay|deposit|move)\b"
EN_MONEY = (
    r"(?:money|funds|\bfee\b|fees|deposit|\$\s?\d+|\d[\d,]*\s*(?:kzt|tenge|tg|usd|\$))"
)
# Kazakh texts often spell the currency the Russian way ("тенге"), so accept both.
KK_MONEY = r"(?:ақша\w*|қаражат\w*|комиссия\w*|төлем\w*|\d[\d\s]*(?:тг|теңге|тенге|₸))"
# Imperatives, and "you have to pay" constructions: "төлеу керек", "аудару қажет".
KK_PAY = (
    r"(?:аударыңыз|жіберіңіз|төлеңіз|салыңыз|енгізіңіз|"
    r"(?:төлеу|аудару|салу)\s+(?:керек|қажет))"
)

# "Safe account" is a red flag on its own, with or without a verb.
SAFE_ACCOUNT = [
    r"(?:безопасн|резервн|защищенн|специальн)\w*\s+сч[её]т\w*",
    r"\b(?:safe|secure|protected|reserve)\s+account\b",
    r"қауіпсіз\s+шот\w*",
]

CODE_PATTERNS = compile_all(
    [
        RU_SHARE + SEP + gap(4) + RU_CODE,
        RU_CODE + SEP + gap(4) + RU_SHARE,
        EN_SHARE + SEP + gap(4) + EN_CODE,
        KK_CODE + SEP + gap(3) + KK_SHARE,
    ]
)

CARD_PATTERNS = compile_all(
    [
        RU_SHARE + SEP + gap(4) + RU_CARD,
        r"(?:нужен|нужны|нужно|требуется|необходим\w*)\s+" + gap(3) + RU_CARD,
        EN_SHARE + SEP + gap(4) + EN_CARD,
        r"\b(?:enter|need|require)\w*\s+" + gap(3) + EN_CARD,
        KK_CARD + SEP + gap(3) + r"(?:" + KK_SHARE + r"|енгізіңіз)",
    ]
)

TRANSFER_PATTERNS = compile_all(
    [
        RU_PAY + SEP + gap(4) + RU_MONEY,
        # English: "send money" but not "your transfer of 5000 KZT was received".
        r"(?<!your\s)(?<!the\s)(?<!a\s)(?<!of\s)" + EN_PAY + SEP + gap(4) + EN_MONEY,
        KK_MONEY + SEP + gap(3) + KK_PAY,
        *SAFE_ACCOUNT,
    ]
)


def detect_requests(message: str) -> list[Signal]:
    """Return code, card-data and transfer requests found in the message."""
    common = dict(tool=TOOL_NAME, severity="high", skip_negated=True)
    signals = (
        find_signals(message, signal_id="code_request", patterns=CODE_PATTERNS, **common)
        + find_signals(message, signal_id="card_data_request", patterns=CARD_PATTERNS, **common)
        + find_signals(message, signal_id="transfer_request", patterns=TRANSFER_PATTERNS, **common)
    )
    return sorted(signals, key=lambda s: s.start)


TOOL = Tool(
    name=TOOL_NAME,
    description=(
        "Rule-based check of the message under analysis. Finds requests to the reader to "
        "share a one-time code, SMS code, PIN, password or CVV (code_request); to give card "
        "number, expiry date or CVV (card_data_request); and to transfer or pay money, "
        "including 'safe account' requests (transfer_request). Warnings such as 'never "
        "share this code' are not reported. Takes no arguments. Returns a JSON list of "
        "signals with the exact evidence text."
    ),
    input_schema=NO_ARGUMENTS,
    run=lambda message, _tool_input: detect_requests(message),
)
