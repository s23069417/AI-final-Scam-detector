"""Urgency detector: time pressure and threats.

Owner: Gulmira. Languages: Russian, Kazakh, English.

Two signals:
- urgency_time_pressure — "срочно", "в течение 30 минут", "today only";
- urgency_threat — "карта будет заблокирована", "final warning", "шот бұғатталады",
  and the scare "на ваше имя оформляют кредит" / "атыңызға несие рәсімделуде".

Urgency alone does not mean fraud (a friend can write "срочно перезвони"),
so both signals are "medium". The verdict logic combines them with other signals.
"""

from __future__ import annotations

from scam_detector.detectors._match import SEP, compile_all, find_signals, gap
from scam_detector.signals import NO_ARGUMENTS, Signal, Tool

TOOL_NAME = "detect_urgency"

TIME_PRESSURE_PATTERNS = compile_all(
    [
        # Russian
        r"\b(?:срочно|немедленно|незамедлительно|безотлагательно|торопитесь|успейте)\b",
        r"\bсейчас\s+же\b",
        r"\bкак\s+можно\s+(?:скорее|быстрее)\b",
        r"\b(?:в\s+течение|в\s+ближайшие|не\s+позднее\s+чем\s+через)\s+\d+\s*(?:минут|мин|час|сут|дн|дня|дней)\w*",
        # Without a number: "в течение часа / суток / получаса"
        r"\bв\s+течение\s+(?:часа|суток|дня|минуты|получаса|одного\s+\w+)\b",
        r"\bосталось\s+(?:всего\s+)?\d+\s*(?:минут|мин|час)\w*",
        r"\bтолько\s+сегодня\b",
        r"\bдо\s+конца\s+(?:дня|суток)\b",
        r"\bпоследн\w+\s+шанс\w*",
        # English
        r"\b(?:urgent|urgently|immediately|asap|hurry)\b",
        r"\bright\s+now\b",
        r"\bact\s+now\b",
        r"\bas\s+soon\s+as\s+possible\b",
        r"\bwithin\s+(?:the\s+next\s+)?\d+\s*(?:minutes?|mins?|hours?|hrs?|days?)\b",
        r"\bwithin\s+(?:an?|one|the\s+next)\s+(?:hour|day|minute)\b",
        r"\btoday\s+only\b",
        r"\blast\s+chance\b",
        r"\bexpires?\s+(?:today|soon|in\s+\d+)",
        # Kazakh
        # "жедел жәрдем" is the ambulance, not time pressure.
        r"(?:шұғыл|дереу|жедел(?!\s+жәрдем)|тез\s+арада|асығыңыз)",
        # "24 сағат ішінде", and with a number word: "бір сағат ішінде"
        r"(?:\d+|бір|екі|үш|бес|он|жарты)\s*(?:минут|сағат|күн)\w*\s+ішінде",
        r"бүгін\s+ғана",
        r"тек\s+бүгін",
        r"соңғы\s+мүмкіндік\w*",
    ]
)

THREAT_PATTERNS = compile_all(
    [
        # Russian: "<card/account> ... будет заблокирован(а)"
        r"(?:карт\w*|сч[её]т\w*|аккаунт\w*|номер\w*|доступ\w*|профил\w*|кабинет\w*)"
        + SEP + gap(3) + r"(?:будет|будут)\s+(?:заблокир|закрыт|отключ|аннулир|удален)\w*",
        r"(?:иначе|в\s+противном\s+случае)" + SEP + gap(5)
        + r"(?:заблокир|закро|закрыт|отключ|штраф|суд|арест|уголовн|потеряете)\w*",
        r"\bпоследнее\s+предупреждение\b",
        r"\bуголовн\w+\s+(?:ответственност|дел)\w*",
        # A common scheme in Kazakhstan: "на ваше имя оформляют кредит".
        r"\bна\s+ваше\s+имя\s+" + gap(3) + r"(?:кредит|заем|займ|микрокредит)\w*",
        r"\b(?:кредит|заем|займ|микрокредит)\w*\s+" + gap(3) + r"на\s+ваше\s+имя\b",
        # English: "<account> ... will be blocked"
        r"\b(?:account|card|number|access|profile|wallet)\b" + SEP + gap(3)
        + r"(?:will|is\s+going\s+to)\s+be\s+(?:blocked|suspended|closed|locked|terminated|deactivated|deleted)\b",
        r"\b(?:otherwise|or\s+else)\b" + SEP + gap(5)
        + r"(?:blocked|suspended|closed|locked|fined|arrest\w*|lose|legal)\b",
        r"\bfinal\s+(?:warning|notice|reminder)\b",
        r"\blegal\s+action\b",
        r"\b(?:loan|credit)\b\s+" + gap(4) + r"in\s+your\s+name\b",
        # Kazakh: "<card/account> ... бұғатталады"
        r"(?:карта\w*|шот\w*|аккаунт\w*|нөмір\w*|профиль\w*)" + SEP + gap(3)
        + r"(?:бұғатталады|бұғаттал\w*|блокта\w*|жабылады|өшіріледі|тоқтатылады)",
        r"әйтпесе" + SEP + gap(5) + r"(?:бұғат|блокта|жабыл|айыппұл|сот)\w*",
        r"соңғы\s+ескерту\w*",
        r"қылмыстық\s+іс\w*",
        r"атыңызға\s+" + gap(2) + r"несие\w*",
        r"несие\w*\s+" + gap(2) + r"атыңызға",
    ]
)


def detect_urgency(message: str) -> list[Signal]:
    """Return time-pressure and threat signals found in the message."""
    common = dict(tool=TOOL_NAME, severity="medium", skip_negated=False)
    signals = find_signals(
        message, signal_id="urgency_time_pressure", patterns=TIME_PRESSURE_PATTERNS, **common
    ) + find_signals(message, signal_id="urgency_threat", patterns=THREAT_PATTERNS, **common)
    return sorted(signals, key=lambda s: s.start)


TOOL = Tool(
    name=TOOL_NAME,
    description=(
        "Rule-based check of the message under analysis for pressure tactics: time pressure "
        "such as 'urgently' or 'within 30 minutes' (urgency_time_pressure) and threats such "
        "as 'your card will be blocked' or 'final warning' (urgency_threat). Urgency alone is "
        "not proof of fraud. Takes no arguments. Returns a JSON list of signals with the "
        "exact evidence text."
    ),
    input_schema=NO_ARGUMENTS,
    run=lambda message, _tool_input: detect_urgency(message),
)
