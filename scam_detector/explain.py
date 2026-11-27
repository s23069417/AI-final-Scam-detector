"""Explanation generation and groundedness check.

Owner: Tomiris.

Turns a Verdict into a human-readable Explanation ready for the web interface.
The groundedness property (fraction of cited ids that tools confirmed) lives on
Verdict; this module formats it for display and annotates each signal as cited
or not.
"""

from __future__ import annotations

from dataclasses import dataclass

from scam_detector.verdict import Verdict

# Display labels in Russian (the primary language of Kazakhstan).
# The LLM rationale is already in the message's own language.
_LABEL_DISPLAY = {
    "scam": "Мошенничество",
    "suspicious": "Подозрительно",
    "legitimate": "Безопасно",
}

# What to do, per verdict.
_ADVICE = {
    "scam": (
        "Не отвечайте на это сообщение и не переходите по ссылкам. "
        "Не сообщайте коды, данные карты или пароли никому. "
        "Заблокируйте номер отправителя и сообщите о нём оператору связи."
    ),
    "suspicious": (
        "Будьте осторожны. Не переходите по ссылкам и не звоните по номерам из сообщения. "
        "Если сообщение якобы от вашего банка — позвоните на официальный номер банка "
        "для проверки."
    ),
    "legitimate": (
        "Сообщение выглядит безопасным. "
        "Всё равно никому не сообщайте OTP-коды и пароли в ответ на входящие "
        "звонки или сообщения."
    ),
}

# Human-readable signal descriptions.
_SIGNAL_LABELS = {
    "code_request": "просит сообщить код",
    "card_data_request": "просит данные карты",
    "transfer_request": "просит перевести деньги",
    "urgency_time_pressure": "создаёт временное давление",
    "urgency_threat": "угрожает или запугивает",
    "lookalike_domain": "поддельный домен банка или ведомства",
    "short_link": "скрытая ссылка (сокращатель URL)",
    "ip_link": "ссылка на IP-адрес вместо домена",
    "risky_tld": "подозрительный домен верхнего уровня",
}


@dataclass
class Warning:
    signal_id: str
    label: str    # human-readable description from _SIGNAL_LABELS
    evidence: str  # the matched text span from the original message
    severity: str  # "low" | "medium" | "high"
    cited: bool    # True when the LLM cited this signal in its verdict


@dataclass
class Explanation:
    label: str              # "scam" | "suspicious" | "legitimate"
    label_display: str      # Russian display name
    rationale: str          # LLM's rationale (in the message's own language)
    warnings: list[Warning]  # all tool signals, formatted for display
    advice: str             # what the user should do
    raised_note: str | None  # note if the safety floor raised the LLM's label
    groundedness: float | None  # fraction of cited ids that tools confirmed
    ungrounded_ids: list[str]   # hallucinated signal ids (LLM cited, tools did not find)
    source: str             # "agent" or "rules_fallback"
    error: str | None       # why the agent fell back to rules, if it did


def build(verdict: Verdict) -> Explanation:
    """Build an Explanation from a Verdict."""
    cited_ids = {s.id for s in verdict.cited}

    warnings = [
        Warning(
            signal_id=s.id,
            label=_SIGNAL_LABELS.get(s.id, s.id),
            evidence=s.evidence,
            severity=s.severity,
            cited=s.id in cited_ids,
        )
        for s in verdict.signals
    ]

    raised_note: str | None = None
    if verdict.raised_by_floor and verdict.llm_label is not None:
        raised_note = (
            f"Инструменты обнаружили дополнительные признаки, которые ИИ не учёл. "
            f"Оценка повышена с «{_LABEL_DISPLAY.get(verdict.llm_label, verdict.llm_label)}» "
            f"до «{_LABEL_DISPLAY.get(verdict.label, verdict.label)}»."
        )

    return Explanation(
        label=verdict.label,
        label_display=_LABEL_DISPLAY.get(verdict.label, verdict.label),
        rationale=verdict.rationale,
        warnings=warnings,
        advice=_ADVICE[verdict.label],
        raised_note=raised_note,
        groundedness=verdict.groundedness,
        ungrounded_ids=verdict.ungrounded_ids,
        source=verdict.source,
        error=verdict.error,
    )
