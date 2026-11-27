"""Tests for scam_detector.explain.

Owner: Tomiris.
"""

from __future__ import annotations

import pytest

from scam_detector.explain import Warning, build
from scam_detector.signals import Signal
from scam_detector.verdict import Verdict, combine, rules_only


def _sig(id: str, severity: str, evidence: str = "example") -> Signal:
    return Signal(id=id, tool="t", severity=severity, evidence=evidence, start=0, end=len(evidence))


def _verdict_from(
    *,
    label: str = "scam",
    llm_label: str = "scam",
    signals: list[Signal] | None = None,
    rationale: str = "test",
    ungrounded_ids: list[str] | None = None,
) -> Verdict:
    sigs = signals or []
    cited_ids = [s.id for s in sigs]
    return combine(
        llm_label=llm_label,
        cited_ids=cited_ids + (ungrounded_ids or []),
        rationale=rationale,
        signals=sigs,
    )


# ------------------------------------------------------------------ label display


def test_label_display_scam():
    v = _verdict_from(label="scam", llm_label="scam")
    exp = build(v)
    assert exp.label == "scam"
    assert exp.label_display == "Мошенничество"


def test_label_display_suspicious():
    v = _verdict_from(llm_label="suspicious")
    exp = build(v)
    assert exp.label_display == "Подозрительно"


def test_label_display_legitimate():
    v = _verdict_from(llm_label="legitimate")
    exp = build(v)
    assert exp.label_display == "Безопасно"


# ------------------------------------------------------------------ warnings


def test_warnings_built_from_signals():
    sigs = [
        _sig("code_request", "high", "пришлите код"),
        _sig("urgency_threat", "medium", "карта заблокируется"),
    ]
    v = _verdict_from(signals=sigs)
    exp = build(v)
    assert len(exp.warnings) == 2
    ids = [w.signal_id for w in exp.warnings]
    assert "code_request" in ids
    assert "urgency_threat" in ids


def test_warning_evidence_preserved():
    sigs = [_sig("short_link", "medium", "bit.ly/xyz")]
    v = _verdict_from(llm_label="suspicious", signals=sigs)
    exp = build(v)
    assert exp.warnings[0].evidence == "bit.ly/xyz"


def test_warnings_empty_when_no_signals():
    v = _verdict_from(llm_label="legitimate")
    exp = build(v)
    assert exp.warnings == []


def test_unknown_signal_id_uses_id_as_label():
    sigs = [Signal(id="future_signal", tool="t", severity="medium",
                   evidence="x", start=0, end=1)]
    v = _verdict_from(llm_label="suspicious", signals=sigs)
    exp = build(v)
    assert exp.warnings[0].label == "future_signal"


# ------------------------------------------------------------------ cited flag


def test_cited_flag_true_for_cited_signals():
    sigs = [_sig("code_request", "high", "send your code")]
    v = _verdict_from(signals=sigs)
    exp = build(v)
    assert exp.warnings[0].cited is True


def test_cited_flag_false_for_uncited_signals():
    sig = _sig("urgency_time_pressure", "medium", "today only")
    v = combine(
        llm_label="suspicious",
        cited_ids=[],  # LLM did not cite urgency
        rationale="suspicious link",
        signals=[sig],
    )
    exp = build(v)
    assert exp.warnings[0].cited is False


# ------------------------------------------------------------------ advice


def test_advice_present_for_all_labels():
    for label in ("scam", "suspicious", "legitimate"):
        v = _verdict_from(llm_label=label)
        exp = build(v)
        assert exp.advice, f"advice missing for label={label}"


def test_scam_advice_mentions_no_sharing():
    v = _verdict_from(llm_label="scam")
    exp = build(v)
    assert "коды" in exp.advice.lower() or "пароли" in exp.advice.lower()


# ------------------------------------------------------------------ raised_note


def test_raised_note_set_when_floor_overrules():
    # LLM says legitimate, but a high signal forces suspicious.
    sigs = [_sig("code_request", "high", "скажите код")]
    v = combine(llm_label="legitimate", cited_ids=["code_request"], rationale="r", signals=sigs)
    exp = build(v)
    assert exp.raised_note is not None
    assert "повышена" in exp.raised_note


def test_raised_note_none_when_llm_already_severe():
    sigs = [_sig("code_request", "high", "скажите код")]
    v = combine(llm_label="scam", cited_ids=["code_request"], rationale="r", signals=sigs)
    exp = build(v)
    assert exp.raised_note is None


# ------------------------------------------------------------------ groundedness


def test_groundedness_none_when_nothing_cited():
    v = _verdict_from(llm_label="legitimate")
    exp = build(v)
    assert exp.groundedness is None


def test_groundedness_one_when_all_cited_found():
    sigs = [_sig("code_request", "high")]
    v = _verdict_from(signals=sigs)
    exp = build(v)
    assert exp.groundedness == 1.0


def test_groundedness_less_than_one_when_ungrounded():
    sigs = [_sig("code_request", "high")]
    # LLM cites code_request (real) + "fake_id" (hallucinated)
    v = combine(
        llm_label="scam",
        cited_ids=["code_request", "fake_id"],
        rationale="test",
        signals=sigs,
    )
    exp = build(v)
    assert 0.0 < exp.groundedness < 1.0
    assert "fake_id" in exp.ungrounded_ids


# ------------------------------------------------------------------ rules fallback


def test_rules_fallback_source():
    sigs = [_sig("code_request", "high")]
    v = rules_only(sigs, error="api_unavailable: ConnectionError")
    exp = build(v)
    assert exp.source == "rules_fallback"
    assert exp.error is not None


def test_rules_fallback_no_raised_note():
    # rules_only has llm_label=None, so raised_by_floor is False
    v = rules_only([], error="no_verdict")
    exp = build(v)
    assert exp.raised_note is None
