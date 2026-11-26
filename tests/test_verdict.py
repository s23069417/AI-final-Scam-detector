"""Tests for the verdict logic."""

import pytest

from scam_detector.signals import Signal
from scam_detector.verdict import combine, rule_floor, rules_only


def sig(signal_id: str, severity: str) -> Signal:
    return Signal(id=signal_id, tool="test", severity=severity, evidence="x", start=0, end=1)


CODE = sig("code_request", "high")
TRANSFER = sig("transfer_request", "high")
TIME = sig("urgency_time_pressure", "medium")
THREAT = sig("urgency_threat", "medium")
INFO = sig("official_bank_domain", "low")  # an informational signal
INFO2 = sig("short_link_resolved", "low")


@pytest.mark.parametrize(
    "signals, expected",
    [
        ([], "legitimate"),
        ([TIME], "legitimate"),  # "срочно перезвони" from a friend is not fraud
        ([TIME, THREAT], "suspicious"),
        ([CODE], "suspicious"),
        ([CODE, TIME], "scam"),
        ([CODE, TRANSFER], "scam"),
        ([CODE, CODE], "suspicious"),  # the same id twice is still one kind of signal
        # Low signals never raise the floor (from Ulzhan's review).
        ([CODE, INFO], "suspicious"),
        ([INFO, INFO2], "legitimate"),
    ],
)
def test_rule_floor(signals, expected):
    assert rule_floor(signals) == expected


def test_floor_raises_a_legitimate_llm_label():
    v = combine(llm_label="legitimate", cited_ids=[], rationale="", signals=[CODE])
    assert v.label == "suspicious"
    assert v.llm_label == "legitimate"
    assert v.raised_by_floor


def test_floor_never_lowers_the_llm_label():
    # The LLM may see a prize scam that no rule catches.
    v = combine(llm_label="scam", cited_ids=[], rationale="prize offer", signals=[])
    assert v.label == "scam"
    assert not v.raised_by_floor


def test_llm_label_kept_when_above_floor():
    v = combine(llm_label="scam", cited_ids=["code_request"], rationale="", signals=[CODE])
    assert v.label == "scam"
    assert v.floor_label == "suspicious"


def test_ungrounded_citations_are_dropped_and_counted():
    v = combine(
        llm_label="scam",
        cited_ids=["code_request", "lookalike_domain", "code_request"],
        rationale="",
        signals=[CODE, TIME],
    )
    assert [s.id for s in v.cited] == ["code_request"]
    assert v.ungrounded_ids == ["lookalike_domain"]
    assert v.groundedness == 0.5


def test_groundedness_is_none_without_citations():
    v = combine(llm_label="legitimate", cited_ids=[], rationale="", signals=[])
    assert v.groundedness is None


def test_unknown_label_is_rejected():
    with pytest.raises(ValueError):
        combine(llm_label="maybe", cited_ids=[], rationale="", signals=[])


def test_rules_only_fallback():
    v = rules_only([CODE, THREAT], error="api unavailable")
    assert v.label == "scam"
    assert v.source == "rules_fallback"
    assert v.llm_label is None
    assert v.error == "api unavailable"
    assert v.to_dict()["label"] == "scam"
