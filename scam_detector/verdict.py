"""Verdict logic: combine the LLM's label with the signals the tools found.

Owner: Gulmira.

Two rules make the verdict safer than the LLM alone:

1. Safety floor. Tool signals set a minimum label. If the message asks for a
   code and the LLM still says "legitimate", the final label is raised to
   "suspicious". A missed scam is the costly error (see PLAN.md), and the floor
   also protects against messages that try to talk the model into "legitimate".
   The floor never lowers the LLM's label.

2. Grounded citations. The LLM names the signal ids behind its label. Ids that
   no tool returned are dropped and counted, so the explanation can only point
   at real evidence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from scam_detector.signals import Signal

LABELS = ("legitimate", "suspicious", "scam")  # ordered from least to most risky


def rank(label: str) -> int:
    return LABELS.index(label)


def rule_floor(signals: Iterable[Signal]) -> str:
    """The lowest label the tool signals allow.

    - scam:       a high-severity signal plus any other distinct signal
                  (e.g. a code request together with urgency);
    - suspicious: one high-severity signal, or two different medium ones;
    - legitimate: otherwise.
    """
    signals = list(signals)
    high_ids = {s.id for s in signals if s.severity == "high"}
    other_ids = {s.id for s in signals if s.severity != "high"}

    if high_ids and (len(high_ids) >= 2 or other_ids):
        return "scam"
    if high_ids or len(other_ids) >= 2:
        return "suspicious"
    return "legitimate"


@dataclass
class Verdict:
    label: str  # final label shown to the user
    floor_label: str  # minimum label implied by the tool signals
    llm_label: str | None  # what the LLM said; None if the LLM gave no verdict
    signals: list[Signal]  # everything the tools found
    cited: list[Signal]  # signals the LLM cited that the tools really found
    ungrounded_ids: list[str]  # ids the LLM cited that no tool found
    rationale: str
    source: str  # "agent" or "rules_fallback"
    error: str | None = None  # why the agent fell back to rules, if it did
    stats: dict[str, Any] = field(default_factory=dict)

    @property
    def raised_by_floor(self) -> bool:
        """True when the tool signals overruled a softer LLM label."""
        return self.llm_label is not None and rank(self.label) > rank(self.llm_label)

    @property
    def groundedness(self) -> float | None:
        """Share of cited ids that a tool really found; None if nothing was cited."""
        cited_ids = {s.id for s in self.cited}
        total = len(cited_ids) + len(self.ungrounded_ids)
        return None if total == 0 else len(cited_ids) / total

    def to_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "floor_label": self.floor_label,
            "llm_label": self.llm_label,
            "raised_by_floor": self.raised_by_floor,
            "signals": [s.to_dict() for s in self.signals],
            "cited": [s.to_dict() for s in self.cited],
            "ungrounded_ids": self.ungrounded_ids,
            "groundedness": self.groundedness,
            "rationale": self.rationale,
            "source": self.source,
            "error": self.error,
            "stats": self.stats,
        }


def combine(
    *,
    llm_label: str,
    cited_ids: Iterable[str],
    rationale: str,
    signals: list[Signal],
    stats: dict[str, Any] | None = None,
) -> Verdict:
    """Final verdict from the LLM's answer and the tool signals."""
    if llm_label not in LABELS:
        raise ValueError(f"unknown label {llm_label!r}")

    floor = rule_floor(signals)
    final = llm_label if rank(llm_label) >= rank(floor) else floor

    found_ids = {s.id for s in signals}
    cited_unique = list(dict.fromkeys(cited_ids))  # keep order, drop repeats
    grounded_ids = [i for i in cited_unique if i in found_ids]
    ungrounded = [i for i in cited_unique if i not in found_ids]

    return Verdict(
        label=final,
        floor_label=floor,
        llm_label=llm_label,
        signals=signals,
        cited=[s for s in signals if s.id in grounded_ids],
        ungrounded_ids=ungrounded,
        rationale=rationale,
        source="agent",
        stats=stats or {},
    )


def rules_only(
    signals: list[Signal], *, error: str | None = None, stats: dict[str, Any] | None = None
) -> Verdict:
    """Verdict without the LLM, used when the API is unavailable or gives no answer."""
    return Verdict(
        label=rule_floor(signals),
        floor_label=rule_floor(signals),
        llm_label=None,
        signals=signals,
        cited=list(signals),
        ungrounded_ids=[],
        rationale="",
        source="rules_fallback",
        error=error,
        stats=stats or {},
    )
