"""Small helpers shared by the rule-based detectors."""

from __future__ import annotations

import re
from typing import Iterable

from scam_detector.signals import Signal

# Separator after a verb: spaces, or a comma as in "Пришлите, пожалуйста, код".
SEP = r"[\s,]+"


# Up to n words between two parts of a phrase, never crossing a sentence end.
# Example: gap(3) lets "продиктуйте, пожалуйста, код" match "продиктуйте ... код".
def gap(n: int) -> str:
    return rf"(?:[^\s.!?]+\s+){{0,{n}}}?"


# Strong negations turn a request into a warning anywhere in the same clause:
# "никому не сообщайте код", "never share this code", "кодты ешкімге айтпаңыз".
STRONG_NEGATION = re.compile(
    r"\b(?:никому|никогда|ни\s+при\s+каких|never|do\s+not|don't|dont|ешкімге|ешқашан)\b",
    re.IGNORECASE,
)
# Weak negations ("не", "not") count only right before the request or inside it.
# Otherwise "Чтобы не потерять деньги, продиктуйте код" would be missed.
WEAK_NEGATION = re.compile(r"\b(?:не|not)\b", re.IGNORECASE)
WEAK_BEFORE = re.compile(r"\b(?:не|not)\s+(?:[^\s]+\s+)?$", re.IGNORECASE)

# A clause ends at sentence punctuation or at , ; :
CLAUSE_END = re.compile(r"[.!?\n,;:]")


def normalize(text: str) -> str:
    """Lower-case the text and replace ё with е, keeping every character offset.

    Offsets must stay the same so that spans found in the normalized text can be
    cut out of the original message as evidence.
    """
    chars = []
    for c in text:
        low = c.lower()
        chars.append(low if len(low) == 1 else c)
    return "".join(chars).replace("ё", "е")


def clause_before(text: str, start: int) -> str:
    """The part of the clause that comes before position `start`."""
    prefix = text[:start]
    ends = list(CLAUSE_END.finditer(prefix))
    return prefix[ends[-1].end():] if ends else prefix


def is_negated(text: str, start: int, end: int) -> bool:
    """True if the matched request is actually a warning not to do it."""
    before = clause_before(text, start)
    inside = text[start:end]
    if STRONG_NEGATION.search(before + inside):
        return True
    if WEAK_NEGATION.search(inside):
        return True
    return WEAK_BEFORE.search(before) is not None


def find_signals(
    message: str,
    *,
    signal_id: str,
    tool: str,
    severity: str,
    patterns: Iterable[re.Pattern],
    skip_negated: bool,
) -> list[Signal]:
    """Run every pattern over the message and return non-overlapping signals."""
    text = normalize(message)
    spans: list[tuple[int, int]] = []
    for pattern in patterns:
        for m in pattern.finditer(text):
            if skip_negated and is_negated(text, m.start(), m.end()):
                continue
            spans.append((m.start(), m.end()))

    # Keep the longest span when two matches overlap.
    spans.sort(key=lambda s: (s[0], -(s[1] - s[0])))
    kept: list[tuple[int, int]] = []
    for start, end in spans:
        if kept and start < kept[-1][1]:
            continue
        kept.append((start, end))

    return [
        Signal(
            id=signal_id,
            tool=tool,
            severity=severity,
            evidence=message[start:end],
            start=start,
            end=end,
        )
        for start, end in kept
    ]


def compile_all(patterns: Iterable[str]) -> list[re.Pattern]:
    return [re.compile(p, re.IGNORECASE) for p in patterns]
