"""The labelled message set: one CSV format for every language.

Owner: Ulzhan.

Each row is one message. Columns (see data/README.md for the full rules):

    id           unique, e.g. "kk-001"
    lang         kk | ru | en | mixed
    label        scam | legitimate          (set by a person, never by the agent)
    category     what kind of message, e.g. fake_bank, bank_notification (CATEGORIES)
    text         the message itself
    source       own | adapted | a public URL the scam example came from
    labelled_by  who set the label
    checked_by   who checked the label (required for the test set, PLAN.md section 4)
    notes        free text

The files are UTF-8 CSV with a comma separator. We read them with "utf-8-sig" so
a file saved by Excel or Google Sheets (which may add a BOM) works too.
"""

from __future__ import annotations

import csv
import re
from dataclasses import asdict, dataclass
from pathlib import Path

LANGS = ("kk", "ru", "en", "mixed")
LABELS = ("scam", "legitimate")
CATEGORIES = (
    # scam
    "fake_bank",  # "служба безопасности банка", card blocked, codes
    "fake_prize",  # lottery, bonus, gift
    "fake_delivery",  # parcel held, delivery fee
    "relative_in_trouble",  # "мама, я попал в беду, переведи"
    "fake_government",  # egov, police, tax, fines
    "investment",  # easy money, crypto, "work from home"
    "other_scam",
    # legitimate
    "bank_notification",  # real-style bank SMS with codes or links (15 in total)
    "personal",  # friends, family, university
    "service",  # shops, delivery, taxi, appointments
    "other_legitimate",
)
FIELDS = (
    "id", "lang", "label", "category", "text", "source",
    "labelled_by", "checked_by", "notes",
)
REQUIRED = ("id", "lang", "label", "category", "text", "source", "labelled_by")


@dataclass(frozen=True)
class Message:
    id: str
    lang: str
    label: str
    category: str
    text: str
    source: str
    labelled_by: str
    checked_by: str = ""
    notes: str = ""


def read_rows(path: Path) -> list[dict[str, str]]:
    """Read a CSV file as a list of dicts, with the line number in "_line"."""
    with open(path, encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        missing = [c for c in FIELDS if c not in (reader.fieldnames or [])]
        if missing:
            raise ValueError(f"{path}: missing columns {', '.join(missing)}")
        rows = []
        for row in reader:
            clean = {k: (row.get(k) or "").strip() for k in FIELDS}
            clean["_line"] = str(reader.line_num)
            rows.append(clean)
        return rows


def load_messages(path: Path) -> list[Message]:
    """Load a CSV file. Raises ValueError if any row is invalid (see check_rows)."""
    rows = read_rows(path)
    problems = check_rows(rows)
    if problems:
        raise ValueError(f"{path}: " + "; ".join(problems))
    return [Message(**{k: row[k] for k in FIELDS}) for row in rows]


def write_messages(path: Path, messages: list[Message]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()
        for message in messages:
            writer.writerow(asdict(message))


# --------------------------------------------------------------------- checks

# Rule 5 of CLAUDE.md: no real personal data. We cannot know whether a number is
# real, so these only produce warnings for a person to look at.
PHONE = re.compile(r"(?:\+7|\b8)[\s(-]*7\d\d[\s)-]*\d{3}[\s-]*\d{2}[\s-]*\d{2}\b")
CARD = re.compile(r"\b(?:\d[ -]?){15,18}\d\b")


def luhn_ok(digits: str) -> bool:
    """The checksum every real card number passes; random 16 digits usually fail."""
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
    return total % 10 == 0


def check_rows(rows: list[dict[str, str]]) -> list[str]:
    """Errors that make the data unusable. An empty list means the rows are fine."""
    problems = []
    seen: dict[str, str] = {}
    for row in rows:
        where = f"line {row.get('_line', '?')} ({row.get('id') or 'no id'})"
        for column in REQUIRED:
            if not row.get(column):
                problems.append(f"{where}: empty {column}")
        if row.get("lang") and row["lang"] not in LANGS:
            problems.append(f"{where}: lang must be one of {', '.join(LANGS)}")
        if row.get("label") and row["label"] not in LABELS:
            problems.append(f"{where}: label must be one of {', '.join(LABELS)}")
        if row.get("category") and row["category"] not in CATEGORIES:
            problems.append(f"{where}: unknown category {row['category']!r}")
        message_id = row.get("id")
        if message_id:
            if message_id in seen:
                problems.append(f"{where}: id repeats {seen[message_id]}")
            seen[message_id] = where
    return problems


def personal_data_warnings(rows: list[dict[str, str]]) -> list[str]:
    """Phone numbers and card numbers that a person must confirm are invented."""
    warnings = []
    for row in rows:
        where = f"line {row.get('_line', '?')} ({row.get('id') or 'no id'})"
        for m in PHONE.finditer(row.get("text", "")):
            warnings.append(f"{where}: phone number {m.group()!r}: is it invented?")
        for m in CARD.finditer(row.get("text", "")):
            digits = re.sub(r"\D", "", m.group())
            if len(digits) == 16 and luhn_ok(digits):
                warnings.append(f"{where}: {m.group()!r} looks like a real card number")
    return warnings
