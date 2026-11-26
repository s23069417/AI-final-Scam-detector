"""Tests for the labelled-data format. All texts are invented."""

from dataclasses import fields

import pytest

from eval.dataset import (
    FIELDS,
    Message,
    check_rows,
    load_messages,
    luhn_ok,
    personal_data_warnings,
    read_rows,
    write_messages,
)

HEADER = ",".join(FIELDS)


def row(**overrides):
    base = {
        "id": "kk-001", "lang": "kk", "label": "scam", "category": "fake_bank",
        "text": "Кодты атаңыз.", "source": "own", "labelled_by": "Ulzhan",
        "checked_by": "", "notes": "", "_line": "2",
    }
    base.update(overrides)
    return base


def write_csv(tmp_path, *lines, bom=False):
    path = tmp_path / "kk.csv"
    path.write_text("\n".join([HEADER, *lines]) + "\n", encoding="utf-8-sig" if bom else "utf-8")
    return path


def test_valid_row_has_no_problems():
    assert check_rows([row()]) == []


@pytest.mark.parametrize(
    "overrides, expected",
    [
        ({"label": ""}, "empty label"),
        ({"labelled_by": ""}, "empty labelled_by"),
        ({"label": "suspicious"}, "label must be one of"),
        ({"lang": "kz"}, "lang must be one of"),
        ({"category": "phishing"}, "unknown category"),
    ],
)
def test_invalid_rows(overrides, expected):
    [problem] = check_rows([row(**overrides)])
    assert expected in problem


def test_repeated_id():
    problems = check_rows([row(), row(_line="3")])
    assert problems == ["line 3 (kk-001): id repeats line 2 (kk-001)"]


def test_load_and_write_round_trip(tmp_path):
    path = write_csv(
        tmp_path,
        'kk-001,kk,scam,fake_bank,"Кодты атаңыз, жедел!",own,Ulzhan,,',
        "kk-002,kk,legitimate,personal,Ертең кездесеміз.,own,Ulzhan,Tomiris,",
        bom=True,  # as saved by Excel
    )
    messages = load_messages(path)
    assert [m.id for m in messages] == ["kk-001", "kk-002"]
    assert messages[0].text == "Кодты атаңыз, жедел!"  # comma inside quotes is kept
    assert messages[1].checked_by == "Tomiris"

    out = tmp_path / "out" / "copy.csv"
    write_messages(out, messages)
    assert load_messages(out) == messages


def test_load_rejects_bad_rows(tmp_path):
    path = write_csv(tmp_path, "kk-001,kk,,fake_bank,Text,own,Ulzhan,,")
    with pytest.raises(ValueError, match="empty label"):
        load_messages(path)


def test_missing_column(tmp_path):
    path = tmp_path / "bad.csv"
    path.write_text("id,lang,text\nkk-001,kk,hi\n", encoding="utf-8")
    with pytest.raises(ValueError, match="missing columns"):
        read_rows(path)


def test_luhn():
    assert luhn_ok("4000000000000002")  # a well-known test card number
    assert not luhn_ok("4000000000000001")


def test_personal_data_warnings():
    rows = [
        row(text="Хабарласыңыз: +7 701 123 45 67"),
        row(id="kk-002", text="Карта 4000 0000 0000 0002 бұғатталды"),
        row(id="kk-003", text="Карта 1234 5678 9012 3456, код 4821"),  # fails Luhn
    ]
    warnings = personal_data_warnings(rows)
    assert len(warnings) == 2
    assert "phone number" in warnings[0]
    assert "real card number" in warnings[1]


def test_message_fields_match_csv_columns():
    assert tuple(f.name for f in fields(Message)) == FIELDS
    assert Message("a", "kk", "scam", "fake_bank", "t", "own", "U").checked_by == ""
