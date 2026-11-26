"""Tests for the data check command. Texts are invented."""

from eval.check_data import main
from eval.dataset import FIELDS, Message, write_messages


def test_report_counts_and_warnings(tmp_path, capsys):
    write_messages(
        tmp_path / "raw" / "kk.csv",
        [
            Message("kk-001", "kk", "scam", "fake_bank", "Кодты атаңыз. +7 701 123 45 67", "own", "U"),
            Message("kk-002", "kk", "legitimate", "bank_notification", "Код 4821.", "own", "U"),
        ],
    )
    assert main(["--data", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "CHECK" in out and "phone number" in out
    assert "kk: scam 1/17, legitimate 1/16 (bank notifications 1/5)" in out


def test_errors_give_exit_code_1(tmp_path, capsys):
    path = tmp_path / "raw" / "kk.csv"
    path.parent.mkdir()
    path.write_text(",".join(FIELDS) + "\nkk-001,kk,,fake_bank,Text,own,U,,\n", encoding="utf-8")
    assert main(["--data", str(tmp_path)]) == 1
    assert "ERROR" in capsys.readouterr().out


def test_counts_unchecked_test_labels_without_printing_them(tmp_path, capsys):
    secret = "Секретное тестовое сообщение"
    write_messages(tmp_path / "raw" / "kk.csv", [Message("kk-001", "kk", "scam", "fake_bank", "a", "own", "U")])
    write_messages(
        tmp_path / "test" / "messages.csv",
        [
            Message("kk-009", "kk", "scam", "fake_bank", secret, "own", "U"),
            Message("kk-010", "kk", "scam", "fake_bank", secret, "own", "U", checked_by="T"),
        ],
    )
    main(["--data", str(tmp_path)])
    out = capsys.readouterr().out
    assert "test set: 1 labels not checked" in out
    assert secret not in out


def test_no_files(tmp_path):
    assert main(["--data", str(tmp_path)]) == 1
