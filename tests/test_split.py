"""Tests for the dev/test split. Messages are generated, not real."""

from collections import Counter

from eval.dataset import Message, load_messages, write_messages
from eval.split import main, split_messages


def make_messages():
    messages = []
    for lang in ("kk", "ru", "en"):
        for label, category, count in (("scam", "fake_bank", 17), ("legitimate", "personal", 16)):
            for i in range(count):
                messages.append(
                    Message(f"{lang}-{label[0]}{i:02d}", lang, label, category, "text", "own", "U")
                )
    return messages  # 99 messages


def test_split_is_30_70_inside_every_group():
    dev, test = split_messages(make_messages())
    assert len(dev) + len(test) == 99
    assert not {m.id for m in dev} & {m.id for m in test}
    dev_groups = Counter((m.lang, m.label) for m in dev)
    assert dev_groups == {
        ("kk", "scam"): 5, ("kk", "legitimate"): 5,
        ("ru", "scam"): 5, ("ru", "legitimate"): 5,
        ("en", "scam"): 5, ("en", "legitimate"): 5,
    }


def test_split_is_reproducible_and_ignores_input_order():
    messages = make_messages()
    first = split_messages(messages)
    again = split_messages(list(reversed(messages)))
    assert first == again


def test_another_seed_gives_another_split():
    messages = make_messages()
    assert split_messages(messages, seed=1) != split_messages(messages, seed=2)


def test_command_line_writes_files_and_refuses_to_overwrite(tmp_path, capsys):
    write_messages(tmp_path / "raw" / "kk.csv", make_messages()[:33])
    assert main(["--data", str(tmp_path)]) == 0
    dev = load_messages(tmp_path / "dev" / "messages.csv")
    test = load_messages(tmp_path / "test" / "messages.csv")
    assert (len(dev), len(test)) == (10, 23)
    assert "text" not in capsys.readouterr().out  # never prints test messages

    assert main(["--data", str(tmp_path)]) == 1  # the split is fixed
    assert main(["--data", str(tmp_path), "--force"]) == 0


def test_command_line_without_data(tmp_path):
    assert main(["--data", str(tmp_path)]) == 1
