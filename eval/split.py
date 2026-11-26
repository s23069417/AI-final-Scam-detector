"""Split the labelled messages into a dev set (30%) and a test set (70%).

Owner: Ulzhan.

    python -m eval.split            # reads data/raw/*.csv, writes data/dev and data/test

PLAN.md section 4: the split is fixed once, before any prompt tuning. So the
script refuses to overwrite an existing split; --force is only for the case when
the team agrees to redo it (record that in DECISIONS.md).

The split is stratified: inside every (language, label) group 30% go to dev.
Then dev and test both keep the mix of languages and of scam / legitimate.
A fixed random seed makes the split the same on every computer.
"""

from __future__ import annotations

import argparse
import random
import sys
from collections import defaultdict
from pathlib import Path

from eval.dataset import Message, load_messages, write_messages

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
DEV_SHARE = 0.3
SEED = 2026


def split_messages(
    messages: list[Message], *, dev_share: float = DEV_SHARE, seed: int = SEED
) -> tuple[list[Message], list[Message]]:
    """Return (dev, test). Every (lang, label) group is split separately."""
    groups: dict[tuple[str, str], list[Message]] = defaultdict(list)
    for message in sorted(messages, key=lambda m: m.id):  # input order must not matter
        groups[(message.lang, message.label)].append(message)

    rng = random.Random(seed)
    dev, test = [], []
    for key in sorted(groups):
        group = groups[key]
        rng.shuffle(group)
        n_dev = round(len(group) * dev_share)
        dev += group[:n_dev]
        test += group[n_dev:]
    return sorted(dev, key=lambda m: m.id), sorted(test, key=lambda m: m.id)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m eval.split")
    parser.add_argument("--data", type=Path, default=DATA_DIR)
    parser.add_argument("--force", action="store_true", help="overwrite an existing split")
    args = parser.parse_args(argv)

    dev_path = args.data / "dev" / "messages.csv"
    test_path = args.data / "test" / "messages.csv"
    if (dev_path.exists() or test_path.exists()) and not args.force:
        print("The split already exists and is fixed (PLAN.md section 4).", file=sys.stderr)
        return 1

    raw_files = sorted((args.data / "raw").glob("*.csv"))
    messages = [m for path in raw_files for m in load_messages(path)]
    if not messages:
        print("No messages in data/raw/*.csv", file=sys.stderr)
        return 1
    ids = [m.id for m in messages]
    if len(ids) != len(set(ids)):
        print("The same id is used in two raw files.", file=sys.stderr)
        return 1

    dev, test = split_messages(messages)
    write_messages(dev_path, dev)
    write_messages(test_path, test)
    # Only counts are printed: nobody should read the test messages (CLAUDE.md rule 3).
    print(f"dev: {len(dev)} messages -> {dev_path}")
    print(f"test: {len(test)} messages -> {test_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
