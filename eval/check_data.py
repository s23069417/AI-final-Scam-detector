"""Check the labelled data before the split and before an evaluation run.

Owner: Ulzhan.

    python -m eval.check_data                  # all of data/raw/*.csv
    python -m eval.check_data data/raw/kk.csv  # one file

Prints format errors (exit code 1), personal-data warnings for a person to look
at, and counts per language, label and category, so we can see how far we are
from the plan (PLAN.md section 4). For the test set it only counts how many
labels are not yet checked by a second member; it never prints test messages.
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

from eval.dataset import check_rows, personal_data_warnings, read_rows
from eval.split import DATA_DIR

# Plan per language (PLAN.md): 100 messages, half scam, a third per language,
# 15 bank notifications in total.
TARGET_PER_LANGUAGE = {"scam": 17, "legitimate": 16, "bank_notification": 5}


def report(paths: list[Path]) -> int:
    rows = []
    for path in paths:
        try:
            rows += [dict(r, _file=path.name) for r in read_rows(path)]
        except ValueError as exc:
            print(f"ERROR {exc}")
            return 1

    problems = check_rows(rows)
    for problem in problems:
        print(f"ERROR {problem}")
    for warning in personal_data_warnings(rows):
        print(f"CHECK {warning}")

    print(f"\n{len(rows)} messages in {', '.join(p.name for p in paths)}")
    by_lang = Counter(r["lang"] for r in rows)
    for lang in sorted(by_lang):
        in_lang = [r for r in rows if r["lang"] == lang]
        labels = Counter(r["label"] for r in in_lang)
        banks = sum(r["category"] == "bank_notification" for r in in_lang)
        print(
            f"  {lang}: scam {labels['scam']}/{TARGET_PER_LANGUAGE['scam']}, "
            f"legitimate {labels['legitimate']}/{TARGET_PER_LANGUAGE['legitimate']} "
            f"(bank notifications {banks}/{TARGET_PER_LANGUAGE['bank_notification']})"
        )
    categories = Counter(r["category"] for r in rows if r["category"])
    print("  categories: " + ", ".join(f"{c} {n}" for c, n in sorted(categories.items())))
    return 1 if problems else 0


def unchecked_test_labels(data_dir: Path = DATA_DIR) -> int | None:
    """How many test labels have no checked_by yet; None if there is no split yet."""
    path = data_dir / "test" / "messages.csv"
    if not path.exists():
        return None
    return sum(not r["checked_by"] for r in read_rows(path))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m eval.check_data")
    parser.add_argument("files", nargs="*", type=Path)
    parser.add_argument("--data", type=Path, default=DATA_DIR)
    args = parser.parse_args(argv)

    paths = args.files or sorted((args.data / "raw").glob("*.csv"))
    if not paths:
        print("No CSV files found in data/raw/", file=sys.stderr)
        return 1
    code = report(paths)

    unchecked = unchecked_test_labels(args.data)
    if unchecked is not None:
        print(f"\ntest set: {unchecked} labels not checked by a second member yet")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
