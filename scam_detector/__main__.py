"""Command line: python -m scam_detector "message text"   (or pipe text on stdin)

Prints the verdict as JSON. Needs ANTHROPIC_API_KEY in the environment or in .env.
"""

from __future__ import annotations

import argparse
import json
import sys

from dotenv import load_dotenv

from scam_detector.agent import InvalidMessageError, ScamAgent


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m scam_detector")
    parser.add_argument("message", nargs="?", help="message text; read from stdin if omitted")
    args = parser.parse_args(argv)

    load_dotenv()
    message = args.message if args.message is not None else sys.stdin.read()

    try:
        verdict = ScamAgent().analyze(message)
    except InvalidMessageError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(json.dumps(verdict.to_dict(), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
