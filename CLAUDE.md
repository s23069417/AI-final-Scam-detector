# Instructions for the coding agent

You are working on AI Scam Detector, a student final project (see PLAN.md).
Every member must be able to explain every line, so prefer plain, readable code over clever code.

## Stack

- Python 3.10+, standard library first. Dependencies go in `requirements.txt`.
- LLM: Anthropic Python SDK (`anthropic`), model from env `SCAM_MODEL` (default `claude-haiku-5-5`).
- Tests: `pytest`. Run `python -m pytest -q` before every commit.

## Layout

- `scam_detector/signals.py` — the shared `Signal` and `Tool` contract. Do not change field names without updating PLAN.md.
- `scam_detector/detectors/` — rule-based detectors, no network.
- `scam_detector/tools/` — tools that may use the network (link inspector).
- `scam_detector/agent.py` — the agent loop. `scam_detector/verdict.py` — the verdict logic.
- `tests/` — unit tests. `data/` — labelled messages. `eval/` — evaluation scripts.

## Hard rules

1. Never put API keys, tokens or passwords in code, tests, logs or commits. Read them from environment variables. `.env` is git-ignored.
2. Tests never call the real API. Use the fake client in `tests/fakes.py`.
3. Do not open, read or print files in `data/test/` while working on prompts or detectors. Tune on `data/dev/` only.
4. Do not change labels in `data/` — labels are set by people.
5. Personal data: no real phone numbers, names or card numbers. Use invented ones.
6. The link inspector may send HEAD requests only. Never download page bodies or bypass any site protection.
7. Keep commits small and focused; one module or one fix per commit.
8. When you are unsure about a design choice, stop and ask instead of guessing. Record important decisions in DECISIONS.md.
