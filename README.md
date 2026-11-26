# AI Scam Detector

Paste a suspicious SMS, WhatsApp or Telegram message (Russian, Kazakh or English) and get a verdict
(`scam` / `suspicious` / `legitimate`), the warning signs that were found, and advice.
It shows risk signals only; it does not prove fraud.

Group 11, Narxoz University: Kabylkhanova Gulmira, Askar Ulzhan, Nurbolat Tomiris.

> Work in progress towards v1.0 (code freeze 13 Dec 2026). See [PLAN.md](PLAN.md) and [DECISIONS.md](DECISIONS.md).

## How it works

An LLM (`claude-haiku-5-5`) runs in a tool-use loop. It decides which checks to run, reads
their results and gives a verdict through a `submit_verdict` tool:

| Tool | What it finds |
|---|---|
| `detect_requests` | requests to share a code / PIN / CVV, to give card data, to transfer money or use a "safe account" |
| `detect_urgency` | time pressure ("срочно", "within 24 hours") and threats ("карта будет заблокирована") |
| `inspect_links` | short-URL redirects and look-alike bank domains *(in progress)* |

The verdict logic then combines the LLM's label with the tool signals: signals set a minimum
label (a code request is never "legitimate"), and the LLM may cite only signals a tool really found.
If the API is unavailable, a rules-only verdict is returned.

## Setup

Requires Python 3.10+ and an Anthropic API key (paid; one full evaluation run costs under $1).

```bash
git clone https://github.com/s23069417/AI-final-Scam-detector.git
cd AI-final-Scam-detector
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env        # then put your ANTHROPIC_API_KEY in .env
```

## Run

```bash
python -m scam_detector "Служба безопасности банка. Срочно продиктуйте код из СМС."
```

The verdict is printed as JSON (`label`, `signals`, `cited`, `rationale`, `stats`).

## Tests

```bash
python -m pytest -q
```

Tests use a fake LLM client and never call the real API, so they need no key.

## Project layout

```
scam_detector/
  signals.py         shared Signal / Tool contract
  detectors/         rule-based detectors (requests, urgency)
  agent.py           the LLM agent loop
  verdict.py         safety floor and grounded citations
  prompts.py         system prompt (draft)
  __main__.py        command line
tests/               pytest tests and the fake client
```

## Third-party components

- [Anthropic Python SDK](https://github.com/anthropics/anthropic-sdk-python) (MIT)
- [python-dotenv](https://github.com/theskumar/python-dotenv) (BSD-3-Clause)
- [pytest](https://pytest.org) (MIT)
