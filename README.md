# AI Scam Detector

Paste a suspicious SMS, WhatsApp or Telegram message (Russian, Kazakh or English) and get a verdict
(`scam` / `suspicious` / `legitimate`), the warning signs that were found, and advice.
It shows risk signals only; it does not prove fraud.

Group 11, Narxoz University: Kabylkhanova Gulmira, Askar Ulzhan, Nurbolat Tomiris.

> Work in progress. Setup instructions are completed before v1.0. See [PLAN.md](PLAN.md).

## Quick start (development)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # then put your ANTHROPIC_API_KEY in .env
python -m pytest -q
```
