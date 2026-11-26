# PLAN — AI Scam Detector

Group 11: Kabylkhanova Gulmira, Askar Ulzhan, Nurbolat Tomiris.
This plan is written before the product code. Changes to it are recorded in DECISIONS.md.

## 1. What we build

A local web app. The user pastes a message (Russian, Kazakh or English) and gets:

- a verdict: `scam` / `suspicious` / `legitimate`;
- a plain-language explanation that names the concrete warning signs;
- advice on what to do.

The app shows risk signals. It does not prove fraud.

## 2. Architecture

```
message text
   │
   ▼
agent loop (LLM, claude-haiku-5-5)  ──calls──►  tools (local Python)
   │   decides which tools to call           ├─ detect_requests  (codes, card data, transfers)
   │   reads their output                    ├─ detect_urgency   (time pressure, threats)
   │   ends with submit_verdict              └─ inspect_links    (short URLs, bank look-alikes)
   ▼
verdict logic  ── combines the LLM label with tool signals,
   │              drops citations of signals no tool found
   ▼
explanation + advice  ──►  web interface
```

### Shared contract (all members code against this)

`scam_detector/signals.py`

- `Signal(id, tool, severity, evidence, start, end)` — one warning sign found by a tool.
  `evidence` is the exact text span, so every explanation can point to it.
- `Tool(name, description, input_schema, run)` — `run(message, tool_input) -> list[Signal]`.
  A new tool is added by registering a `Tool`; the agent loop does not change.

Signal ids (extend in this table, never rename):

| id | tool | severity | meaning |
|---|---|---|---|
| `code_request` | detect_requests | high | asks the user to share an SMS code, OTP, PIN or CVV |
| `card_data_request` | detect_requests | high | asks for card number, expiry date or CVV |
| `transfer_request` | detect_requests | high | asks to transfer or pay money, "safe account" |
| `urgency_time_pressure` | detect_urgency | medium | "urgently", "within 30 minutes", "today only" |
| `urgency_threat` | detect_urgency | medium | "your card will be blocked", "final warning" |
| `lookalike_domain` | inspect_links | high | a link pretends to be a bank or government site but is not on the official list ("kaspi-bonus.kz", "kаspi.kz" with a Cyrillic letter, "kaspl.kz") |
| `short_link` | inspect_links | medium | a URL shortener (bit.ly, clck.ru, ...) hides where the link leads; it is followed with HEAD requests and the final address is checked too |
| `ip_link` | inspect_links | medium | a bare IP address instead of a site name |
| `risky_tld` | inspect_links | low | cheap top-level domain popular with scam sites (.xyz, .top, ...); informational, never raises the floor |

## 3. Who does what

| Member | Modules | Data |
|---|---|---|
| Gulmira | `agent.py` (agent loop), `verdict.py`, `detectors/requests.py`, `detectors/urgency.py`, README | Russian messages |
| Ulzhan | `tools/links.py` (link and domain inspector), `eval/` (metrics, runner), both baselines | Kazakh messages |
| Tomiris | `explain.py` (explanation, groundedness check), `prompts/`, web UI | English, mixed-language, edge cases |

Each member tests their own part, reviews one other member's pull request, rates explanations, keeps agent logs, and commits from their own account.
Work goes on a personal branch (`<name>/<topic>`) and reaches `main` through a pull request reviewed by another member.

## 4. Evaluation

- 100 labelled messages: 50 scam, 50 legitimate (15 of them realistic bank notifications with codes or links), a third per language.
- Split 30 dev / 70 test, fixed before any prompt tuning. Labels are set before the system is run; a second member checks each test label.
- Prompts are tuned on dev only. The prompt author does not look at test messages before the freeze.
- Metrics: accuracy (suspicious counts as scam), missed-scam rate, false-alarm rate, groundedness, explanation quality (0–2 rubric, two raters, 20 explanations), edge-case robustness, LLM calls and time per message.
- Baselines: keyword rules only; the same LLM with one prompt and no tools.

## 5. Milestones

| Date | Goal |
|---|---|
| 28 Nov | Agent loop, request and urgency detectors, verdict logic with tests (Gulmira); link inspector first version (Ulzhan); UI skeleton (Tomiris) |
| 1 Dec | Dev set (30) and test set (70) labelled and cross-checked |
| 4 Dec | End-to-end in the web UI with all three tools; first full evaluation run |
| 8 Dec | Prompts frozen; baselines run; results table |
| 11 Dec | README from a clean machine, DECISIONS.md, REFLECTION.md, agent logs |
| 13 Dec | Tag `v1.0` (code freeze) |

## 6. Stretch goals (only after v1.0 scope is done)

- Screenshot input (model reads the text, same pipeline).
- Telegram bot on the same pipeline.

## 7. Risks

- Few real Kazakh scam texts → adapt from Russian ones and mark them `adapted`.
- Legitimate bank messages contain codes and links → detectors must respect "do not share this code" phrasing; covered by tests.
- API cost → Haiku model, one full evaluation run under $1; tests never call the real API.
