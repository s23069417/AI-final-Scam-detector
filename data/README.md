# Labelled messages

## Format

Each file is JSONL (one JSON object per line). Fields:

| Field | Description |
|---|---|
| `id` | Unique id, e.g. `en001`, `kz015`, `ru042` |
| `text` | The message text, as the user would paste it |
| `label` | `scam`, `suspicious`, or `legitimate` — set by a human before the system is run |
| `language` | `ru` (Russian), `kz` (Kazakh), `en` (English), `mixed`, or `edge` |
| `notes` | Why this label; what signals we expect; for `adapted` messages, the source |

## Labelling rules

- Labels are set before the system is run on the message.
- Each test-set label is checked by a second group member.
- Prompts are tuned on `dev/` only. No group member looks at `test/` messages
  before the prompt freeze (see PLAN.md).
- Phone numbers, card numbers, and names are invented (never real).
- Kazakh scam texts adapted from Russian are marked `"adapted": true`.

## Ownership

| Member | Messages |
|---|---|
| Gulmira | Russian messages (`ru*`) |
| Ulzhan | Kazakh messages (`kz*`), evaluation scripts |
| Tomiris | English (`en*`), mixed-language (`mx*`), edge cases (`edge*`) |
