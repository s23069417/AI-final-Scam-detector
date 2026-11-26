# Labelled messages

The evaluation set from PLAN.md section 4. Format and scripts: `eval/dataset.py` (Ulzhan).

## Workflow

1. Each member writes their language into `data/raw/<lang>.csv`:
   Gulmira `ru.csv`, Ulzhan `kk.csv`, Tomiris `en.csv` (+ `mixed` rows).
2. The person who writes a message sets its label **before** the system is run.
   The coding agent never sets or changes labels (CLAUDE.md rule 4).
3. `python -m eval.check_data` — format errors, personal-data warnings, counts against the plan.
4. When all three files are complete: `python -m eval.split` once.
   It writes `data/dev/messages.csv` (30%) and `data/test/messages.csv` (70%) and refuses to
   overwrite them later. The split is stratified by language and label, with a fixed seed.
5. A second member checks every **test** label and writes their name into `checked_by`.
   Disagreements are discussed and recorded in DECISIONS.md.
6. Prompts are tuned on `data/dev/` only. Nobody opens `data/test/` while working on prompts
   or detectors (CLAUDE.md rule 3).

## Plan per language

| | count |
|---|---|
| scam | 17 |
| legitimate | 16, of them 5 `bank_notification` (real-style bank SMS with codes or links) |

Spread scam messages over several categories; do not write 17 copies of one scheme.

## Columns

| column | values |
|---|---|
| `id` | unique: `kk-001`, `ru-001`, `en-001`, ... |
| `lang` | `kk`, `ru`, `en`, `mixed` |
| `label` | `scam` or `legitimate` (only two; the system's `suspicious` counts as scam) |
| `category` | scam: `fake_bank`, `fake_prize`, `fake_delivery`, `relative_in_trouble`, `fake_government`, `investment`, `other_scam`; legitimate: `bank_notification`, `personal`, `service`, `other_legitimate` |
| `text` | the message |
| `source` | `own` (written by us), `adapted` (translated or adapted from a real Russian scam), or the URL of the public warning it comes from |
| `labelled_by` | who set the label |
| `checked_by` | who checked it (required for the test set) |
| `notes` | anything else, e.g. why a hard case got its label |

## Rules

- No real personal data: invent phone numbers, names and card numbers.
  `check_data` warns about phone numbers and card numbers that pass the Luhn checksum.
- Public scam examples: collect by hand from public warnings (banks, news, official pages);
  no scraping of protected sites. Put the URL in `source`.
- Kazakh scam texts are scarce: adapting a real Russian one is fine; mark it `adapted`.
- Editing: Google Sheets (File → Download → CSV) or VS Code. Excel with a Russian locale
  may save with `;` instead of `,` — then `check_data` reports missing columns.
