**AI Scam Detector**

**Final Project Proposal · Repository: github.com/s23069417/AI-final-Scam-detector**

**Group №11: Kabylkhanova Gulmira, Askar Ulzhan, Nurbolat Tomiris**
# **Problem and user**
Fraudulent SMS and WhatsApp/Telegram messages (“your card is blocked”, “you won a prize”, “send the code from the SMS”) are hard for ordinary people to recognise. Our users are students and their parents, who receive such messages often and have no quick way to check them. AI Scam Detector is a web app: the user pastes a message in Russian, Kazakh or English and gets a verdict (scam / suspicious / legitimate), a plain-language explanation that points to the specific warning signs, and advice on what to do. It shows risk signals only; it does not prove fraud.
# **AI feature and how we measure it**
The AI feature is an LLM with tool use. The LLM decides which tools to call and reads their output: a link and domain inspector (follows short-URL redirects via HEAD requests without loading pages; checks domains against a list of official Kazakhstan bank domains and flags look-alikes), and rule-based detectors of urgency and of requests for codes, card data or transfers. The verdict combines the LLM’s judgement with the tool results, and an explanation may cite only signals that the tools actually found. We freeze the prompts, then evaluate on 100 labelled messages (50 scam, 50 legitimate incl. 15 realistic bank-style notifications with codes or links; a third each in Russian, Kazakh, English), split 30 development / 70 held-out test, plus edge cases such as empty, very long and mixed-language messages. Labels are assigned before running the system and each test label is checked by a second member; prompts are tuned only on the development set, and the prompt author does not see test messages before the freeze. Scarce Kazakh scam texts are adapted from real Russian ones (marked). Per-language results (~23 test messages each) are indicative.

|**Metric**|**How it is measured**|
| :- | :- |
|Accuracy|Share of test messages classified correctly (suspicious counted as scam)|
|Missed-scam rate|Share of scam messages the system labels legitimate (the costly error)|
|False-alarm rate|Share of legitimate messages the system labels scam or suspicious|
|Groundedness|Share of signals named in explanations that match the tool output|
|Explanation quality|0–2 rubric (correct, specific, actionable), two independent raters, 20 explanations|
|Robustness and cost|Edge cases handled cleanly; LLM calls and time per message|

We compare against two baselines: simple keyword rules, and the same LLM in a single prompt with no tools.
# **Agentic tool**
All members build the project with Claude Code, a paid terminal agent that plans, writes, runs and fixes code in the repository. We chose it because free tiers allow too few requests for several people working daily. PLAN.md is written before the code, sessions are kept short and focused, and any tool switch will be recorded in DECISIONS.md. The LLM API used inside the product is billed separately and funded by the group.
# **MVP and stretch goals**
MVP by 16 November: a first end-to-end version for text messages (paste a message, get a verdict and an explanation) with the link check and at least one more tool, a first labelled set, first tests and the first agent logs. By the code freeze: the full evaluation on 100 messages with both baselines, tests, README and the required process files.

Stretch goals (only if time allows):

- Screenshots of messages: the model reads the text from the image, then the same pipeline runs.
- A Telegram bot on top of the same pipeline.

**Data and APIs**

The project uses no personal data. Phone numbers, names and card numbers in examples are replaced or invented, and we do not collect other people’s private conversations. All sources are named in the README.

|**Source**|**Used for**|**Access**|
| :- | :- | :- |
|Public fraud warnings (banks, news, official pages)|Scam examples|Public pages; collected by hand in week 1, no scraping of protected sites|
|Messages written by us|Legitimate and synthetic examples|Own data|
|Claude API (Anthropic), claude-haiku-5-5|The agent (image input for the stretch goal)|Yes, key available, funded by the group; under $1 per full evaluation run. Key and model in env variables.|
|Telegram Bot API|Bot (stretch)|Free token from BotFather|
# **Who does what**

|**Member**|**Responsible for**|
| :- | :- |
|Kabylkhanova Gulmira|LLM agent loop and verdict logic; detector of requests for codes, card data, transfers; urgency detector; README; Russian messages|
|Askar Ulzhan|Link and domain inspector; evaluation scripts and metrics; both baselines; Kazakh messages|
|Nurbolat Tomiris|Explanation generation and groundedness check; prompts; web interface; English, mixed-language and edge-case messages|

Each member tests their own part, reviews others’ code, rates explanations, keeps agent logs and commits.
