"""The agent loop: the LLM decides which tools to call, reads their output and
ends with a verdict.

Owner: Gulmira.

One call of `ScamAgent.analyze(message)`:

    send message + tool list to the LLM
    repeat (at most `max_turns` LLM calls):
        LLM answers with tool calls  -> run them, send the results back
        LLM calls submit_verdict     -> stop
        LLM answers with text only   -> remind it once to call submit_verdict
    run the tools the LLM skipped    -> the safety floor always sees every signal
    combine LLM label + signals      -> verdict.combine()

If the API is down, rate limited, refuses, or never gives a verdict, the agent
returns a rules-only verdict (verdict.rules_only) and records why in `error`.
Configuration errors (bad key, unknown model, bad request) are raised, because
silently falling back would hide them during the evaluation.

We write the loop by hand instead of using the SDK's beta tool runner: the loop
is the part of the project we must explain line by line, and we need to stop on
submit_verdict and collect per-message statistics (LLM calls, tokens, time).
"""

from __future__ import annotations

import json
import os
import time
from typing import Any

import anthropic

from scam_detector import prompts
from scam_detector.signals import Signal, Tool
from scam_detector.verdict import LABELS, Verdict, combine, rules_only

DEFAULT_MODEL = "claude-haiku-5-5"
DEFAULT_EFFORT = "medium"
MAX_MESSAGE_CHARS = 5000  # longer inputs are rejected, never silently cut

SUBMIT_VERDICT = "submit_verdict"
SUBMIT_VERDICT_TOOL = {
    "name": SUBMIT_VERDICT,
    "description": (
        "Give the final verdict for the message. Call exactly once, after checking the "
        "message with the other tools."
    ),
    "strict": True,
    "input_schema": {
        "type": "object",
        "properties": {
            "label": {"type": "string", "enum": list(LABELS)},
            "cited_signal_ids": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Ids of tool signals that support the label.",
            },
            "rationale": {"type": "string"},
        },
        "required": ["label", "cited_signal_ids", "rationale"],
        "additionalProperties": False,
    },
}


class InvalidMessageError(ValueError):
    """The input cannot be analysed (empty or too long)."""


def default_tools() -> list[Tool]:
    """All tools of the product. The link inspector is added once it exists."""
    from scam_detector.detectors import requests, urgency

    tools = [requests.TOOL, urgency.TOOL]
    try:
        from scam_detector.tools import links  # Ulzhan's module

        tools.append(links.TOOL)
    except ImportError:
        pass
    return tools


class ScamAgent:
    def __init__(
        self,
        tools: list[Tool] | None = None,
        *,
        client: Any = None,
        model: str | None = None,
        effort: str | None = None,
        max_turns: int = 6,
    ) -> None:
        self.tools = {t.name: t for t in (tools if tools is not None else default_tools())}
        if SUBMIT_VERDICT in self.tools:
            raise ValueError(f"tool name {SUBMIT_VERDICT!r} is reserved")
        self._client = client
        self.model = model or os.environ.get("SCAM_MODEL", DEFAULT_MODEL)
        self.effort = effort or os.environ.get("SCAM_EFFORT", DEFAULT_EFFORT)
        self.max_turns = max_turns

    @property
    def client(self) -> Any:
        # Created on first use, so tests and the rules-only path need no API key.
        if self._client is None:
            self._client = anthropic.Anthropic()  # reads ANTHROPIC_API_KEY
        return self._client

    # ------------------------------------------------------------------ public

    def analyze(self, message: str) -> Verdict:
        if not message or not message.strip():
            raise InvalidMessageError("The message is empty.")
        if len(message) > MAX_MESSAGE_CHARS:
            raise InvalidMessageError(
                f"The message is longer than {MAX_MESSAGE_CHARS} characters."
            )

        started = time.monotonic()
        stats: dict[str, Any] = {
            "model": self.model,
            "prompt_version": prompts.PROMPT_VERSION,
            "llm_calls": 0,
            "input_tokens": 0,
            "output_tokens": 0,
            "tools_called_by_llm": [],
            "tool_errors": [],
        }
        signals: dict[str, list[Signal]] = {}  # tool name -> its signals

        answer, error = self._loop(message, signals, stats)

        # Tools the LLM did not call still run: the safety floor needs them.
        for name in self.tools:
            if name not in signals:
                self._run_tool(name, message, {}, signals, stats)
        stats["seconds"] = round(time.monotonic() - started, 3)

        all_signals = sorted(
            (s for found in signals.values() for s in found), key=lambda s: s.start
        )
        if answer is None:
            return rules_only(all_signals, error=error, stats=stats)
        return combine(
            llm_label=answer["label"],
            cited_ids=answer["cited_signal_ids"],
            rationale=answer["rationale"],
            signals=all_signals,
            stats=stats,
        )

    # ------------------------------------------------------------------ loop

    def _loop(
        self, message: str, signals: dict[str, list[Signal]], stats: dict[str, Any]
    ) -> tuple[dict | None, str | None]:
        """Run the conversation. Returns (verdict input, None) or (None, error)."""
        tool_definitions = [t.api_definition() for t in self.tools.values()]
        tool_definitions.append(SUBMIT_VERDICT_TOOL)
        messages: list[dict[str, Any]] = [
            {"role": "user", "content": prompts.user_prompt(message)}
        ]
        nudged = False

        for _ in range(self.max_turns):
            try:
                response = self.client.messages.create(
                    model=self.model,
                    max_tokens=4096,
                    system=prompts.SYSTEM_PROMPT,
                    tools=tool_definitions,
                    messages=messages,
                    output_config={"effort": self.effort},
                )
            except (anthropic.APIConnectionError, anthropic.RateLimitError) as exc:
                return None, f"api_unavailable: {type(exc).__name__}"
            except anthropic.APIStatusError as exc:
                if exc.status_code >= 500:
                    return None, f"api_unavailable: HTTP {exc.status_code}"
                raise  # 400/401/403/404: our configuration is wrong, do not hide it

            stats["llm_calls"] += 1
            usage = getattr(response, "usage", None)
            if usage is not None:
                stats["input_tokens"] += usage.input_tokens
                stats["output_tokens"] += usage.output_tokens

            if response.stop_reason in ("refusal", "max_tokens"):
                return None, f"llm_stopped: {response.stop_reason}"

            # Append the whole content (thinking blocks included) unchanged.
            messages.append({"role": "assistant", "content": response.content})
            tool_uses = [b for b in response.content if b.type == "tool_use"]

            if not tool_uses:
                if nudged:
                    return None, "no_verdict"
                messages.append({"role": "user", "content": prompts.NUDGE})
                nudged = True
                continue

            results = []
            answer = None
            for block in tool_uses:
                if block.name == SUBMIT_VERDICT:
                    problem = _check_verdict_input(block.input)
                    if problem is None:
                        answer = block.input
                    results.append(_tool_result(block.id, problem or "Verdict recorded.",
                                                is_error=problem is not None))
                elif block.name in self.tools:
                    stats["tools_called_by_llm"].append(block.name)
                    found = self._run_tool(block.name, message, block.input, signals, stats)
                    if found is None:
                        results.append(_tool_result(block.id, "The tool failed.", is_error=True))
                    else:
                        payload = {"signals": [s.to_dict() for s in found]}
                        results.append(
                            _tool_result(block.id, json.dumps(payload, ensure_ascii=False))
                        )
                else:
                    results.append(
                        _tool_result(block.id, f"Unknown tool {block.name!r}.", is_error=True)
                    )

            if answer is not None:
                return answer, None
            # All results of one turn go back in a single user message.
            messages.append({"role": "user", "content": results})

        return None, "turn_limit"

    def _run_tool(
        self,
        name: str,
        message: str,
        tool_input: dict,
        signals: dict[str, list[Signal]],
        stats: dict[str, Any],
    ) -> list[Signal] | None:
        """Run one tool and store its signals. Returns None if the tool crashed."""
        try:
            found = self.tools[name].run(message, tool_input or {})
        except Exception as exc:  # a broken tool must not break the whole verdict
            stats["tool_errors"].append(f"{name}: {type(exc).__name__}: {exc}")
            signals.setdefault(name, [])
            return None
        # If the LLM calls the same tool twice, keep the latest result.
        signals[name] = list(found)
        return signals[name]


def _tool_result(tool_use_id: str, content: str, *, is_error: bool = False) -> dict:
    result = {"type": "tool_result", "tool_use_id": tool_use_id, "content": content}
    if is_error:
        result["is_error"] = True
    return result


def _check_verdict_input(data: Any) -> str | None:
    """Return a problem description, or None if the verdict input is valid."""
    if not isinstance(data, dict):
        return "The verdict must be an object."
    if data.get("label") not in LABELS:
        return f"label must be one of {', '.join(LABELS)}."
    cited = data.get("cited_signal_ids")
    if not isinstance(cited, list) or not all(isinstance(i, str) for i in cited):
        return "cited_signal_ids must be a list of strings."
    if not isinstance(data.get("rationale"), str):
        return "rationale must be a string."
    return None
