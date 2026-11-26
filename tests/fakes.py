"""A fake Anthropic client for tests. Tests never call the real API."""

from __future__ import annotations

import itertools
from types import SimpleNamespace

_ids = itertools.count(1)


def tool_use(name: str, tool_input: dict | None = None) -> SimpleNamespace:
    return SimpleNamespace(type="tool_use", id=f"toolu_{next(_ids)}", name=name,
                           input=tool_input if tool_input is not None else {})


def text(value: str) -> SimpleNamespace:
    return SimpleNamespace(type="text", text=value)


def verdict(label: str, cited: list[str] | None = None, rationale: str = "") -> SimpleNamespace:
    return tool_use("submit_verdict",
                    {"label": label, "cited_signal_ids": cited or [], "rationale": rationale})


def response(*blocks, stop_reason: str | None = None) -> SimpleNamespace:
    if stop_reason is None:
        stop_reason = "tool_use" if any(b.type == "tool_use" for b in blocks) else "end_turn"
    return SimpleNamespace(
        content=list(blocks),
        stop_reason=stop_reason,
        usage=SimpleNamespace(input_tokens=100, output_tokens=20),
    )


class FakeClient:
    """Returns scripted responses in order; an Exception in the script is raised."""

    def __init__(self, *script):
        self.script = list(script)
        self.calls: list[dict] = []
        self.messages = self  # so that client.messages.create(...) works

    def create(self, **kwargs):
        # Copy the list: the agent keeps appending to the same list object.
        self.calls.append({**kwargs, "messages": list(kwargs["messages"])})
        if not self.script:
            raise AssertionError("the agent made more LLM calls than the test expected")
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item
