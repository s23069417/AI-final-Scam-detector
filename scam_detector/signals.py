"""Shared contract between the tools, the agent loop and the verdict logic.

Every tool returns a list of Signal objects. A Signal always carries the exact
text span (`evidence`, `start`, `end`), so an explanation can only point at
things a tool really found in the message.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Callable

SEVERITIES = ("low", "medium", "high")


@dataclass(frozen=True)
class Signal:
    id: str  # e.g. "code_request"; the full list is in PLAN.md
    tool: str  # name of the tool that found it
    severity: str  # "low" | "medium" | "high"
    evidence: str  # the matched text, copied from the original message
    start: int  # character offsets in the original message
    end: int

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"unknown severity {self.severity!r}")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# run(message, tool_input) -> list[Signal]
ToolFunction = Callable[[str, dict], list[Signal]]


@dataclass(frozen=True)
class Tool:
    name: str
    description: str  # what the LLM reads to decide whether to call the tool
    input_schema: dict  # JSON Schema of the arguments the LLM may pass
    run: ToolFunction

    def api_definition(self) -> dict[str, Any]:
        """The tool definition in the format the Claude Messages API expects."""
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": self.input_schema,
        }


# Schema for tools that need no arguments: they analyse the message itself.
NO_ARGUMENTS = {"type": "object", "properties": {}, "additionalProperties": False}
