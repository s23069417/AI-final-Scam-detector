"""Flask web interface for AI Scam Detector.

Owner: Tomiris.

Run with:
    flask --app scam_detector.app run
    # or
    python scam_detector/app.py

Needs ANTHROPIC_API_KEY in the environment or in a .env file.
"""

from __future__ import annotations

import os

from dotenv import load_dotenv
from flask import Flask, render_template, request

from scam_detector.agent import InvalidMessageError, ScamAgent
from scam_detector.explain import build as build_explanation

load_dotenv()

app = Flask(__name__, template_folder="templates")

# Created once per process; reused across requests.
_agent: ScamAgent | None = None


def _get_agent() -> ScamAgent:
    global _agent
    if _agent is None:
        _agent = ScamAgent()
    return _agent


@app.route("/", methods=["GET", "POST"])
def index():
    explanation = None
    message = ""
    input_error: str | None = None

    if request.method == "POST":
        message = request.form.get("message", "")
        try:
            verdict = _get_agent().analyze(message)
            explanation = build_explanation(verdict)
        except InvalidMessageError as exc:
            input_error = str(exc)
        except Exception as exc:
            input_error = f"Unexpected error: {exc}"

    return render_template(
        "index.html",
        message=message,
        explanation=explanation,
        input_error=input_error,
    )


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
