"""Gemini Decisions configuration and HTTP adapter contracts."""

import copy
import json
from decimal import Decimal

import httpx
import pytest
from pydantic_ai import BinaryContent
from pydantic_ai.exceptions import ModelHTTPError

from sleeper_service.cli.main import SEED_MODELS
from sleeper_service.runtime import decisions
from sleeper_service.runtime.providers import validate_model_registration
from tests.test_jev import install_transport

MODEL = "google:gemini-decision-1"
QUESTIONS = {
    "refund": {"type": "noul", "instructions": "Refund requested?"},
    "department": {
        "type": "choice",
        "instructions": "Which department?",
        "criteria": {"billing": "Billing issues", "technical": "Technical issues"},
    },
    "urgency": {
        "type": "score",
        "instructions": "How urgent?",
        "legend": ["Low", "High"],
    },
}
ANSWERS = {
    "refund": {"type": "noul", "noul": 0.98, "confidence": 0.98},
    "department": {
        "type": "choice",
        "choice": "billing",
        "confidence": 0.95,
        "probabilities": {"billing": 0.95, "technical": 0.05},
    },
    "urgency": {
        "type": "score",
        "score": 0.8,
        "confidence": 0.9,
        "probabilities": {"0": 0.2, "1": 0.8},
    },
}
USAGE = {
    "total_input_tokens": 142,
    "total_output_tokens": 0,
    "estimated_cost_usd": "0.0000142",
}


def test_registration_and_configuration():
    assert ("google", "gemini-decision-1", MODEL) in SEED_MODELS
    assert validate_model_registration("google", MODEL) is None
    assert decisions.is_decision_model(MODEL)
    assert not decisions.is_decision_model("google:gemini-4-hydrogen")
    assert decisions.validate_decision_config(MODEL, {"questions": QUESTIONS}) is None


@pytest.mark.parametrize(
    "params",
    [
        {},
        {"questions": []},
        {"questions": {}},
        {"questions": QUESTIONS, "temperature": 0.2},
        {"questions": {"q": {"type": "predicate", "instructions": "Refund?"}}},
        {"questions": {"": {"type": "noul", "instructions": "Refund?"}}},
        {
            "questions": {
                "q": {"type": "choice", "instructions": "Choose", "criteria": {"only": None}}
            }
        },
        {"questions": {"q": {"type": "score", "instructions": "Score", "legend": ["only"]}}},
        {"questions": {"q": {"type": "noul", "instructions": {"text": "Refund?"}}}},
    ],
)
def test_invalid_configuration(params):
    assert decisions.validate_decision_config(MODEL, params)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"tool_grants": [{}]},
        {"data_store_grants": [{}]},
        {"options": {"delegation": "tenant"}},
        {"options": {"memory": True}},
        {"options": {"learning": True}},
        {"options": {"human_escalation": True}},
        {"output_schema": {}},
    ],
)
def test_unsupported_features(kwargs):
    assert decisions.validate_decision_config(MODEL, {"questions": QUESTIONS}, **kwargs)


@pytest.mark.parametrize("key", [None, "scoped-key"])
async def test_request_and_usage(monkeypatch, key):
    monkeypatch.setenv("GEMINI_API_KEY", "environment-key")
    original = copy.deepcopy(QUESTIONS)

    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == "https://generativelanguage.googleapis.com/v1beta/decisions"
        assert request.headers["x-goog-api-key"] == (key or "environment-key")
        body = json.loads(request.content)
        assert body["model"] == "gemini-decision-1"
        assert body["input"] == "My order arrived damaged."
        assert body["questions"]["refund"]["instructions"] == "Be concise.\n\nRefund requested?"
        return httpx.Response(200, json={"answers": ANSWERS, "usage": USAGE})

    install_transport(monkeypatch, handler)
    output, usage, cost = await decisions.run_decisions(
        MODEL, key, "Be concise.", ["My order arrived damaged."], original
    )

    assert original == QUESTIONS
    assert output == {"answers": ANSWERS}
    assert usage.input_tokens == 142
    assert usage.output_tokens == 0
    assert cost == Decimal("0.0000142")


async def test_multimodal_input_encoding(monkeypatch):
    monkeypatch.setenv("GOOGLE_API_KEY", "google-env-key")
    image = BinaryContent(data=b"png-bytes", media_type="image/png")

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["x-goog-api-key"] == "google-env-key"
        body = json.loads(request.content)
        assert body["input"] == [
            {"text": "Check this photo."},
            {"inlineData": {"mimeType": "image/png", "data": "cG5nLWJ5dGVz"}},
        ]
        return httpx.Response(200, json={"answers": ANSWERS, "usage": USAGE})

    install_transport(monkeypatch, handler)
    await decisions.run_decisions(
        MODEL, None, "", ["Check this photo.", image], QUESTIONS
    )


async def test_http_error_raises_model_http_error(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, text="rate limited")

    install_transport(monkeypatch, handler)
    with pytest.raises(ModelHTTPError) as exc_info:
        await decisions.run_decisions(MODEL, "key", "", ["hi"], QUESTIONS)
    assert exc_info.value.status_code == 429


async def test_rejects_mismatched_answers(monkeypatch):
    bad_answers = {**ANSWERS, "department": {**ANSWERS["department"], "choice": "unknown"}}

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"answers": bad_answers, "usage": USAGE})

    install_transport(monkeypatch, handler)
    with pytest.raises(ValueError, match="unknown choices"):
        await decisions.run_decisions(MODEL, "key", "", ["hi"], QUESTIONS)
