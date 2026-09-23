"""Starter model registration and provider request compatibility."""

import pytest
from pydantic_ai.models import infer_model
from pydantic_ai.models.anthropic import AnthropicModel
from pydantic_ai.models.openai import OpenAIResponsesModel
from sqlalchemy import select

from sleeper_service.cli.main import _seed_models
from sleeper_service.db.models import Model
from sleeper_service.db.session import get_sessionmaker
from sleeper_service.runtime.providers import build_model, validate_model_registration


async def test_seed_models_registers_gpt6_and_opus55_once():
    await _seed_models()
    async with get_sessionmaker()() as db:
        first = {row.id for row in await db.scalars(select(Model))}
    await _seed_models()
    async with get_sessionmaker()() as db:
        rows = list(await db.scalars(select(Model)))
    assert {row.id for row in rows} == first
    registered = {(row.provider, row.name): row.model_string for row in rows}
    for provider, name in (
        ("openai", "gpt-6-sol"),
        ("openai", "gpt-6-astra"),
        ("openai", "gpt-6-luna"),
        ("anthropic", "claude-opus-5-5"),
    ):
        assert registered[provider, name] == f"{provider}:{name}"
        assert validate_model_registration(provider, registered[provider, name]) is None


@pytest.mark.parametrize("name", ["gpt-6-sol", "gpt-6-astra", "gpt-6-luna"])
@pytest.mark.parametrize("scoped_key", [None, "scoped-key"])
def test_gpt6_uses_responses_with_scoped_or_environment_credentials(monkeypatch, name, scoped_key):
    monkeypatch.setenv("OPENAI_API_KEY", "environment-key")
    model = infer_model(build_model(f"openai:{name}", scoped_key))
    assert isinstance(model, OpenAIResponsesModel)
    assert model.model_name == name
    assert model.client.api_key == (scoped_key or "environment-key")
    assert model.profile["openai_supports_reasoning"]
    assert model.profile["openai_supports_encrypted_reasoning_content"]
    assert model.profile["openai_supports_phase"]
    assert model.profile["thinking_always_enabled"] == (name == "gpt-6-astra")
    assert model.profile["openai_supports_reasoning_effort_none"] == (name != "gpt-6-astra")


@pytest.mark.parametrize("scoped_key", [None, "scoped-key"])
def test_opus55_uses_native_output_without_forced_tools(monkeypatch, scoped_key):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "environment-key")
    model = infer_model(build_model("anthropic:claude-opus-5-5", scoped_key))
    assert isinstance(model, AnthropicModel)
    assert model.model_name == "claude-opus-5-5"
    assert model.client.api_key == (scoped_key or "environment-key")
    assert model.profile["default_structured_output_mode"] == "native"
    assert model.profile["supports_json_schema_output"]
    assert model.profile["thinking_always_enabled"]
    assert not model.profile["anthropic_supports_forced_tool_choice"]
