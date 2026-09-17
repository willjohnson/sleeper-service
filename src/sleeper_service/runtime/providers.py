"""Provider model construction with scoped credential resolution.

Order: agent → team → tenant provider credential (encrypted rows; narrowest
wins, so spend maps to the vendor bill at the right level) → process
environment (pydantic-ai's own env-var lookup). The `test` provider maps to
pydantic-ai's TestModel so demos, tests, and CI run without vendor keys.
"""

import time
from decimal import Decimal
from typing import NamedTuple

import anyio
import httpx
from pydantic_ai.exceptions import ModelHTTPError
from pydantic_ai.models import Model as PaiModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sleeper_service.constants import KeyScope
from sleeper_service.crypto import decrypt
from sleeper_service.db.models import Agent, ProviderCred

SUPPORTED_PROVIDERS = {"anthropic", "openai", "google", "openrouter", "test"}


# OpenRouter records the real charge per generation, which is the only source
# that knows what a call through an aggregator actually cost. Bounded tightly:
# this runs on the job's finishing path and must never delay or fail it.
OPENROUTER_COST_URL = "https://openrouter.ai/api/v1/generation"
OPENROUTER_COST_TIMEOUT_S = 5.0
OPENROUTER_COST_ATTEMPTS = 3
OPENROUTER_COST_BACKOFF_S = 1.0
# Whole-call ceiling. Per-generation retries alone bound nothing: a run with
# several generations multiplies them, and this sits on the finishing path.
OPENROUTER_COST_DEADLINE_S = 20.0


class CostLookup(NamedTuple):
    """What the generation records could say about a run's real charge.

    `total` is the sum over the generations that answered — None when none of
    them did. `missing` counts those whose record never arrived, and is the
    part that matters to a caller: a sum with missing generations is a lower
    bound, not the charge, and the difference is money that no spending limit
    will ever see.
    """

    total: Decimal | None
    missing: int


async def fetch_openrouter_cost(api_key: str, generation_ids: list[str]) -> CostLookup:
    """Real USD charged for these generations, as far as it can be known.

    Static price tables cannot price an aggregator: OpenRouter routes a request
    to whichever upstream is available, and bills what that upstream charged.
    genai-prices has no entry for most of these model refs at all, so without
    this the cost is recorded as zero and the agent's spending limit — enforced
    against accumulated cost — never binds.

    Fails open, always. A pricing lookup is not worth failing finished work
    over, and the caller keeps its zero-and-say-so behaviour when `total` is
    None. The record is written asynchronously by OpenRouter and is not always
    there the instant a completion returns, hence the short retry — and the
    one most likely to be missing is the final, largest generation, the one
    that just returned. Reporting that sum as the charge understates a run by
    exactly its most expensive call, so a gap is counted and returned rather
    than folded silently into a plausible-looking number.
    """
    if not api_key or not generation_ids:
        return CostLookup(None, 0)
    deadline = time.monotonic() + OPENROUTER_COST_DEADLINE_S
    total = Decimal(0)
    found = False
    missing = 0
    async with httpx.AsyncClient(timeout=OPENROUTER_COST_TIMEOUT_S) as http:
        for generation_id in generation_ids:
            resolved = False
            for attempt in range(OPENROUTER_COST_ATTEMPTS):
                if time.monotonic() >= deadline:
                    break
                try:
                    response = await http.get(
                        OPENROUTER_COST_URL,
                        params={"id": generation_id},
                        headers={"Authorization": f"Bearer {api_key}"},
                    )
                    if response.status_code == 404:
                        # Not written yet; give it a moment before giving up.
                        await anyio.sleep(OPENROUTER_COST_BACKOFF_S * (attempt + 1))
                        continue
                    response.raise_for_status()
                    cost = (response.json() or {}).get("data", {}).get("total_cost")
                    if cost is not None:
                        total += Decimal(str(cost))
                        found = True
                        resolved = True
                    break
                except Exception:
                    break
            if not resolved:
                missing += 1
    return CostLookup(total if found else None, missing)


def validate_model_registration(provider: str, model_string: str) -> str | None:
    """Check a registry row before it is written. Returns an error, or None.

    The two fields drive different things at run time and neither validates
    the other: `resolve_api_key` looks the credential up by the `provider`
    column, while `build_model` picks the SDK from the model string's own
    prefix. A row where they disagree fetches one vendor's key and hands it to
    another vendor's client — an authentication failure at job time, with
    nothing in the message pointing back at the registry. So they have to
    agree here, where the mistake is still visible.
    """
    prefix, sep, _ = model_string.partition(":")
    if provider not in SUPPORTED_PROVIDERS:
        return f"Unknown provider {provider!r}; one of {sorted(SUPPORTED_PROVIDERS)}"
    if not sep:
        return f"Model string {model_string!r} must be 'provider:model', e.g. {provider}:some-model"
    if prefix != provider:
        return (
            f"Model string {model_string!r} names provider {prefix!r}, but the row says "
            f"{provider!r} — the credential is looked up by the latter and the client built "
            "from the former, so they must match"
        )
    return None


async def resolve_api_key(db: AsyncSession, agent: Agent, provider: str) -> str | None:
    for scope, scope_id in (
        (KeyScope.AGENT, agent.id),
        (KeyScope.TEAM, agent.team_id),
        (KeyScope.TENANT, agent.tenant_id),
    ):
        cred = await db.scalar(
            select(ProviderCred).where(
                ProviderCred.scope == scope,
                ProviderCred.scope_id == scope_id,
                ProviderCred.provider == provider,
            )
        )
        if cred is not None:
            return decrypt(cred.credentials_enc)
    return None


def build_model(model_string: str, api_key: str | None) -> PaiModel | str:
    provider_name, _, model_name = model_string.partition(":")

    if provider_name == "test":
        if model_name == "flaky":
            # Always raises a retryable 503 — exercises the DLQ/alerting path
            # in demos and tests without a real provider outage.
            from pydantic_ai.messages import ModelResponse
            from pydantic_ai.models.function import AgentInfo, FunctionModel

            def _raise_503(messages: list, info: AgentInfo) -> ModelResponse:
                raise ModelHTTPError(status_code=503, model_name="test:flaky")

            return FunctionModel(_raise_503)

        from pydantic_ai.models.test import TestModel

        return TestModel()

    if api_key is None:
        # Let pydantic-ai resolve credentials from the environment.
        return model_string

    if provider_name == "anthropic":
        from pydantic_ai.models.anthropic import AnthropicModel
        from pydantic_ai.providers.anthropic import AnthropicProvider

        return AnthropicModel(model_name, provider=AnthropicProvider(api_key=api_key))
    if provider_name == "openai":
        from pydantic_ai.models.openai import OpenAIChatModel
        from pydantic_ai.providers.openai import OpenAIProvider

        return OpenAIChatModel(model_name, provider=OpenAIProvider(api_key=api_key))
    if provider_name == "google":
        from pydantic_ai.models.google import GoogleModel
        from pydantic_ai.providers.google import GoogleProvider

        return GoogleModel(model_name, provider=GoogleProvider(api_key=api_key))
    if provider_name == "openrouter":
        from pydantic_ai.models.openai import OpenAIChatModel
        from pydantic_ai.providers.openrouter import OpenRouterProvider

        return OpenAIChatModel(model_name, provider=OpenRouterProvider(api_key=api_key))

    raise ValueError(f"Unsupported provider {provider_name!r}")
