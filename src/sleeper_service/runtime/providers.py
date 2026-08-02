"""Provider model construction with per-tenant credential resolution.

Order: tenant provider credential (encrypted row) → process environment
(pydantic-ai's own env-var lookup). The `test` provider maps to pydantic-ai's
TestModel so demos, tests, and CI run without vendor keys.
"""

import uuid

from pydantic_ai.models import Model as PaiModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sleeper_service.constants import KeyScope
from sleeper_service.crypto import decrypt
from sleeper_service.db.models import ProviderCred


async def resolve_api_key(db: AsyncSession, tenant_id: uuid.UUID, provider: str) -> str | None:
    cred = await db.scalar(
        select(ProviderCred).where(
            ProviderCred.scope == KeyScope.TENANT,
            ProviderCred.scope_id == tenant_id,
            ProviderCred.provider == provider,
        )
    )
    return decrypt(cred.credentials_enc) if cred else None


def build_model(model_string: str, api_key: str | None) -> PaiModel | str:
    provider_name, _, model_name = model_string.partition(":")

    if provider_name == "test":
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
