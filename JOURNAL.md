## 2026-09-22 05:47 #jev #providers
- OpenRouter lists `typesafe/jev-1.13` and the alias `~typesafe/jev-latest`.
- Jev uses a structured-decision API; it accepts state and typed questions and cannot generate prose or call tools. OpenRouter's example uses `alpha.decisions.create` (https://openrouter.ai/labs/jev/compile).
- Sleeper's OpenRouter integration constructs PydanticAI's OpenAIChatModel. Registering Jev alone would not provide a working integration.
- Requested Will's direction on adding decision-agent configuration and execution, since this changes the agent runtime and supported capabilities.
- OpenRouter documents `POST https://openrouter.ai/api/v1/systemone`, accepting `model`, `state`, and `questions`, returning `answers` plus `usage.input_tokens`, `usage.output_tokens`, and `usage.cost`. Existing OpenRouter credentials can be reused (https://openrouter.ai/docs/guides/community/typesafe-sdk).
- Proposed integration: register the pinned Jev model, store typed questions in immutable version configuration, execute one decision request within the existing job lifecycle, preserve returned probabilities and billed cost, and reject unsupported tools or output configurations. No application code changed pending the runtime scope decision.

## 2026-09-22 06:12 #jev #implementation
- Will approved adding decision-agent support. Questions use existing immutable version `params.questions`; no database migration is needed.
- OpenRouter's live API and public OpenAPI schema require instructions for every question, unlike TypeSafe's schema. Optional noul criteria require both true and false descriptions. Validation follows OpenRouter's contract.
- A live request with synthetic support text successfully returned noul, choice, and score answers through the adapter: 393 input tokens, USD 0.000016506 billed. Its probabilities and confidence values were preserved.
- Starter models include Jev 1.13; demo setup selects its tool-capable Gemini model explicitly so seeding Jev cannot change demo behavior.
- Jev, job, infrastructure, and UI regression checks: 197 passed. Six existing Starlette status-name deprecation warnings remain outside the Jev paths. Formatting and lint checks passed.
- Final full-suite verification: 361 passed, with 22 existing Starlette status-name deprecation warnings. No new dependencies or migrations. Existing installations register Jev by running `sleeper seed-models` after deploying the code.

## 2026-09-22 06:28 #release #pr
- Will requested a pull request and specified version 0.1.5. Package metadata, runtime version, and lockfile agree on 0.1.5; offline lockfile validation, formatting, lint, and diff checks pass.
