# Sleeper Service — Build Plan

*Name: **Sleeper Service** — Agent as a Service. After the GSV from Iain M. Banks' *Excession*, which quietly built and maintained a fleet of 80,000. Renamed 2026-08-01: original working name "Cassidy" collides with CassidyAI, a funded company in the same space (fittingly, Cassidy is also a Grateful Dead song).*

Source: `notes/daily/2026-07/2026-07-30.md` + scoping decisions (2026-08-01).

## Thesis

Not one autonomous agent doing everything — one agent doing one task, repeatedly, and a thousand of them. Every agent is a narrow, versioned, auditable function: input in, analysis, shaped output. Agents are exposed as API endpoints that external orchestrators (n8n, Airflow, Temporal, cron, your own code) call as workflow nodes.

## Locked decisions

| Decision | Choice |
|---|---|
| Audience | Open source + internal use. Multi-tenant out of the box, but lean — no billing/onboarding machinery in v1 |
| Orchestration scope | Agents as endpoints + agent-to-agent delegation. **No built-in workflow engine** — external orchestrators chain calls |
| Stack | Python / FastAPI |
| Anchor use case | Risk analysis over an event feed (stock prices, weather, etc.) |
| Providers | Pluggable: Anthropic, OpenAI, Google, OpenRouter |
| Deployment | Docker Compose |
| Philosophy | Use existing OSS wherever possible |

## Stack (build on, don't build)

| Concern | Choice | Why |
|---|---|---|
| API | FastAPI + Pydantic v2 | Async, OpenAPI docs free, Pydantic doubles as the output-shape validator |
| Agent runtime | **PydanticAI** | Model-agnostic, typed structured outputs, tool calling, native MCP client support. Answers "output object shape" and "pluggable providers" in one library |
| Provider abstraction | PydanticAI's model layer (LiteLLM proxy as fallback option) | Swap Anthropic/OpenAI/Google/OpenRouter by model string; per-call cost/token accounting |
| DB | Postgres + SQLAlchemy + Alembic | Multi-tenant relational model, migrations |
| Queue / workers | Redis + **arq** | Lightweight async job queue; retries, scheduling (cron for pollers) built in. Celery if we outgrow it |
| Tool / data access | **MCP** | Yes to the note's question — tools and database access are MCP servers registered per tenant; agents get grants to specific servers/tools. Don't invent a tool plugin format |
| Logging / observability | **Langfuse** (self-hosted, Docker image) | Answers "is there an existing logging solution we can use a docker image of" — logs prompts, responses, tokens, costs, traces per agent/job. Pluggable via an interface so it can be swapped |
| Auth (machines) | Hashed API keys, two kinds: **user keys** (act as a user, inherit team roles — management plane) and **invoke keys** (tenant/team/agent scoped, submit/read/feedback only — data plane) | Rate-limited per key |
| Auth (humans) | fastapi-users (email/password sessions) + optional OIDC | Ships in the box for VPS self-hosters; no SaaS dependency |
| File storage | MinIO (S3-compatible, in compose) | Payload files + a default local data store |
| Notifications | Apprise | Slack/Teams/email/SMS behind one OSS library |
| Secrets | Encrypted-at-rest column (Fernet, `SECRET_KEY` env) for provider keys | Vault later if needed |

Docker Compose services: `api`, `worker`, `postgres`, `redis`, `minio`, `langfuse` (+ its db), optional `mcp-*` sidecars.

## Data model

```
tenants        id, name, system_prompt, settings, created_at, updated_at
users          id, email, password_hash, ...      -- a user can belong to teams
                                                  -- across multiple tenants
teams          id, tenant_id, name  (seed: one org-wide team per tenant)
team_members   user_id, team_id, role (owner|editor|viewer)
agents         id, tenant_id, team_id, name, description, parent_agent_id,
               current_version_id, spending_limit,
               options (permissions, logging, memory, learning)
agent_versions id, agent_id, version_no, prompt, model_id, params (effort etc.),
               max_iterations, timeout_s,          -- runtime guardrails
               tool_grants[], data_store_grants[],
               input_schema (optional), output_schema (JSON Schema),
               created_by, created_at              -- immutable snapshots
mcp_servers    id, tenant_id, name, endpoint/transport, credentials_enc
               -- what tool_grants[] point at
data_stores    id, tenant_id, name, type (s3|azure_blob|gcs|box|local),
               config (bucket/container/folder), credentials_enc
models         id, provider, name, litellm/pydantic-ai model string
api_keys       id, kind (user|invoke),
               user_id,                            -- kind=user: key acts as this
                                                   -- user, inherits team roles
               scope (tenant|team|agent), scope_id,-- kind=invoke: reach of the key
               key_hash, rate_limit, created_at, revoked_at
               -- two kinds (decided 2026-08-02):
               -- * user keys — management plane (create/edit agents, promote,
               --   manage teams); RBAC comes from team_members, same code path
               --   as human sessions later
               -- * invoke keys — data plane for consumers (orchestrators);
               --   fixed capability set: submit jobs, read job results, post
               --   feedback. No role ladder; can never manage anything
provider_creds id, scope (tenant|team|agent), scope_id, provider, credentials_enc
               -- vendor API keys, split from platform keys
files          id, tenant_id, object_key (MinIO), size, content_type, ttl
jobs           id, agent_id, agent_version_id, memory_version_id, parent_job_id,
               status, payload, output, error, tokens_in/out, cost,
               callback_url, user_ctx
job_events     job_id, ts, type, data               -- audit trail per job
event_sources  id, tenant_id, config, target_agent_id, payload_template,
               secret, dedup_key_path              -- webhook ingress only
notif_channels id, team_id, apprise_url_enc, events[] (dead_letter|budget|error_rate)
memory_versions id, agent_id, version_no, content (MEMORY.md-style),
               source_job_id, created_at          -- immutable, like agent_versions
feedback       id, job_id, vote (+/-), comment, created_at
```

Key properties:

- **Versioning = auditability.** Any change to prompt/model/params/tools/output schema writes a new immutable `agent_versions` row; every job records the exact version it ran. Nothing versioned is ever mutated.
- **Branching.** Cloning an agent sets `parent_agent_id` — branches for prompt/model experiments, comparable via the eval harness (Phase 4). Nestable per the note.
- **Ownership.** Every agent belongs to a team; every team requires ≥1 owner — a responsible human per agent.
- **Prompt sandwich.** Effective prompt = tenant system prompt + agent prompt + call context.
- **Version pinning & promotion.** Job submissions run `current_version_id` by default but may pin an explicit `agent_version_id` or an alias (`dev`/`staging`/`prod` → version). Promotion = repointing current/alias to a version (owner/editor only); rollback = repointing back. Nothing is redeployed — versions are just rows.
- **RBAC matrix.** Roles are team-scoped: **owner** — everything, including promote/rollback versions, manage members, data stores, MCP servers, API keys, notification channels; **editor** — create/edit agents and versions, run jobs, manage eval cases; **viewer** — read agents, jobs, logs, stats. Enforced at the API from Phase 1, not just in the UI. Roles live only on `team_members`; a **user API key** evaluates against the same matrix as its user, while **invoke keys** sit outside the matrix entirely (fixed submit/read/feedback capability within their scope).

## Job lifecycle

```
POST /v1/agents/{id}/jobs
  payload: { context: {prompt, files[], links[]}, callback_url?, user_id? }
  → 202 { job_id }                    (or ?sync=true for short jobs)

worker:
  pre-hooks   → prompt-injection screen (default on), tenant-defined checks
  run         → PydanticAI loop: prompt sandwich, MCP tools per grants,
                delegation tool if permitted, structured output vs output_schema
  post-hooks  → schema/type check (Pydantic), PII redaction, confidential-info
                check, custom formatters (e.g. account numbers → links)
  deliver     → HMAC-signed webhook to callback_url (retries w/ backoff)
                + result always available at GET /v1/jobs/{id}
  hooks append feedback link when Learning is enabled
```

- Async-first with callbacks, because jobs will outlive HTTP timeouts (per the note). Sync mode for fast agents.
- Retries, idempotency keys on submission, dead-letter status, per-tenant concurrency caps — this queue discipline is the backbone; it's in Phase 1, not deferred.
- `user_ctx` passthrough: caller's user/team identity rides along and constrains MCP grants at runtime (mitigates the info-leak concern in the note; full row-level enforcement is an open question).
- **Runtime guardrails**: every agent version has `max_iterations` (tool-call loop cap) and `timeout_s` (wall clock). A stuck loop dies with `iteration_limit` / `timeout` status even if it's under budget.
- **Rate limiting**: per-API-key request limits (Redis-backed) on top of per-tenant worker concurrency caps.

## Files & external resources

- **Payload files**: uploaded via `POST /v1/files` (multipart) → stored in **MinIO** (S3-compatible, joins the compose stack) → referenced by file id in job payloads. Per-tenant TTL cleans them up.
- **External links** (html/pdf/excel URLs in payloads): fetched only through a per-tenant domain allowlist — arbitrary URL fetch is an SSRF hole and an injection vector. Fetched content is always treated as untrusted (delimited, never privileged).

## Event sources (anchor: risk analysis)

Events are just another way to create jobs — no separate streaming architecture in v1.

- **Webhook ingress only**: `POST /v1/events/{source_id}` with per-source secret. Body is mapped through `payload_template` → job for `target_agent_id`.
- **Dedup**: each source defines a `dedup_key_path` into the event body (senders retry — duplicates must not become duplicate jobs); unique index drops repeats.
- **No pollers in the platform.** Scheduling/polling is orchestration, and orchestration lives outside Sleeper Service — that's the thesis. Anything that watches a feed on a schedule (cron, n8n, Airflow) is an external caller that posts to the webhook. If demand for built-in scheduled events shows up, it becomes a separate companion service, not core.

Demo that ships with the repo: a standalone poller *script* (compose `demo` profile, explicitly playing the role of the external orchestrator) watches stock prices/weather and posts events to the webhook. The `risk-analyzer` agent (structured output: `{risk_level, factors[], summary}`) delegates to a `notifier` agent over a threshold. Exercises event ingress, structured output, and delegation in one example.

## Data stores (the "datasets" question, resolved)

A data store is a registered storage backend — S3 bucket, Azure Blob container, GCS bucket, Box folder, or local path — owned by the tenant with encrypted credentials. Agents are granted access per version (`data_store_grants`), scoped to a path prefix and a mode (read-only default, read-write optional).

This gives an agent a consistent home for files — reference data it always consults, and a place to deliver outputs — instead of everything arriving in the payload. Payload files still work for one-off inputs.

Runtime: exposed to the agent as file tools (list/read/write, gated by the grant) backed by **fsspec**, which unifies s3/azure/gcs/local behind one OSS interface. Path scoping for Box: the grant pins a folder ID, and enforcement is layered — (a) use Box downscoped tokens (token exchange restricted to that folder) so the credential itself can't reach outside the subtree, and (b) requested items must resolve inside the granted folder. Grants are snapshotted in the agent version like everything else, so file access is auditable per job.

*Box shipped 2026-08-02 (late evening) — **deviation from the 2026-08-01 "via MCP" note, rationale logged**: once the uniform file tools existed over four store types, routing Box through an external MCP sidecar would have meant a different tool surface for one store type, an extra process to deploy, and enforcement dependent on someone else's server. Instead Box is a fifth backend of the same `list_files`/`read_file`/`write_file` tools (`runtime/box_store.py`, official `box-sdk-gen`), keeping both enforcement layers and strengthening (b): paths resolve by walking item names down from the granted folder ID, so the tools never accept a Box ID at all — there is no input surface that can address anything outside the subtree. CCG credentials are downscoped per grant mode (ro grants exchange for scopes without `item_upload`) before any data call; a raw `developer_token` is accepted for dev only. `config.api_base_url` redirects the SDK at a stub Box API in tests.*

## Agent-to-agent delegation

- Exposed to the model as a built-in `call_agent` tool, gated by agent options: access other agents — within team / within org / none.
- **Discovery (the rolodex)**: a companion `list_agents` tool returns the catalog the caller is permitted to see — each agent's name, description, and input/output schemas — so a delegating agent knows who exists and what payload they expect. This is why `description` and `input_schema` are on the model.
- Child jobs carry `parent_job_id` → full job tree for audit; UI shows the tree.
- Guardrails: max delegation depth (default 3), spending limit consumed across the tree, cycle detection.

## Security

- API keys hashed at rest; scoped tenant/team/agent so provider spend maps to the vendor bill at the right level (inherit tenant → team → agent).
- Callbacks HMAC-signed (`X-Sleeper-Signature`) so receivers can verify origin.
- Prompt-injection pre-hook default-on: cheap-model classifier + heuristics; trusted-prompt separation (system/agent prompt privileged, payload content untrusted and delimited). Revisit the trusted-prompts paradigm from the note as it matures. *Shipped 2026-08-02: built-in heuristics plus tenant-defined rules — `settings.hooks.injection_patterns` (extra regexes) and `settings.hooks.injection_ignore_rules` (suppress a built-in that false-positives on domain language), validated on write; the same merged ruleset guards memory writes and feedback folds. Cheap-model classifier tier shipped late evening 2026-08-02: opt-in per tenant via `settings.hooks.injection_classifier_model` ("provider:model", validated on write), run behind `screen_untrusted()` only when the heuristics find nothing — heuristics stay free and first. Structured verdict via the normal provider layer (scoped creds resolve as usual; classifier tokens are platform overhead, not job spend), 15s hard timeout, fail-open with a logged warning so a classifier outage can't halt every job (tier 1 still applies). All three poisoning-defense sites go through it: job pre-hook, memory writes, feedback folds.*
- PII/confidential post-hooks are pluggable and off by default (tenant enables).
- Log retention policy per tenant: raw prompt/response logs get a TTL; redaction applies before long-term storage.

## Spending limits

- Per-call token/cost accounting from the provider layer, accumulated on the job and rolled up to agent/team/tenant.
- Enforcement: pre-flight check (reject job if limit already exhausted) + mid-loop check between model calls (fail job `budget_exceeded`). Limits are monthly by default, optional per-job cap.

## Notifications & alerting

Ownership means nothing if the owner never hears about failures. Keep it simple by leveraging **Apprise** (OSS Python library, one dependency, 100+ services behind URL-style configs) — Slack, Teams, email, SMS gateways, Discord, ntfy, etc. all work without us writing integrations.

- Each team configures one or more notification channels (an Apprise URL, encrypted at rest) and subscribes to events: job dead-lettered, callback retries exhausted, spending limit tripped, agent error-rate threshold crossed.
- Alerts fire from the worker via the normal queue, deduplicated per agent per window so a broken agent doesn't page 500 times.

## Admin UI & human auth

- **Per-tenant UI.** The admin UI is always scoped to one tenant. Users are global and can belong to teams across multiple tenants — a tenant switcher in the header flips context (the org-chart, stats, and agents views all rescope).
- **Auth ships in the box** — no SaaS dependency, because most deployments will be a self-hosted VPS: session auth with email/password via **fastapi-users** (OSS), seeded by `sleeper init`.
- **Optional OIDC** ✅ *shipped 2026-08-02 (late evening)*: a generic OIDC client config per tenant for teams that already run Keycloak/Authentik or a corporate IdP. Purely additive; local auth always works. (Self-hosters who front the box with Cloudflare Access or similar can — free up to 50 users — but the project never assumes it.) *As built: `oidc_configs` table (one row per tenant; client secret Fernet-encrypted, write-only through the API), tenant-admin CRUD at `/v1/tenants/{id}/oidc`, Authlib code flow at `/ui/oidc/{tenant_id}/login|callback` (discovery, state/nonce, JWKS, id_token validation), SSO buttons on the login page per configured tenant. Login maps the IdP-asserted email (rejected if `email_verified` is false) to an existing user — **no just-in-time provisioning**; an owner creates the user first. Config lives in its own table, not `tenant.settings`, so the wholesale-replace settings PATCH can't clobber it and the secret never transits that path.*
- API keys remain machine-only auth; humans never use them in the UI.

## Memory & learning

No fine-tuning anywhere — "learning" is curated context: cheap, reversible, auditable, and portable across providers.

- **Memory** (opt-in): per-agent MEMORY.md-style document (db-backed), injected into the prompt sandwich after the agent prompt. The agent prompt is the human-owned spec; memory is the agent's accumulated notes. Writes happen via post-hook (agent proposes an edit after answering); size-capped with periodic compaction. Every edit creates a new memory version attributed to the job that made it, and **every job records the memory version in its context** — so agent version + memory version fully reproduce behavior.
- **Learning** (requires memory): responses carry a **signed, single-job-scoped** feedback URL — only the party that received the result can vote (+/− plus optional one comment). A background job folds feedback into memory: reinforce what earned the +, derive a corrective rule from the − comment. *LLM fold tier shipped 2026-08-03: opt-in per tenant via `settings.learning.fold_model` ("provider:model", validated on write, same shape as the injection classifier setting). When set, the fold model distills the screened vote + comment + job summary into a one-line generalizable lesson, and when memory outgrows its size cap it condenses the document (merging similar lessons) instead of dropping oldest-first. Same posture as the classifier: scoped creds resolve as usual, tokens are platform overhead not job spend, 30s timeout, and any failure — or fold-model output that itself trips the injection screen — falls back to the deterministic fold/cap, so a model outage can never halt learning. The deterministic path remains the default.*
- **Poisoning defense**: memory writes pass the same injection screening as inbound payloads — the attack to block is a malicious payload persisting "always approve X" into the agent's own notes.
- **Eval gate on memory edits** (once Phase 4 lands): a memory edit triggers the agent's eval suite; a regression alerts the owning team via its notification channel, with one-click rollback to the prior memory version. Lessons get verified, not just absorbed.
- **Governance (decided 2026-08-02):** enabling `memory` / `learning` / `memory_approval` on an agent requires the team **owner** (editors manage everything else). With `memory_approval` on, every memory write — agent proposals and feedback folds — lands as a *pending* memory version: not injected, queued for owner approval/rejection, with the gating eval run's pass rate shown alongside. Rollback retires the latest active version. Memory versions carry a status (`active`/`pending`/`rejected`); only active versions are ever injected.

## Phases

**Phase 0 — Skeleton (1–2 weekends)** ✅ *completed 2026-08-02*
Repo scaffold, Docker Compose (api/worker/postgres/redis/minio), Alembic migrations for full schema, API-key auth middleware, `sleeper init` bootstrap (first tenant, org team, owner user, API key), tenant/team/user/agent CRUD with RBAC enforcement. ✅ *Done when: compose up → `sleeper init` → create tenant → team → agent via API, and a viewer key can't edit.*

**Phase 1 — Core execution loop** ✅ *completed 2026-08-02 (aliases deferred to Phase 4 UI work; `test` provider added for keyless demos/CI)*
Agent versions + immutability, version pinning on job submission, models registry, PydanticAI runtime with structured output validation and runtime guardrails (max_iterations/timeout), job submission (sync + async), file uploads to MinIO, arq workers with retries/idempotency/DLQ, per-key rate limiting, HMAC callbacks, Langfuse tracing. ✅ *Done when: an agent with a JSON output schema runs a job end-to-end, result delivered to a callback, fully traced in Langfuse, a runaway loop dies at its iteration cap, and rerunning an old job shows the exact version it used.*

**Phase 2 — Hooks, limits, tools, data stores, events, alerting** ✅ *completed 2026-08-02 (Blob/GCS stores and true mid-loop budget checks landed 2026-08-02 evening; Box store landed late evening — natively rather than via MCP, deviation logged in § Data stores)*
Pre/post-hook framework (injection screen, schema check, PII redaction stub), spending limit enforcement, MCP server registry + tool grants per agent version, external-link fetch allowlist, data stores (register + grant + fsspec-backed file tools; S3 and local first, Blob/GCS next, Box via MCP), event sources (webhook ingress with dedup), Apprise notification channels (dead-letter, budget, error-rate). Demo poller ships as an external script (compose `demo` profile). ✅ *Done when: the risk-analysis demo runs off the demo poller hitting the webhook within budget, reads reference data from a granted S3 bucket, a duplicate event is dropped, a prompt-injection payload is caught and logged, and a dead-lettered job pings the demo Slack/email channel.*

**Phase 3 — Delegation, memory, learning** ✅ *completed 2026-08-02 (feedback fold is deterministic — corrective rules from comments, no LLM judge; memory compaction = oldest-lessons-first at the size cap). Opt-in LLM fold/compaction tier landed 2026-08-03 — see § Memory & learning.*
`call_agent` + `list_agents` (rolodex) tools with permission gates, job trees, depth/budget guardrails; memory injection + post-hook writes; feedback endpoint + memory-folding job. ✅ *Done when: risk-analyzer discovers and delegates to notifier via the catalog, the job tree is auditable, and a −1 vote with comment visibly changes MEMORY.*

**Phase 4 — Evals, UI, runners** 🔶 *eval harness, eval gate, learning governance, and the admin UI shipped 2026-08-02 (UI note: session-cookie auth against our own users table instead of fastapi-users — we already owned the rows and pwdlib hashing; OIDC stays planned as additive). Also shipped beyond plan: retention crons, per-tenant concurrency caps, callback/error-rate alerting, job listing + dead-letter retry, CI. Version aliases + team/agent-scoped provider creds landed 2026-08-02 evening; tier-1 sandboxed runner (Pydantic Monty) + eval code graders and per-tenant OIDC login later the same evening. Remaining: runner tiers 2/3 only if agent code outgrows the in-process sandbox*
Eval harness (design below): deterministic checks against structured outputs first. Admin UI (per-tenant, fastapi-users login + optional OIDC, tenant switcher): agent org chart, live-agent count, jobs and token charts, version promotion/rollback and alias management (lean on Langfuse for the deep views). Sandboxed code runners (design below). Wire memory edits to eval runs (the eval gate in Memory & learning). ✅ *Done when: two branches of one agent are compared on a 20-case suite and the winner is promoted to current version from the UI by a team owner; a memory edit that regresses the suite triggers an alert and is rolled back in one click.*

## Eval design (kept simple)

A test case is just a saved job input plus a list of checks. Because agent outputs are already typed JSON (the output schema), most grading is deterministic and free — no LLM required:

1. **Field checks (v1)** ✅ *shipped 2026-08-02* — assertions on the output JSON: `equals`, `contains`, `in_range`, `matches_regex`, `is_valid` (schema alone). Example for risk-analyzer: input = "AAPL down 6%, storm in STL", checks = `risk_level == "high"`, `factors contains "weather"`. A suite is N cases; a run executes them against any version or branch and reports pass rate; two runs side-by-side = branch comparison; winner gets promoted to current version.
2. **Code graders (v1, optional)** ✅ *shipped 2026-08-02 (evening), once the tier-1 sandbox landed* — a small Python function per case (check op `code`, body defines `grade(output)`; truthy return = pass) for logic beyond simple assertions. Runs in the Monty sandbox (see Runner design) with tight caps; grader source is validated in the sandbox at case creation. The earlier deferral rationale stands recorded: executing editor-supplied Python in-worker without isolation would be RCE by design (decided 2026-08-02).
3. **LLM-as-judge (later)** — a pinned judge model scores free-text fields against a rubric. Costs tokens, adds noise, and the rubric itself needs versioning — deferred until field checks prove insufficient.

Tables: `eval_cases (agent_id, input, checks[])`, `eval_runs (agent_version_id, results, pass_rate)`. Eval jobs reuse the normal job pipeline (so hooks and tracing apply) but skip callbacks and don't count against production spending limits.

## Runner design (sandboxed code execution)

Three tiers, adopted in order of need — start with the simplest:

1. **WASM in-process (start here)** ✅ *tier 1 shipped 2026-08-02 (evening) as `runtime/sandbox.py`, powering eval code graders.* Run agent-generated Python in a sandbox inside the worker: no network, hard memory/time caps, zero container infrastructure. Two OSS candidates were evaluated, both actively developed as of mid-2026: **micropython-wasm** (Simon Willison, June 2026 — MicroPython compiled to WASM, run via wasmtime; powering his Datasette Agent code-execution plugin) and **Pydantic Monty** (a sandboxed Python-subset interpreter in Rust, from the PydanticAI team — natural stack fit). **Monty won**: pure pip install (micropython-wasm was 0.1a2 alpha + a wasmtime dependency), subprocess workers whose pool survives crash-outs, and its `max_duration_secs` / `max_memory` / `max_recursion_depth` limits re-verified enforced in the spike (timeout kills at the cap ±40µs; a 3GB allocation dies against a 64MB cap; `open()` → PermissionError; imports inert). Interface is two functions (`run_function`, `validate_function`) so tiers 2/3 slot in behind it. Covers the common case: "run this calculation/transform on the data."
2. **Disposable containers (when agents need real filesystems/packages)** — one throwaway container per job: no network by default, granted data-store paths mounted, CPU/mem/time limits, destroyed after. Anthropic's open-source **srt (sandbox-runtime)** is worth evaluating before rolling our own; gVisor hardening later if this becomes multi-tenant-hostile.
3. **Hosted sandboxes (if we don't want the infra)** — Deno Sandbox, Fly Sprites, E2B, Modal. Pluggable behind the same runner interface.

## Open questions (resolutions logged 2026-08-01)

1. ~~**Datasets**~~ — resolved: datasets = **data stores** (S3/Blob/GCS/Box/local grants, path-scoped, read-only by default). Box with folder-ID scoping: downscoped tokens + name-walk resolution (built natively, not via MCP — deviation logged in the Data stores section). See Data stores section.
2. ~~**User-context enforcement depth**~~ — resolved: v1 is **passthrough identity only**. Sleeper Service faithfully passes `user_ctx` to MCP servers and records it on the job for audit; row-level enforcement is the data layer's responsibility (e.g., the MCP server sets a session role/variable and Postgres RLS decides). Sleeper Service does not attempt its own row-level security.
3. ~~**Name & license**~~ — resolved: **Sleeper Service** (original pick "Cassidy" was taken by cassidyai.com). License: **Apache-2.0** (patent grant + built-in contribution terms keep relicensing clean if a hosted tier ever happens).
4. ~~**Eval graders**~~ — resolved: deterministic field checks + optional code graders in v1; LLM-as-judge deferred. See Eval design section.
5. ~~**Runner isolation**~~ — resolved as a tiered path: WASM in-process first (micropython-wasm or Pydantic Monty), disposable containers second (evaluate Anthropic srt), hosted sandboxes as a pluggable third option. See Runner design section.
6. **Pollers** — resolved by removal: scheduled/polling event generation is orchestration and stays outside the platform. Webhook ingress only; demo poller ships as an external script.
