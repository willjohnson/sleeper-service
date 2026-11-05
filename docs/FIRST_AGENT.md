# From a running service to a working agent

[`DEPLOY.md`](DEPLOY.md) ends with a service that answers `/healthz`. This picks
up there and builds something real on it: an agent that reads a file from
object storage, produces structured output, is driven from outside by a script,
and is scored by a second agent.

The worked example is a model eval — port a 1980s BASIC game to a modern
browser game, then judge the result — because it exercises nearly every seam:
data stores, grants, schemas, invoke keys, the job trail, delegation-shaped
composition, and per-model comparison. Substitute your own task; the shape
holds.

## 1. A bucket for tenant data

Do not reuse the payload bucket from `DEPLOY.md`. That one holds every tenant's
uploads and the platform's own credentials for them, and `config.py` is explicit
that a tenant-configurable S3 data store pointed at it turns "read a file" into
a cross-tenant read. Keep the boundary even when you are the only tenant.

1. Create a second R2 bucket — `sleeper-data`.
2. Create an **Account** API token scoped to that bucket alone, *Object Read &
   Write*. Leave client IP filtering empty: a managed host's egress addresses
   are not stable.
3. Upload your source file under a prefix, e.g. `basic/GAME2.BAS`.

## 2. Register it as a data store

**Connections → new data store.** A store is the *registration* — bucket,
endpoint, encrypted credentials — and is reusable. Scoping happens later, at the
grant.

| Field | Value |
|---|---|
| Name | `game-source` |
| Type | `s3` |
| Config | `{"bucket": "sleeper-data", "endpoint_url": "https://<account-id>.r2.cloudflarestorage.com"}` |
| Credentials | `{"access_key": "…", "secret_key": "…"}` |

**Fill in Credentials even though the form lets you skip it.** An instance
superuser may save a credential-less store, which then runs on the platform's
ambient identity — the payload-bucket token, which cannot see this bucket. It
saves cleanly and fails at job time against the wrong bucket.

## 3. The agent

**Agents → New**, in a team of its own so spend and alerts stay separate.

The create form publishes a complete first version — prompt, model, guardrails,
params, schemas and grants. Fill in all of it. An agent whose purpose is reading
a store is not merely limited without the grant; it is *misleading*, because
without the grant there is no `read_file` tool at all and the model answers from
the prompt alone. That looks like a working agent until you check what it saw.

**Spending limit is US dollars per month, not tokens.** It sits next to
max-iterations and timeout and reads as a bare number.

The grant is three fields — store, prefix, mode:

```
game-source   basic   ro
```

Grants live on the **version**, not the agent and not the store. Versions are
immutable: there is no route that edits one, so changing a prompt, a param or a
grant means publishing a new version. That is the point rather than the cost —
every job records exactly which version ran, so "what produced this output" is
always answerable.

### Paths are relative to the grant

The grant prefix is already applied. With the grant above, the agent reads
`GAME2.BAS`, not `basic/GAME2.BAS`, and `list_files` returns paths in that same
form so an entry can be passed straight back to `read_file`.

### The payload is a prompt string

A job's input is `{"context": {"prompt": "..."}}` — free text, plus optional
file ids and links. It is not an arbitrary JSON object, so a prompt that refers
to "the `source_file` field of the input" refers to nothing. Say what you want
in the prompt text.

`input_schema` is real but does not validate anything: it exists so `list_agents`
can tell a *delegating* agent what payload you expect. Only output is
schema-validated.

### Give the model room

`params` is passed through to the provider, and `max_tokens` caps the
**response**, not the input. A large generated artifact needs a large ceiling —
you are billed for what is produced, so an unused ceiling costs nothing. Too low
does not truncate the artifact gracefully; it breaks the JSON string and
surfaces as a schema violation, which reads like the model failing to follow
instructions.

## 4. Drive it from outside

The admin UI's Test run is for smoke tests. The product's actual story is an
orchestrator calling an agent, so use an invoke key.

**Issue a team-scoped key** if more than one agent is involved. Keys are scoped
to an agent, a team, or a tenant, and an agent-scoped key reaches exactly one
agent — correct until a second one exists. Invoke keys are data-plane only:
submit jobs, read results, post feedback. They cannot edit an agent or publish a
version.

One boundary to know: `/v1/files` admits only **tenant**-scoped invoke keys.
Narrower keys stay on the job surface. If you need to pass a large artifact to
an agent and do not want a tenant-wide key, put it in the prompt — the request
body cap is 1 MiB.

Keep the key out of your shell history and out of files:

```bash
security add-generic-password -a "$USER" -s sleeper-invoke-key -w   # macOS
```

Submitting is a POST and a poll:

```
POST /v1/agents/{agent_id}/jobs   Authorization: Bearer <key>
     {"context": {"prompt": "..."}}          -> 202 + job id
GET  /v1/jobs/{job_id}                       -> status, tokens, cost, output
GET  /v1/jobs/{job_id}/events                -> the trail
```

`?sync=true` runs inline for fast agents and is capped by
`SYNC_JOB_TIMEOUT_S`; anything slow should be async.

## 5. Read the trail

`GET /v1/jobs/{id}/events` is where a job explains itself:

- `tool_call` — one per call, with the tool, the outcome, and the shape of its
  arguments. This is how you know the agent used its grant rather than answering
  from the prompt. An `outcome` of `retry` means the tool refused and the model
  tried again, which can still end in a succeeded job.
- `cost_unpriced` — the run's cost is **unknown**, not zero. Spending limits are
  enforced against accumulated cost, so a limit does not bind for a model
  nothing can price. Models routed through an aggregator are priced by asking
  the aggregator; anything else depends on a static table's coverage.
- `output_mode_fallback` — the model refused a forced tool call, so the schema
  was asked for in the prompt and parsed. Worth knowing when comparing runs.
- `requeued` — the worker was restarted mid-run and the job went back on the
  queue. Expected on a host that redeploys on push.

## 6. Score it with a second agent

Deterministic checks cannot judge whether a result is *good*. Eval checks are
`equals`, `contains`, `in_range`, `matches_regex`, `is_valid`, and `code` — and
`code` graders run in a sandbox with no imports, filesystem or network, so they
do string and structure work only.

The way through is a second agent that turns judgement into numbers, which
`in_range` can then assert on. Give it an output schema of scores rather than
prose, and ask for the specific failure you fear by name — a judge told to look
for unreachable states will trace them, where one asked for "quality" returns a
paragraph.

This works better than it sounds. In the worked example the judge read a
generated game and reported `playable: 1/5`, naming the exact handler
responsible for a dead end a human had found by playing it.

## 7. Compare models

A version pins one model, so comparison is one version per model against the
same eval suite. Two things bite before the models do:

- **Not every model accepts a forced tool call**, which is how structured output
  is normally requested. The runtime falls back to prompted output and records
  it, but the modes differ, so note which runs fell back.
- **A provider key may be scoped wrongly.** An organisation-level Anthropic key
  is rejected without a workspace header, which the platform does not send —
  create the key inside a workspace.

Register each model under **Models** with its provider, your label, and the
pydantic-ai model string. The provider column selects the stored API key while
the model string selects the client, so they must agree: an aggregator-routed
model keeps the aggregator as its provider, whichever vendor built the model.

## Keep the prompt and the checks in step

The most expensive mistake in this example was not a bug. A check demanded a
`<canvas>` the prompt never asked for, and later the prompt lost a requirement a
check still wanted. Both times the model did exactly as told and the eval
disagreed.

Whatever the suite asserts, the prompt must require — changed in the same edit,
or the scores measure the gap between two documents rather than the models.
