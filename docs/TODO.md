# Outstanding work

State as of 2026-08-02 (late evening): Phases 0–3 complete; Phase 4 mostly
complete (evals, governance, admin UI, ops hardening shipped). Quick-win batch
landed 2026-08-02: version aliases, true mid-loop budget checks, team/agent-
scoped provider creds, Azure Blob/GCS data stores. Tier-1 sandboxed runner
(Pydantic Monty, `runtime/sandbox.py`) + eval code graders (check op `code`)
landed later that evening. 86 tests green. See BUILD_PLAN.md for design intent
and the decision log embedded in each section.

## Remaining from the build plan

1. **Runner tiers 2/3** (BUILD_PLAN § Runner design) — tier 1 (in-process
   Monty sandbox) shipped and powers eval code graders. Disposable
   containers (evaluate Anthropic srt) and hosted sandboxes remain, needed
   only if agent code requires real filesystems/packages.
2. **OIDC login** — additive to the existing session auth (see
   `ui/routes.py` docstring for the fastapi-users deviation rationale).
3. **Data stores: Box** — via MCP with folder-ID scoping: downscoped tokens +
   wrapper verification (design in BUILD_PLAN § Data stores).
4. **Cheap-model injection classifier** — second screening tier behind the
   existing `hooks.screen_injection()` seam, for content heuristics miss.
5. **LLM-based memory folding/compaction** — v1 fold is deterministic;
   compaction is oldest-lessons-dropped at the size cap.

## Housekeeping

- **Repo is on GitHub (private):** https://github.com/willjohnson/sleeper-service —
  flip visibility with `gh repo edit --visibility public` when ready; CI runs
  on push.
- **Demo poller is running** (`docker compose --profile demo`) and posts a
  real OpenRouter job every 30s (~$0.30/day). Stop with
  `docker compose --profile demo down` when not demoing.
- **Demo risk-analyzer has `memory_approval` on**, so its memory proposals
  queue as pending in the UI (`/ui`, login = the `sleeper init` credentials).
  Approve/reject or toggle the option off.
- **Placeholder Langfuse keys** (`pk-lf-sleeper-dev`) and demo passwords in
  `.env` — fine locally, regenerate for any shared deployment.
- Structured logging is minimal (request IDs + basicConfig); JSON logs and
  API↔worker correlation would help at scale.

## Dev environment notes (this machine)

- Compose defaults to standard host ports (5432/6379); this machine overrides
  to 5433/6380 via POSTGRES_HOST_PORT/REDIS_HOST_PORT in the gitignored .env
  (native services occupy the defaults here). Tests honor the same overrides
  and create a `sleeper_test` DB.
- colima runs docker (4 CPU / 6 GiB — resized for Langfuse; no buildx, keep
  the Dockerfile legacy-builder-compatible).
- `scripts/screenshots.py` recaptures the README screenshots against a
  running stack (Playwright chromium is a dev dep).
