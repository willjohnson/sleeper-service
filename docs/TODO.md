# Outstanding work

State as of 2026-08-03: Phases 0–3 complete; Phase 4 mostly complete (evals,
governance, admin UI, ops hardening shipped). Quick-win batch landed
2026-08-02: version aliases, true mid-loop budget checks, team/agent-
scoped provider creds, Azure Blob/GCS data stores. Tier-1 sandboxed runner
(Pydantic Monty, `runtime/sandbox.py`) + eval code graders (check op `code`),
per-tenant OIDC login (Authlib; `oidc_configs` + `/ui/oidc/...` flow), Box
data stores (native `box-sdk-gen` backend — MCP deviation logged in
BUILD_PLAN § Data stores), and the cheap-model injection classifier
(opt-in `hooks.injection_classifier_model`, fail-open tier 2 behind
`screen_untrusted()`) landed later that evening. LLM memory fold/compaction
(opt-in `settings.learning.fold_model`, deterministic fallback — BUILD_PLAN
§ Memory & learning) landed 2026-08-03, as did runner tier 2 (`runtime/
runners.py` protocol + registry; `docker` throwaway-container backend behind
`RUNNER_BACKENDS`, per-check `"runner"` field on eval code graders; srt and
E2B-as-abstraction evaluated and passed over — rationale in BUILD_PLAN
§ Runner design). 126 tests green. See BUILD_PLAN.md for design intent and
the decision log embedded in each section.

## Remaining from the build plan

1. **Runner tier 3 — hosted sandboxes** (BUILD_PLAN § Runner design) —
   extension point only: an E2B/Modal backend drops into the
   `runtime/runners.py` REGISTRY if an operator ever wants VM-grade
   isolation without local infra. No planned work.

## Security follow-ups (low severity, from audit-2 review)

Two security audits ran 2026-08-03 — Gemini 3.6 Flash ([SECURITY_AUDIT_REPORT.md](SECURITY_AUDIT_REPORT.md)) and GPT-5.6 Sol ([SECURITY_AUDIT_REPORT_2.md](SECURITY_AUDIT_REPORT_2.md)); all findings are remediated with regression tests. Remaining low-severity items from the review of the audit-2 fixes:

- [ ] Rotate the CSRF token on login instead of carrying the pre-auth token into
  the authenticated session (`ui/routes.py` login, `ui/oidc.py` callback)
- [ ] Key the login rate limit on the real client IP behind a reverse proxy —
  `request.client.host` is the proxy, making the limit per-email and enabling
  cheap account-lockout DoS
- [ ] Treat a delivery-time `OutboundUrlError` as permanent instead of retrying
  the callback `callback_max_tries` times (`runtime/callbacks.py`)

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
  `.env` — fine locally, regenerate for any shared deployment. Now surfaced:
  README quickstart note, `.env.example` LANGFUSE_INIT_* hints, and a
  `sleeper init` warning when the well-known dev keys are configured.
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
