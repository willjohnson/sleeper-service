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

Two security audits ran 2026-08-03 — Gemini 3.6 Flash ([SECURITY_AUDIT_REPORT.md](SECURITY_AUDIT_REPORT.md)) and GPT-5.6 Sol ([SECURITY_AUDIT_REPORT_2.md](SECURITY_AUDIT_REPORT_2.md)); all findings are remediated with regression tests. A third audit ran 2026-08-04 ([SECURITY_AUDIT_REPORT_3.md](SECURITY_AUDIT_REPORT_3.md)); its critical and high findings (#1 `local` data store, #2 OIDC issuer SSRF, #3 event-source file isolation) are remediated with regression tests. Review of those fixes found #2's incomplete — the endpoints the discovery document advertises were still unvalidated — and closed it; see the report's Post-Audit Review. Remaining low-severity items from the review of the audit-2 fixes:

- [ ] Rotate the CSRF token on login instead of carrying the pre-auth token into
  the authenticated session (`ui/routes.py` login, `ui/oidc.py` callback)
- [ ] Key the login rate limit on the real client IP behind a reverse proxy —
  `request.client.host` is the proxy, making the limit per-email and enabling
  cheap account-lockout DoS
- [ ] Treat a delivery-time `OutboundUrlError` as permanent instead of retrying
  the callback `callback_max_tries` times (`runtime/callbacks.py`)

Open by design from audit-3 (require a threat-model decision before tightening):

- [ ] **Tenant-defined injection regex ReDoS** (audit-3 #4): `settings.hooks.injection_patterns`
  are tenant-admin-supplied and run synchronously in worker threads via
  `screen_injection` with no thread offload or timeout (unlike the tier-2
  classifier, which is wrapped in `anyio.fail_after`). A catastrophic-
  backtracking regex could hang workers against crafted inbound content. Options:
  run the heuristic pass in a thread with a hard timeout, or restrict custom
  regex authorship to instance superusers (which removes a tenant feature
  audit 2 deliberately added).
- [ ] **Notification (Apprise) URLs unvalidated outbound** (audit-3 #5):
  `POST /v1/teams/{team_id}/notif-channels` accepts arbitrary Apprise URLs
  from team owners and `runtime/notify` POSTs alert titles/bodies to them —
  a server-side outbound path with no `validate_callback_*`-style check.
  Alert content is platform-controlled so leakage is limited, but an owner
  could confirm internal reachability. Options: an `apprise_allowlist` per
  team/tenant, or restricting Apprise schemes to a vetted set.

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
