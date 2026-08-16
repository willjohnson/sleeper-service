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

Since then the security follow-up list below has been worked down: as of
2026-08-11 the only open item is screening text inside binary uploads, and
172 tests are green.

## Remaining from the build plan

1. **Runner tier 3 — hosted sandboxes** (BUILD_PLAN § Runner design) —
   extension point only: an E2B/Modal backend drops into the
   `runtime/runners.py` REGISTRY if an operator ever wants VM-grade
   isolation without local infra. No planned work.

## Security follow-ups (low severity, from audit-2 review)

Two security audits ran 2026-08-03 — Gemini 3.6 Flash ([SECURITY_AUDIT_REPORT.md](SECURITY_AUDIT_REPORT.md)) and GPT-5.6 Sol ([SECURITY_AUDIT_REPORT_2.md](SECURITY_AUDIT_REPORT_2.md)); all findings are remediated with regression tests. A third audit ran 2026-08-04 ([SECURITY_AUDIT_REPORT_3.md](SECURITY_AUDIT_REPORT_3.md)); its critical and high findings (#1 `local` data store, #2 OIDC issuer SSRF, #3 event-source file isolation) are remediated with regression tests. Review of those fixes found #2's incomplete — the endpoints the discovery document advertises were still unvalidated — and closed it; see the report's Post-Audit Review.

A fourth audit ran 2026-08-04 ([SECURITY_AUDIT_REPORT_4.md](SECURITY_AUDIT_REPORT_4.md)) — Claude Opus 5, whole codebase rather than a diff. Six findings (3 high, 3 medium), **all remediated with regression tests in the same pass**: SSO sessions carrying roles in every tenant, link fetching never resolving its destination, unauthenticated Redis on `0.0.0.0` plus arq's pickle deserializer, credential-less cloud data stores running on the platform's own cloud identity, anonymous tenant enumeration on the login page, and a client-declared content type skipping the injection screen. 154 tests green.

**Deploy notes from audit 4** (do these when shipping it). Nothing has been
deployed anywhere yet, and the local dev environment was checked on 2026-08-05
and needs none of them — Redis was empty (and has no volume, so it is
ephemeral), and the one local data store has credentials:

- [x] ~~**Drain the arq queue** before/while deploying — jobs are now
  JSON-serialized, and pickle payloads already in Redis will not
  deserialize.~~ — closed 2026-08-15. The serializer change had already been
  deployed to the only Sleeper Service environment (local); Redis DB 0 was
  inspected afterward and `arq:queue` had length 0, with no `arq:job:*` or
  `arq:result:*` keys. The sole `arq:*` key was the current worker's health
  check, so there were no legacy payloads to delete. A fresh deployment also
  starts with an empty queue.
- [x] ~~**Review existing credential-less `s3` / `gcs` / `azure_blob`
  data-store rows** — the new gate cannot establish who created historical
  rows (same caveat as the audit-3 `local` rows).~~ — closed 2026-08-16. The
  only Sleeper Service environment is local. Its `data_stores` table contains
  one `s3` row with encrypted credentials, no `gcs` or `azure_blob` rows, and
  no credential-less rows of any of those three types. No historical rows
  needed remediation; the creation gate covers new rows.
- [x] ~~**Set `requirepass` on Redis** and move `REDIS_URL` to
  `redis://:pw@redis:6379/0`. Loopback binding closed the remote path; this
  closes reachability-as-authorization. Left undone because it needs a
  coordinated env change.~~ — done 2026-08-16. Compose now requires a
  URL-safe `REDIS_PASSWORD`, starts Redis with `requirepass`, authenticates
  its health check through `REDISCLI_AUTH`, and injects authenticated URLs
  into the API and worker. Host-side tests use the same password on isolated
  DB 1. The local credential was generated in the gitignored `.env`, Redis,
  API, and worker were recreated, authenticated `PING` returned `PONG`, an
  unauthenticated one returned `NOAUTH`, `/healthz` reported Redis healthy,
  the worker became healthy, and all 172 tests passed.

Remaining low-severity items from the review of the audit-2 fixes:

- [x] ~~Rotate the CSRF token on login instead of carrying the pre-auth token
  into the authenticated session~~ — done 2026-08-05. `rotate_csrf_token()`
  mints a fresh token after the session is rebuilt, on both the local login
  and the SSO callback. Regression tests assert the pre-auth token stops
  working and the new one starts; both were confirmed to fail against the
  pre-fix code.
- [x] ~~Key the login rate limit on the real client IP behind a reverse
  proxy~~ — done 2026-08-05. `client_ip()` reads X-Forwarded-For, but only as
  far as the new `TRUSTED_PROXY_HOPS` setting says there are real proxies
  (default 0 = ignore the header, since trusting it on a directly-exposed
  deployment would let anyone bypass the limit by varying it per request).
  Regression test: one address exhausting its budget no longer locks the
  account for another.
- [x] ~~Treat a delivery-time `OutboundUrlError` as permanent instead of
  retrying the callback `callback_max_tries` times~~ — done 2026-08-05. It
  now raises `CallbackDestinationRejected` (a `CallbackDeliveryError`
  subclass), which the worker records and alerts on immediately instead of
  scheduling retries that would re-resolve the same name and fail
  identically. Transient failures retry exactly as before.

**This clears the audit-2 review list.** What remains below needs a
threat-model decision rather than an implementation.

Items that were parked for a threat-model decision. Both audit-3 entries are
now closed; the audit-4 residual at the end is the only one still open, and it
is the one that genuinely needs a policy call rather than a validator:

- [x] ~~**Tenant-defined injection regex ReDoS** (audit-3 #4)~~ — closed
  2026-08-05 by bounding execution rather than restricting authorship, so
  tenant admins keep self-service patterns. Three changes: the injection
  patterns moved from stdlib `re` to `regex`, which resists catastrophic
  backtracking far better *and* honours a `timeout=` checked during matching
  (a stdlib match cannot be interrupted at all — it runs in C and ignores
  cancel scopes, so the "wrap it in `anyio.fail_after`" option originally
  written here would not have worked); the whole pass shares one
  `INJECTION_SCREEN_TIMEOUT_S` budget so extra rules do not buy extra worker
  time; and it runs via `screen_injection_async` off the event loop, since
  the workers are shared across tenants. Exhausting the budget **fails
  closed**, returning `screen_timeout:<rule>` so unscreened content is
  rejected and the offending pattern is named in the job events.

  Two corrections to the original write-up, both found while fixing it: the
  blocking was on the worker's **event loop**, not a thread, so a hostile
  pattern stalled every concurrent job in the process rather than one; and
  `regex` alone removes the classic catastrophic cases at small inputs (58s →
  1ms on `^(\w+\s?)*$`), but they still blow up at realistic content sizes of
  a few KB, which is what makes the timeout load-bearing rather than
  decorative.
- [x] ~~**Notification (Apprise) URLs unvalidated outbound** (audit-3 #5)~~ —
  closed 2026-08-11 by doing both of the options originally listed here, since
  they turned out to solve different halves. The scheme allowlist is what stops
  `dbus://` / `macosx://` / `syslog://`, which notify the **worker host** rather
  than the network — a case the write-up above missed by framing the finding as
  purely a reachability probe. The host check is what closes the probe itself.
  `HOSTED_APPRISE_SCHEMES` (endpoint fixed by the provider, so the authority is
  credentials — `slack://TokenA/TokenB/TokenC` — and resolving it would reject a
  good URL) is split from `CUSTOM_HOST_APPRISE_SCHEMES` (self-hosted servers and
  generic webhooks, host validated exactly like a callback); anything on neither
  list is refused. `NOTIF_EXTRA_SCHEMES` widens the set but always as
  custom-host, so widening can never buy an exemption from the address check,
  and tenant `notif_scheme_allowlist` intersects rather than unions. Validated
  at creation and again at delivery against a fresh resolution.

  Two notes from building it. `mailto://` is deliberately **not** allowlisted:
  Apprise connects to a provider-mapped server or `smtp.<domain>`, never the
  URL's own host, so host validation there would be validating the wrong name —
  email alerts go through `mailgun` / `sendgrid` / `ses` instead. And the
  compose demo alerts to `json://demo-sink:8080/alerts`, an in-network name that
  the new rule correctly rejects; `NOTIF_ALLOW_PRIVATE_HOSTS=true` is the
  supported way to run it (also the honest answer for self-hosters alerting to
  an internal Mattermost or Gotify), and `sleeper demo-seed` now says so.
- [ ] **Screen text inside binary uploads** (audit-4 #6 residual): the
  content-type sniffer stops injection text from *posing* as a PDF, but a
  genuine PDF with the text in a compressed content stream still reaches the
  model unscreened — models extract it, `hooks.screen_untrusted` cannot.
  **Designed 2026-08-12 — see [BUILD_PLAN](BUILD_PLAN.md) § Binary upload
  screening.** Worth correcting one framing in the line above: this is not a
  missing hook. The pre-hook is default-on and correct; `_load_file_content`
  simply never adds a binary file to the list it screens, so the hook is
  handed an empty feed. The work is an extraction step upstream of it, and
  the screen itself does not change.

  Two things the design surfaced that make this more than a library call.
  Extraction means running pypdf over hostile input **inside the worker**,
  which holds `SECRET_KEY` and every decrypted provider credential — the
  `docker` runner backend is the obvious containment, but it is opt-in behind
  `RUNNER_BACKENDS`, so the sandboxed path cannot be the default. And
  coverage is inherently partial (encrypted PDFs, scans, unknown formats),
  which is what makes the fail-open / fail-closed / conditional-on-grants
  choice the real decision rather than an implementation detail.
  Recommendation is in the section: conditional on grants, phased in behind
  a fail-open first cut.

## Housekeeping

- **Repo is public on GitHub:** https://github.com/willjohnson/sleeper-service —
  CI runs on push.
- **Demo poller is stopped** (as of 2026-08-05). `api` and `worker` **are**
  running as of 2026-08-11 — the earlier note here said otherwise and was
  wrong; they were up, just idle, so `/ui` is reachable. Nothing is spending
  OpenRouter credit while the demo profile is down. Restart the app after
  source changes with `docker compose up -d --build api worker` (the `--build`
  is needed to pick them up), and add `--profile demo` for the poller, which
  posts a real OpenRouter job every 30s (~$0.30/day). Stop it again with
  `docker compose --profile demo down` when not demoing. The demo's alert
  channel needs `NOTIF_ALLOW_PRIVATE_HOSTS=true` to deliver (see audit-3 #5
  above); it is **not** set in the local `.env`.
- **Demo risk-analyzer has `memory_approval` on**, so its memory proposals
  queue as pending in the UI (`/ui`, login = the `sleeper init` credentials).
  Approve/reject or toggle the option off.
- [x] ~~**MinIO credentials** (audit-4, the one that mattered most here)~~ —
  rotated 2026-08-11, and the shipped default is gone rather than replaced.
  `minio_access_key` / `minio_secret_key` are now required settings with no
  default, and compose uses `${MINIO_ACCESS_KEY:?...}` instead of a fallback,
  so there is nothing left to leave unrotated: BYO s3 endpoints are an intended
  feature, a tenant admin can point a data store at the platform's own MinIO,
  and a published pair made that a cross-tenant read of the payload bucket.
  Verified locally: a roundtrip succeeds on the new pair and `sleeper` /
  `sleeper-minio-secret` now gets `PermissionError`. **The demo `reference`
  data store had the old pair encrypted in its row** and was re-encrypted with
  the new one — worth remembering for any real deployment, since rotating the
  server alone silently breaks every data store configured with the old pair.
  CI names its own throwaway pair; `tests/conftest.py` reads `.env` for it the
  same way it already read the host-port overrides.
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
