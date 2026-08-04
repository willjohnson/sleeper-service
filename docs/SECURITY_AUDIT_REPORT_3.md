# Sleeper Service Security Audit Report 3

**Date:** 2026-08-04  
**Audit run by:** GLM-5.2 (high reasoning)  
**Scope:** Surfaces not covered by, or regressed against, the prior audits —
the data-store registry and runtime file tools, OIDC issuer handling, event
source ingress, tenant-defined injection rules, notification egress, and
miscellaneous crypto/hardening consistency.  
**Method:** Manual review of every API route, the runner/toolset runtime, the
sandbox, and the outbound/callback validation layer, with adversarial test
cases written before each fix.

## Executive Summary

The audit identified one critical, two high, two medium, and several
defense-in-depth findings. The highest-impact path let a tenant administrator
register a `local` data store pointing at an arbitrary path in the service
container, which the runtime file tools then read and wrote as the service
user — a clean tenant-admin → instance-wide compromise that bypasses every
other boundary fixed in audit 2.

Findings 1 and 3 are remediated with code and regression coverage. Finding 2
is remediated with the same outbound-validation layer the callback path uses,
behind a dev-only escape hatch matching the existing `SESSION_HTTPS_ONLY`
pattern. Findings 4 and 5 are documented as residual risk requiring a design
decision: they change the threat model for tenant-admin-configured outbound
destinations and are intentionally not silently tightened here.

## Findings And Remediation

### 1. Critical: `local` Data Store Let Tenant Admins Read/Write Any Path in the Container

**Original issue:** `POST /v1/tenants/{tenant_id}/data-stores` gated on
`require_tenant_admin` (org-team owner or superuser). The `local` backend was
accepted with an arbitrary `config.base_path`. At run time,
`runtime/toolsets._StoreGrant.fs_and_root()` returned
`fsspec.filesystem("file"), cfg["base_path"]`, and the file tools issued
`fs.cat_file(f"{root}/{full}")` / `fs.pipe_file(...)`. `_StoreGrant.resolve()`
only constrained `full` against the grant *prefix* via `..`; it never
constrained `root`.

With `base_path="/"` and an empty grant prefix, an agent directed by the
tenant admin could `read_file` any file in the api/worker container —
`/proc/self/environ` returns `SECRET_KEY`, `DATABASE_URL`, MinIO and Langfuse
credentials — and `write_file` any path, overwriting application source for
RCE. The tenant admin controls the agent prompt and reads job outputs, so
exfiltration is direct. `SECRET_KEY` then decrypts every Fernet blob in the
database across all tenants (provider creds, MCP `user_ctx_signing_secret`s,
OIDC client secrets, apprise URLs).

This is the same trust-boundary violation audit 2 closed for stdio MCP ("only
instance superusers may register"). `local` points the service at its own
filesystem and has no legitimate tenant-admin use.

**Fix:** Only instance superusers may register `local` data stores, mirroring
the stdio MCP restriction. Tenant admins retain management of s3 / azure_blob
/ gcs / box. Operators should review existing `local` rows after upgrade.

**Regression coverage:** A tenant administrator with valid tenant-admin rights
is denied (403) when attempting to register a `local` data store; a superuser
succeeds. Other types remain tenant-admin-creatable.

### 2. High: OIDC Issuer Was an Unvalidated Server-Side Request Vector

**Original issue:** `OidcConfigSet.issuer` only validated the URL scheme
(`^https?://`). On login the server fetched
`{issuer}/.well-known/openid-configuration` and then POSTed the tenant's client
secret + authorization code to whatever `token_endpoint` that metadata
advertised, plus fetched JWKS/userinfo. A tenant admin could set `issuer` to
an internal address (cloud metadata, internal admin services) or to their own
server whose metadata pointed the `token_endpoint` anywhere — turning the
platform into a server-side request forger with controllable GET (discovery)
and POST (token callback) carrying the tenant's own secret.

The callback and link-fetch paths both pass through
`runtime/outbound.validate_callback_url` / `validate_callback_target`; the
OIDC issuer bypassed that layer entirely.

**Fix:** OIDC issuer configuration now runs the same two-phase outbound
validation: `validate_callback_url` (syntax + policy, no DNS) at write time,
and `validate_callback_target` (resolve + reject non-global addresses) at
login time immediately before Authlib fetches discovery. A dev/test escape
hatch `OIDC_ALLOW_LOOPBACK_ISSUERS` (default false, mirrors
`SESSION_HTTPS_ONLY`) lets the e2e stub IdP on 127.0.0.1 through; it must stay
false in production. Schemes remain http/https and credentials in the issuer
URL are rejected.

**Regression coverage:** A non-global IP-literal issuer and a loopback
hostname are rejected at config time; a metadata-suffix issuer without
credentials is accepted. With the dev hatch on, the stub IdP login flow still
succeeds (existing e2e test).

> **Review note (2026-08-04):** this fix was incomplete — see
> [Post-Audit Review](#post-audit-review). Validating the issuer did not
> validate the endpoints the discovery document advertises, which is where the
> client secret is actually sent. Closed separately.

### 3. High: Event-Source Ingress Did Not Validate File ids Against the Tenant

**Original issue:** `POST /v1/events/{source_id}` validated `context.links`
against the tenant allowlist but did not validate `context.files` belonged to
the agent's tenant — unlike `submit_job`, which checks every file id:

```python
for file_id in body.context.files:
    file = await db.get(File, file_id)
    if file is None or file.tenant_id != agent.tenant_id:
        raise HTTPException(422, f"Unknown file {file_id}")
```

The payload template is owner-defined but `{{path}}` substitution lets the
external event submitter (who holds only the per-source secret) supply file id
strings. `runtime/runner._load_file_content()` loads files by id with no
tenant check. A holder of an event source secret could therefore cause the
agent to ingest another tenant's file by id, surfacing its content in an
output the agent's team can read — a cross-tenant file read.

**Fix:** `ingest_event` now runs the same per-file tenant check as
`submit_job`.

**Regression coverage:** An event referencing a file id from another tenant is
rejected with 422; a same-tenant file is accepted.

### 4. Medium: Tenant-Defined Injection Regex Ran Synchronously in Worker Threads

**Original issue:** `runtime/hooks._tenant_rules` compiles
`settings.hooks.injection_patterns` (tenant-admin-supplied) and
`screen_injection` runs them synchronously from the runner, memory writes, and
feedback folds — no thread offload and no timeout, unlike the tier-2
classifier which is wrapped in `anyio.fail_after`. A catastrophic-backtracking
regex (intentional or accidental) could hang worker threads against crafted
inbound content submitted by anyone holding an invoke key or an event secret.

**Status: deferred for design decision.** Mitigations under consideration:
run the heuristic pass in a thread with a hard timeout, or restrict custom
regex authorship to instance superusers (which removes a tenant feature audit
2 deliberately added). Documented here so the tradeoff is explicit; no code
change in this remediation pass.

### 5. Medium: Notification (Apprise) URLs Are an Unvalidated Outbound Vector

**Original issue:** `POST /v1/teams/{team_id}/notif-channels` accepts arbitrary
Apprise URLs from team owners; `runtime/notify` POSTs alert titles and bodies
to them. Apprise supports many schemes, so this is a server-side outbound path
with no `validate_callback_*`-style check. Alert content is platform-controlled
(spend, error rate, eval regression), so leakage is limited, but an owner could
point delivery at internal endpoints to confirm reachability or exfiltrate.

**Status: deferred for design decision.** Inherent to bring-your-own notifier.
Mitigations under consideration: an `apprise_allowlist` per team/tenant, or
restricting Apprise schemes to a vetted set. Documented here; no code change in
this remediation pass.

### 6. Low / Defense-In-Depth

- **Event-source secret compare was not constant-time.** `events.ingest_event`
  used `hash_key(x_event_secret) != source.secret_hash` (Python `!=` on hex
  strings) while `feedback.submit_feedback` correctly used
  `hmac.compare_digest`. SHA-256 preimage makes this practically unexploitable,
  but the inconsistency is now fixed: both compare hashes with
  `hmac.compare_digest`.
- **Feedback token travels in the URL query string.**
  `learning.feedback_url` puts the signed token in `?token=`, which leaks via
  access logs / Referer. Single-job-scoped and one-vote-per-job, so impact is
  minimal; a header-based channel would be cleaner. Noted; no change.
- **File download echoes uploader content-type with no `Content-Disposition`.**
  `files.download_file` returns the uploader-supplied `media_type`. Not
  same-origin-exploitable today because API auth is Bearer, but a
  `Content-Disposition: attachment` header would harden against future UI
  changes that proxy downloads via cookies. Noted; no change.
- **BYO storage endpoints** (s3 `endpoint_url`, box `api_base_url`) are
  tenant-admin-controlled outbound connections carrying the tenant's own
  credentials. Inherent to bring-your-own storage; noted alongside finding 2.

## Verification

- Focused security regression suite: new tests added for findings 1, 2, 3, and
  the constant-time compare (6).
- Full test suite run after remediation.

## Post-Audit Review

**Reviewed by:** Claude Fable 5, 2026-08-04, against the remediation diff.

Findings 1, 3, and the constant-time compare in 6 were confirmed accurate and
completely fixed: `local` stores are the only registration path (there is no
update endpoint and nothing else in the repo creates one), and the two
`create_job` call sites are now the only ways a file id reaches a job, both
validating tenancy. Finding 2's remediation was incomplete. Four changes
followed.

1. **OIDC discovery endpoints are now validated (completes finding 2).**
   Validating the issuer left the vector one level down: Authlib was still
   handed a `server_metadata_url`, fetched the document itself, and used
   whatever `token_endpoint` and `jwks_uri` it advertised. A tenant admin with
   a *public* issuer — passing both new checks — could serve metadata pointing
   `token_endpoint` at an internal address and receive the tenant's client
   secret and authorization code there, with errors reflected back through the
   login page. `ui/oidc._discover` now fetches discovery itself (no redirects),
   requires the advertised `issuer` to match the configured one (RFC 8414 §3.3,
   so a hostile document cannot move the id_token `iss` trust anchor), runs
   `validate_callback_target` over `token_endpoint` and `jwks_uri`, policy-checks
   the browser-facing `authorization_endpoint`, and hands Authlib a filtered,
   pre-loaded metadata dict. With no `server_metadata_url`, Authlib's
   `load_server_metadata()` is a no-op and issues no unvalidated request.
   Filtering also matters on its own: Authlib assigns leftover `register()`
   kwargs straight to client config, so splatting raw metadata would let an IdP
   set fields like `client_secret` or reintroduce `server_metadata_url`.
2. **The callback path validates too.** It previously performed no check at
   all, and builds a fresh client per request, so it re-fetched discovery
   unvalidated. Both paths now revalidate on the request that does the fetching,
   closing the rebinding window between login and callback.
3. **The dev hatch relaxes loopback only.** `allow_loopback` skipped the whole
   non-public-hostname block, so `.local` and `.internal` were admitted with it.
   Those stay rejected either way now. `tests/conftest.py` also set the hatch
   for the entire suite, meaning production issuer behavior was exercised by
   exactly one test; it is now scoped to the stub-IdP fixture, and every other
   test runs the deployed default.
4. **The runner re-checks file tenancy (defense in depth for finding 3).**
   `runner._load_file_content` loaded files by id with no tenant check, so
   ingress was the only line of defense and any future ingress path would
   inherit the bug. It now takes the job's tenant and skips foreign files.

Error messages from the shared outbound validators take a `label`, so an admin
configuring SSO no longer gets told their "callback URL" is non-public.

**Regression coverage:** a stub IdP advertising a link-local `token_endpoint`,
a private `jwks_uri`, or a mismatched `issuer` is rejected at login (400) while
the honest document still completes the flow. Full suite: 148 passed.

## Residual Risks And Operational Requirements

1. Findings 4 and 5 remain open by design; see their status above.
2. Existing `local` data-store rows should be reviewed by an instance operator
   during upgrade — the creation restriction cannot establish who created
   historical rows.
3. `OIDC_ALLOW_LOOPBACK_ISSUERS` must remain false in production. It exists only
   so the e2e stub IdP (on 127.0.0.1) can exercise the real Authlib code flow in
   tests; it mirrors the existing `SESSION_HTTPS_ONLY` dev hatch.
4. Network egress policy remains the strongest defense against DNS rebinding
   for OIDC discovery, callback delivery, link fetching, and notification
   delivery alike; workers should not reach cloud metadata or management
   networks.