# Sleeper Service Security Audit Report 2

**Date:** 2026-08-03  
**Scope:** FastAPI management/data planes, admin UI, OIDC, background worker,
callbacks, MCP integrations, data-store grants, delegation, and tenant/team
authorization.  
**Method:** Manual trust-boundary and object-authorization review, adversarial
regression tests, Ruff, Bandit, `pip-audit`, Alembic graph validation, and the
complete test suite.

## Executive Summary

The audit identified two critical, four high, and two medium-severity security
issues. The highest-impact paths allowed a tenant-controlled OIDC provider to
authenticate global users and allowed tenant administrators to register commands
executed by the worker through stdio MCP. Other findings crossed tenant, team,
browser, and outbound-network boundaries.

All findings below have code fixes and regression coverage. The changes make
tenant and instance administration separate security roles, recheck authorization
at every returned object, treat caller-supplied context as untrusted, and validate
outbound callback destinations immediately before connecting.

## Findings And Remediation

### 1. Critical: Tenant OIDC Could Impersonate Global Users

**Original issue:** Tenant administrators could configure an arbitrary OIDC
issuer. The callback matched the asserted email against the global users table,
without checking membership in the configured tenant or excluding instance
superusers. A malicious tenant IdP could therefore authenticate as another
tenant's user or as an instance superuser.

**Fix:** OIDC login now requires `email_verified == true`, rejects all superuser
accounts from tenant OIDC, and requires an existing team membership in the
specific tenant. Instance superusers must use instance-controlled local auth.

**Regression coverage:** Tenant OIDC is tested against both a superuser email and
an existing non-member email; neither receives a session.

### 2. Critical: Tenant-Managed Stdio MCP Allowed Host Command Execution

**Original issue:** A tenant administrator could register `transport=stdio` with
an arbitrary command line. When granted to a version, the worker launched that
command in the service container.

**Fix:** Only instance superusers may register stdio MCP servers. Tenant admins
retain management of HTTP/SSE MCP definitions. Existing stdio definitions should
be reviewed after upgrade because the creation restriction cannot establish who
created historical rows.

**Regression coverage:** A tenant administrator with valid tenant-admin rights is
denied when attempting to register a stdio MCP server.

### 3. High: UUID Integration Grants Bypassed Tenant Isolation

**Original issue:** MCP server and data-store lookup applied `tenant_id` to name
references but used unrestricted primary-key lookup for UUID references. Knowing
another tenant's integration UUID could bind its endpoint and credentials to an
attacker-controlled agent version.

**Fix:** UUID and name lookups now both include `tenant_id` in the database query.

**Regression coverage:** A cross-tenant UUID returns no integration while the
same UUID resolves for its owning tenant.

### 4. High: Callback Delivery Allowed Server-Side Request Forgery

**Original issue:** Job submitters could provide any callback URL. The worker
later issued a POST from its trusted network without validating the destination.

**Fix:** Callback URLs are syntax-checked at submission and resolved again in the
worker immediately before connection. Credentials in URLs, local hostnames, and
all non-global IP classes are rejected. Tenants may additionally configure a
`callback_allowlist`. Redirects remain disabled.

**Regression coverage:** Link-local IP literals and hostnames resolving to
loopback addresses are rejected, while existing callback delivery behavior is
tested with network validation isolated from the mock transport.

### 5. High: Caller-Supplied MCP Identity Context Was Forgeable

**Original issue:** `JobSubmit.user_ctx` was copied directly into
`X-Sleeper-User-Ctx`, despite documentation positioning it as downstream identity
for row-level enforcement. Invoke-key holders could claim arbitrary identities.

**Fix:** Jobs now store server-derived `auth_ctx` separately from untrusted
application `user_ctx`. When user context is forwarded, the MCP server must have
a per-server `user_ctx_signing_secret`. The worker sends a canonical envelope
containing authenticated principal and untrusted context, plus timestamp and
HMAC-SHA256 signature headers. Jobs with user context fail closed when the server
has no signing secret.

**Regression coverage:** Unsigned forwarding is rejected and signed envelopes
are verified byte-for-byte in tests. A migration adds the nullable `jobs.auth_ctx`
JSONB column.

### 6. High: Delegation Trees Exposed Unauthorized Descendant Jobs

**Original issue:** API and UI tree views authorized only the root. Tenant-wide
delegation can create descendants owned by other teams, exposing their job
payloads, outputs, errors, callback URLs, and user context.

**Fix:** Every descendant agent is authorized against the requesting principal.
Invisible branches are omitted. UI traversal also has cycle and depth guards.

**Regression coverage:** A user authorized for the root but not the child team
receives an empty child list.

### 7. Medium: Dashboard Queries Ignored Team Visibility

**Original issue:** Any tenant member received tenant-wide agent counts, spend,
token usage, and recent job metadata, including teams they could not otherwise
view.

**Fix:** Every dashboard query now uses agent IDs restricted to the user's visible
teams. Superusers retain tenant-wide visibility.

**Regression coverage:** A hidden team's agent name and job ID do not appear in a
different team's dashboard.

### 8. Medium: Admin UI Browser Controls Were Incomplete

**Original issue:** Session cookies were not `Secure`, state-changing forms had
no CSRF token, login did not rotate session contents, and password attempts had
no throttle.

**Fix:** Session cookies default to `Secure`, session lifetime defaults to eight
hours, every mutating UI request requires a session-bound CSRF token, successful
login clears and rebuilds the session, and Redis enforces an IP-plus-email login
attempt window. Local HTTP development must explicitly set
`SESSION_HTTPS_ONLY=false`.

**Regression coverage:** Missing CSRF tokens return 403 and excess login attempts
return 429.

## Verification

- Focused security regression suite: **29 passed**.
- Alembic migration graph: **one head** (`91b8df4e2c1a`).
- Ruff: **clean after formatting fixes**.
- Bandit: **no findings**.
- `pip-audit`: **no known vulnerabilities** in the installed dependency set.
- Full test suite: **143 passed**, with 14 Starlette HTTP-422 deprecation warnings.

## Residual Risks And Operational Requirements

1. Application validation reduces callback SSRF, but network egress policy is
   still required for robust DNS-rebinding resistance. Workers should not be able
   to reach cloud metadata or management networks.
2. Existing stdio MCP rows and local data-store definitions should be reviewed by
   an instance operator during upgrade.
3. MCP consumers must verify the context timestamp and HMAC with a constant-time
   comparison and reject stale envelopes. The signing secret is per MCP server;
   it must not be the application `SECRET_KEY`.
4. Terminate TLS before the application, preserve the original host safely, and
   leave secure cookies enabled outside isolated local development.
5. Rotate `SECRET_KEY` and integration credentials if they were ever shared with
   callback receivers or exposed through earlier cross-tenant integration grants.
