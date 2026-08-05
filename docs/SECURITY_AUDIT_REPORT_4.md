# Sleeper Service Security Audit Report 4

**Date:** 2026-08-04
**Audit run by:** Claude Opus 5 (high reasoning)
**Scope:** Whole codebase at `70cf6dc` — no pending diff; this was a full-repo
pass rather than a review of changes. All ~8k LOC of source across the v1 API,
admin UI and OIDC, agent runtime, auth/crypto, data layer, and the deployment
surface.
**Method:** Per-surface review with every finding re-verified against the
source, including re-deriving the data-store path resolver and confirming
third-party defaults (`arq`'s pickle serializer, `s3fs`'s credential chain) in
the installed packages rather than from memory.

> **Process note.** The intent was to fan out across six surfaces in parallel
> sub-agents. Five of seven stalled at the harness watchdog, so auth/crypto,
> the v1 API routes, and most of the runtime were audited directly; the
> UI/OIDC, infra, and runner surfaces completed as agents and their findings
> were then re-verified by hand. Two agent findings were dropped in that
> verification (see *Not reported*), which is the reason for the step.

## Executive Summary

Six findings: three high, three medium. All six are fixed with regression
coverage in this pass.

The three highs are independent paths to the same place — code or credentials
belonging to the platform rather than to a tenant:

1. an SSO session carried the user's roles in **every** tenant, so a tenant
   admin who controls their own IdP could inherit another tenant's access;
2. link fetching was the one server-initiated HTTP path that never checked
   where its destination resolved, so a tenant admin could make the worker
   read cloud metadata and hand the response to an agent;
3. the shipped compose file published an unauthenticated Redis on all
   interfaces, and `arq` deserializes queued jobs with `pickle` by default —
   together, remote code execution in the worker from an anonymous attacker.

The mediums are a credential-less cloud data store silently running on the
platform's own cloud identity, an anonymous tenant-enumeration on the login
page, and a prompt-injection screen that a client-declared content type could
skip.

Findings from audits 1–3, and the items deferred by design in
[TODO.md](TODO.md), were excluded from scope; none of the six below is a
regression of an earlier fix.

## Findings And Remediation

### 1. High: An OIDC Session Was Not Scoped To The Tenant That Authenticated It

**Original issue:** `ui/oidc.oidc_callback` correctly refused superusers and
users with no membership in the path tenant — the audit-2 fix — but the session
it then minted was global: `{"user_id", "tenant_id", "csrf_token"}`, where
`tenant_id` was only a display preference. `ui/routes.ui_user` rebuilt the
principal from **every** `TeamMember` row, and `_visible_tenants` returned
every tenant the user held any role in. The membership check gated entry to the
flow, not its scope.

The IdP behind that check is entirely tenant-controlled (`PUT
/v1/tenants/{tenant_id}/oidc` is tenant-admin), so the asserted `email` /
`email_verified` claims are attacker-authored. A tenant admin whose tenant
shares any user with a higher-value tenant — a contractor, a consultant, a
dual-tenant employee — could have their IdP assert that user's address, pass
the membership check legitimately, and receive a full session carrying that
user's roles everywhere else: agent prompts, job payloads and outputs, memory
contents, and every owner-gated mutation.

**Fix:** The callback now records `auth_tenant_id` alongside the display
`tenant_id`, and `ui_user` narrows the principal's roles to teams inside that
tenant whenever it is present (`_roles_within_tenant`). Local password auth is
an instance-controlled credential and keeps the user's full scope, so the
change costs nothing for the normal path.

**Note on the aggravating factor:** neither `create_team` (via
`body.owner_user_id`) nor `set_member` verifies that the target user already
belongs to the tenant, so a tenant admin who knows a user's UUID can
*manufacture* the membership precondition. That is deliberately **not**
changed: granting membership to a user from outside the tenant is how
onboarding works, and the session scoping above neutralizes the escalation
regardless of how the membership arose.

**Regression coverage:** a user belonging to two tenants sees both after local
login, but a session established through one tenant's IdP cannot reach the
other (`/ui/t/{other}` redirects home).

### 2. High: Link Fetching Never Validated The Resolved Address

**Original issue:** every other server-initiated HTTP destination passes
through `runtime/outbound` — callbacks (`runtime/callbacks`), the OIDC issuer
and its advertised endpoints (`api/v1/oidc`, `ui/oidc`), and job submission —
which resolves the host and rejects any non-global address. The link path used
none of it. `check_links` and `_fetch_one_link` validated only the scheme and a
literal hostname match against the tenant's `link_allowlist`, on the initial
request and on each redirect hop alike. Neither resolved anything.

Audit 1 closed *redirect* following on this path and left the destination
class open. A tenant admin controls `link_allowlist` (via `PATCH
/v1/tenants/{tenant_id}`) and the DNS behind their own domain, so either an IP
literal in the allowlist or a public name with a private `A` record made the
worker — which sits on the internal network and holds `SECRET_KEY` — fetch an
internal address. `runner.execute_job` splices the response body straight into
the agent's prompt, from where it reaches the job output the tenant admin
reads.

**Fix:** `_fetch_one_link` now calls `validate_callback_target` before the
initial request and before following every redirect, in addition to the
existing allowlist check. The allowlist remains a constraint; it is no longer
the only one. (The import is function-local: `outbound` imports `host_allowed`
from `links`.)

**Regression coverage:** an allowlisted hostname resolving to `169.254.169.254`
is blocked, as is the metadata address placed directly in the allowlist; the
existing redirect and deny-by-default tests still pass with DNS pinned the way
the callback tests already pin it.

### 3. High: Unauthenticated Redis On All Interfaces + arq's Pickle Deserializer

**Original issue:** two verified facts composing into remote code execution.

The shipped `docker-compose.yml` — which the README presents as the way to run
the platform — published Redis with no bind address and no `requirepass`
(`"${REDIS_HOST_PORT:-6379}:6379"` against `redis:7-alpine`), so Docker bound
`0.0.0.0` and, on Linux, inserted DNAT rules that bypass host firewalls such as
ufw. Postgres and MinIO were published the same way. None of it is needed:
`api` and `worker` reach each service over the compose network by name.

And `arq` serializes queued jobs with pickle by default — confirmed in the
installed package, where `deserialize_job`, `deserialize_job_raw`, and
`deserialize_result` all fall back to `pickle.loads`. Neither `queue.get_pool`
nor `WorkerSettings` supplied a serializer.

So an anonymous attacker who could reach the host wrote a pickle payload into
the queue and got code execution as the worker — which holds `SECRET_KEY` (the
Fernet key for every tenant's provider, MCP, data-store, OIDC, and notification
credentials), the database URL, and the MinIO credentials.

**Fix:** both halves.

1. Redis, Postgres, and MinIO now publish to `127.0.0.1` only, preserving the
   documented host-side developer workflow while removing the exposure. `api`
   (8000) and `langfuse-web` (3000) remain the only services on `0.0.0.0`,
   which is their purpose.
2. `queue.py` defines a JSON `job_serializer` / `job_deserializer` and passes
   them to `create_pool`; `WorkerSettings` uses the same pair. Every enqueued
   argument is already a plain UUID string, so JSON loses nothing, and
   `pickle.loads` is off the path that decodes whatever is sitting in Redis.

**Upgrade note:** the serializer change is not backward compatible with jobs
already queued as pickle. Drain the queue (or accept that in-flight jobs fail
to deserialize once and are retried) when deploying this. Setting
`requirepass` on Redis is still worth doing and is left to the operator, since
it needs a coordinated `REDIS_URL` change.

**Regression coverage:** queue payloads are asserted to be JSON, both ends are
asserted to use the same codec, and a pickle stream fed to the deserializer is
rejected as malformed rather than decoded.

### 4. Medium: Anonymous Enumeration Of Tenant Names And IDs

**Original issue:** `ui/routes.render_login` ran an unfiltered instance-wide
join of every tenant with an `OidcConfig` and rendered each as a
`Continue with {{ tenant_name }} SSO` link to `/ui/oidc/{{ tenant_id }}/login`.
`GET /ui/login` is anonymous, so anyone who could reach the admin UI received
the operator's SSO customer list: display names plus stable tenant UUIDs — the
same identifiers used throughout `/ui/t/{tenant_id}` and
`/v1/tenants/{tenant_id}/…`, which undercuts the assumption that they are
unguessable. It also revealed which tenants were SSO-backed and which were
password-only.

**Fix:** standard SSO discovery. `render_login` takes an optional `org` name
and resolves at most one `OidcConfig` from it; the bare page renders a small
"Organization" form instead of a list. Probing now requires guessing an
organization's name rather than reading them all off the page.

**Regression coverage:** the bare login page contains neither the tenant name
nor its UUID; naming the org (case-insensitively) still yields exactly one SSO
button, and an unknown org yields none.

### 5. Medium: Credential-less Cloud Data Stores Ran On The Platform's Own Cloud Identity

**Original issue:** `credentials` is optional at data-store registration, and
`_StoreGrant.fs_and_root` passed whatever it had straight to fsspec. With none,
every cloud backend falls back to the *host process's* ambient identity: s3fs
with `key=None` uses botocore's chain (env, shared config, then the
EC2/ECS/EKS instance role — `anon` defaults to `False`, verified in the
installed package), gcsfs uses application default credentials, and adlfs uses
`DefaultAzureCredential`.

A tenant admin could therefore register `{"type": "s3", "config": {"bucket":
"<any bucket the platform can reach>"}}` with no credentials, have an editor
attach a grant to an agent version, and drive `read_file` / `write_file`
against that bucket under the platform's IAM role — with the paths chosen by an
LLM whose tool arguments a prompt injection controls. This is the same
confused-deputy shape as the `local` store that audit 3 gated, for the cloud
identity instead of the container filesystem, and it was not gated at all.

Severity is conditional and stated as such: on the shipped compose topology the
worker holds no ambient cloud credentials, so this is inert. On EC2/ECS/EKS/GKE
with an instance or workload identity — the normal way to run this without
MinIO — it is a tenant-admin → instance-wide compromise.

**Fix:** the same superuser-only gate the `local` type carries, applied to
credential-less `s3` / `azure_blob` / `gcs` stores
(`AMBIENT_CREDENTIAL_TYPES`). Operators who genuinely want an ADC-backed store
still can; tenant admins must supply explicit credentials. `box` is unaffected —
it has no ambient-identity fallback.

**Regression coverage:** a tenant admin is refused (403) for all three
credential-less types, a superuser succeeds, the same store with explicit
credentials succeeds, and `box` is unaffected.

**Operational note:** as with the `local` and stdio-MCP gates, the restriction
cannot establish who created historical rows. Operators should review existing
credential-less `s3` / `gcs` / `azure_blob` stores after upgrade.

### 6. Medium: The Injection Screen Was Bypassed By A Client-Declared Content Type

**Original issue:** `runner._load_file_content` added a file to the list handed
to `hooks.screen_untrusted` only when `content_type.startswith(TEXT_TYPES)`;
everything else went to the model as opaque `BinaryContent`, unscreened. That
deciding value came verbatim from the client's multipart header in
`files.upload_file`, with no sniffing.

So anyone who can upload — an invoke-key holder or any tenant member, the
*lowest* authenticated tier — could take injection text, declare it
`application/pdf` or `image/png`, and skip the screen entirely, while the
identical bytes sent as `text/plain` are caught and the job finalized
`rejected`. Models read PDFs and images natively, so the content still lands.
A control documented as default-on was effectively opt-out.

**Fix:** `files.sniff_content_type` derives the type from the bytes — magic
numbers for the formats a model reads natively (PDF, PNG, JPEG, GIF, ZIP-based
Office formats), a text heuristic otherwise — and the declared type is kept
only where it does not contradict the content. Text bytes wearing a binary
label now become `text/plain` and reach the screen. The runner's `TEXT_TYPES`
and the upload path now share one `constants.TEXT_CONTENT_TYPES`, so the two
cannot drift.

**Regression coverage:** injection text declared as PDF/PNG/octet-stream
resolves to `text/plain`; honest text types survive; real binaries keep their
real type whatever the client claimed.

**Residual risk:** a genuine PDF with injected text inside a compressed content
stream is still unscreened — closing that needs server-side text extraction
from binary formats, which is a larger change and is recorded in
[TODO.md](TODO.md) rather than done here.

## Not Reported

Recorded because they were raised during the audit and deliberately dropped —
the reasoning matters as much as the findings.

- **Tenant-controlled S3 `endpoint_url` as an SSRF vector.** Already accepted
  residual risk in [audit 3](SECURITY_AUDIT_REPORT_3.md) §6, and correctly so:
  pointing a data store at an arbitrary S3-compatible endpoint is the *purpose*
  of a BYO store, and denying non-global endpoints would break the on-prem and
  self-hosted-gateway deployments the feature exists for. Not a defect.

  The one case worth naming is that a tenant admin can point a store at the
  platform's *own* MinIO — but only by supplying the platform's own MinIO
  credentials, so the exposure is entirely a function of whether those have
  been rotated away from the compose defaults. The dependency is recorded
  against the credential-rotation item in [TODO.md](TODO.md) rather than
  treated as a problem with the store design, because rotation is what
  separates an intended feature from a cross-tenant read.
- **gcsfs `token` as a filesystem path for arbitrary file read.** gcsfs does
  accept a key-file path, but the contents would have to surface through a
  JSON-decode exception message for this to be a read primitive. Too
  speculative.

## Verified Clean

- **No injection primitives in `src/`** — a full sweep found no `pickle`,
  `yaml.load`, `eval`, `os.system`, `subprocess`, `shell=True`, `__import__`,
  or `marshal` in application code. The single `exec` is the Docker sandbox
  harness, in a throwaway container with `network_disabled`, `cap_drop=ALL`,
  `no-new-privileges`, pids/memory/CPU caps, uid 65534, and no volume or socket
  mounts. stdio MCP uses `shlex.split` with no shell and is superuser-only.
- **No SQL injection** — the only raw SQL is the constant `text("SELECT 1")` in
  `main.py`.
- **Data-store path traversal is genuinely closed** — `_StoreGrant.resolve` was
  re-derived and attacked with absolute paths, `..` variants, `%2f`,
  backslashes, `//`, trailing slashes, empty prefixes, and prefixes containing
  `..`; it holds and is cwd-independent.
- **Object-level authorization** — every route in all eighteen v1 route modules
  was enumerated and checked; each re-checks tenant ownership and role, and
  sub-resources are consistently loaded scoped to their parent. The
  superuser-only gates on `local` stores and stdio MCP have no update endpoint
  to bypass.
- **No mass assignment or secret leakage in `schemas.py`** — `tenant_id`,
  `team_id`, `role`, `is_superuser`, and `status` are never client-settable
  outside superuser-only routes; no encrypted blob, secret hash, or `auth_ctx`
  appears in any response model.
- **Crypto and randomness** — all tokens and keys use `secrets.token_urlsafe`;
  `hmac.compare_digest` is used consistently; Fernet keys derive from
  `SECRET_KEY` via SHA-256.
- **CSRF and XSS in the admin UI** — all mutating UI routes carry the
  router-level `_csrf_protect` dependency, which runs before `ui_user`;
  autoescaping is on and the three `|safe` uses are `escape`-guarded or
  `json.dumps` of platform-controlled literals.

## Verification

- Full test suite: **154 passed** (148 before this pass; 6 new regression
  tests, 2 existing tests updated where they asserted the old behavior).
- Ruff check and format: clean.

## Residual Risks And Operational Requirements

1. **Drain the arq queue when deploying finding 3's fix** — JSON and pickle
   payloads are not interchangeable.
2. **Review existing credential-less `s3` / `gcs` / `azure_blob` data-store
   rows**, as with the `local` rows from audit 3: the creation gate cannot
   establish who created historical rows.
3. **Set `requirepass` on Redis.** Loopback binding removes the remote path;
   authentication would remove reachability-as-authorization, and is left to
   the operator because it needs a coordinated `REDIS_URL` change.
4. Binary files whose extractable text the screen cannot see remain unscreened
   (finding 6's residual).
5. Network egress policy remains the strongest defense against DNS rebinding
   for link fetching, callback delivery, OIDC discovery, and notification
   delivery alike — finding 2 closes the application-layer gap, not the
   rebinding window.
