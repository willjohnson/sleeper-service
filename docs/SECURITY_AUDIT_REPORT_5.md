# Sleeper Service Security Audit Report 5

**Date:** 2026-08-19
**Audit run by:** GLM 5.3 via pi (high reasoning)
**Scope:** Whole codebase at `e0230f3` (working tree clean; the audit and its
fixes landed together on the `security/audit-5` branch). Full pass over the
v1 API, admin UI and OIDC, agent runtime, auth/crypto, data layer, queue and
deployment surface, with particular attention to the handoffs between
components — API → queue → worker, upload → runner, registration → connect,
submission → delivery.
**Method:** Every server-initiated outbound path was enumerated and checked
against `runtime/outbound`; every cross-component data handoff (job payload,
file references, tool grants, session state, queue payloads) was traced from
producer to consumer. Findings were re-verified against the installed
packages (`fastmcp`'s HTTP transports, Starlette's `UploadFile`) rather than
from memory.

## Executive Summary

Three findings: one high, one medium, one low. All three are fixed with
regression coverage in this pass.

The high is the last unguarded server-initiated HTTP path. Callbacks, fetched
links, OIDC discovery endpoints, and Apprise destinations all resolve and
reject non-public addresses — MCP server endpoints did not. A tenant admin
could register `http://169.254.169.254/mcp` (or any internal address, or a
name that resolves to one) and have the worker connect to it on every granted
job, carrying tenant-chosen headers and the signed user-context envelope.

The medium is a memory-exhaustion path in file upload: the 50 MiB cap was
checked only after `read()` had pulled the entire body into memory, so anyone
who can upload could post a body of any size and have it resident before the
rejection. The low is a scope inconsistency: agent- and team-scoped invoke
keys were resolving to tenant-wide file upload/read access, beyond both the
documented file policy ("tenant-covering invoke key") and the invoke-key
capability model.

Findings from audits 1–4 and the items deferred in [TODO.md](TODO.md) were
excluded from scope; none of the three below is a regression of an earlier
fix.

## Findings And Remediation

### 1. High: MCP HTTP Endpoints Never Passed Through The Outbound Validators

**Original issue:** audit 4 closed the equivalent gap in link fetching by
noting that "every other server-initiated HTTP destination passes through
`runtime/outbound`" — but that enumeration missed one: `McpServer.endpoint`
for `streamable_http`/`sse` transports. Registration (`POST
/v1/tenants/{tenant_id}/mcp-servers`, tenant-admin gated) accepted any
string, and `build_mcp_toolsets` handed it straight to `MCPToolset`, which
wraps a plain `httpx` client (verified in the installed `fastmcp`). No
syntax or address policy at registration, no resolution check at connect
time — on either the initial connection or any later job.

The worker therefore connected, on every job granting the server, to a
destination chosen by a tenant admin: an internal reachability probe from a
process holding `SECRET_KEY` and every decrypted provider credential, with
tenant-chosen `credentials.headers` attached, plus the signed user-context
envelope when `user_ctx` is present. Unlike the S3 `endpoint_url` case
accepted as residual in audit 4, no credential is required to make the
connection, and the *response* has a path back to the tenant: a destination
that answers with JSON-RPC-shaped MCP messages (a real internal MCP sidecar
of another tenant, run without authentication on the compose network, is the
cleanest case) has its tool definitions and tool results spliced into the
agent's prompt and from there into job output. Plain GET-style endpoints
(cloud metadata) do not speak JSON-RPC, so the read primitive against them
is conditional — the connect/probe primitive is not.

**Fix:** the same two-phase check callbacks use. `outbound.validate_mcp_url`
runs at registration (scheme, credentials-in-URL, hostname, and the address
policy — `.local`/`.internal`, loopback, non-global literals) for
`422`-fast-feedback; `outbound.validate_mcp_target` runs in
`build_mcp_toolsets` before the toolset is constructed, resolving the
endpoint so a name that was public at registration but points internal by
run time is refused (the job fails with a `GrantError`, like an unknown
server). stdio endpoints are command lines, superuser-gated, and untouched.

`MCP_ALLOW_PRIVATE_HOSTS` (operator-level, default false) mirrors
`NOTIF_ALLOW_PRIVATE_HOSTS` for deployments whose MCP servers genuinely share
a network with the worker — the compose `mcp-*` sidecar shape anticipated in
the BUILD_PLAN. With it set, the full URL syntax policy (scheme, hostname,
no credentials-in-URL, valid port) is still enforced through the shared
validator — only the address policy and connect-time resolution are skipped;
widening is a deployment decision, never a tenant one.

**Regression coverage:** registration refuses a metadata literal, a loopback
name, and a `.internal` host while accepting a public endpoint and leaving
stdio untouched; a build whose endpoint resolves to `169.254.169.254` raises
`GrantError`; with the operator flag set, a private endpoint registers and
builds with no DNS resolution occurring at all (asserted, not assumed). Two
existing toolset tests now pin DNS the way the callback tests already do.

**Operational note:** as with the audit-3 `local`-store and audit-4
ambient-credential gates, the registration check cannot establish who
created historical rows. Operators should review existing `mcp_servers` rows
with HTTP transports after upgrading, and set `MCP_ALLOW_PRIVATE_HOSTS=true`
only if internal endpoints are intended.

### 2. Medium: The Upload Size Cap Was Checked After The Body Was In Memory

**Original issue:** `files.upload_file` did `data = await file.read()` and
only then compared `len(data)` against `MAX_FILE_SIZE`. Starlette spools
multipart parts to disk while receiving them (after 1 MiB), but `read()`
returns the whole spooled file as one bytes object — so the 50 MiB cap
rejected the upload only after first making its entire content resident. A
single authenticated caller (any tenant member, or any invoke key — the
lowest tiers) could post a multi-gigabyte body and exhaust API-process
memory before the check ever ran. The 50 MiB cap existed precisely to bound
this and was enforced one step too late.

**Fix:** Starlette tracks the rolled size on `UploadFile.size`; the endpoint
now rejects on that before reading, keeping the post-read check as a backstop
for the `size is None` case. The two checks return the same `413`.

**Regression coverage:** the route is invoked directly with an upload stub
whose `size` exceeds the cap and whose `read()` raises — the pre-fix code
tripped the raise, the fixed code returns `413` without reading.

### 3. Low: Invoke Keys Scoped Below The Tenant Got Tenant-Wide File Access

**Original issue:** `_check_tenant_access` in `api/v1/files.py` accepted any
invoke principal whose scope *resolved to* the tenant — via
`resolve_tenant_for_invoke`, which mapped team and agent scopes through to
their tenant. So a key issued for a single agent could upload to and read
any file in the tenant (`GET /v1/files/{id}/content`), and a team-scoped key
likewise. Both the module's own docstring ("any member of a team in the
tenant, **or a tenant-covering invoke key**") and the invoke-key capability
model ("job submission / result reads / feedback within their scope, and
nothing else") say narrower keys get no file surface. The gap is quiet in
practice — file ids are unguessable UUIDs — but a data-plane credential
embedded in some external system should not carry a capability its issuer
cannot see when issuing it, and an agent-scoped key could attach any tenant
file it learned the id of to a job.

**Fix:** only `KeyScope.TENANT` invoke keys pass the file boundary now;
`resolve_tenant_for_invoke` is gone (it existed only to widen this check).
The job surface enforces the same boundary: a `context.files` reference has
the runner inline the file's content into the prompt, and the submitter reads
it back through the job output — the same read by another door — so job
submission refuses (403) `context.files` from invoke keys scoped below the
tenant. User submissions and tenant-covering keys are unaffected:
`context.files` references are validated against the agent's tenant at submit
and re-checked in the runner.

**Regression coverage:** a tenant-covering key uploads and reads; an
agent-scoped key gets 404 on read, metadata, and upload alike, and 403 when
referencing a tenant file in a job submission.

## Design Tensions — Decided And Remediated (Post-Audit)

Raised during the audit as behavior that was designed in
[BUILD_PLAN.md](BUILD_PLAN.md) rather than broken, and therefore not
silently "fixed" without a decision. Will decided all three on 2026-08-19:
close them. Each is remediated below with regression coverage in
[tests/test_audit5.py](../tests/test_audit5.py).

- **Eval runs were exempt from spending limits and from spend rollups.**
  `run_eval` executed real provider calls under `is_eval=True`; the runner's
  budget pre-flight and mid-run check skipped eval jobs, and `month_spend`
  excluded them — so any editor could trigger provider spend that was both
  unbounded (never refused) and invisible (absent from the spend dashboard).
  **Remediation:** eval jobs are subject to the budget pre-flight and mid-run
  check exactly like production jobs, their cost rolls into `month_spend`, and
  `POST /agents/{id}/eval-runs` refuses (409) at an exhausted budget before
  creating the run — the same shape as job submission. `run_eval` itself also
  refuses at the top and aborts mid-suite if the budget runs out, marking the
  run `budget_exceeded` (with an owner notification) rather than completing it
  at a fabricated 0% pass rate — which would fire a spurious regression alert,
  become the baseline a real regression is compared against, and make a
  pending memory version look like it failed its gate. This covers the memory
  eval gate, which enqueues runs without going through the API route. Eval
  jobs keep their other distinctions: no callbacks, excluded from error-rate
  alerting. BUILD_PLAN § Eval design updated to record the change.
- **Unbounded request bodies on authenticated JSON paths.** `JobSubmit`
  prompts and `user_ctx`, and event-source webhook bodies, had no size cap;
  only files were capped (finding 2 fixed the enforcement of that cap).
  **Remediation:** `BodyLimitMiddleware` (main.py) rejects bodies over
  `REQUEST_BODY_MAX_BYTES` (default 1 MiB) with a 413 — on the Content-Length
  header when present, and on the bytes as they stream in when it is not, so
  chunked requests cannot slip past. The cap applies regardless of declared
  content type, because FastAPI buffers the body before it inspects the
  Content-Type or resolves auth — a JSON-only cap would be bypassed by
  relabelling the body. Multipart uploads are the one exemption: Starlette
  streams them to disk and the files route enforces `MAX_FILE_SIZE` on the
  rolled size.
- **`matches_regex` eval checks used stdlib `re` with no timeout.** The
  injection screen moved to the `regex` module with a checked timeout
  precisely because a stdlib match cannot be interrupted; the eval grader's
  regex op still compiled editor-supplied patterns with `re` and searched
  model output with them, inside a thread that holds the GIL while matching.
  **Remediation:** the op now runs on `regex` bounded by
  `REGEX_CHECK_TIMEOUT_S` (5s), failing the check on timeout; creation-time
  validation also rejects invalid patterns (which previously crashed the
  whole eval run at grade time), and a stored invalid pattern fails its check
  with the reason instead of raising.

## Not Reported

- **Box `config.api_base_url`.** A tenant admin can point a Box store at an
  internal address, and the worker's Box SDK calls follow it. This is the
  same shape as the S3 `endpoint_url` residual accepted in audit 4: BYO
  gateway endpoints are the documented purpose of the config key ("tests or
  gateways"), and unlike an MCP endpoint the store needs real Box
  credentials to return data. If finding 1's fix makes the asymmetry feel
  wrong, the consistent move would be an analogous `DATASTORE_ALLOW_PRIVATE_ENDPOINTS`
  operator flag — recorded here rather than built, per YAGNI.
- **gcsfs `token` as a filesystem path** — already assessed as too
  speculative in audit 4; nothing has changed.

## Verified Clean

Re-verified rather than assumed, since these were the hot spots of earlier
audits and this pass focused on the same seams:

- **Queue handoff** — both `queue.get_pool` and `WorkerSettings` still pass
  the JSON serializer pair; a pickle stream fed to the deserializer is
  rejected as malformed (audit-4 regression tests still green). Job
  arguments are UUID strings that must resolve to API-created rows.
- **Upload → runner handoff** — content-type sniffing and the shared
  `TEXT_CONTENT_TYPES` constant are intact; file tenancy is re-checked in
  `_load_file_content` against the *agent's* tenant, so every ingress path
  that skips the submit-time check (evals, delegation) still cannot pull
  another tenant's file.
- **Link and callback paths** — per-hop allowlist + resolved-address checks
  unchanged and covered; OIDC discovery still validates issuer, token and
  JWKS endpoints with pre-loaded Authlib metadata.
- **UI session handoffs** — SSO sessions stay scoped by `auth_tenant_id`,
  CSRF tokens rotate on both login paths, and the login limiter still keys
  on `client_ip` with `TRUSTED_PROXY_HOPS` honored.
- **Delegation handoff** — child jobs carry the submitting principal's
  `auth_ctx` by design (it is the submitter's identity, not the executor's);
  depth and cycle guards are intact, and permitted targets are
  tenant-qualified.
- **Object-level authorization** — the eighteen v1 route modules were
  re-walked; no new route had appeared without tenant scoping, and the
  MCP/data-store registries still have no update endpoint to bypass their
  gates.

## Verification

- Full test suite: **187 passed** (172 before this pass; 5 regression tests
  for the findings, 10 for the post-audit follow-up, and 2 existing toolset
  tests updated to pin DNS for the now-validating MCP path).
- Ruff check and format: clean.

## Residual Risks And Operational Requirements

1. **Review existing HTTP-transport `mcp_servers` rows** when deploying
   finding 1's fix — the registration gate cannot establish who created
   historical rows, and run-time rejection will fail jobs that were working
   against internal endpoints. Intentional internal deployments should set
   `MCP_ALLOW_PRIVATE_HOSTS=true` (coordinated with the worker, which also
   reads it).
2. Network egress policy remains the strongest defense against DNS
   rebinding on every outbound path — the MCP connect-time check closes the
   application-layer gap, not the rebinding window.
3. One behavioral note on the eval-budget change: an automatic memory-gate
   eval for an agent at its limit still triggers, and its jobs are refused
   by the runner pre-flight — the run completes with the refusals recorded
   per case, which is the auditable artifact of why the gate could not run.
   Manual runs are refused up front (409) instead.
