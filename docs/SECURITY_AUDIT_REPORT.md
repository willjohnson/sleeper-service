# Sleeper Service Security & Codebase Audit Report

**Date:** 2026-08-03
**Audit run by:** Gemini 3.6 Flash (high reasoning)
**Fixes reviewed and hardened by:** Claude Fable 5 (commit `9596f2b`)

## Executive Summary
A comprehensive security and cross-layer codebase review of **Sleeper Service** was performed. Several critical and high-severity security vulnerabilities and cross-layer edge-case bugs were identified and remediated.

All **131 unit & integration tests** are passing cleanly.

---

## Key Vulnerabilities & Bugs Remediated

### 1. 🚨 [CRITICAL] Data Store Path Traversal when Grant Prefix is Empty
- **Location**: [`src/sleeper_service/runtime/toolsets.py`](../src/sleeper_service/runtime/toolsets.py#L92-L99)
- **Vulnerability**: When an agent was granted access to a data store with an empty prefix (`prefix=""`), the path escaping check `candidate.startswith(self.prefix + "/" if self.prefix else "")` evaluated `candidate.startswith("")`, which returns `True` for **any string**. An agent or attacker could supply `path="../../etc/passwd"`, bypassing prefix restrictions and accessing arbitrary files on the host filesystem when using `local` storage backends.
- **Fix**: Replaced the startswith check in `_StoreGrant.resolve` with pure string checks on the normalized candidate: reject anything resolving to `..`, `../*`, or `/*`, and (for non-empty prefixes) anything outside `prefix/`. An earlier draft used `posixpath.relpath`, which was rejected in review because `relpath` resolves against `os.getcwd()` — with cwd `/` (the common container default) the traversal check silently passed. A cwd-independence regression test now pins this.

### 2. 🌐 [HIGH] SSRF via HTTP Redirects in External Link Fetching
- **Location**: [`src/sleeper_service/runtime/links.py`](../src/sleeper_service/runtime/links.py#L34-L54)
- **Vulnerability**: While `check_links` verified requested URLs against the tenant's `link_allowlist` at job submission time, `fetch_links` executed `httpx.AsyncClient(follow_redirects=True)`. An attacker could submit an allowlisted URL that returned an HTTP 301/302 redirect pointing to internal resources (e.g., `http://169.254.169.254/latest/meta-data/` or `http://localhost:8000/internal`), bypassing domain allowlisting.
- **Fix**: Updated `fetch_links` to accept `tenant_settings`, handle redirects manually up to 5 hops, and re-validate scheme (`http`/`https`) and target host against `host_allowed` on every redirect. The fetch side uses the same deny-by-default as `check_links`: a tenant with no `link_allowlist` configured fetches nothing, so the two layers cannot drift apart (e.g., if the allowlist is removed while jobs are queued).

### 3. ♾️ [HIGH] Delegation Ancestry & Job Tree Infinite Loop / Stack Overflow
- **Location**: [`src/sleeper_service/runtime/delegation.py`](../src/sleeper_service/runtime/delegation.py#L43-L54) and [`src/sleeper_service/api/v1/jobs.py`](../src/sleeper_service/api/v1/jobs.py#L267-L284)
- **Vulnerability**: `_ancestry` traversed parent jobs via `while current.parent_job_id is not None:`. If a circular `parent_job_id` reference existed in the database, `_ancestry` hung infinitely. Similarly, `get_job_tree` used unbounded recursion without tracking visited node IDs.
- **Fix**: Added `visited_jobs` tracking in `_ancestry` and `visited` set + depth limits (max 50) in `get_job_tree`.

### 4. 💥 [MEDIUM] Unhandled 500 Error on Event Source Deletion
- **Location**: [`src/sleeper_service/api/v1/events.py`](../src/sleeper_service/api/v1/events.py#L148-L149)
- **Vulnerability**: `delete_event_source` attempted `agent.team_id` assuming `agent` existed. If the target agent was deleted, `agent` was `None`, causing an unhandled `AttributeError` (500 Internal Server Error).
- **Fix**: Added a check for `agent is None`, falling back to `require_tenant_admin` for orphaned event sources.

### 5. 📁 [MEDIUM] Unsanitized Filename Path Traversal in Uploaded Files
- **Location**: [`src/sleeper_service/api/v1/files.py`](../src/sleeper_service/api/v1/files.py#L71)
- **Vulnerability**: Uploaded filenames (`file.filename`) were used directly in object storage keys (`f"{tenant_id}/payload/{file_id}/{file.filename}"`). Filenames containing path traversal elements (`../../malicious.txt`) could corrupt key paths.
- **Fix**: Used `Path(file.filename).name` to sanitize filenames and strip directory path components.

### 6. 🛡️ [MEDIUM] Missing Null Checks in Worker Concurrency Guard
- **Location**: [`src/sleeper_service/worker.py`](../src/sleeper_service/worker.py#L97-L98)
- **Vulnerability**: `_tenant_at_capacity` dereferenced `agent.tenant_id` without verifying `agent is not None`.
- **Fix**: Added explicit null checks for `agent` and `tenant`.

---

## Verification & Testing
Added unit test suite [`tests/test_security_fixes.py`](../tests/test_security_fixes.py) covering:
1. `_StoreGrant.resolve` path traversal rejection for empty and non-empty prefixes, including a cwd-independence test run from `/`.
2. `_ancestry` loop termination with circular job chains.
3. `fetch_links` SSRF redirect blocking to unauthorized targets, and deny-by-default when no `link_allowlist` is configured.
4. Clean execution of all 131 test cases across the codebase.
