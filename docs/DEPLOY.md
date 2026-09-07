# Deploying to Render

`render.yaml` in the repo root is a [Render Blueprint](https://render.com/docs/blueprint-spec)
that declares the whole stack: the API, the arq worker, Postgres, and Key Value
(Render's managed Redis). Object storage is the one piece Render does not
offer, so payload files go to Cloudflare R2.

Roughly **$31.50/month**:

| Service | Plan | Cost |
|---|---|---|
| `sleeper-api` (web) | `0.5c-512mb` | $7.00 |
| `sleeper-worker` (background worker) | `0.5c-512mb` | $7.00 |
| `sleeper-db` (Postgres 17) | `0.1c-256mb` + 5GB disk | $7.50 |
| `sleeper-kv` (Key Value) | `256mb` | $10.00 |
| Cloudflare R2 | 10 GB free tier | $0.00 |

Database storage is billed separately from database compute, at $0.30 per
provisioned GB — so the `diskSizeGB` in the blueprint is a real line item, and
one that can only ever be raised.

Stay on an individual (free) workspace — per-service billing is identical, and
the $25/month Pro plan only adds team seats.

## 1. Create the R2 bucket first

The API calls `ensure_bucket()` during startup, so it will not boot without
reachable object storage.

1. Cloudflare dashboard → **R2** → **Create bucket**, named `sleeper-files`.
   Create it by hand rather than letting the app do it — `ensure_bucket()` only
   creates a bucket when one is missing, and pre-creating keeps the running
   service's credentials free of any bucket-creation permission.
2. **Manage R2 API Tokens** → **Create Account API token** (not a *User* token,
   which Cloudflare deactivates if you leave the organization — it would take
   the running service down with it). Permissions *Object Read & Write*, applied
   to that one bucket. Leave client IP filtering empty: Render's egress
   addresses are not stable, and an allowlist here fails later and obscurely.
3. Note your S3 endpoint: `https://<account-id>.r2.cloudflarestorage.com`.

R2 speaks S3, and payload storage goes through `s3fs`, so no code changes are
needed — only `MINIO_ENDPOINT` pointing at R2 instead of a local MinIO.

Check the credentials before deploying, so a storage problem surfaces here
rather than as a container that will not boot:

```
MINIO_ENDPOINT=https://<account-id>.r2.cloudflarestorage.com \
MINIO_ACCESS_KEY=... MINIO_SECRET_KEY=... \
MINIO_BUCKET=sleeper-files AWS_DEFAULT_REGION=auto \
uv run python scripts/preflight_storage.py
```

Use the **Access Key ID** and **Secret Access Key** from the token screen, not
the "Token value" beside them — that one is a bearer token for Cloudflare's own
REST API and is not an S3 credential. The secret is shown once.

## 2. Deploy the blueprint

In Render: **New → Blueprint**, pick the `sleeper-service` repo, leave the
branch on `main`, and Render reads `render.yaml`. It prompts for the values
marked `sync: false` *before* showing the cost estimate:

| Variable | Value |
|---|---|
| `MINIO_ENDPOINT` | `https://<account-id>.r2.cloudflarestorage.com` |
| `MINIO_ACCESS_KEY` | R2 access key ID |
| `MINIO_SECRET_KEY` | R2 secret access key |
| `PUBLIC_BASE_URL` | `http://placeholder` — the real value is step 4 |

**You are asked for each of these twice**, once for `sleeper-api` and once for
`sleeper-worker`. Give both services identical values. Render only prompts for
variables declared on a service — it ignores `sync: false` inside an
environment group, silently — so these cannot be shared the way the rest are.

It also only prompts during **initial** Blueprint creation. On a later sync it
disregards `sync: false` entirely, so a variable added this way after the fact
has to be typed into each service by hand.

`SECRET_KEY` is not among the prompts: Render generates it into the
`sleeper-shared` group, where both services read the one value. That sharing is
load-bearing rather than tidy — provider credentials are Fernet-encrypted with
a key derived from it, the API writes those rows and the worker decrypts them,
so two separately generated values would encrypt fine and fail to decrypt.

Expect the first build to take several minutes: it is a cold `uv sync` with no
layer cache. Later deploys reuse it.

## 3. Confirm it came up

Wait for `sleeper-api` and `sleeper-worker` to both read **Deployed**, and the
database and Key Value to read **Available**.

A green `sleeper-api` is already proof the storage credentials are right, which
saves checking them by hand:

- `minio_access_key` and `minio_secret_key` have no defaults, so `Settings`
  raises before the app starts if either is missing
- `ensure_bucket()` runs unguarded in the lifespan startup, so a wrong endpoint
  or bad credentials kills the container
- the health check is `/healthz`, which round-trips Postgres and Redis, and
  Render only marks a service Deployed once that returns 200

The worker may crash-loop for a few seconds during the first deploy: it starts
against a database whose tables do not exist until the API's pre-deploy command
finishes `alembic upgrade head`. It settles on its own.

## 4. Set `PUBLIC_BASE_URL`

Take the API's URL from its service page — `https://<name>.onrender.com` — and
set `PUBLIC_BASE_URL` to it on **both `sleeper-api` and `sleeper-worker`**.
Saving triggers a redeploy of each.

It lives on the services rather than in the `sleeper-shared` group for the
reason in step 2, and it cannot be baked into `render.yaml`: the URL is not
known until after the first deploy, and hardcoding one deployment's URL would
hand every other person deploying this blueprint a set of feedback links
pointing at someone else's server.

The environment page is under the **service's own** left nav — not the
workspace-level nav, where Blueprints and Environment Groups live. Render's
promotional cards can also push the lower nav entries out of view. Addressing
the sub-pages by URL sidesteps both problems, and works the same way for
`/env`, `/shell`, `/logs` and `/settings`:

```
https://dashboard.render.com/web/srv-XXXXXXXX/env       # sleeper-api
https://dashboard.render.com/worker/srv-YYYYYYYY/env    # sleeper-worker
```

Setting this explicitly is unavoidable: signed feedback links are generated by
the worker, and Render only injects its built-in `RENDER_EXTERNAL_URL` into web
services.

## 5. Bootstrap the first tenant

This has to run **inside the api container**, not on your own machine. The
blueprint gives `sleeper-db` an empty `ipAllowList`, so the database accepts no
external connections at all — only `sleeper-api` and `sleeper-worker` reach it,
over Render's private network. Running the CLI locally would bootstrap whatever
`DATABASE_URL` your local `.env` names, which is not this deployment.

Use the service's **Shell** tab. It sits under `MANAGE` in the service's own
left nav, where Render's promotional cards can push it out of view; the direct
URL avoids the hunt, using the Service ID shown on the service page:

```
https://dashboard.render.com/web/srv-XXXXXXXX/shell
```

Then:

```
sleeper init --tenant-name default --email you@example.com
```

`sleeper` is on `PATH` in the container — the Dockerfile puts `/app/.venv/bin`
first — so no `uv run` or venv activation is needed. It prompts for a password
and prints a bootstrap API key: copy it before closing the tab, since keys are
hashed at rest and never shown again. `init` refuses to run against a
placeholder `SECRET_KEY`, which the Render-generated value satisfies.

Choose the tenant name deliberately. It is the org label across the dashboard,
and nothing renames it afterwards: `TenantUpdate` carries only `system_prompt`
and `settings`, and the admin UI's tenant form is the same two fields, so
changing it later means a direct `UPDATE` against a database that accepts no
external connections.

Then register the starter models, in the same shell:

```
sleeper seed-models
```

`init` does not do this — the models table starts empty, which leaves the
create-agent form with nothing to select and 422s version creation on
`resolve_model`. The command is idempotent and adds five, including the
keyless `test/default` and the always-failing `test/flaky` used for
retry and dead-letter demos.

## 6. Smoke-test

```
curl https://<name>.onrender.com/healthz
```

`{"status":"ok","postgres":"ok","redis":"ok"}` means both backing services are
reachable; `/docs` serves the OpenAPI UI. Then log in to `/ui` with the user
from step 5 and run a job with the `test` provider — it exercises the full
queue → worker → callback path without needing any vendor API key.

## Iterating

Both services auto-deploy on push to `main`. Migrations run on each deploy
through the pre-deploy command. Changes to `render.yaml` itself are picked up
from the Blueprint page.

## Deliberately not enabled

- **`docker` runner backend.** `RUNNER_BACKENDS` is pinned to `monty`. The
  Docker backend needs a mounted Docker socket, which is root-equivalent on the
  host and not available on Render in any case. Monty covers tier-1 code
  graders.
- **Langfuse.** The compose profile runs ClickHouse, which is far too heavy for
  a $7 instance. The tracing seam is plain OTLP — point `LANGFUSE_HOST` and the
  key pair at Langfuse Cloud if you want traces.
- **The demo profile.** Local-only.

## Notes on the managed backing services

- **Postgres URL rewriting.** Render hands out `postgresql://…`, while this app
  is async end to end and needs `postgresql+asyncpg://`. `Settings` normalizes
  the scheme (and translates libpq's `sslmode` to asyncpg's `ssl`), so the
  Render connection string works unmodified. The same rewrite makes Neon,
  Supabase and RDS URLs work.
- **Key Value is Valkey, not Redis.** Render's engine is the Valkey fork.
  `redis-py` and `arq` talk to it unchanged, and `/healthz` reports it as
  `redis`.
- **`maxmemoryPolicy: noeviction` on Key Value.** This instance is the job
  queue, not a cache. Under memory pressure an eviction policy would silently
  drop queued jobs — arq would simply never run them, and nothing would surface
  as a failure. Refusing writes is the safe failure.
- **arq polls; the interval is tunable.** arq has no push wakeup, so the worker
  asks Redis for work on a timer — one command per tick, and its entire idle
  traffic. `WORKER_POLL_DELAY_S` defaults to 1.0s (~2.6M commands/month); 5s
  brings that to ~520k at the cost of up to 5s before an async job starts.
  `?sync=true` runs inline in the API and is never affected. Render's Key Value
  is flat-rate, so the default is fine here — the knob matters on per-command
  managed Redis (Upstash and similar), though note that even 5s exceeds most
  serverless free tiers, so those are not a drop-in substitute.
- **Backups.** Render Postgres at this plan keeps daily backups. Point-in-time
  recovery starts at higher plans.
