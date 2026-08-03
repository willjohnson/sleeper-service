"""Pluggable sandboxed code runners (BUILD_PLAN § Runner design).

The abstraction over the three runner tiers is this module's small protocol
— run a function, validate a function — mirroring how data stores unify five
storage backends behind one tool surface. Backends:

- **monty** (tier 1, default): in-process Pydantic Monty via
  runtime/sandbox.py. Python subset, no imports/fs/network, zero infra.
- **docker** (tier 2): one throwaway container per call — real CPython with
  stdlib and whatever packages the configured image carries, no network,
  memory/CPU/wall-clock caps, destroyed after. Needs the Docker socket
  (mount /var/run/docker.sock into api and worker).
- Hosted sandboxes (tier 3 — E2B, Modal, …) slot into REGISTRY the same way
  when someone needs VM-grade isolation without local infra. Not shipped:
  they'd make an external account a dependency of an OSS install.

Operators opt in via RUNNER_BACKENDS (comma-separated; first entry is the
default backend). Callers select per call — eval code checks carry an
optional "runner" name, validated against the enabled set on write.

All runners are synchronous and may block for up to their duration cap —
async callers offload to a thread, as evals already does.
"""

import json
from typing import Any, Protocol

from sleeper_service.config import get_settings
from sleeper_service.runtime import sandbox
from sleeper_service.runtime.sandbox import DEFAULT_LIMITS, SandboxError

__all__ = ["DEFAULT_LIMITS", "Runner", "SandboxError", "enabled_backends", "get_runner"]


class Runner(Protocol):
    def run(self, code: str, entrypoint: str, argument: Any, *, limits: dict | None = None) -> Any:
        """Execute `code`, call `entrypoint(argument)`, return its value.
        Raises SandboxError on rejection, failure, or a blown limit."""
        ...

    def validate(self, code: str, entrypoint: str, *, limits: dict | None = None) -> str | None:
        """Check that `code` runs and defines `entrypoint` as a function
        (without calling it). Returns an error detail, or None when valid."""
        ...


class MontyRunner:
    """Tier 1 — in-process Monty; see runtime/sandbox.py for the guarantees."""

    def run(self, code: str, entrypoint: str, argument: Any, *, limits: dict | None = None) -> Any:
        return sandbox.run_function(code, entrypoint, argument, limits=limits)

    def validate(self, code: str, entrypoint: str, *, limits: dict | None = None) -> str | None:
        return sandbox.validate_function(code, entrypoint, limits=limits)


# --- Tier 2: disposable Docker containers ---

# Runs inside the container and never sees untrusted input outside it: the
# request (code + argument) arrives via an environment variable as JSON, the
# verdict leaves as one JSON line on stdout.
_DOCKER_HARNESS = """\
import json, os, sys
req = json.loads(os.environ["SANDBOX_REQUEST"])
ns = {}
try:
    exec(compile(req["code"], "<sandbox>", "exec"), ns)
    fn = ns.get(req["entrypoint"])
    if not callable(fn):
        print(json.dumps({"ok": False, "error": repr(req["entrypoint"]) + " is not a function"}))
        sys.exit(0)
    if req["mode"] == "validate":
        print(json.dumps({"ok": True, "result": None}))
        sys.exit(0)
    result = fn(req["argument"])
    print(json.dumps({"ok": True, "result": result}))
except Exception as e:
    print(json.dumps({"ok": False, "error": type(e).__name__ + ": " + str(e)}))
"""

_DOCKER_WAIT_GRACE_S = 10  # container startup on top of the code's own cap


class DockerRunner:
    """Tier 2 — one hardened throwaway container per call.

    No network, all capabilities dropped, no privilege escalation, pids and
    memory capped (no swap), one CPU, runs as nobody. The wall-clock cap is
    enforced from outside: expired containers are killed, and every container
    is force-removed on the way out.
    """

    def __init__(self) -> None:
        import docker

        self._docker = docker
        self._client = docker.from_env()

    def _execute(self, request: dict, duration_s: float, memory: int) -> dict:
        image = get_settings().runner_docker_image
        try:
            self._client.images.get(image)
        except self._docker.errors.ImageNotFound:
            self._client.images.pull(image)

        container = self._client.containers.create(
            image,
            command=["python", "-c", _DOCKER_HARNESS],
            environment={"SANDBOX_REQUEST": json.dumps(request)},
            network_disabled=True,
            mem_limit=memory,
            memswap_limit=memory,
            nano_cpus=1_000_000_000,
            pids_limit=64,
            user="65534:65534",
            cap_drop=["ALL"],
            security_opt=["no-new-privileges"],
        )
        try:
            container.start()
            try:
                exit_info = container.wait(timeout=duration_s + _DOCKER_WAIT_GRACE_S)
            except Exception as e:  # requests timeout — the code blew its cap
                raise SandboxError(
                    f"timed out after {duration_s + _DOCKER_WAIT_GRACE_S:.0f}s"
                ) from e
            stdout = container.logs(stdout=True, stderr=False).decode(errors="replace")
            try:
                return json.loads(stdout.strip().splitlines()[-1])
            except (IndexError, ValueError):
                stderr = container.logs(stdout=False, stderr=True).decode(errors="replace")
                container.reload()
                oom = " (out of memory)" if container.attrs["State"].get("OOMKilled") else ""
                raise SandboxError(
                    f"exit code {exit_info.get('StatusCode')}{oom}: {stderr.strip()[-500:]}"
                ) from None
        finally:
            container.remove(force=True)

    def _request(self, mode: str, code: str, entrypoint: str, argument: Any, limits: dict) -> dict:
        request = {"mode": mode, "code": code, "entrypoint": entrypoint, "argument": argument}
        try:
            return self._execute(
                request,
                float(limits["max_duration_secs"]),
                int(limits["max_memory"]),
            )
        except SandboxError:
            raise
        except Exception as e:  # daemon trouble, not user code
            raise SandboxError(f"docker runner unavailable: {e}") from e

    def run(self, code: str, entrypoint: str, argument: Any, *, limits: dict | None = None) -> Any:
        verdict = self._request("run", code, entrypoint, argument, limits or DEFAULT_LIMITS)
        if not verdict.get("ok"):
            raise SandboxError(str(verdict.get("error")))
        return verdict.get("result")

    def validate(self, code: str, entrypoint: str, *, limits: dict | None = None) -> str | None:
        verdict = self._request("validate", code, entrypoint, None, limits or DEFAULT_LIMITS)
        return None if verdict.get("ok") else str(verdict.get("error"))


REGISTRY: dict[str, type] = {"monty": MontyRunner, "docker": DockerRunner}

_instances: dict[str, Runner] = {}


def enabled_backends() -> list[str]:
    """Operator-enabled backends, in order; the first is the default."""
    names = [n.strip() for n in get_settings().runner_backends.split(",") if n.strip()]
    return [n for n in names if n in REGISTRY] or ["monty"]


def get_runner(name: str | None = None) -> Runner:
    """The named backend, or the default when name is None. Raises
    SandboxError for unknown or disabled names — callers validated the name
    on write, so hitting this means config drift, not user error."""
    enabled = enabled_backends()
    name = name or enabled[0]
    if name not in enabled:
        raise SandboxError(
            f"runner backend {name!r} is not enabled (RUNNER_BACKENDS={','.join(enabled)})"
        )
    if name not in _instances:
        _instances[name] = REGISTRY[name]()
    return _instances[name]
