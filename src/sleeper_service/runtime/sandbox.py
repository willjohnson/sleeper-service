"""Sandboxed code execution (BUILD_PLAN § Runner design).

Tier 1, this module: **Pydantic Monty** — a Rust interpreter for a Python
subset, executed in subprocess workers with hard caps on wall clock, heap,
and recursion depth, and no imports, filesystem, or network. Picked over
micropython-wasm 2026-08-02: pure pip install (no wasmtime), limits verified
enforced (timeout kills at the cap, allocations die at max_memory, the pool
survives worker crashes), and the obvious PydanticAI-stack fit.

Tiers 2/3 (disposable containers — evaluate Anthropic srt — and hosted
sandboxes) slot in behind the same two functions if agent code ever needs
real filesystems or packages.

Monty releases the GIL while it blocks, so async callers should wrap calls
in anyio.to_thread to keep their event loop responsive.
"""

from typing import Any

import pydantic_monty

DEFAULT_LIMITS: pydantic_monty.ResourceLimits = {
    "max_duration_secs": 5.0,
    "max_memory": 64 * 1024 * 1024,
    "max_recursion_depth": 200,
}


class SandboxError(Exception):
    """Code was rejected or failed in the sandbox; str(exc) is the detail."""


def run_function(
    code: str,
    entrypoint: str,
    argument: Any,
    *,
    limits: pydantic_monty.ResourceLimits | None = None,
) -> Any:
    """Execute `code`, then call `entrypoint(argument)` and return its value.

    `code` must define `entrypoint` at the top level; the argument is passed
    in as a sandbox input, never interpolated into source.
    """
    script = f"{code}\n\n_sandbox_result = {entrypoint}(_sandbox_arg)\n_sandbox_result"
    try:
        with pydantic_monty.Monty() as pool, pool.checkout(limits=limits or DEFAULT_LIMITS) as s:
            return s.feed_run(script, inputs={"_sandbox_arg": argument})
    except pydantic_monty.MontyError as e:
        raise SandboxError(str(e)) from e


def validate_function(
    code: str,
    entrypoint: str,
    *,
    limits: pydantic_monty.ResourceLimits | None = None,
) -> str | None:
    """Run `code` (top-level statements execute; the entrypoint is not
    called) and confirm it defines an `entrypoint` function. Returns an
    error detail, or None when valid."""
    script = f"{code}\n\nstr(type({entrypoint}))"  # Monty has no callable()
    try:
        with pydantic_monty.Monty() as pool, pool.checkout(limits=limits or DEFAULT_LIMITS) as s:
            kind = s.feed_run(script)
    except pydantic_monty.MontyError as e:
        return str(e)
    if kind != "<class 'function'>":
        return f"{entrypoint!r} is not a function (got {kind})"
    return None
