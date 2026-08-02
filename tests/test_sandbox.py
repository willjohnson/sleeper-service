"""Tier-1 sandbox (runtime/sandbox.py): Monty enforces the caps that make
editor-supplied grader code safe to run in-process."""

import time

from sleeper_service.runtime import sandbox

FAST: dict = {"max_duration_secs": 0.5, "max_memory": 16 * 1024 * 1024}


def test_run_function_returns_value() -> None:
    code = "def grade(output):\n    return output['risk_level'] == 'high'"
    assert sandbox.run_function(code, "grade", {"risk_level": "high"}) is True
    assert sandbox.run_function(code, "grade", {"risk_level": "low"}) is False


def test_run_function_arbitrary_return() -> None:
    code = "def shape(x):\n    return {'n': len(x), 'keys': sorted(x)}"
    assert sandbox.run_function(code, "shape", {"b": 1, "a": 2}) == {"n": 2, "keys": ["a", "b"]}


def test_timeout_enforced() -> None:
    t0 = time.monotonic()
    try:
        spin = "def grade(output):\n    while True:\n        pass"
        sandbox.run_function(spin, "grade", {}, limits=FAST)
        raise AssertionError("timeout not enforced")
    except sandbox.SandboxError as e:
        assert "time limit" in str(e)
    assert time.monotonic() - t0 < 5


def test_memory_cap_enforced() -> None:
    code = "def grade(output):\n    return len([0] * (64 * 1024 * 1024))"
    try:
        sandbox.run_function(code, "grade", {}, limits=FAST)
        raise AssertionError("memory cap not enforced")
    except sandbox.SandboxError as e:
        assert "memory limit" in str(e)


def test_no_filesystem_access() -> None:
    code = "def grade(output):\n    return open('/etc/passwd').read()"
    try:
        sandbox.run_function(code, "grade", {}, limits=FAST)
        raise AssertionError("filesystem access not blocked")
    except sandbox.SandboxError as e:
        assert "Permission" in str(e)


def test_grader_exception_surfaces_detail() -> None:
    code = "def grade(output):\n    return output['missing_key']"
    try:
        sandbox.run_function(code, "grade", {}, limits=FAST)
        raise AssertionError("expected SandboxError")
    except sandbox.SandboxError as e:
        assert "missing_key" in str(e)


def test_validate_function() -> None:
    assert sandbox.validate_function("def grade(output):\n    return True", "grade") is None
    # syntax error
    assert sandbox.validate_function("def grade(output:\n    pass", "grade") is not None
    # doesn't define the entrypoint
    assert sandbox.validate_function("def other(output):\n    return True", "grade") is not None
    # entrypoint defined but not callable
    assert sandbox.validate_function("grade = 42", "grade") is not None
