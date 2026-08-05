"""Pluggable code runners (BUILD_PLAN § Runner design): the monty/docker
registry behind runtime/runners.py, backend gating via RUNNER_BACKENDS, and
the optional "runner" field on eval code checks. Docker tests need a daemon
and skip cleanly without one."""

import pytest

from sleeper_service.config import get_settings
from sleeper_service.runtime import evals, runners


def _docker_available() -> bool:
    try:
        import docker

        docker.from_env().ping()
        return True
    except Exception:
        return False


needs_docker = pytest.mark.skipif(not _docker_available(), reason="no docker daemon")


@pytest.fixture
def docker_enabled(monkeypatch):
    monkeypatch.setattr(get_settings(), "runner_backends", "monty,docker")


# --- registry ---


def test_default_backend_is_monty() -> None:
    assert runners.enabled_backends() == ["monty"]
    assert isinstance(runners.get_runner(), runners.MontyRunner)
    assert isinstance(runners.get_runner("monty"), runners.MontyRunner)


def test_disabled_backend_refused() -> None:
    with pytest.raises(runners.SandboxError, match="not enabled"):
        runners.get_runner("docker")
    with pytest.raises(runners.SandboxError, match="not enabled"):
        runners.get_runner("e2b")


def test_unknown_names_dropped_from_config(monkeypatch) -> None:
    monkeypatch.setattr(get_settings(), "runner_backends", "e2b, bogus")
    assert runners.enabled_backends() == ["monty"]  # never an empty set


def test_first_enabled_backend_is_default(docker_enabled) -> None:
    assert runners.enabled_backends() == ["monty", "docker"]
    assert isinstance(runners.get_runner(), runners.MontyRunner)


def test_monty_runner_round_trip() -> None:
    runner = runners.get_runner("monty")
    assert runner.run("def grade(output):\n    return output['x'] + 1", "grade", {"x": 2}) == 3
    assert runner.validate("def grade(output):\n    return 1", "grade") is None
    assert runner.validate("grade = 5", "grade") is not None


# --- docker backend ---


@needs_docker
def test_docker_runner_real_python(docker_enabled) -> None:
    # imports work — the whole point of tier 2 over Monty
    code = "import statistics\ndef grade(output):\n    return statistics.mean(output['xs'])"
    assert runners.get_runner("docker").run(code, "grade", {"xs": [1, 2, 3]}) == 2


@needs_docker
def test_docker_runner_validate(docker_enabled) -> None:
    runner = runners.get_runner("docker")
    assert runner.validate("def grade(output):\n    return True", "grade") is None
    assert "not a function" in runner.validate("grade = 5", "grade")
    assert "SyntaxError" in runner.validate("def grade(:", "grade")


@needs_docker
def test_docker_runner_exceptions_are_sandbox_errors(docker_enabled) -> None:
    with pytest.raises(runners.SandboxError, match="ZeroDivisionError"):
        runners.get_runner("docker").run("def grade(output):\n    return 1/0", "grade", {})


@needs_docker
def test_docker_runner_no_network(docker_enabled) -> None:
    code = (
        "import urllib.request\n"
        "def grade(output):\n"
        "    urllib.request.urlopen('http://example.com', timeout=3)\n"
        "    return True"
    )
    with pytest.raises(runners.SandboxError, match=r"URLError|OSError|gaierror"):
        runners.get_runner("docker").run(code, "grade", {})


@needs_docker
def test_docker_runner_wall_clock_cap(docker_enabled) -> None:
    code = "import time\ndef grade(output):\n    time.sleep(600)"
    limits = {**runners.DEFAULT_LIMITS, "max_duration_secs": 2.0}
    with pytest.raises(runners.SandboxError, match="timed out"):
        runners.get_runner("docker").run(code, "grade", {}, limits=limits)


@needs_docker
def test_docker_runner_unserializable_result(docker_enabled) -> None:
    with pytest.raises(runners.SandboxError, match="TypeError"):
        runners.get_runner("docker").run("def grade(output):\n    return set()", "grade", {})


# --- eval check integration ---


def test_check_validation_rejects_disabled_runner() -> None:
    checks = [{"op": "code", "code": "def grade(output):\n    return True", "runner": "docker"}]
    assert "not enabled" in evals.validate_checks(checks)


@needs_docker
def test_code_check_runs_on_selected_backend(docker_enabled) -> None:
    check = {
        "op": "code",
        "code": "import math\ndef grade(output):\n    return math.isclose(output['p'], 0.5)",
        "runner": "docker",
    }
    assert evals.validate_checks([check]) is None
    passed, detail = evals.run_check(check, {"p": 0.5}, None)
    assert passed, detail
    passed, _ = evals.run_check(check, {"p": 0.9}, None)
    assert not passed
