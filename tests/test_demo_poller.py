"""Demo poller: event ids must not repeat across runs, since the event sources
dedup on event.id and a restarted poller would otherwise only replay old jobs."""

import importlib.util
from pathlib import Path

POLLER = Path(__file__).parent.parent / "demo" / "poller.py"


def _load_poller(monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "test-secret")
    spec = importlib.util.spec_from_file_location("demo_poller", POLLER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _ids(poller) -> list[str]:
    return [
        poller.next_market_event(1)["event"]["id"],
        poller.next_market_event(3)["event"]["id"],  # every 4th event is weather
        poller.INJECTION_EVENT["event"]["id"],
        poller.FLAKY_EVENT["event"]["id"],
    ]


def test_event_ids_are_fresh_each_run(monkeypatch) -> None:
    first, second = _load_poller(monkeypatch), _load_poller(monkeypatch)
    assert not set(_ids(first)) & set(_ids(second))


def test_event_ids_are_stable_within_a_run(monkeypatch) -> None:
    # The poller posts each event twice to show dedup, so a run must give the
    # same event the same id.
    poller = _load_poller(monkeypatch)
    assert _ids(poller) == _ids(poller)
