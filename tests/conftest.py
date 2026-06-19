from __future__ import annotations

import pytest

from sentinel.reliability.subprocess import CommandResult


@pytest.fixture(autouse=True)
def _fast_hermetic_env(monkeypatch):
    """Make the suite fast and hermetic.

    Two dominant costs were removed here:

    * **Network**: keep Hugging Face offline (the embedding model is cached), so
      a failed DNS lookup doesn't trigger tenacity retry backoff per call.
    * **Slither**: ``static.run_slither`` shells out to slither/crytic-compile,
      which can take minutes (it was hitting its 180s timeout) on a throwaway
      repo and dominated nearly every pipeline test. Stub the static-tool
      subprocess to a fast empty result. ``run_slither`` then writes its own
      empty-but-valid JSON and reports OK with no detectors — which is all the
      pipeline tests need. The dedicated slither tests in
      ``test_real_solidity_tools.py`` re-patch this same symbol in their own
      body (which runs after this fixture), so they still exercise the real
      classification logic.
    """
    monkeypatch.setenv("HF_HUB_OFFLINE", "1")
    monkeypatch.setenv("TRANSFORMERS_OFFLINE", "1")

    def _fast_static_run(command, cwd, timeout=60, env=None):
        return CommandResult(command=list(command), cwd=str(cwd), return_code=0, stdout="", stderr="")

    monkeypatch.setattr("sentinel.tools.static.run_command", _fast_static_run, raising=False)


def pytest_collection_modifyitems(config, items):
    """Auto-mark tests under tests/integration/ so `-m "not integration"` gives a
    fast unit-only run."""
    for item in items:
        if "/integration/" in str(item.fspath).replace("\\", "/"):
            item.add_marker(pytest.mark.integration)
