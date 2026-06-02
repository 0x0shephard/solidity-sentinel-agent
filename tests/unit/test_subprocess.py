import pytest
import sys

from sentinel.reliability.subprocess import run_command


def test_run_command_requires_list_arguments():
    with pytest.raises(ValueError):
        run_command([], cwd=".")


def test_run_command_captures_output():
    result = run_command([sys.executable, "--version"], cwd=".", timeout=15)

    assert result.command == [sys.executable, "--version"]
    assert result.return_code == 0
    assert result.timed_out is False
