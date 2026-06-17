"""Live progress streaming for an audit run.

Long audits (static analysis, planner rounds, per-hypothesis research) can run
for minutes. Rather than make the user stare at a silent terminal, the pipeline
emits concise progress lines as work happens. A sink is installed only when the
caller asks (the CLI in interactive mode); tests and the eval runner leave it
unset, so ``emit`` is a cheap no-op everywhere else.

Lines go to stderr so stdout stays clean for the final summary / benchmark
markdown. The format is ``[mm:ss] <message>`` with elapsed wall-clock time.
"""

from __future__ import annotations

import sys
import threading
import time
from collections.abc import Callable

_sink: Callable[[str], None] | None = None
_start = time.monotonic()
_lock = threading.Lock()


def set_progress_sink(sink: Callable[[str], None] | None) -> None:
    """Install (or clear) the progress sink and reset the elapsed-time clock.

    Args:
        sink: A ``(line) -> None`` callable, or None to disable streaming.
    Returns:
        None.
    """
    global _sink, _start
    with _lock:
        _sink = sink
        _start = time.monotonic()


def emit(message: str) -> None:
    """Emit one progress line (no-op when no sink is installed).

    Args:
        message: The human-readable progress message.
    Returns:
        None. Prepends an ``[mm:ss]`` elapsed-time stamp and forwards to the sink.
    """
    with _lock:
        sink = _sink
        elapsed = time.monotonic() - _start
    if sink is None:
        return
    minutes, seconds = divmod(int(elapsed), 60)
    try:
        sink(f"[{minutes:02d}:{seconds:02d}] {message}")
    except Exception:
        pass


def console_sink(message: str) -> None:
    """Default sink: write a progress line to stderr, flushed immediately.

    Args:
        message: The fully-formatted progress line.
    Returns:
        None.
    """
    print(message, file=sys.stderr, flush=True)
