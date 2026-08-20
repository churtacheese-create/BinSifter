"""Generic hard-timeout wrapper around a picklable worker function, run in
a child process so a slow/hung/pathological call can be forcibly
terminated rather than merely "asked" to stop.

Built specifically to guard capa_scan.py's vivisect-backed analysis (see
that module: certain modern Windows binaries - bash.exe, curl.exe,
notepad.exe among them - get vivisect's aarch64 register-context
construction stuck for 30-90+ seconds, a third-party bug in the installed
`envi`/`vivisect` packages, not something fixable in BinSifter's own code).
Kept generic/reusable rather than capa-specific, since any other
in-process analysis library (FLOSS, Speakeasy) could hit a similar
pathological-input problem against some future real-world sample.

A subprocess, not a signal-based timeout (e.g. `signal.alarm`), is used
deliberately, for two independent reasons:
1. A SIGALRM-raised exception can be silently swallowed by a broad
   except-Exception deep inside vivisect's own analysis loop, letting the
   "cancelled" work run to completion anyway - reproduced against bash.exe
   (a signal.alarm(30) fired mid-analysis, but the surrounding vivisect
   code caught the resulting exception and kept going, finishing ~10
   seconds later regardless of the "timeout"). A signal can be caught and
   ignored by code that doesn't know it's supposed to stop; a forceful
   process terminate()/kill() cannot.
2. `signal.alarm` is POSIX-only and unavailable on Windows, BinSifter's
   primary target platform - a non-starter regardless of point 1.

multiprocessing's "spawn" context is used explicitly (not the platform
default, which is "fork" on Linux) so this behaves identically on Windows
and Linux - "spawn" is the only start method Windows supports at all, and
using it everywhere means the exact same code path gets exercised in this
sandbox's test runs as on a real Windows machine.
"""

from __future__ import annotations

import multiprocessing
from collections.abc import Callable
from typing import Any

# How long to wait for a terminated child to actually exit before escalating
# to an unconditional kill - mirrors the PowerShell version's own two-stage
# "Kill() then wait, then just move on" pattern used elsewhere for external
# tool processes (see results.py's Sigcheck/Speakeasy worker threads for the
# closest existing analogue in this port).
_TERMINATE_GRACE_SECONDS = 5


def _run_and_report(func: Callable[..., Any], args: tuple, result_queue: "multiprocessing.Queue") -> None:
    """Runs in the child process - never propagates an exception out of the
    process itself (that would just look like an unexplained non-zero exit
    code to the parent); instead reports success/failure back through the
    queue so the parent can raise a clear, real exception of its own."""
    try:
        result_queue.put(("ok", func(*args)))
    except Exception as exc:  # noqa: BLE001 - report back to the parent instead of a silent process exit
        result_queue.put(("error", str(exc)))


def run_with_timeout(
    func: Callable[..., Any],
    args: tuple,
    timeout_seconds: float,
    label: str = "operation",
) -> Any:
    """Runs func(*args) in a child process and returns its result.

    Raises TimeoutError if the child is still running after timeout_seconds
    (it is terminated, then killed if it doesn't exit within
    _TERMINATE_GRACE_SECONDS of the terminate signal). Raises RuntimeError
    if the child raised an exception, or exited without producing a result
    at all (e.g. a native-code crash - a real, accepted risk of running
    vivisect/capa in-process rather than as a disposable subprocess, same
    tradeoff already made for Speakeasy - see speakeasy_scan.py).

    func and args must be picklable: func must be a real top-level module
    function (not a bound method, lambda, or closure), since "spawn" needs
    to reimport it by name in the fresh child interpreter, and args must be
    plain, picklable data - not a capa RuleSet, PE handle, or similar
    live object tied to the parent process's memory.
    """
    ctx = multiprocessing.get_context("spawn")
    result_queue: multiprocessing.Queue = ctx.Queue()
    process = ctx.Process(target=_run_and_report, args=(func, args, result_queue))
    process.start()
    process.join(timeout_seconds)

    if process.is_alive():
        process.terminate()
        process.join(_TERMINATE_GRACE_SECONDS)
        if process.is_alive():
            process.kill()
            process.join()
        raise TimeoutError(f"{label} timed out after {timeout_seconds}s")

    if not result_queue.empty():
        status, payload = result_queue.get()
        if status == "ok":
            return payload
        raise RuntimeError(f"{label} raised in worker process: {payload}")

    raise RuntimeError(f"{label} worker process exited unexpectedly (exit code {process.exitcode})")
