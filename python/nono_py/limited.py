"""Run commands under resource limits by driving the tested ``nono`` CLI.

Resource limiting (a memory ceiling and/or a process-count cap) is enforced by
the ``nono`` command-line tool's trusted supervisor, which creates a cgroup v2
leaf on Linux and lets the kernel police the whole process tree:

- ``--memory`` sets ``memory.max`` (+ ``memory.swap.max=0`` + ``memory.oom.group=1``);
  a tree that exceeds it is OOM-killed (SIGKILL, exit ``137``).
- ``--max-processes`` sets ``pids.max``; at the cap the kernel refuses the next
  ``fork``/``clone`` with ``EAGAIN``. **Nothing is killed** — the offending
  process just fails to spawn — so there is no fixed exit code, unlike the
  memory OOM path. The failing command surfaces its own error and status.
  This is a hard, per-tree, unescapable cap. The in-process
  :func:`~nono_py.sandboxed_exec` offers ``max_processes`` (RLIMIT_NPROC), a
  best-effort per-UID cap that a child can escape (e.g. via ``setsid``); prefer
  this cgroup cap where cgroup v2 delegation is available.

That enforcement code lives in the ``nono`` binary and is exercised by its own
live cgroup tests.

Rather than re-implement that security-critical, ``unsafe`` libc machinery in a
second place, this module *drives* the existing binary: it translates a
:class:`~nono_py.CapabilitySet` into ``nono run`` flags, adds ``--memory`` and/or
``--max-processes``, and runs the command as a child of the supervisor.

Example::

    from nono_py import CapabilitySet, AccessMode
    from nono_py import limited

    caps = CapabilitySet()
    caps.allow_path("/work", AccessMode.READ_WRITE)

    result = limited.run(
        caps, ["python", "hog.py"], memory="512M", max_processes=64
    )
    if result.oom_killed:
        print("process exceeded its memory cap and was killed")
    elif not result.ok:
        print(f"failed ({result.returncode}): {result.stderr}")

Requirements and limitations:

- The ``nono`` binary must be available at runtime (found on ``PATH``, via the
  ``NONO_BIN`` environment variable, or passed as ``nono_bin=``).
- Resource enforcement is Linux + cgroup v2 only. On other platforms, or without
  cgroup v2 delegation, ``nono`` fails closed and this call returns its non-zero
  exit and error text rather than running with an unenforced limit.
- Only filesystem grants and ``block_network()`` are translated into CLI flags.
  ``proxy_only()`` network mode is **not** carried: the in-process proxy handle
  cannot cross the subprocess boundary. Use ``block_network()``, or run under a
  nono profile, if you need restricted (non-blocked) network here.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from nono_py._nono_py import AccessMode, CapabilitySet

__all__ = [
    "OOM_EXIT_CODE",
    "RunResult",
    "build_argv",
    "caps_to_flags",
    "find_nono_binary",
    "run",
]

# Exit code reported for a process killed by SIGKILL (128 + 9), which is how the
# kernel terminates a tree that busts its cgroup memory cap.
OOM_EXIT_CODE = 137


@dataclass(frozen=True)
class RunResult:
    """Outcome of a resource-limited run driven through the ``nono`` CLI."""

    argv: list[str]
    """The full ``nono`` command line that was executed (useful for debugging)."""

    returncode: int
    """Exit status of ``nono`` (which forwards the child's status)."""

    stdout: str | bytes | None
    """Captured standard output, or ``None`` when output was not captured."""

    stderr: str | bytes | None
    """Captured standard error, or ``None`` when output was not captured."""

    @property
    def ok(self) -> bool:
        """True if the command exited cleanly (status 0)."""
        return self.returncode == 0

    @property
    def oom_killed(self) -> bool:
        """True if the process was killed at its memory cap (SIGKILL / 137).

        This is the expected outcome when a run busts its ``--memory`` ceiling,
        but 137 is also produced by any other SIGKILL, so treat it as a strong
        hint rather than proof.
        """
        return self.returncode == OOM_EXIT_CODE


def find_nono_binary(explicit: str | os.PathLike[str] | None = None) -> str:
    """Locate the ``nono`` binary.

    Resolution order: ``explicit`` argument, then the ``NONO_BIN`` environment
    variable, then a ``nono`` on ``PATH``.

    Raises:
        FileNotFoundError: If no usable ``nono`` executable is found.
    """
    candidate = os.fspath(explicit) if explicit is not None else os.environ.get("NONO_BIN")
    if candidate:
        resolved = shutil.which(candidate)
        if resolved is None:
            raise FileNotFoundError(f"nono binary not found or not executable: {candidate!r}")
        return resolved
    resolved = shutil.which("nono")
    if resolved is None:
        raise FileNotFoundError(
            "nono binary not found on PATH; install nono, pass nono_bin=, or set NONO_BIN"
        )
    return resolved


def _format_memory(memory: int | str | None) -> str | None:
    """Normalize a memory limit into a ``nono --memory`` size string.

    An ``int`` is treated as a raw byte count; a ``str`` is passed through (e.g.
    ``"512M"``, ``"1Gi"``). ``nono`` performs the authoritative parsing and
    validation (rejecting zero and overflow), so this only rejects values that
    are obviously malformed.
    """
    if memory is None:
        return None
    if isinstance(memory, bool):  # bool is an int subclass; reject it explicitly
        raise TypeError("memory must be an int (bytes) or a size string, not bool")
    if isinstance(memory, int):
        if memory <= 0:
            raise ValueError(f"memory limit must be positive, got {memory}")
        return str(memory)
    text = memory.strip()
    if not text:
        raise ValueError("memory limit string cannot be empty")
    return text


def _format_max_processes(max_processes: int | None) -> str | None:
    """Normalize a process-count cap into a ``nono --max-processes`` value.

    The cap is a plain task count (processes + threads), so only an ``int`` is
    accepted — there is no size-string form as there is for ``--memory``. ``nono``
    rejects zero (a cap of 0 would forbid the sandbox from running anything), so
    this requires at least 1 to fail early with a clear message.
    """
    if max_processes is None:
        return None
    if isinstance(max_processes, bool):  # bool is an int subclass; reject it explicitly
        raise TypeError("max_processes must be an int count, not bool")
    if not isinstance(max_processes, int):
        raise TypeError(f"max_processes must be an int count, got {type(max_processes).__name__}")
    if max_processes < 1:
        raise ValueError(f"max_processes must be at least 1, got {max_processes}")
    return str(max_processes)


def caps_to_flags(caps: CapabilitySet) -> list[str]:
    """Translate a :class:`CapabilitySet` into ``nono run`` flags.

    Filesystem grants map to ``--allow``/``--read``/``--write`` (directories) and
    ``--allow-file``/``--read-file``/``--write-file`` (single files), using each
    grant's canonicalized path. ``block_network()`` maps to ``--block-net``. See
    the module docstring for what is intentionally not translated.

    Raises:
        ValueError: If a read+write *directory* grant's path contains a comma.
            The ``nono`` CLI's ``--allow`` flag treats commas as a value
            separator, so it would split such a path and silently grant the
            wrong (or no) directory. Rather than mis-grant, we fail loudly.
            Only ``--allow`` has this delimiter; the other flags are unaffected.
    """
    flags: list[str] = []
    for cap in caps.fs_capabilities():
        path = cap.resolved
        if cap.is_file:
            if cap.access == AccessMode.READ:
                flags += ["--read-file", path]
            elif cap.access == AccessMode.WRITE:
                flags += ["--write-file", path]
            else:
                flags += ["--allow-file", path]
        else:
            if cap.access == AccessMode.READ:
                flags += ["--read", path]
            elif cap.access == AccessMode.WRITE:
                flags += ["--write", path]
            elif "," in path:
                raise ValueError(
                    f"cannot grant read+write to a directory whose path contains a "
                    f"comma via the nono CLI: {path!r}. The --allow flag treats commas "
                    f"as a value separator and would split the path. Rename the "
                    f"directory, or grant it read and write separately."
                )
            else:
                flags += ["--allow", path]
    if caps.is_network_blocked:
        flags.append("--block-net")
    return flags


def build_argv(
    caps: CapabilitySet,
    command: Sequence[str],
    *,
    memory: int | str | None = None,
    max_processes: int | None = None,
    nono_bin: str | os.PathLike[str] | None = None,
) -> list[str]:
    """Build the ``nono run`` argument vector for a resource-limited command.

    Separated from :func:`run` so callers (and tests) can inspect the exact
    command line without executing it.

    Raises:
        ValueError: If ``command`` is empty, or ``memory`` / ``max_processes``
            is malformed.
        TypeError: If ``max_processes`` is not an int count.
        FileNotFoundError: If the ``nono`` binary cannot be located.
    """
    if not command:
        raise ValueError("command must contain at least the program to run")

    binary = find_nono_binary(nono_bin)
    argv = [binary, "run", *caps_to_flags(caps)]
    mem = _format_memory(memory)
    if mem is not None:
        argv += ["--memory", mem]
    procs = _format_max_processes(max_processes)
    if procs is not None:
        argv += ["--max-processes", procs]
    argv += ["--", *command]
    return argv


def run(
    caps: CapabilitySet,
    command: Sequence[str],
    *,
    memory: int | str | None = None,
    max_processes: int | None = None,
    cwd: str | os.PathLike[str] | None = None,
    timeout: float | None = None,
    env: Mapping[str, str] | None = None,
    capture_output: bool = True,
    text: bool = True,
    nono_bin: str | os.PathLike[str] | None = None,
) -> RunResult:
    """Run ``command`` under a resource limit via the ``nono`` CLI supervisor.

    Args:
        caps: Capabilities to grant, translated into ``nono run`` flags.
        command: Program and arguments to execute (must be non-empty).
        memory: Memory ceiling as a byte count (int) or size string (e.g.
            ``"512M"``). ``None`` runs sandboxed without a memory cap.
        max_processes: Maximum number of processes and threads in the tree
            (``pids.max``). At the cap, new forks are refused with ``EAGAIN``
            rather than anything being killed. ``None`` runs without a cap.
        cwd: Working directory for the child.
        timeout: Seconds before the run is killed (raises
            :class:`subprocess.TimeoutExpired`).
        env: Environment for ``nono`` and its child. ``None`` inherits the
            current process environment.
        capture_output: Capture stdout/stderr into the result; if False, the
            child inherits this process's streams and the result carries ``None``.
        text: Decode captured output as text (str) rather than bytes.
        nono_bin: Explicit path to the ``nono`` binary.

    Returns:
        RunResult: exit status and captured output.

    Raises:
        ValueError: If ``command`` is empty, or ``memory`` / ``max_processes``
            is malformed.
        TypeError: If ``max_processes`` is not an int count.
        FileNotFoundError: If the ``nono`` binary cannot be located.
        subprocess.TimeoutExpired: If ``timeout`` elapses.
    """
    argv = build_argv(caps, command, memory=memory, max_processes=max_processes, nono_bin=nono_bin)
    completed = subprocess.run(  # noqa: S603 - argv is built from caps, not a shell string
        argv,
        cwd=os.fspath(cwd) if cwd is not None else None,
        env=dict(env) if env is not None else None,
        capture_output=capture_output,
        text=text,
        timeout=timeout,
        check=False,
    )
    return RunResult(
        argv=argv,
        returncode=completed.returncode,
        stdout=completed.stdout if capture_output else None,
        stderr=completed.stderr if capture_output else None,
    )
