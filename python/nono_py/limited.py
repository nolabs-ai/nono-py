"""Run commands under resource limits by driving the tested ``nono`` CLI.

Resource limiting (currently a memory ceiling) is enforced by the ``nono``
command-line tool's trusted supervisor, which creates a cgroup v2 leaf on Linux
(``memory.max`` + ``memory.swap.max=0`` + ``memory.oom.group=1``) and lets the
kernel OOM-kill the whole process tree if it exceeds the cap. That enforcement
code lives in the ``nono`` binary and is exercised by its own live cgroup tests.

Rather than re-implement that security-critical, ``unsafe`` libc machinery in a
second place, this module *drives* the existing binary: it translates a
:class:`~nono_py.CapabilitySet` into ``nono run`` flags, adds ``--memory``, and
runs the command as a child of the supervisor. This mirrors how the nono
resource-limiting proof-of-concepts (``node-poc``, ``nono-resource-demo``) do
it — one tested implementation, driven, not copied.

Example::

    from nono_py import CapabilitySet, AccessMode
    from nono_py import limited

    caps = CapabilitySet()
    caps.allow_path("/work", AccessMode.READ_WRITE)

    result = limited.run(caps, ["python", "hog.py"], memory="512M")
    if result.oom_killed:
        print("process exceeded its memory cap and was killed")

Requirements and limitations:

- The ``nono`` binary must be available at runtime (found on ``PATH``, via the
  ``NONO_BIN`` environment variable, or passed as ``nono_bin=``).
- Memory enforcement is Linux + cgroup v2 only. On other platforms, or without
  cgroup v2 delegation, ``nono`` fails closed and this call returns its non-zero
  exit and error text rather than running with an unenforced ceiling.
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
    candidate = str(explicit) if explicit is not None else os.environ.get("NONO_BIN")
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
    validation (including its minimum-size rule), so this only rejects values
    that are obviously malformed.
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


def caps_to_flags(caps: CapabilitySet) -> list[str]:
    """Translate a :class:`CapabilitySet` into ``nono run`` flags.

    Filesystem grants map to ``--allow``/``--read``/``--write`` (directories) and
    ``--allow-file``/``--read-file``/``--write-file`` (single files), using each
    grant's canonicalized path. ``block_network()`` maps to ``--block-net``. See
    the module docstring for what is intentionally not translated.
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
    nono_bin: str | os.PathLike[str] | None = None,
) -> list[str]:
    """Build the ``nono run`` argument vector for a resource-limited command.

    Separated from :func:`run` so callers (and tests) can inspect the exact
    command line without executing it.

    Raises:
        ValueError: If ``command`` is empty or ``memory`` is malformed.
        FileNotFoundError: If the ``nono`` binary cannot be located.
    """
    if not command:
        raise ValueError("command must contain at least the program to run")

    binary = find_nono_binary(nono_bin)
    argv = [binary, "run", *caps_to_flags(caps)]
    mem = _format_memory(memory)
    if mem is not None:
        argv += ["--memory", mem]
    argv += ["--", *command]
    return argv


def run(
    caps: CapabilitySet,
    command: Sequence[str],
    *,
    memory: int | str | None = None,
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
        ValueError: If ``command`` is empty or ``memory`` is malformed.
        FileNotFoundError: If the ``nono`` binary cannot be located.
        subprocess.TimeoutExpired: If ``timeout`` elapses.
    """
    argv = build_argv(caps, command, memory=memory, nono_bin=nono_bin)
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
