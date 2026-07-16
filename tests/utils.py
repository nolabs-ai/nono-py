"""Shared test utilities."""

import contextlib
import pathlib
import sys

from nono_py import AccessMode, CapabilitySet

_SYSTEM_PATHS = ["/usr", "/bin", "/sbin", "/lib"]
_MACOS_PATHS = ["/private", "/Library/Frameworks", "/dev"]
_LINUX_EXTRA_PATHS = ["/lib64", "/usr/lib", "/usr/lib64"]


def add_system_paths(caps: CapabilitySet) -> None:
    """Add system paths to a capability set, ignoring missing ones."""
    for sys_path in _SYSTEM_PATHS + _MACOS_PATHS:
        with contextlib.suppress(FileNotFoundError):
            caps.allow_path(sys_path, AccessMode.READ)
    py_prefix = str(pathlib.Path(sys.executable).resolve().parent.parent)
    with contextlib.suppress(FileNotFoundError):
        caps.allow_path(py_prefix, AccessMode.READ)
    if sys.prefix != py_prefix:
        with contextlib.suppress(FileNotFoundError):
            caps.allow_path(sys.prefix, AccessMode.READ)


def add_minimal_exec_paths(caps: CapabilitySet) -> None:
    """Grant paths needed for sandboxed_exec to run shell utilities.

    Unlike ``add_system_paths``, this omits ``/private`` on macOS so tests that
    expect ``/etc/hosts`` denials are not masked by a broad read grant over
    ``/private/etc``. On Linux it includes loader/library paths required for
    dynamically linked ``/bin/sh``.
    """
    for sys_path in _SYSTEM_PATHS:
        with contextlib.suppress(FileNotFoundError):
            caps.allow_path(sys_path, AccessMode.READ)
    if sys.platform == "darwin":
        for sys_path in ["/Library/Frameworks", "/dev"]:
            with contextlib.suppress(FileNotFoundError):
                caps.allow_path(sys_path, AccessMode.READ)
    else:
        for sys_path in _LINUX_EXTRA_PATHS:
            with contextlib.suppress(FileNotFoundError):
                caps.allow_path(sys_path, AccessMode.READ)
