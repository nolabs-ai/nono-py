"""Shared test utilities."""

import contextlib
import pathlib
import sys

from nono_py import AccessMode, CapabilitySet

_SYSTEM_PATHS = ["/usr", "/bin", "/sbin", "/lib"]
_MACOS_PATHS = ["/private", "/Library/Frameworks", "/dev"]


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
