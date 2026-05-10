"""Pytest configuration and fixtures."""

import contextlib
import pathlib
import sys

import pytest  # ty:ignore[unresolved-import]  # noqa: F401

from nono_py import AccessMode, CapabilitySet

_SYSTEM_PATHS = ["/usr", "/bin", "/sbin", "/lib"]
_MACOS_PATHS = ["/private", "/Library/Frameworks", "/dev"]


def add_system_paths(caps: CapabilitySet) -> None:
    """Add system paths to a capability set, ignoring missing ones."""
    for sys_path in _SYSTEM_PATHS + _MACOS_PATHS:
        with contextlib.suppress(FileNotFoundError):
            caps.allow_path(sys_path, AccessMode.READ)
    # Allow the Python installation so tests can exec sys.executable in the sandbox.
    # Resolves symlinks so venv -> toolcache paths are covered on CI.
    py_prefix = str(pathlib.Path(sys.executable).resolve().parent.parent)
    with contextlib.suppress(FileNotFoundError):
        caps.allow_path(py_prefix, AccessMode.READ)
    # Also allow the venv prefix (pyvenv.cfg, venv site-packages) when running in a venv.
    if sys.prefix != py_prefix:
        with contextlib.suppress(FileNotFoundError):
            caps.allow_path(sys.prefix, AccessMode.READ)


@pytest.fixture
def temp_dir(tmp_path):
    """Provide a temporary directory for tests."""
    return tmp_path


@pytest.fixture
def temp_file(tmp_path):
    """Provide a temporary file for tests."""
    file_path = tmp_path / "test_file.txt"
    file_path.write_text("test content")
    return file_path
