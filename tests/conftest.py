"""Pytest configuration and fixtures."""

import pytest  # ty:ignore[unresolved-import]  # noqa: F401
from utils import add_minimal_exec_paths, add_system_paths

from nono_py import AccessMode, CapabilitySet, is_supported, sandboxed_exec

# Re-export so existing tests that do `from conftest import add_system_paths` keep working.
__all__ = ["add_minimal_exec_paths", "add_system_paths"]


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


@pytest.fixture
def session_dir(tmp_path):
    """Empty session directory for audit log tests."""
    d = tmp_path / "session"
    d.mkdir()
    return d


@pytest.fixture
def snapshot_session_dir(tmp_path):
    """Empty session directory for SnapshotManager tests."""
    d = tmp_path / "snap_session"
    d.mkdir()
    return d


@pytest.fixture
def tracked_dir(tmp_path):
    """Tracked directory pre-populated with two seed files."""
    d = tmp_path / "tracked"
    d.mkdir()
    (d / "file_a.txt").write_text("content_a")
    (d / "file_b.txt").write_text("content_b")
    return d


@pytest.fixture(scope="session")
def _sandboxed_exec_available(tmp_path_factory: pytest.TempPathFactory) -> bool:
    """Return True if sandboxed_exec can initialize in this process.

    Returns False when the platform does not support sandboxing or when
    tests run inside an existing nono/Seatbelt sandbox (nested sandboxing
    is prohibited on macOS).
    """
    if not is_supported():
        return False
    try:
        tmp = tmp_path_factory.mktemp("exec_probe")
        caps = CapabilitySet()
        add_system_paths(caps)
        caps.allow_path(str(tmp), AccessMode.READ_WRITE)
        result = sandboxed_exec(caps, ["true"], cwd=str(tmp))
        return result.exit_code == 0
    except RuntimeError:
        return False


@pytest.fixture
def require_sandboxed_exec(_sandboxed_exec_available: bool) -> None:
    """Skip the test if sandboxed_exec cannot initialize."""
    if not _sandboxed_exec_available:
        pytest.skip("sandboxed_exec unavailable in this environment")
