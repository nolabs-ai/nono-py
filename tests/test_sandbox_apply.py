"""Tests for the sandbox apply family and Landlock ABI detection.

Covers ``apply_landlock``, ``apply_seccomp``, ``apply_external``, the
``*_with_abi`` variants, and ``detect_abi`` / ``DetectedAbi``.

Applying a sandbox is **irreversible**, so the enforcement tests run in a
forked child process; the parent (the test runner) stays unsandboxed.
"""

import os
import sys
from collections.abc import Callable
from pathlib import Path

import pytest
from utils import add_system_paths

import nono_py
from nono_py import (
    AccessMode,
    CapabilitySet,
    DetectedAbi,
    apply_auto_with_abi,
    apply_external,
    apply_landlock,
    apply_landlock_with_abi,
    apply_seccomp,
    apply_seccomp_with_abi,
    detect_abi,
    is_supported,
)

IS_LINUX = sys.platform == "linux"

_NEW_SYMBOLS = [
    "DetectedAbi",
    "apply_auto_with_abi",
    "apply_external",
    "apply_landlock",
    "apply_landlock_with_abi",
    "apply_seccomp",
    "apply_seccomp_with_abi",
    "detect_abi",
]


def _run_in_child(fn: Callable[[], int]) -> int:
    """Run ``fn`` in a forked child and return its exit code.

    ``fn`` must return an int exit code; the child never returns to the
    caller. Used to exercise irreversible sandbox application in isolation.
    """
    pid = os.fork()
    if pid == 0:  # child
        code = 99
        try:
            code = fn()
        except BaseException:  # noqa: BLE001 - report via exit code
            code = 98
        finally:
            os._exit(code)
    _, status = os.waitpid(pid, 0)
    assert os.WIFEXITED(status), "child did not exit normally"
    return os.WEXITSTATUS(status)


class TestExposure:
    """The full apply family is exported regardless of platform."""

    def test_symbols_exported(self) -> None:
        for name in _NEW_SYMBOLS:
            assert hasattr(nono_py, name), f"{name} missing from nono_py"
            assert name in nono_py.__all__, f"{name} missing from __all__"


@pytest.mark.skipif(IS_LINUX, reason="Landlock/seccomp are Linux-only")
class TestNonLinuxRaises:
    """On non-Linux platforms the Linux-only API raises RuntimeError."""

    def test_detect_abi_raises(self) -> None:
        with pytest.raises(RuntimeError):
            detect_abi()

    def test_apply_landlock_raises(self) -> None:
        with pytest.raises(RuntimeError):
            apply_landlock(CapabilitySet())

    def test_apply_seccomp_raises(self) -> None:
        with pytest.raises(RuntimeError):
            apply_seccomp(CapabilitySet())

    def test_apply_seccomp_external_tcp_raises(self) -> None:
        with pytest.raises(RuntimeError):
            apply_seccomp(CapabilitySet(), external_tcp=True)

    def test_apply_external_raises(self) -> None:
        with pytest.raises(RuntimeError):
            apply_external()


@pytest.mark.skipif(not IS_LINUX, reason="Landlock ABI detection is Linux-only")
class TestDetectAbi:
    """detect_abi returns a DetectedAbi describing the kernel's features."""

    def test_returns_detected_abi(self) -> None:
        assert isinstance(detect_abi(), DetectedAbi)

    def test_version_is_nonempty_string(self) -> None:
        assert isinstance(detect_abi().version, str)
        assert detect_abi().version

    def test_feature_flags_are_bools(self) -> None:
        abi = detect_abi()
        for attr in (
            "has_refer",
            "has_truncate",
            "has_execute",
            "has_network",
            "has_ioctl_dev",
            "has_scoping",
        ):
            assert isinstance(getattr(abi, attr), bool)

    def test_feature_names_is_str_list(self) -> None:
        names = detect_abi().feature_names
        assert isinstance(names, list)
        assert all(isinstance(n, str) for n in names)

    def test_repr(self) -> None:
        assert "DetectedAbi" in repr(detect_abi())


@pytest.mark.skipif(not IS_LINUX, reason="Landlock enforcement is Linux-only")
class TestApplyEnforcement:
    """Actual sandbox application, exercised in forked children."""

    def _fs_caps(self, allowed: Path) -> CapabilitySet:
        caps = CapabilitySet()
        add_system_paths(caps)
        caps.allow_path(str(allowed), AccessMode.READ)
        return caps

    def test_landlock_blocks_unlisted_path(self, tmp_path: Path) -> None:
        if not is_supported():
            pytest.skip("sandboxing unsupported in this environment")
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        (allowed / "ok.txt").write_text("ok")
        denied = tmp_path / "denied"
        denied.mkdir()
        (denied / "secret.txt").write_text("secret")

        def child() -> int:
            apply_landlock(self._fs_caps(allowed))
            # Granted path must remain readable.
            if (allowed / "ok.txt").read_text() != "ok":
                return 11
            # Unlisted path must now be denied.
            try:
                (denied / "secret.txt").read_text()
            except (PermissionError, OSError):
                return 0
            return 12  # denial did not take effect

        assert _run_in_child(child) == 0

    def test_apply_seccomp_succeeds(self, tmp_path: Path) -> None:
        if not is_supported():
            pytest.skip("sandboxing unsupported in this environment")
        allowed = tmp_path / "allowed"
        allowed.mkdir()

        def child() -> int:
            apply_seccomp(self._fs_caps(allowed))
            return 0

        assert _run_in_child(child) == 0

    def test_apply_auto_with_abi_succeeds(self, tmp_path: Path) -> None:
        if not is_supported():
            pytest.skip("sandboxing unsupported in this environment")
        allowed = tmp_path / "allowed"
        allowed.mkdir()

        def child() -> int:
            abi = detect_abi()
            apply_auto_with_abi(self._fs_caps(allowed), abi)
            return 0

        assert _run_in_child(child) == 0

    def test_apply_landlock_with_abi_enforces(self, tmp_path: Path) -> None:
        if not is_supported():
            pytest.skip("sandboxing unsupported in this environment")
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        (allowed / "ok.txt").write_text("ok")
        denied = tmp_path / "denied"
        denied.mkdir()
        (denied / "secret.txt").write_text("secret")

        def child() -> int:
            abi = detect_abi()
            apply_landlock_with_abi(self._fs_caps(allowed), abi)
            try:
                (denied / "secret.txt").read_text()
            except (PermissionError, OSError):
                return 0
            return 12

        assert _run_in_child(child) == 0

    def test_apply_seccomp_with_abi_succeeds(self, tmp_path: Path) -> None:
        if not is_supported():
            pytest.skip("sandboxing unsupported in this environment")
        allowed = tmp_path / "allowed"
        allowed.mkdir()

        def child() -> int:
            abi = detect_abi()
            apply_seccomp_with_abi(self._fs_caps(allowed), abi)
            return 0

        assert _run_in_child(child) == 0
