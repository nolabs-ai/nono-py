#!/usr/bin/env python3
"""Enforce a policy by running child processes under sandboxed_exec().

This example is safer than calling apply(): only the child process is
sandboxed, while the parent remains unsandboxed.
"""

from __future__ import annotations

import contextlib
from pathlib import Path

from nono_py import (
    AccessMode,
    CapabilitySet,
    apply_unlink_overrides,
    load_policy,
    sandboxed_exec,
    validate_deny_overlaps,
)

SYSTEM_PATHS = ["/usr", "/bin", "/sbin", "/lib", "/private", "/Library/Frameworks", "/dev"]


def add_system_paths(caps: CapabilitySet) -> None:
    """Add the minimum read-only system paths needed to execute commands."""
    for path in SYSTEM_PATHS:
        with contextlib.suppress(FileNotFoundError):
            caps.allow_path(path, AccessMode.READ)


def build_caps(policy_path: Path, project_dir: Path) -> CapabilitySet:
    """Load the example policy and resolve it into a capability set."""
    policy = load_policy(policy_path.read_text())
    caps = CapabilitySet()

    add_system_paths(caps)

    # The example JSON contains a placeholder path. Add the real project path here.
    caps.allow_path(str(project_dir), AccessMode.READ_WRITE)

    resolved = policy.resolve_groups(
        ["system_tmp_read", "deny_secrets"],
        caps,
    )

    if resolved.needs_unlink_overrides:
        apply_unlink_overrides(caps)
    validate_deny_overlaps(resolved.deny_paths, caps)

    return caps


def main() -> None:
    example_dir = Path(__file__).parent
    policy_path = example_dir / "policy_example.json"
    project_dir = Path("/tmp")  # noqa: S108
    allowed_file = project_dir / "nono-policy-demo.txt"

    allowed_file.write_text("hello from policy demo\n")

    caps = build_caps(policy_path, project_dir)

    print(f"Policy: {policy_path}")
    print("Resolved capability summary:")
    print(caps.summary())
    print()

    print("1. Allowed read from /tmp:")
    result = sandboxed_exec(
        caps,
        ["cat", str(allowed_file)],
        cwd=str(project_dir),
    )
    print(f"   exit_code: {result.exit_code}")
    print(f"   stdout: {result.stdout.decode().strip()}")
    if result.stderr:
        print(f"   stderr: {result.stderr.decode().strip()}")
    print()

    print("2. Denied read from ~/.ssh/config:")
    result = sandboxed_exec(
        caps,
        ["cat", str(Path.home() / ".ssh" / "config")],
        cwd=str(project_dir),
    )
    print(f"   exit_code: {result.exit_code}")
    if result.stdout:
        print(f"   stdout: {result.stdout.decode().strip()}")
    print(f"   stderr: {result.stderr.decode().strip()}")
    print()

    print("3. Writes remain allowed inside granted directories:")
    target = project_dir / "sandbox-write.txt"
    result = sandboxed_exec(
        caps,
        ["sh", "-c", f"printf 'sandbox write\\n' > {target}"],
        cwd=str(project_dir),
    )
    print(f"   exit_code: {result.exit_code}")
    print(f"   wrote file: {target.exists()}")


if __name__ == "__main__":
    main()
