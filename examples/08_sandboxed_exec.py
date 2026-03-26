#!/usr/bin/env python3
"""Sandboxed command execution.

Demonstrates sandboxed_exec(), which forks the current process, applies
OS-level sandbox restrictions in the child, then exec's a command. The
parent captures output and remains unsandboxed — so it can call
sandboxed_exec() repeatedly with different capabilities.

This is the primitive that sandbox backends (e.g., LangChain Deep Agents)
use to run agent commands under OS-enforced isolation.
"""

import contextlib
import os
import sys
import tempfile

from nono_py import AccessMode, CapabilitySet, is_supported, sandboxed_exec


def build_caps(workdir: str) -> CapabilitySet:
    """Build a capability set for sandboxed command execution."""
    caps = CapabilitySet()

    # System paths needed for shell commands to run
    for sys_path in ["/usr", "/bin", "/sbin", "/lib"]:
        with contextlib.suppress(FileNotFoundError):
            caps.allow_path(sys_path, AccessMode.READ)

    # macOS-specific system paths
    for sys_path in ["/private", "/Library/Frameworks", "/dev"]:
        with contextlib.suppress(FileNotFoundError):
            caps.allow_path(sys_path, AccessMode.READ)

    # Grant read-write to the working directory
    caps.allow_path(workdir, AccessMode.READ_WRITE)

    # Block all network access
    caps.block_network()

    return caps


def main() -> None:
    if not is_supported():
        print("Sandboxing not supported on this platform")
        sys.exit(1)

    with tempfile.TemporaryDirectory() as workdir:
        caps = build_caps(workdir)
        print(f"Working directory: {workdir}")
        print(f"Capabilities:\n{caps.summary()}\n")

        # --- Basic command execution ---
        print("1. Running 'echo hello' in sandbox:")
        result = sandboxed_exec(caps, ["echo", "hello world"], cwd=workdir)
        print(f"   stdout: {result.stdout.decode().strip()}")
        print(f"   exit_code: {result.exit_code}\n")

        # --- Write and read a file inside the sandbox ---
        print("2. Writing and reading a file:")
        result = sandboxed_exec(
            caps,
            ["bash", "-c", "echo 'sandboxed content' > output.txt && cat output.txt"],
            cwd=workdir,
        )
        print(f"   stdout: {result.stdout.decode().strip()}")
        print(f"   exit_code: {result.exit_code}")
        # Verify from the parent (unsandboxed) side
        output_path = os.path.join(os.path.realpath(workdir), "output.txt")
        if os.path.exists(output_path):
            with open(output_path) as f:
                print(f"   parent verified: {f.read().strip()}\n")

        # --- Environment variable injection ---
        print("3. Passing environment variables:")
        result = sandboxed_exec(
            caps,
            ["bash", "-c", "echo API_KEY=$API_KEY"],
            cwd=workdir,
            env=[("API_KEY", "sk-redacted-for-demo")],
        )
        print(f"   stdout: {result.stdout.decode().strip()}\n")

        # --- Sandbox enforcement: access denied ---
        print("4. Attempting to read /etc/passwd (should fail):")
        result = sandboxed_exec(
            caps,
            ["cat", "/etc/passwd"],
            cwd=workdir,
        )
        print(f"   exit_code: {result.exit_code}")
        print(f"   stderr: {result.stderr.decode().strip()}\n")

        # --- Multiple commands: parent stays unsandboxed ---
        print("5. Running 3 commands sequentially (parent stays unsandboxed):")
        for i in range(3):
            result = sandboxed_exec(
                caps,
                ["bash", "-c", f"echo 'iteration {i}' >> log.txt && wc -l < log.txt"],
                cwd=workdir,
            )
            lines = result.stdout.decode().strip()
            print(f"   iteration {i}: {lines} line(s) in log.txt")
        print()

        # --- Timeout handling ---
        print("6. Running a command with timeout (0.5s):")
        result = sandboxed_exec(
            caps,
            ["sleep", "60"],
            cwd=workdir,
            timeout_secs=0.5,
        )
        print(f"   exit_code: {result.exit_code} (124 = timed out)\n")

        print("All examples completed.")


if __name__ == "__main__":
    main()
