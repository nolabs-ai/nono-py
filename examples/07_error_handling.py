#!/usr/bin/env python3
"""Error handling patterns.

This example demonstrates how to handle various errors that can occur
when working with nono-py, including path validation errors, permission
errors, and platform support issues.
"""

import tempfile

from nono_py import (
    AccessMode,
    CapabilitySet,
    SandboxState,
    is_supported,
    support_info,
)


def demo_path_errors() -> None:
    """Demonstrate path-related errors."""
    print("Path Validation Errors")
    print("-" * 50)

    caps = CapabilitySet()

    # FileNotFoundError: Path doesn't exist
    try:
        caps.allow_path("/nonexistent/path/that/does/not/exist", AccessMode.READ)
    except FileNotFoundError as e:
        print(f"FileNotFoundError: {e}")

    # ValueError: Using allow_path on a file
    with tempfile.NamedTemporaryFile(delete=False) as f:
        temp_file = f.name

    try:
        caps.allow_path(temp_file, AccessMode.READ)
    except ValueError as e:
        print(f"ValueError (file as directory): {e}")

    # ValueError: Using allow_file on a directory
    try:
        caps.allow_file("/tmp", AccessMode.READ)  # noqa: S108
    except ValueError as e:
        print(f"ValueError (directory as file): {e}")

    import os

    os.unlink(temp_file)
    print()


def demo_state_errors() -> None:
    """Demonstrate state serialization/deserialization errors."""
    print("State Serialization Errors")
    print("-" * 50)

    # ValueError: Invalid JSON
    try:
        SandboxState.from_json("not valid json")
    except ValueError as e:
        print(f"ValueError (invalid JSON): {e}")

    # ValueError: Valid JSON but wrong structure
    try:
        SandboxState.from_json('{"wrong": "structure"}')
    except ValueError as e:
        print(f"ValueError (wrong structure): {e}")

    # FileNotFoundError: Path in state no longer exists
    with tempfile.NamedTemporaryFile(delete=False) as f:
        temp_file = f.name

    caps = CapabilitySet()
    caps.allow_file(temp_file, AccessMode.READ)
    state = SandboxState.from_caps(caps)
    json_str = state.to_json()

    # Delete the file
    import os

    os.unlink(temp_file)

    # Now try to restore - should fail because path doesn't exist
    try:
        restored_state = SandboxState.from_json(json_str)
        restored_state.to_caps()
    except FileNotFoundError as e:
        print(f"FileNotFoundError (path gone): {e}")

    print()


def demo_platform_errors() -> None:
    """Demonstrate platform support handling."""
    print("Platform Support")
    print("-" * 50)

    info = support_info()
    print(f"Platform: {info.platform}")
    print(f"Supported: {info.is_supported}")
    print(f"Details: {info.details}")

    if not is_supported():
        print("\nSandboxing is not available on this platform.")
        print("Common reasons:")
        print("  - Linux without Landlock support (kernel < 5.13)")
        print("  - Unsupported operating system")
    print()


def demo_platform_rule_errors() -> None:
    """Demonstrate platform rule validation errors."""
    print("Platform Rule Errors")
    print("-" * 50)

    caps = CapabilitySet()

    # Dangerous rules are rejected
    dangerous_rules = [
        '(allow file-read* (subpath "/"))',  # Too broad
        '(allow file-write* (subpath "/"))',  # Too broad
        '(allow process-exec (subpath "/"))',  # Too broad
    ]

    for rule in dangerous_rules:
        try:
            caps.platform_rule(rule)
        except ValueError as e:
            print(f"Rejected: {rule[:40]}...")
            print(f"  Reason: {e}")

    print()


def safe_sandbox_setup(allowed_paths: list[tuple[str, AccessMode]]) -> CapabilitySet | None:
    """Example of robust sandbox setup with error handling."""
    print("Safe Sandbox Setup Pattern")
    print("-" * 50)

    if not is_supported():
        info = support_info()
        print(f"Cannot create sandbox: {info.details}")
        return None

    caps = CapabilitySet()
    errors = []

    for path, mode in allowed_paths:
        try:
            # Determine if it's a file or directory
            import os

            if os.path.isfile(path):
                caps.allow_file(path, mode)
            elif os.path.isdir(path):
                caps.allow_path(path, mode)
            else:
                errors.append(f"Path does not exist: {path}")
        except FileNotFoundError:
            errors.append(f"Path not found: {path}")
        except ValueError as e:
            errors.append(f"Invalid path {path}: {e}")

    if errors:
        print("Setup completed with warnings:")
        for error in errors:
            print(f"  - {error}")
    else:
        print("Setup completed successfully")

    return caps


if __name__ == "__main__":
    demo_path_errors()
    demo_state_errors()
    demo_platform_errors()
    demo_platform_rule_errors()

    # Example safe setup
    print()
    safe_sandbox_setup(
        [
            ("/tmp", AccessMode.READ_WRITE),  # noqa: S108
            ("/usr", AccessMode.READ),
            ("/nonexistent", AccessMode.READ),  # Will be skipped
        ]
    )
