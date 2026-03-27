#!/usr/bin/env python3
"""Basic sandbox example.

This example demonstrates the fundamental usage of nono-py:
creating a capability set, adding permissions, and applying the sandbox.

"""

import sys
import tempfile

from nono_py import AccessMode, CapabilitySet, apply, is_supported, support_info


def main() -> None:
    # Check if sandboxing is supported on this platform
    if not is_supported():
        info = support_info()
        print(f"Sandboxing not supported: {info.details}")
        sys.exit(1)

    # Show platform information
    info = support_info()
    print(f"Platform: {info.platform}")
    print(f"Details: {info.details}")
    print()

    # Create a capability set (starts empty - denies everything)
    caps = CapabilitySet()

    # Allow read-write access to a temporary directory
    with tempfile.TemporaryDirectory() as tmpdir:
        caps.allow_path(tmpdir, AccessMode.READ_WRITE)

        # Allow read-only access to /usr (for system libraries)
        caps.allow_path("/usr", AccessMode.READ)

        # Block all network access
        caps.block_network()

        # Print a summary of what the sandbox will allow
        print("Sandbox configuration:")
        print(caps.summary())
        print()

        # Apply the sandbox (IRREVERSIBLE!)
        print("Applying sandbox...")
        apply(caps)
        print("Sandbox applied successfully!")

        # Now test that the sandbox is working
        # This should succeed (tmpdir is allowed)
        test_file = f"{tmpdir}/test.txt"
        with open(test_file, "w") as f:
            f.write("Hello from inside the sandbox!")
        print(f"Created file: {test_file}")

        with open(test_file) as f:
            content = f.read()
        print(f"Read content: {content}")

        # This would fail (home directory is not allowed):
        # with open(os.path.expanduser("~/secret.txt"), "r") as f:
        #     pass  # PermissionError!


if __name__ == "__main__":
    main()
