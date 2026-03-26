#!/usr/bin/env python3
"""Query permissions without applying the sandbox.

This example shows how to use QueryContext to test what operations
would be allowed or denied, without actually applying the sandbox.
Useful for validation, debugging, and building permission UIs.
"""

import tempfile

from nono_py import AccessMode, CapabilitySet, QueryContext


def main() -> None:
    # Create a capability set with specific permissions
    caps = CapabilitySet()
    caps.allow_path("/tmp", AccessMode.READ)
    caps.allow_path("/var/log", AccessMode.READ_WRITE)
    caps.block_network()

    # Create a query context from the capabilities
    ctx = QueryContext(caps)

    # Query various path operations
    print("Path permission queries:")
    print("-" * 50)

    queries = [
        ("/tmp/data.txt", AccessMode.READ),
        ("/tmp/data.txt", AccessMode.WRITE),
        ("/var/log/app.log", AccessMode.READ),
        ("/var/log/app.log", AccessMode.WRITE),
        ("/etc/passwd", AccessMode.READ),
        ("/home/user/secrets.txt", AccessMode.READ),
    ]

    for path, mode in queries:
        result = ctx.query_path(path, mode)
        status = result["status"]
        reason = result["reason"]
        mode_str = str(mode).split(".")[-1]  # e.g., "AccessMode.READ" -> "READ"

        if status == "allowed":
            granted = result.get("granted_path", "N/A")
            print(f"{mode_str:10} {path}")
            print(f"  -> ALLOWED (granted by: {granted})")
        else:
            print(f"{mode_str:10} {path}")
            print(f"  -> DENIED ({reason})")
            if reason == "insufficient_access":
                granted = result.get("granted", "unknown")
                requested = result.get("requested", "unknown")
                print(f"     granted={granted}, requested={requested}")
        print()

    # Query network access
    print("Network permission query:")
    print("-" * 50)
    net_result = ctx.query_network()
    net_status = net_result["status"]
    net_reason = net_result["reason"]
    print(f"Network access: {net_status} ({net_reason})")


def demo_file_vs_directory() -> None:
    """Demonstrate the difference between file and directory capabilities."""
    print("\n" + "=" * 50)
    print("File vs Directory Capabilities")
    print("=" * 50 + "\n")

    with tempfile.NamedTemporaryFile(delete=False) as f:
        temp_file = f.name
        f.write(b"test content")

    caps = CapabilitySet()
    # Allow only this specific file, not the whole directory
    caps.allow_file(temp_file, AccessMode.READ)

    ctx = QueryContext(caps)

    # The exact file is allowed
    result = ctx.query_path(temp_file, AccessMode.READ)
    file_status = result["status"]
    print(f"Query exact file: {file_status}")

    # But sibling files in the same directory are NOT
    import os

    sibling = os.path.join(os.path.dirname(temp_file), "other.txt")
    result = ctx.query_path(sibling, AccessMode.READ)
    sibling_status = result["status"]
    print(f"Query sibling file: {sibling_status}")

    os.unlink(temp_file)


if __name__ == "__main__":
    main()
    demo_file_vs_directory()
