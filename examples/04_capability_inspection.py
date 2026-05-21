#!/usr/bin/env python3
"""Inspect capability set contents.

This example shows how to examine the capabilities in a CapabilitySet,
including filesystem capabilities, their sources, and access modes.
"""

import tempfile

from nono_py import AccessMode, CapabilitySet, CapabilitySource


def main() -> None:
    # Create a capability set with various permissions
    caps = CapabilitySet()

    # Add some directory permissions
    caps.allow_path("/tmp", AccessMode.READ)  # noqa: S108
    caps.allow_path("/var/log", AccessMode.READ_WRITE)

    # Add a file permission
    with tempfile.NamedTemporaryFile(delete=False) as f:
        temp_file = f.name
    caps.allow_file(temp_file, AccessMode.WRITE)

    # Block network
    caps.block_network()

    # Inspect all filesystem capabilities
    print("Filesystem Capabilities:")
    print("-" * 60)

    for cap in caps.fs_capabilities():
        print(f"Original path:  {cap.original}")
        print(f"Resolved path:  {cap.resolved}")
        print(f"Access mode:    {cap.access}")
        print(f"Is file:        {cap.is_file}")
        print(f"Source:         {cap.source}")
        print()

    # Check network status
    print(f"Network blocked: {caps.is_network_blocked}")
    print()

    # Check if specific paths are covered
    # Note: Use resolved paths for accurate checks on macOS (symlinks like /tmp -> /private/tmp)
    print("Path coverage checks:")
    print("-" * 60)

    # Get the resolved paths from capabilities for accurate testing
    resolved_paths = {cap.resolved for cap in caps.fs_capabilities()}
    print(f"Resolved capability paths: {resolved_paths}")
    print()

    # Test against resolved paths
    import os

    test_paths = [
        os.path.realpath("/tmp"),  # Resolves symlinks  # noqa: S108
        os.path.join(os.path.realpath("/tmp"), "subdir/file.txt"),  # noqa: S108
        os.path.join(os.path.realpath("/var/log"), "app.log"),
        os.path.realpath("/var/cache") if os.path.exists("/var/cache") else "/var/cache",
        "/etc/passwd",
    ]

    for path in test_paths:
        covered = caps.path_covered(path)
        status = "COVERED" if covered else "NOT COVERED"
        print(f"{path}: {status}")

    # Clean up
    import os

    os.unlink(temp_file)


def demo_capability_sources() -> None:
    """Demonstrate different capability sources."""
    print("\n" + "=" * 50)
    print("Capability Sources")
    print("=" * 50 + "\n")

    # Sources indicate where a capability came from
    user_source = CapabilitySource.user()
    group_source = CapabilitySource.group("developers")
    system_source = CapabilitySource.system()

    print(f"User source:   {user_source}")
    print(f"Group source:  {group_source}")
    print(f"System source: {system_source}")


def demo_deduplication() -> None:
    """Demonstrate capability deduplication."""
    print("\n" + "=" * 50)
    print("Capability Deduplication")
    print("=" * 50 + "\n")

    caps = CapabilitySet()

    # Add overlapping permissions for the same path
    caps.allow_path("/tmp", AccessMode.READ)  # noqa: S108
    caps.allow_path("/tmp", AccessMode.WRITE)  # noqa: S108
    caps.allow_path("/tmp", AccessMode.READ)  # noqa: S108

    print(f"Before deduplication: {len(caps.fs_capabilities())} capabilities")
    for cap in caps.fs_capabilities():
        print(f"  - {cap.resolved}: {cap.access}")

    # Deduplicate
    caps.deduplicate()

    print(f"\nAfter deduplication: {len(caps.fs_capabilities())} capabilities")
    for cap in caps.fs_capabilities():
        print(f"  - {cap.resolved}: {cap.access}")


if __name__ == "__main__":
    main()
    demo_capability_sources()
    demo_deduplication()
