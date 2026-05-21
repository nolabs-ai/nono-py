#!/usr/bin/env python3
"""CapabilitySet basics.

This example demonstrates filesystem and network restrictions.
"""

from nono_py import AccessMode, CapabilitySet


def main() -> None:
    caps = CapabilitySet()

    # Filesystem restrictions
    caps.allow_path("/tmp", AccessMode.READ_WRITE)  # noqa: S108
    caps.allow_path("/usr", AccessMode.READ)
    caps.block_network()

    print("Basic configuration:")
    print(caps.summary())


def demo_build_environment() -> None:
    """Example: Configure a sandbox for a local build environment."""
    print("\n" + "=" * 50)
    print("Build Environment Sandbox")
    print("=" * 50 + "\n")

    caps = CapabilitySet()

    # Filesystem access
    caps.allow_path("/tmp", AccessMode.READ_WRITE)  # noqa: S108
    caps.allow_path("/usr", AccessMode.READ)
    # /lib exists on Linux but not macOS
    import os

    if os.path.isdir("/lib"):
        caps.allow_path("/lib", AccessMode.READ)

    # Block network
    caps.block_network()

    print("Build environment configured:")
    print(f"  Network: {'blocked' if caps.is_network_blocked else 'allowed'}")


if __name__ == "__main__":
    main()
    demo_build_environment()
