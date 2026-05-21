#!/usr/bin/env python3
"""Serialize and deserialize sandbox state.

This example demonstrates SandboxState for transferring sandbox
configurations between processes or persisting them to disk.
Useful for subprocess sandboxing and configuration management.
"""

import json
import tempfile

from nono_py import AccessMode, CapabilitySet, SandboxState


def main() -> None:
    # Create a capability set
    caps = CapabilitySet()
    caps.allow_path("/tmp", AccessMode.READ_WRITE)  # noqa: S108
    caps.allow_path("/usr", AccessMode.READ)
    caps.block_network()

    print("Original capability set:")
    print(caps.summary())
    print()

    # Create a serializable state from the capabilities
    state = SandboxState.from_caps(caps)
    print(f"Network blocked in state: {state.net_blocked}")

    # Serialize to JSON
    json_str = state.to_json()
    print("\nSerialized state (JSON):")
    # Pretty-print the JSON
    parsed = json.loads(json_str)
    print(json.dumps(parsed, indent=2))
    print()

    # This JSON could be:
    # - Passed to a subprocess via environment variable or file
    # - Stored in a configuration file
    # - Sent over a network to configure remote sandboxes

    # Deserialize back to state
    restored_state = SandboxState.from_json(json_str)
    print(f"Restored state network blocked: {restored_state.net_blocked}")

    # Reconstruct the capability set
    # Note: This will fail if any paths no longer exist!
    restored_caps = restored_state.to_caps()
    print("\nRestored capability set:")
    print(restored_caps.summary())


def demo_cross_process() -> None:
    """Demonstrate how state could be passed to a subprocess."""
    print("\n" + "=" * 50)
    print("Cross-Process State Transfer Pattern")
    print("=" * 50 + "\n")

    with tempfile.TemporaryDirectory() as workdir:
        # Parent process creates the sandbox configuration
        caps = CapabilitySet()
        caps.allow_path(workdir, AccessMode.READ_WRITE)
        caps.block_network()

        state = SandboxState.from_caps(caps)
        json_str = state.to_json()

        # In practice, you would pass this to subprocess:
        # subprocess.run(
        #     ["python", "worker.py"],
        #     env={**os.environ, "NONO_STATE": json_str}
        # )

        print("Parent would set environment variable:")
        print(f"  NONO_STATE={json_str[:60]}...")
        print()

        # Child process (worker.py) would do:
        # json_str = os.environ["NONO_STATE"]
        # state = SandboxState.from_json(json_str)
        # caps = state.to_caps()
        # apply(caps)

        print("Child would reconstruct and apply:")
        print("  state = SandboxState.from_json(os.environ['NONO_STATE'])")
        print("  caps = state.to_caps()")
        print("  apply(caps)")


if __name__ == "__main__":
    main()
    demo_cross_process()
