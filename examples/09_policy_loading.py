#!/usr/bin/env python3
"""Load a policy.json file and resolve groups into a capability set.

This example is safe to run: it does not call apply().
"""

from pathlib import Path

from nono_py import (
    AccessMode,
    CapabilitySet,
    QueryContext,
    apply_unlink_overrides,
    load_policy,
    validate_deny_overlaps,
)


def main() -> None:
    example_dir = Path(__file__).parent
    policy_path = example_dir / "policy_example.json"
    policy = load_policy(policy_path.read_text())

    print(f"Loaded policy from: {policy_path}")
    print("Available groups:")
    for name in policy.group_names():
        print(f"  - {name}: {policy.group_description(name)}")
    print()

    caps = CapabilitySet()
    resolved = policy.resolve_groups(
        ["system_tmp_read", "deny_secrets"],
        caps,
    )

    if resolved.needs_unlink_overrides:
        apply_unlink_overrides(caps)
    validate_deny_overlaps(resolved.deny_paths, caps)

    print("Resolved groups:", resolved.names)
    print("Collected deny paths:", resolved.deny_paths)
    print()
    print("Capability summary:")
    print(caps.summary())
    print()

    ctx = QueryContext(caps)
    print("Permission checks:")
    print("  /tmp/example.txt read:", ctx.query_path("/tmp/example.txt", AccessMode.READ))
    print(
        "  ~/.ssh/config read:",
        ctx.query_path(str(Path.home() / ".ssh" / "config"), AccessMode.READ),
    )


if __name__ == "__main__":
    main()
