#!/usr/bin/env python3
"""Full supervisor flow: proxy + sandbox + snapshots.

Demonstrates the complete orchestration pattern: start the proxy, take a
baseline snapshot, run a sandboxed child with proxy env vars injected,
capture an incremental snapshot, collect audit events, and optionally
roll back.

Manual testing steps:

    1. Run this script:
       uv run python examples/13_proxy_with_sandbox.py

    2. The script:
       - Starts a proxy with domain filtering (only example.com allowed)
       - Creates a workspace with an initial file
       - Takes a baseline snapshot
       - Runs a sandboxed child that modifies the workspace and makes an
         HTTP request through the proxy
       - Takes an incremental snapshot showing what changed
       - Drains audit events showing what network requests were made
       - Rolls back the workspace to its baseline state

    Note: The child's HTTP request may fail (no real server), but the
    proxy will still log the attempt as an audit event.
"""

import contextlib
import os
import sys
import tempfile

from nono_py import (
    AccessMode,
    CapabilitySet,
    ExclusionConfig,
    ProxyConfig,
    SessionMetadata,
    SnapshotManager,
    is_supported,
    sandboxed_exec,
    start_proxy,
)


def build_caps(workdir: str) -> CapabilitySet:
    """Build sandbox capabilities for the child process."""
    caps = CapabilitySet()

    # System paths needed for shell commands
    for sys_path in ["/usr", "/bin", "/sbin", "/lib"]:
        with contextlib.suppress(FileNotFoundError):
            caps.allow_path(sys_path, AccessMode.READ)

    # macOS-specific system paths
    for sys_path in ["/private", "/Library/Frameworks", "/dev"]:
        with contextlib.suppress(FileNotFoundError):
            caps.allow_path(sys_path, AccessMode.READ)

    # Workspace access
    caps.allow_path(workdir, AccessMode.READ_WRITE)

    # Block direct network — child must go through the proxy
    caps.block_network()

    return caps


def main() -> None:
    if not is_supported():
        print("Sandboxing not supported on this platform")
        sys.exit(1)

    with tempfile.TemporaryDirectory() as session_dir, \
         tempfile.TemporaryDirectory() as workspace:

        print("=== Supervisor: proxy + sandbox + snapshots ===\n")

        # --- 1. Start proxy ---
        print("1. Starting proxy (allowed: example.com only)")
        config = ProxyConfig(allowed_hosts=["example.com"])
        proxy = start_proxy(config)
        print(f"   Listening on 127.0.0.1:{proxy.port}\n")

        # --- 2. Set up workspace ---
        print("2. Setting up workspace")
        initial_file = os.path.join(workspace, "data.txt")
        with open(initial_file, "w") as f:
            f.write("initial data\n")
        print("   Created: data.txt\n")

        # --- 3. Baseline snapshot ---
        print("3. Taking baseline snapshot")
        mgr = SnapshotManager(
            session_dir=session_dir,
            tracked_paths=[workspace],
            exclusion=ExclusionConfig(use_gitignore=False),
        )
        baseline = mgr.create_baseline()
        print(f"   Baseline: {baseline!r}")
        print(f"   Merkle root: {baseline.merkle_root.hex()[:32]}...\n")

        # --- 4. Run sandboxed child ---
        print("4. Running sandboxed child")
        caps = build_caps(workspace)

        # Merge proxy env vars for the child
        env = list(proxy.env_vars().items()) + list(proxy.credential_env_vars().items())

        # The child will:
        #   a) Modify data.txt
        #   b) Create results.txt
        #   c) Attempt an HTTP request through the proxy
        child_script = (
            "echo 'modified by agent' > data.txt && "
            "echo 'agent output' > results.txt && "
            "curl -sf -o /dev/null http://example.com 2>&1 || true"
        )

        result = sandboxed_exec(
            caps,
            ["bash", "-c", child_script],
            cwd=workspace,
            env=env,
            timeout_secs=10.0,
        )
        print(f"   Exit code: {result.exit_code}")
        if result.stdout:
            print(f"   stdout: {result.stdout.decode().strip()}")
        if result.stderr:
            print(f"   stderr: {result.stderr.decode().strip()}")
        print()

        # --- 5. Incremental snapshot ---
        print("5. Taking incremental snapshot")
        manifest, changes = mgr.create_incremental()
        print(f"   Snapshot: {manifest!r}")
        print(f"   Changes: {len(changes)}")
        for change in changes:
            print(f"     {change.change_type}: {os.path.basename(change.path)}")
        print()

        # --- 6. Collect audit events ---
        print("6. Network audit trail")
        events = proxy.drain_audit_events()
        print(f"   {len(events)} event(s) recorded")
        for event in events:
            decision = event["decision"]
            target = event["target"]
            mode = event["mode"]
            print(f"     [{decision}] {mode} -> {target}")
        print()

        # --- 7. Build session metadata ---
        print("7. Session metadata")
        meta = SessionMetadata(
            session_id="example-session-001",
            command=["bash", "-c", child_script],
            tracked_paths=[workspace],
        )
        meta.exit_code = result.exit_code
        meta.snapshot_count = mgr.snapshot_count()
        meta.add_merkle_root(baseline.merkle_root)
        meta.add_merkle_root(manifest.merkle_root)
        meta.set_network_events(events)
        mgr.save_session_metadata(meta)
        print(f"   Saved: {meta!r}")
        print(f"   Merkle roots: {len(meta.merkle_roots)}")
        print()

        # --- 8. Roll back ---
        print("8. Rolling back to baseline")
        applied = mgr.restore_to(0)
        print(f"   Applied {len(applied)} change(s)")

        # Verify
        with open(initial_file) as f:
            print(f"   data.txt: {f.read().strip()!r}")
        results_file = os.path.join(workspace, "results.txt")
        print(f"   results.txt exists: {os.path.exists(results_file)}")
        print()

        # --- 9. Cleanup ---
        proxy.shutdown()
        print("9. Proxy shut down.\n")
        print("=== Complete ===")


if __name__ == "__main__":
    main()
