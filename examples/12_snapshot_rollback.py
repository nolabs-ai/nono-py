#!/usr/bin/env python3
"""Filesystem snapshots and rollback.

Demonstrates the undo/snapshot system: content-addressable storage,
baseline capture, incremental change detection, dry-run diffs, and
full filesystem rollback.

Manual testing steps:

    1. Run this script:
       uv run python examples/12_snapshot_rollback.py

    2. Observe:
       - Baseline captures the initial file state
       - After modifications, incremental snapshot detects creates/modifies
       - Dry-run diff shows what restore would change
       - Restore rolls back all changes (modified file restored, new file deleted)
       - Merkle roots differ between baseline and incremental (state commitment)
"""

import os
import tempfile

from nono_py import ExclusionConfig, SnapshotManager


def main() -> None:
    with tempfile.TemporaryDirectory() as session_dir, \
         tempfile.TemporaryDirectory() as workspace:

        # --- 1. Set up initial workspace ---
        print("1. Setting up workspace\n")
        readme = os.path.join(workspace, "README.md")
        config_file = os.path.join(workspace, "config.json")
        with open(readme, "w") as f:
            f.write("# My Project\nInitial content.\n")
        with open(config_file, "w") as f:
            f.write('{"debug": false}\n')
        print(f"   Workspace: {workspace}")
        print(f"   Files: README.md, config.json")

        # --- 2. Create snapshot manager ---
        print("\n2. Creating snapshot manager\n")
        exclusion = ExclusionConfig(
            use_gitignore=False,
            exclude_patterns=["__pycache__", "node_modules"],
            exclude_globs=["*.pyc"],
        )
        mgr = SnapshotManager(
            session_dir=session_dir,
            tracked_paths=[workspace],
            exclusion=exclusion,
        )
        print(f"   Manager: {mgr!r}")
        print(f"   Exclusion: {exclusion!r}")

        # --- 3. Create baseline snapshot ---
        print("\n3. Creating baseline snapshot\n")
        baseline = mgr.create_baseline()
        print(f"   Snapshot: {baseline!r}")
        print(f"   Merkle root: {baseline.merkle_root.hex()[:32]}...")
        print(f"   Files tracked: {len(baseline.files)}")
        for path, state in sorted(baseline.files.items()):
            print(f"     {os.path.basename(path)}: {state.size} bytes, hash={state.hash.hex()[:16]}...")

        # --- 4. Simulate agent making changes ---
        print("\n4. Simulating agent changes\n")

        # Modify an existing file
        with open(readme, "w") as f:
            f.write("# My Project\nModified by agent.\nNew section added.\n")
        print("   Modified: README.md")

        # Create a new file
        output = os.path.join(workspace, "output.txt")
        with open(output, "w") as f:
            f.write("Agent generated output\n")
        print("   Created: output.txt")

        # Delete a file
        os.remove(config_file)
        print("   Deleted: config.json")

        # --- 5. Create incremental snapshot ---
        print("\n5. Creating incremental snapshot\n")
        manifest, changes = mgr.create_incremental()
        print(f"   Snapshot: {manifest!r}")
        print(f"   Merkle root: {manifest.merkle_root.hex()[:32]}...")
        print(f"   Changes detected: {len(changes)}")
        for change in changes:
            delta = f" ({change.size_delta:+d} bytes)" if change.size_delta is not None else ""
            print(f"     {change.change_type}: {os.path.basename(change.path)}{delta}")

        # --- 6. Verify Merkle roots differ ---
        print("\n6. State commitment verification\n")
        print(f"   Baseline root:     {baseline.merkle_root.hex()[:32]}...")
        print(f"   Incremental root:  {manifest.merkle_root.hex()[:32]}...")
        print(f"   Roots differ: {baseline.merkle_root != manifest.merkle_root}")

        # --- 7. Dry-run restore diff ---
        print("\n7. Dry-run restore to baseline\n")
        diff = mgr.compute_restore_diff(0)
        print(f"   Changes that would be applied: {len(diff)}")
        for change in diff:
            print(f"     {change.change_type}: {os.path.basename(change.path)}")

        # --- 8. Perform actual restore ---
        print("\n8. Restoring to baseline\n")
        applied = mgr.restore_to(0)
        print(f"   Applied {len(applied)} changes")

        # Verify
        with open(readme) as f:
            content = f.read()
        print(f"   README.md content: {content.strip()!r}")
        print(f"   config.json exists: {os.path.exists(config_file)}")
        print(f"   output.txt exists: {os.path.exists(output)}")

        # Read restored config.json
        if os.path.exists(config_file):
            with open(config_file) as f:
                print(f"   config.json content: {f.read().strip()!r}")

        print(f"\n   Snapshot count: {mgr.snapshot_count()}")
        print("\nAll examples completed.")


if __name__ == "__main__":
    main()
