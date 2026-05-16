"""Integration tests for SnapshotManager: baseline, incremental, restore, metadata."""

from pathlib import Path

import pytest

from nono_py import (
    ContentHash,
    ExclusionConfig,
    SessionMetadata,
    SnapshotManager,
    SnapshotManifest,
)


@pytest.mark.integration
class TestBaseline:
    def test_manifest_properties(self, snapshot_session_dir: Path, tracked_dir: Path) -> None:
        """Baseline manifest has number=0, no parent, non-empty files, and a ContentHash root."""
        mgr = SnapshotManager(str(snapshot_session_dir), [str(tracked_dir)])
        manifest = mgr.create_baseline()
        assert isinstance(manifest, SnapshotManifest)
        assert manifest.number == 0
        assert manifest.parent is None
        assert len(manifest.files) > 0
        assert isinstance(manifest.merkle_root, ContentHash)

    def test_load_manifest_roundtrip(self, snapshot_session_dir: Path, tracked_dir: Path) -> None:
        """load_manifest retrieves the baseline with the same number and merkle_root."""
        mgr = SnapshotManager(str(snapshot_session_dir), [str(tracked_dir)])
        baseline = mgr.create_baseline()
        loaded = mgr.load_manifest(0)
        assert loaded.number == baseline.number
        assert loaded.merkle_root == baseline.merkle_root


@pytest.mark.integration
class TestIncremental:
    def test_detects_modified_file(self, snapshot_session_dir: Path, tracked_dir: Path) -> None:
        """A file change between baseline and incremental is reported as 'modified'."""
        mgr = SnapshotManager(str(snapshot_session_dir), [str(tracked_dir)])
        mgr.create_baseline()

        (tracked_dir / "file_a.txt").write_text("changed_content")
        _, changes = mgr.create_incremental()

        change_types = {c.change_type for c in changes}
        assert "modified" in change_types

    def test_detects_created_file(self, snapshot_session_dir: Path, tracked_dir: Path) -> None:
        """A new file created after baseline is reported as 'created'."""
        mgr = SnapshotManager(str(snapshot_session_dir), [str(tracked_dir)])
        mgr.create_baseline()

        (tracked_dir / "new_file.txt").write_text("new")
        _, changes = mgr.create_incremental()

        change_types = {c.change_type for c in changes}
        assert "created" in change_types

    def test_detects_deleted_file(self, snapshot_session_dir: Path, tracked_dir: Path) -> None:
        """A file deleted after baseline is reported as 'deleted'."""
        mgr = SnapshotManager(str(snapshot_session_dir), [str(tracked_dir)])
        mgr.create_baseline()

        (tracked_dir / "file_a.txt").unlink()
        _, changes = mgr.create_incremental()

        change_types = {c.change_type for c in changes}
        assert "deleted" in change_types

    def test_no_changes_returns_empty_list(
        self, snapshot_session_dir: Path, tracked_dir: Path
    ) -> None:
        """create_incremental with no filesystem changes returns an empty change list."""
        mgr = SnapshotManager(str(snapshot_session_dir), [str(tracked_dir)])
        mgr.create_baseline()
        _, changes = mgr.create_incremental()
        assert changes == []


@pytest.mark.integration
class TestRestore:
    def test_restore_to_baseline(self, snapshot_session_dir: Path, tracked_dir: Path) -> None:
        """restore_to(0) reverts a modified file to its baseline content."""
        target = tracked_dir / "file_a.txt"
        original = target.read_text()

        mgr = SnapshotManager(str(snapshot_session_dir), [str(tracked_dir)])
        mgr.create_baseline()

        target.write_text("overwritten")
        mgr.restore_to(0)

        assert target.read_text() == original

    def test_compute_restore_diff(self, snapshot_session_dir: Path, tracked_dir: Path) -> None:
        """compute_restore_diff reports what would change without modifying the filesystem."""
        target = tracked_dir / "file_a.txt"
        mgr = SnapshotManager(str(snapshot_session_dir), [str(tracked_dir)])
        mgr.create_baseline()

        target.write_text("overwritten")
        diff = mgr.compute_restore_diff(0)

        assert len(diff) > 0
        assert target.read_text() == "overwritten"


@pytest.mark.integration
class TestSessionMetadata:
    def test_persist_and_load(self, snapshot_session_dir: Path, tracked_dir: Path) -> None:
        """save_session_metadata → load_session_metadata round-trips key fields."""
        mgr = SnapshotManager(str(snapshot_session_dir), [str(tracked_dir)])
        meta = SessionMetadata(
            session_id="integ-session-abc",
            command=["python", "-m", "pytest"],
            tracked_paths=[str(tracked_dir)],
        )
        meta.exit_code = 0
        mgr.save_session_metadata(meta)

        loaded = SnapshotManager.load_session_metadata(str(snapshot_session_dir))
        assert loaded.session_id == "integ-session-abc"
        assert loaded.command == ["python", "-m", "pytest"]
        assert loaded.exit_code == 0


@pytest.mark.integration
class TestExclusionConfig:
    def test_excluded_glob_not_tracked(self, snapshot_session_dir: Path, tracked_dir: Path) -> None:
        """Files matching exclude_globs are absent from the baseline manifest."""
        (tracked_dir / "excluded.tmp").write_text("should not appear")
        (tracked_dir / "included.txt").write_text("should appear")

        exclusion = ExclusionConfig(use_gitignore=False, exclude_globs=["*.tmp"])
        mgr = SnapshotManager(str(snapshot_session_dir), [str(tracked_dir)], exclusion=exclusion)
        manifest = mgr.create_baseline()

        file_paths = list(manifest.files.keys())
        assert not any(p.endswith(".tmp") for p in file_paths)
        assert any(p.endswith("included.txt") for p in file_paths)
