"""Tests for policy loading and group resolution."""

import json
import sys

import pytest

from nono_py import (
    AccessMode,
    CapabilitySet,
    apply_unlink_overrides,
    embedded_policy_json,
    load_embedded_policy,
    load_policy,
    validate_deny_overlaps,
)


class TestPolicyLoading:
    """Tests for loading policy documents."""

    def test_embedded_policy_json_is_valid(self) -> None:
        """The bundled policy JSON should parse."""
        payload = json.loads(embedded_policy_json())
        assert "groups" in payload
        assert "deny_credentials" in payload["groups"]

    def test_load_embedded_policy(self) -> None:
        """The embedded policy should expose known groups."""
        policy = load_embedded_policy()
        assert "deny_credentials" in policy.group_names()
        assert policy.group_description("deny_credentials") is not None

    def test_load_policy_invalid_json_raises(self) -> None:
        """Invalid policy JSON should fail fast."""
        with pytest.raises(ValueError):
            load_policy("not json")


class TestPolicyResolution:
    """Tests for resolving groups into capability sets."""

    def test_resolve_allow_group_adds_capability(self, tmp_path) -> None:
        """Allow rules should add filesystem grants with group provenance."""
        allowed_dir = tmp_path / "allowed"
        allowed_dir.mkdir()
        policy = load_policy(
            json.dumps(
                {
                    "groups": {
                        "tmp_read": {
                            "description": "Temporary read access",
                            "allow": {"read": [str(allowed_dir)]},
                        }
                    }
                }
            )
        )

        caps = CapabilitySet()
        resolved = policy.resolve_groups(["tmp_read"], caps)

        assert resolved.names == ["tmp_read"]
        assert not resolved.needs_unlink_overrides
        fs_caps = caps.fs_capabilities()
        assert len(fs_caps) == 1
        assert fs_caps[0].access == AccessMode.READ
        assert str(fs_caps[0].source) == "group:tmp_read"

    def test_resolve_unknown_group_raises(self) -> None:
        """Unknown group names should be rejected."""
        policy = load_policy(json.dumps({"groups": {}}))

        with pytest.raises(ValueError):
            policy.resolve_groups(["missing"], CapabilitySet())

    def test_platform_filtered_group_is_skipped(self, tmp_path) -> None:
        """Groups for the other platform should not resolve."""
        allowed_dir = tmp_path / "allowed"
        allowed_dir.mkdir()
        other_platform = "linux" if sys.platform == "darwin" else "macos"
        policy = load_policy(
            json.dumps(
                {
                    "groups": {
                        "other_platform": {
                            "description": "Other platform only",
                            "platform": other_platform,
                            "allow": {"read": [str(allowed_dir)]},
                        }
                    }
                }
            )
        )

        caps = CapabilitySet()
        resolved = policy.resolve_groups(["other_platform"], caps)

        assert resolved.names == []
        assert caps.fs_capabilities() == []

    def test_validate_group_exclusions_rejects_required_groups(self) -> None:
        """Required groups cannot be excluded."""
        policy = load_policy(
            json.dumps(
                {
                    "groups": {
                        "required_group": {
                            "description": "Required",
                            "required": True,
                        }
                    }
                }
            )
        )

        with pytest.raises(ValueError):
            policy.validate_group_exclusions(["required_group"])

    def test_resolve_deny_paths_returns_expanded_paths(self, tmp_path) -> None:
        """Deny path resolution should return collected paths."""
        denied_dir = tmp_path / "denied"
        policy = load_policy(
            json.dumps(
                {
                    "groups": {
                        "blocked": {
                            "description": "Blocked directory",
                            "deny": {"access": [str(denied_dir)]},
                        }
                    }
                }
            )
        )

        deny_paths = policy.resolve_deny_paths(["blocked"])
        assert str(denied_dir) in deny_paths


class TestPolicyHelpers:
    """Tests for post-resolution helpers."""

    def test_apply_unlink_overrides_is_safe_noop(self, tmp_path) -> None:
        """Applying unlink overrides should be safe for writable paths."""
        caps = CapabilitySet()
        caps.allow_path(str(tmp_path), AccessMode.READ_WRITE)
        apply_unlink_overrides(caps)

    def test_validate_deny_overlaps_matches_platform_behavior(self, tmp_path) -> None:
        """Linux should reject overlapping deny rules; macOS should allow them."""
        caps = CapabilitySet()
        caps.allow_path(str(tmp_path), AccessMode.READ)
        deny_path = str(tmp_path / "child")

        if sys.platform == "darwin":
            validate_deny_overlaps([deny_path], caps)
        else:
            with pytest.raises(RuntimeError):
                validate_deny_overlaps([deny_path], caps)
