"""Tests for policy loading and group resolution."""

import json
import sys

import pytest

from nono_py import (
    AccessMode,
    CapabilitySet,
    ProxyConfig,
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

    def test_resolve_network_block_group_blocks_network(self) -> None:
        """Network policy in JSON should map to blocked network capabilities."""
        policy = load_policy(
            json.dumps(
                {
                    "groups": {
                        "offline": {
                            "description": "Disable outbound network",
                            "network": {"block": True},
                        }
                    }
                }
            )
        )

        caps = CapabilitySet()
        resolved = policy.resolve_groups(["offline"], caps)

        assert resolved.names == ["offline"]
        assert caps.is_network_blocked

    def test_resolve_network_allow_group_leaves_network_enabled(self) -> None:
        """Explicit network.block=false should leave network access unchanged."""
        policy = load_policy(
            json.dumps(
                {
                    "groups": {
                        "online": {
                            "description": "Leave outbound network enabled",
                            "network": {"block": False},
                        }
                    }
                }
            )
        )

        caps = CapabilitySet()
        resolved = policy.resolve_groups(["online"], caps)

        assert resolved.names == ["online"]
        assert not caps.is_network_blocked

    def test_resolve_proxy_config_returns_allowed_hosts(self) -> None:
        """Proxy config should resolve allowed hosts from profile-style network JSON."""
        policy = load_policy(
            json.dumps(
                {
                    "groups": {
                        "proxy_web": {
                            "description": "Proxy-filtered web access",
                            "network": {
                                "allow_proxy": ["example.com", "*.example.org"],
                                "max_connections": 32,
                            },
                        }
                    }
                }
            )
        )

        config = policy.resolve_proxy_config(["proxy_web"])

        assert isinstance(config, ProxyConfig)
        assert config is not None
        assert config.allowed_hosts == ["example.com", "*.example.org"]
        assert config.max_connections == 32

    def test_resolve_proxy_config_supports_canonical_allow_domain_key(self) -> None:
        """Canonical allow_domain should behave the same as allow_proxy."""
        policy = load_policy(
            json.dumps(
                {
                    "groups": {
                        "proxy_web": {
                            "description": "Proxy-filtered web access",
                            "network": {
                                "allow_domain": ["api.openai.com"],
                            },
                        }
                    }
                }
            )
        )

        config = policy.resolve_proxy_config(["proxy_web"])

        assert config is not None
        assert config.allowed_hosts == ["api.openai.com"]

    def test_resolve_proxy_config_returns_none_when_absent(self) -> None:
        """Policies without network.proxy should not fabricate proxy config."""
        policy = load_policy(
            json.dumps(
                {
                    "groups": {
                        "offline": {
                            "description": "Disable outbound network",
                            "network": {"block": True},
                        }
                    }
                }
            )
        )

        assert policy.resolve_proxy_config(["offline"]) is None

    def test_resolve_proxy_config_rejects_conflicting_upstream_proxies(self) -> None:
        """Multiple groups cannot silently overwrite different upstream proxies."""
        policy = load_policy(
            json.dumps(
                {
                    "groups": {
                        "corp_a": {
                            "description": "First upstream proxy",
                            "network": {"external_proxy": "proxy-a.corp:3128"},
                        },
                        "corp_b": {
                            "description": "Conflicting upstream proxy",
                            "network": {"external_proxy": "proxy-b.corp:3128"},
                        },
                    }
                }
            )
        )

        with pytest.raises(ValueError, match="Conflicting upstream_proxy values"):
            policy.resolve_proxy_config(["corp_a", "corp_b"])


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
