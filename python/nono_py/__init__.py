"""nono: Capability-based sandboxing for Python.

This module provides OS-enforced sandboxing using Landlock (Linux) and
Seatbelt (macOS). Once a sandbox is applied, unauthorized operations are
structurally impossible.

Example:
    >>> from nono_py import CapabilitySet, AccessMode, apply
    >>> caps = CapabilitySet()
    >>> caps.allow_path("/tmp", AccessMode.READ_WRITE)
    >>> caps.block_network()
    >>> apply(caps)  # Irreversible!

Classes:
    AccessMode: File system access mode (READ, WRITE, READ_WRITE)
    CapabilitySet: Collection of sandbox permissions
    CapabilitySource: Origin of a capability grant
    FsCapability: A filesystem capability grant
    SandboxState: Serializable snapshot of capabilities
    SupportInfo: Platform support information
    QueryContext: Query permissions without applying sandbox

Functions:
    apply(caps): Apply the sandbox (irreversible)
    is_supported(): Check if sandboxing is available
    support_info(): Get platform support details
"""

from nono_py import audit
from nono_py._nono_py import (
    AccessMode,
    CapabilitySet,
    CapabilitySource,
    Change,
    ContentHash,
    ExclusionConfig,
    ExecResult,
    ExternalProxyConfig,
    FileState,
    FsCapability,
    InjectMode,
    Policy,
    ProxyConfig,
    ProxyHandle,
    QueryContext,
    ResolvedPolicy,
    RouteConfig,
    SandboxState,
    SessionMetadata,
    SnapshotManager,
    SnapshotManifest,
    SupportInfo,
    apply,
    apply_unlink_overrides,
    embedded_policy_json,
    is_supported,
    load_embedded_policy,
    load_policy,
    sandboxed_exec,
    start_proxy,
    support_info,
    validate_deny_overlaps,
)

__all__ = [
    "AccessMode",
    "audit",
    "CapabilitySet",
    "CapabilitySource",
    "Change",
    "ContentHash",
    "ExclusionConfig",
    "ExecResult",
    "ExternalProxyConfig",
    "FileState",
    "FsCapability",
    "InjectMode",
    "Policy",
    "ProxyConfig",
    "ProxyHandle",
    "QueryContext",
    "ResolvedPolicy",
    "RouteConfig",
    "SandboxState",
    "SessionMetadata",
    "SnapshotManager",
    "SnapshotManifest",
    "SupportInfo",
    "apply",
    "apply_unlink_overrides",
    "embedded_policy_json",
    "is_supported",
    "load_embedded_policy",
    "load_policy",
    "sandboxed_exec",
    "start_proxy",
    "support_info",
    "validate_deny_overlaps",
]

__version__ = "0.7.0"
