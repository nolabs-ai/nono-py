"""Type stubs for the nono native module."""

from enum import Enum
from typing import TypedDict

class AccessMode(Enum):
    """File system access mode."""

    READ = ...
    WRITE = ...
    READ_WRITE = ...

    def __repr__(self) -> str: ...
    def __str__(self) -> str: ...
    def __hash__(self) -> int: ...
    def __eq__(self, other: object) -> bool: ...

class CapabilitySource:
    """Source/origin of a capability grant."""

    @staticmethod
    def user() -> CapabilitySource:
        """Create a user-sourced capability."""
        ...

    @staticmethod
    def group(name: str) -> CapabilitySource:
        """Create a group-sourced capability."""
        ...

    @staticmethod
    def system() -> CapabilitySource:
        """Create a system-sourced capability."""
        ...

    def __repr__(self) -> str: ...
    def __str__(self) -> str: ...

class FsCapability:
    """A filesystem capability grant (read-only view)."""

    @property
    def original(self) -> str:
        """The original user-specified path."""
        ...

    @property
    def resolved(self) -> str:
        """The canonicalized absolute path."""
        ...

    @property
    def access(self) -> AccessMode:
        """The access mode granted."""
        ...

    @property
    def is_file(self) -> bool:
        """True if this grants access to a single file."""
        ...

    @property
    def source(self) -> CapabilitySource:
        """The origin of this capability."""
        ...

    def __repr__(self) -> str: ...
    def __str__(self) -> str: ...

class CapabilitySet:
    """A collection of capabilities that define sandbox permissions."""

    def __init__(self) -> None:
        """Create a new empty capability set."""
        ...

    def allow_path(self, path: str, mode: AccessMode) -> None:
        """Add directory access for the given path.

        Args:
            path: Path to the directory
            mode: Access mode (READ, WRITE, or READ_WRITE)

        Raises:
            FileNotFoundError: If the path does not exist
            ValueError: If the path is not a directory
        """
        ...

    def allow_file(self, path: str, mode: AccessMode) -> None:
        """Add single-file access for the given path.

        Args:
            path: Path to the file
            mode: Access mode (READ, WRITE, or READ_WRITE)

        Raises:
            FileNotFoundError: If the path does not exist
            ValueError: If the path is not a file
        """
        ...

    def block_network(self) -> None:
        """Block all outbound network access."""
        ...

    def proxy_only(self, proxy: ProxyHandle) -> None:
        """Restrict network to proxy-only mode.

        Blocks all outbound network except localhost TCP to the proxy's port.
        Use ``proxy.sandbox_env()`` to get the env vars for ``sandboxed_exec``.

        Args:
            proxy: A running ProxyHandle from ``start_proxy()``
        """
        ...

    def platform_rule(self, rule: str) -> None:
        """Add a raw platform-specific sandbox rule.

        Args:
            rule: Platform-specific rule string

        Raises:
            ValueError: If the rule is malformed or grants dangerous access
        """
        ...

    def deduplicate(self) -> None:
        """Remove duplicate filesystem capabilities."""
        ...

    def path_covered(self, path: str) -> bool:
        """Check if the given path is covered by an existing capability."""
        ...

    def fs_capabilities(self) -> list[FsCapability]:
        """Get a list of all filesystem capabilities."""
        ...

    @property
    def is_network_blocked(self) -> bool:
        """True if network access is blocked."""
        ...

    def summary(self) -> str:
        """Get a plain-text summary of the capability set."""
        ...

    def __repr__(self) -> str: ...

class Policy:
    """Parsed policy.json document."""

    def group_names(self) -> list[str]:
        """Return all policy group names in sorted order."""
        ...

    def group_description(self, name: str) -> str | None:
        """Return a group's description if it exists."""
        ...

    def resolve_groups(self, group_names: list[str], caps: CapabilitySet) -> ResolvedPolicy:
        """Resolve named policy groups into a capability set."""
        ...

    def resolve_deny_paths(self, group_names: list[str]) -> list[str]:
        """Resolve deny.access paths for the given groups."""
        ...

    def resolve_proxy_config(self, group_names: list[str]) -> ProxyConfig | None:
        """Resolve proxy configuration from network.proxy sections."""
        ...

    def validate_group_exclusions(self, excluded_groups: list[str]) -> None:
        """Reject exclusions that target required groups."""
        ...

    def __repr__(self) -> str: ...

class ResolvedPolicy:
    """Details returned from policy group resolution."""

    @property
    def names(self) -> list[str]:
        """Resolved group names after platform filtering."""
        ...

    @property
    def needs_unlink_overrides(self) -> bool:
        """Whether unlink overrides should be applied after final path grants."""
        ...

    @property
    def deny_paths(self) -> list[str]:
        """Expanded deny.access paths gathered during resolution."""
        ...

    def __repr__(self) -> str: ...

class SupportInfo:
    """Information about sandbox support on the current platform."""

    @property
    def is_supported(self) -> bool:
        """True if sandboxing is supported on this platform."""
        ...

    @property
    def platform(self) -> str:
        """Platform identifier."""
        ...

    @property
    def details(self) -> str:
        """Human-readable support details."""
        ...

    def __repr__(self) -> str: ...

class SandboxState:
    """Serializable snapshot of a CapabilitySet."""

    @staticmethod
    def from_caps(caps: CapabilitySet) -> SandboxState:
        """Create a SandboxState snapshot from a CapabilitySet."""
        ...

    def to_json(self) -> str:
        """Serialize the state to a JSON string."""
        ...

    @staticmethod
    def from_json(json: str) -> SandboxState:
        """Deserialize state from a JSON string.

        Raises:
            ValueError: If the JSON is invalid
        """
        ...

    def to_caps(self) -> CapabilitySet:
        """Reconstruct a CapabilitySet from this state.

        Raises:
            FileNotFoundError: If a referenced path no longer exists
        """
        ...

    @property
    def net_blocked(self) -> bool:
        """True if network access is blocked in this state."""
        ...

    def __repr__(self) -> str: ...

class _QueryResultBase(TypedDict):
    status: str  # "allowed" or "denied" — always set
    reason: str  # explanation tag — always set

class QueryResultAllowed(_QueryResultBase, total=False):
    """Query result for an allowed operation.

    ``status`` and ``reason`` are always set; ``granted_path`` and
    ``access`` are populated only for allowed path queries.
    """

    granted_path: str
    access: str

class QueryResultDenied(_QueryResultBase, total=False):
    """Query result for a denied operation.

    ``status`` and ``reason`` are always set; ``granted`` and ``requested``
    are populated only when ``reason == "insufficient_access"``.
    """

    granted: str
    requested: str

QueryResult = QueryResultAllowed | QueryResultDenied

class QueryContext:
    """Context for querying permissions without applying the sandbox."""

    def __init__(self, caps: CapabilitySet) -> None:
        """Create a new query context from a capability set."""
        ...

    def query_path(self, path: str, mode: AccessMode) -> QueryResult:
        """Query whether a path operation is permitted.

        Returns:
            Dict with 'status' ('allowed' or 'denied') and reason details
        """
        ...

    def query_network(self) -> QueryResult:
        """Query whether network access is permitted.

        Returns:
            Dict with 'status' ('allowed' or 'denied') and 'reason'
        """
        ...

class ExecResult:
    """Result of a sandboxed command execution."""

    @property
    def stdout(self) -> bytes:
        """Raw bytes from the child's stdout."""
        ...

    @property
    def stderr(self) -> bytes:
        """Raw bytes from the child's stderr."""
        ...

    @property
    def exit_code(self) -> int:
        """Process exit code (0 = success, -N = killed by signal N)."""
        ...

    def __repr__(self) -> str: ...

def sandboxed_exec(
    caps: CapabilitySet,
    command: list[str],
    cwd: str | None = None,
    timeout_secs: float | None = None,
    env: list[tuple[str, str]] | None = None,
) -> ExecResult:
    """Execute a command in a sandboxed child process.

    Args:
        caps: Capability set defining the child's permitted operations
        command: List of command + arguments
        cwd: Working directory for the child
        timeout_secs: Maximum execution time in seconds (None = no limit)
        env: Optional environment variable overrides

    Returns:
        ExecResult with stdout, stderr, and exit_code

    Raises:
        RuntimeError: If fork fails or command cannot be executed
        ValueError: If command is empty or timeout is negative
    """
    ...

def apply(caps: CapabilitySet) -> None:
    """Apply the sandbox with the given capabilities.

    **This is irreversible.** Once applied, the current process and all children
    can only access resources granted by the capabilities.

    Args:
        caps: The capability set defining permitted operations

    Raises:
        RuntimeError: If the platform is not supported or sandbox initialization fails
    """
    ...

def apply_unlink_overrides(caps: CapabilitySet) -> None:
    """Apply post-resolution unlink overrides for writable paths."""
    ...

def embedded_policy_json() -> str:
    """Return the raw embedded policy.json string."""
    ...

def is_supported() -> bool:
    """Check if sandboxing is supported on this platform.

    Returns:
        True if sandboxing is available (Linux with Landlock, or macOS)
    """
    ...

def load_embedded_policy() -> Policy:
    """Load the embedded policy bundled with this package."""
    ...

def load_policy(json: str) -> Policy:
    """Parse a policy.json document."""
    ...

def support_info() -> SupportInfo:
    """Get detailed information about sandbox support on this platform.

    Returns:
        SupportInfo object with platform details
    """
    ...

def validate_deny_overlaps(deny_paths: list[str], caps: CapabilitySet) -> None:
    """Validate deny.access paths against the final capability set."""
    ...

# ---------------------------------------------------------------------------
# Proxy types
# ---------------------------------------------------------------------------

class InjectMode(Enum):
    """Credential injection method for reverse proxy routes."""

    HEADER = ...
    URL_PATH = ...
    QUERY_PARAM = ...
    BASIC_AUTH = ...

    def __repr__(self) -> str: ...
    def __str__(self) -> str: ...
    def __hash__(self) -> int: ...
    def __eq__(self, other: object) -> bool: ...

class RouteConfig:
    """Configuration for a reverse proxy credential injection route."""

    def __init__(
        self,
        prefix: str,
        upstream: str,
        credential_key: str | None = None,
        inject_mode: InjectMode = InjectMode.HEADER,
        inject_header: str = "Authorization",
        credential_format: str = "Bearer {}",
        path_pattern: str | None = None,
        path_replacement: str | None = None,
        query_param_name: str | None = None,
        env_var: str | None = None,
    ) -> None: ...
    @property
    def prefix(self) -> str: ...
    @property
    def upstream(self) -> str: ...
    @property
    def credential_key(self) -> str | None: ...
    @property
    def inject_mode(self) -> InjectMode: ...
    @property
    def inject_header(self) -> str: ...
    @property
    def credential_format(self) -> str: ...
    @property
    def path_pattern(self) -> str | None: ...
    @property
    def path_replacement(self) -> str | None: ...
    @property
    def query_param_name(self) -> str | None: ...
    @property
    def env_var(self) -> str | None: ...
    def __repr__(self) -> str: ...

class ExternalProxyConfig:
    """Configuration for enterprise proxy passthrough."""

    def __init__(
        self,
        address: str,
        bypass_hosts: list[str] = ...,
    ) -> None: ...
    @property
    def address(self) -> str: ...
    @property
    def bypass_hosts(self) -> list[str]: ...
    def __repr__(self) -> str: ...

class ProxyConfig:
    """Configuration for the nono network filtering proxy."""

    def __init__(
        self,
        allowed_hosts: list[str] = ...,
        routes: list[RouteConfig] = ...,
        external_proxy: ExternalProxyConfig | None = None,
        bind_addr: str = "127.0.0.1",
        bind_port: int = 0,
        max_connections: int = 256,
    ) -> None: ...
    @property
    def bind_addr(self) -> str: ...
    @property
    def bind_port(self) -> int: ...
    @property
    def allowed_hosts(self) -> list[str]: ...
    @property
    def routes(self) -> list[RouteConfig]: ...
    @property
    def max_connections(self) -> int: ...
    def __repr__(self) -> str: ...

class NetworkAuditEvent(TypedDict):
    """A network request observed by the proxy.

    All keys are always present. Nullable fields are populated only for
    request shapes where they apply (e.g. ``port`` for CONNECT/external,
    ``method``/``path``/``status`` for reverse-proxy events,
    ``reason`` for denials).
    """

    timestamp_unix_ms: int
    mode: str  # "connect", "reverse", "external"
    decision: str  # "allow", "deny"
    target: str
    port: int | None
    method: str | None
    path: str | None
    status: int | None
    reason: str | None

class ProxyHandle:
    """Handle to a running nono proxy instance."""

    @property
    def port(self) -> int:
        """The port the proxy is listening on."""
        ...

    def env_vars(self) -> dict[str, str]:
        """Environment variables to inject into the sandboxed child process."""
        ...

    def credential_env_vars(self) -> dict[str, str]:
        """Environment variables for reverse proxy credential routes."""
        ...

    def sandbox_env(self) -> list[tuple[str, str]]:
        """All env vars for a sandboxed child (env_vars + credential_env_vars combined)."""
        ...

    def drain_audit_events(self) -> list[NetworkAuditEvent]:
        """Drain and return collected network audit events."""
        ...

    def shutdown(self) -> None:
        """Signal the proxy to shut down gracefully."""
        ...

    def __repr__(self) -> str: ...

def start_proxy(config: ProxyConfig) -> ProxyHandle:
    """Start the nono network filtering proxy.

    Args:
        config: Proxy configuration

    Returns:
        ProxyHandle for the running proxy

    Raises:
        RuntimeError: If the proxy fails to start
    """
    ...

# ---------------------------------------------------------------------------
# Undo/snapshot types
# ---------------------------------------------------------------------------

class ContentHash:
    """SHA-256 content hash for content-addressable storage."""

    def hex(self) -> str:
        """Return the hash as a 64-character hex string."""
        ...

    def __repr__(self) -> str: ...
    def __str__(self) -> str: ...
    def __hash__(self) -> int: ...
    def __eq__(self, other: object) -> bool: ...

class FileState:
    """Filesystem state of a single file within a snapshot."""

    @property
    def hash(self) -> ContentHash: ...
    @property
    def size(self) -> int: ...
    @property
    def mtime(self) -> int: ...
    @property
    def permissions(self) -> int: ...
    def __repr__(self) -> str: ...

class Change:
    """A filesystem change detected between snapshots."""

    @property
    def path(self) -> str: ...
    @property
    def change_type(self) -> str:
        """One of: "created", "modified", "deleted", "permissions_changed"."""
        ...
    @property
    def size_delta(self) -> int | None: ...
    def __repr__(self) -> str: ...

class SnapshotManifest:
    """A snapshot manifest recording the state of all tracked files."""

    @property
    def number(self) -> int: ...
    @property
    def timestamp(self) -> str: ...
    @property
    def parent(self) -> int | None: ...
    @property
    def merkle_root(self) -> ContentHash: ...
    @property
    def files(self) -> dict[str, FileState]: ...
    def __repr__(self) -> str: ...

class ExclusionConfig:
    """Configuration for excluding files from snapshot tracking."""

    def __init__(
        self,
        use_gitignore: bool = True,
        exclude_patterns: list[str] = ...,
        exclude_globs: list[str] = ...,
        force_include: list[str] = ...,
    ) -> None: ...
    @property
    def use_gitignore(self) -> bool: ...
    @property
    def exclude_patterns(self) -> list[str]: ...
    @property
    def exclude_globs(self) -> list[str]: ...
    @property
    def force_include(self) -> list[str]: ...
    def __repr__(self) -> str: ...

class SessionMetadata:
    """Metadata for a sandboxed session including snapshots and audit trail."""

    def __init__(
        self,
        session_id: str,
        command: list[str],
        tracked_paths: list[str],
    ) -> None: ...
    @property
    def session_id(self) -> str: ...
    @property
    def started(self) -> str: ...
    @property
    def ended(self) -> str | None: ...
    @ended.setter
    def ended(self, value: str | None) -> None: ...
    @property
    def command(self) -> list[str]: ...
    @property
    def tracked_paths(self) -> list[str]: ...
    @property
    def snapshot_count(self) -> int: ...
    @snapshot_count.setter
    def snapshot_count(self, value: int) -> None: ...
    @property
    def exit_code(self) -> int | None: ...
    @exit_code.setter
    def exit_code(self, value: int | None) -> None: ...
    @property
    def merkle_roots(self) -> list[ContentHash]: ...
    def add_merkle_root(self, root: ContentHash) -> None: ...
    @property
    def executable_identity(self) -> ExecutableIdentity | None: ...
    @property
    def audit_event_count(self) -> int: ...
    @property
    def audit_integrity(self) -> AuditIntegritySummary | None: ...
    @property
    def audit_attestation(self) -> AuditAttestationSummary | None: ...
    @property
    def network_events(self) -> list[NetworkAuditEvent]: ...
    def set_network_events(self, events: list[NetworkAuditEvent]) -> None: ...
    def to_json(self) -> str: ...
    @staticmethod
    def from_json(json: str) -> SessionMetadata: ...
    def __repr__(self) -> str: ...

class ExecutableIdentity(TypedDict):
    """Canonical identity of the executable launched for a session."""

    resolved_path: str
    sha256: str  # 64-char hex SHA-256

class AuditIntegritySummary(TypedDict):
    """Append-only audit log integrity metadata."""

    hash_algorithm: str
    event_count: int
    chain_head: str  # 64-char hex
    merkle_root: str  # 64-char hex

class AuditAttestationSummary(TypedDict):
    """Signed attestation metadata for an audit session."""

    predicate_type: str
    key_id: str
    public_key: str  # base64 DER
    bundle_filename: str

class SnapshotManager:
    """Manages content-addressable filesystem snapshots for a session."""

    def __init__(
        self,
        session_dir: str,
        tracked_paths: list[str],
        exclusion: ExclusionConfig | None = None,
        max_entries: int = 300_000,
        max_bytes: int = 2_147_483_648,
    ) -> None: ...
    def create_baseline(self) -> SnapshotManifest:
        """Create a baseline snapshot of the current filesystem state."""
        ...

    def create_incremental(self) -> tuple[SnapshotManifest, list[Change]]:
        """Create an incremental snapshot capturing changes since the last snapshot."""
        ...

    def compute_restore_diff(self, snapshot_number: int) -> list[Change]:
        """Compute what changes would be needed to restore to a given snapshot."""
        ...

    def restore_to(self, snapshot_number: int) -> list[Change]:
        """Restore the filesystem to the state captured in a snapshot."""
        ...

    def load_manifest(self, number: int) -> SnapshotManifest:
        """Load a snapshot manifest by number."""
        ...

    def save_session_metadata(self, meta: SessionMetadata) -> None:
        """Save session metadata to the session directory."""
        ...

    def snapshot_count(self) -> int:
        """Number of snapshots taken in this session."""
        ...

    @staticmethod
    def load_session_metadata(session_dir: str) -> SessionMetadata:
        """Load session metadata from a session directory."""
        ...

    def __repr__(self) -> str: ...
