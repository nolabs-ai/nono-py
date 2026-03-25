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

class QueryResultAllowed(TypedDict, total=False):
    """Query result for an allowed operation."""

    status: str  # "allowed"
    reason: str  # "granted_path" or "network_allowed"
    granted_path: str
    access: str

class QueryResultDenied(TypedDict, total=False):
    """Query result for a denied operation."""

    status: str  # "denied"
    reason: str  # "path_not_granted", "insufficient_access", or "network_blocked"
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
