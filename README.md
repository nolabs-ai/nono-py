<div align="center">

<img src="assets/nono-py.png" alt="nono logo" width="500"/>

<p>
  <a href="https://opensource.org/licenses/Apache-2.0">
    <img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License"/>
  </a>
  <a href="https://github.com/always-further/nono-py/actions/workflows/ci.yml">
    <img src="https://github.com/always-further/nono-py/actions/workflows/ci.yml/badge.svg" alt="CI Status"/>
  </a>
  <a href="https://docs.nono.sh">
    <img src="https://img.shields.io/badge/Docs-docs.nono.sh-green.svg" alt="Documentation"/>
  </a>
</p>
<p>
  <a href="https://discord.gg/pPcjYzGvbS">
    <img src="https://img.shields.io/badge/Chat-Join%20Discord-7289da?style=for-the-badge&logo=discord&logoColor=white" alt="Join Discord"/>
  </a>
</p>

</div>

# nono-py

Python bindings for [nono](https://github.com/always-further/nono), a capability-based sandboxing library.

nono provides OS-enforced sandboxing using Landlock (Linux) and Seatbelt (macOS). Once a sandbox is applied, unauthorized operations are structurally impossible.

## Installation

```bash
pip install nono-py
```

### From source

Requires Rust toolchain and maturin:

```bash
pip install maturin
maturin develop
```

## Usage

```python
from nono_py import CapabilitySet, AccessMode, apply, is_supported

# Check platform support
if not is_supported():
    print("Sandboxing not supported on this platform")
    exit(1)

# Build capability set
caps = CapabilitySet()
caps.allow_path("/tmp", AccessMode.READ_WRITE)
caps.allow_path("/home/user/project", AccessMode.READ)
caps.allow_file("/etc/hosts", AccessMode.READ)
caps.block_network()

# Apply sandbox (irreversible!)
apply(caps)

# Now the process can only access granted paths
# Network access is blocked
# This applies to all child processes too
```

## API Reference

### Sandboxing

#### `CapabilitySet` + `apply()`

Sandbox the current process (irreversible):

```python
caps = CapabilitySet()
caps.allow_path("/tmp", AccessMode.READ_WRITE)
caps.block_network()
apply(caps)  # Process is now sandboxed
```

#### `sandboxed_exec`

Run a command in a sandboxed child process. The parent stays unsandboxed
and can call this repeatedly with different capabilities:

```python
caps = CapabilitySet()
caps.allow_path("/workspace", AccessMode.READ_WRITE)
caps.block_network()
result = sandboxed_exec(caps, ["python", "agent.py"], cwd="/workspace", timeout_secs=30.0)
print(result.stdout, result.exit_code)
```

`sandboxed_exec` does not inherit the parent process environment by default.
Pass only the variables the child needs through `env=[("NAME", "value")]`.
Full parent environment inheritance requires `inherit_env=True`; dynamic-loader
variables such as `LD_*` and `DYLD_*` are rejected.

### Network Proxy

Domain-filtered network access for sandboxed children. The proxy intercepts
outbound HTTP requests and enforces a host allowlist. For API calls, it
performs credential injection: the sandboxed process sends a dummy token, and
the proxy transparently swaps in the real API key (loaded from the OS keyring)
before forwarding upstream. The sandboxed process never sees the real secret.

```python
from nono_py import ProxyConfig, RouteConfig, start_proxy

config = ProxyConfig(
    allowed_hosts=["api.openai.com", "*.anthropic.com"],
    routes=[
        RouteConfig(prefix="/openai", upstream="https://api.openai.com", credential_key="openai-key"),
    ],
)
proxy = start_proxy(config)

# Inject only the current proxy/session env vars into the sandboxed child
env = proxy.sandbox_env(extra_env=[("NONO_SESSION_ID", "session-001")])
result = sandboxed_exec(caps, ["python", "agent.py"], env=env)

# Audit trail
events = proxy.drain_audit_events()
proxy.shutdown()
```

### Filesystem Snapshots

Content-addressable snapshots with Merkle-committed state and rollback:

```python
from nono_py import SnapshotManager, ExclusionConfig

mgr = SnapshotManager(
    session_dir="~/.nono/rollbacks/session-001",
    tracked_paths=["/workspace"],
    exclusion=ExclusionConfig(exclude_patterns=["node_modules", "__pycache__"]),
)
mgr.create_baseline()

# ... agent runs and modifies files ...

manifest, changes = mgr.create_incremental()
for change in changes:
    print(f"{change.change_type}: {change.path}")

# Roll back
mgr.restore_to(snapshot_number=0)
```

### Audit Trail

Append-only, Merkle-chained audit logging with tamper detection:

```python
from nono_py.audit import AlphaRecorder, verify_log, iter_session, session_started, session_ended

recorder = AlphaRecorder()
with open("audit-events.ndjson", "w") as f:
    recorder.write(f, session_started(started="2026-01-01T00:00:00Z", command=["agent"]))
    recorder.write(f, session_ended(ended="2026-01-01T00:05:00Z", exit_code=0))

# Verify integrity — detects any tampering
result = verify_log("/path/to/session")
assert result["records_verified"]
```

### Other Classes

- `QueryContext` - Check permissions without applying the sandbox
- `SandboxState` - Serialize/restore capability sets as JSON
- `SupportInfo` - Platform support details
- `Policy` / `ResolvedPolicy` - Load and resolve `policy.json` documents
- `SessionMetadata` - Session audit trail with Merkle roots and network events
- `ExecResult` - Result of `sandboxed_exec` (stdout, stderr, exit_code)
- `InjectMode` - Credential injection method enum

### Functions

- `apply(caps)` - Apply sandbox (**irreversible**)
- `sandboxed_exec(caps, command, ...)` - Run command in sandboxed child
- `start_proxy(config)` - Start network filtering proxy
- `is_supported()` / `support_info()` - Platform support
- `load_policy(json)` / `load_embedded_policy()` - Policy loading
- `embedded_policy_json()` - Raw embedded policy JSON
- `validate_deny_overlaps(paths, caps)` - Validate deny paths against capabilities

## Platform Support

| Platform | Backend | Requirements |
|----------|---------|--------------|
| Linux | Landlock | Kernel 5.13+ with Landlock enabled |
| macOS | Seatbelt | macOS 10.5+ |
| Windows | - | Not supported |

## Development

```bash
# Install dev dependencies
pip install maturin pytest mypy

# Build and install for development
make dev

# Run tests
make test

# Run linters
make lint

# Format code
make fmt
```

## License

Apache-2.0
