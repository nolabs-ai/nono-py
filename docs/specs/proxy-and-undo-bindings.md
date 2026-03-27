# Specification: Proxy and Undo/Snapshot Python Bindings

## Overview

Expose the network proxy (`nono-proxy` crate) and undo/snapshot system
(`nono::undo` module) to Python through PyO3 bindings in `nono-py`. This
enables Python-based supervisors to orchestrate sandboxed child processes with
domain-filtered, credential-injected network access and content-addressable
filesystem rollback.

## Motivation

`nono-py` currently exposes filesystem sandboxing, policy resolution, and
sandboxed child execution. It does not surface the network proxy or the
undo/snapshot system. A Python supervisor that spawns sandboxed agents needs
all three to provide a complete security boundary:

- **Filesystem** sandbox (already available via `CapabilitySet` / `apply()` /
  `sandboxed_exec()`)
- **Network** filtering and credential isolation (requires proxy bindings)
- **Rollback** of filesystem changes made by the agent (requires undo bindings)

## Dependency Changes

Add `nono-proxy` as a dependency in `nono-py/Cargo.toml`. The core `nono`
crate (already a dependency at `0.24.0`) contains the undo/snapshot system
and the shared audit types. No changes are needed to either Rust crate.

```toml
[dependencies]
nono = "0.24.0"
nono-proxy = { version = "...", path = "..." }  # or crates.io version
pyo3 = { version = "0.23", features = ["extension-module"] }
tokio = { version = "1", features = ["rt-multi-thread"] }
```

`tokio` is required to host the proxy server's async runtime within the
synchronous Python binding layer.

## Part 1: Proxy Bindings

### Rust Types to Bind

All types originate from the `nono-proxy` crate.

#### ProxyConfig

Wraps `nono_proxy::ProxyConfig`. Constructor with keyword arguments:

```python
config = ProxyConfig(
    allowed_hosts=["api.openai.com", "*.anthropic.com"],
    routes=[...],
    external_proxy=None,
    bind_addr="127.0.0.1",
    bind_port=0,
    max_connections=256,
)
```

| Field | Python type | Default | Notes |
|---|---|---|---|
| `bind_addr` | `str` | `"127.0.0.1"` | Parsed to `IpAddr` |
| `bind_port` | `int` | `0` | 0 = OS-assigned ephemeral |
| `allowed_hosts` | `list[str]` | `[]` | Empty = allow all (except hardcoded deny) |
| `routes` | `list[RouteConfig]` | `[]` | Reverse proxy credential routes |
| `external_proxy` | `ExternalProxyConfig \| None` | `None` | Enterprise proxy passthrough |
| `max_connections` | `int` | `256` | 0 = unlimited |

#### RouteConfig

Wraps `nono_proxy::RouteConfig`:

```python
route = RouteConfig(
    prefix="/openai",
    upstream="https://api.openai.com",
    credential_key="openai-key",
    inject_mode=InjectMode.HEADER,
)
```

| Field | Python type | Default | Notes |
|---|---|---|---|
| `prefix` | `str` | required | Path prefix for routing |
| `upstream` | `str` | required | Upstream URL |
| `credential_key` | `str \| None` | `None` | OS keyring account name |
| `inject_mode` | `InjectMode` | `InjectMode.HEADER` | Credential injection method |
| `inject_header` | `str` | `"Authorization"` | Header name (header mode) |
| `credential_format` | `str` | `"Bearer {}"` | Format string with `{}` placeholder |
| `path_pattern` | `str \| None` | `None` | URL path mode: match pattern |
| `path_replacement` | `str \| None` | `None` | URL path mode: replacement pattern |
| `query_param_name` | `str \| None` | `None` | Query param mode: param name |
| `env_var` | `str \| None` | `None` | Override env var name for phantom token |

#### InjectMode

Wraps `nono_proxy::InjectMode`. Frozen enum:

```python
class InjectMode(Enum):
    HEADER = ...
    URL_PATH = ...
    QUERY_PARAM = ...
    BASIC_AUTH = ...
```

#### ExternalProxyConfig

Wraps `nono_proxy::ExternalProxyConfig`:

```python
ext = ExternalProxyConfig(
    address="squid.corp.internal:3128",
    bypass_hosts=["*.internal"],
)
```

| Field | Python type | Default | Notes |
|---|---|---|---|
| `address` | `str` | required | Proxy address |
| `bypass_hosts` | `list[str]` | `[]` | Hosts that bypass the external proxy |

#### ProxyHandle

Wraps `nono_proxy::ProxyHandle`. Returned by `start_proxy()`. Not
user-constructable.

```python
proxy = start_proxy(config)

proxy.port                    # int — assigned listening port
proxy.env_vars()              # dict[str, str] — HTTP_PROXY, HTTPS_PROXY, etc.
proxy.credential_env_vars()   # dict[str, str] — base URL overrides + phantom tokens
proxy.drain_audit_events()    # list[dict] — network audit events
proxy.shutdown()              # signal graceful shutdown
```

**`env_vars()`** returns:

| Key | Value |
|---|---|
| `HTTP_PROXY` | `http://nono:<token>@127.0.0.1:<port>` |
| `HTTPS_PROXY` | `http://nono:<token>@127.0.0.1:<port>` |
| `http_proxy` | (lowercase duplicate) |
| `https_proxy` | (lowercase duplicate) |
| `NO_PROXY` | `localhost,127.0.0.1` |
| `no_proxy` | (lowercase duplicate) |
| `NONO_PROXY_TOKEN` | raw 64-char hex session token |
| `NODE_USE_ENV_PROXY` | `1` |

**`credential_env_vars()`** returns per-route entries:

| Key | Value | Condition |
|---|---|---|
| `<PREFIX>_BASE_URL` | `http://127.0.0.1:<port>/<prefix>` | Always |
| `<CREDENTIAL_KEY>` or `<env_var>` | session token (phantom) | Only if credential loaded |

**`drain_audit_events()`** returns `list[dict]` where each dict contains:

| Key | Type | Notes |
|---|---|---|
| `timestamp_unix_ms` | `int` | |
| `mode` | `str` | `"connect"`, `"reverse"`, `"external"` |
| `decision` | `str` | `"allow"`, `"deny"` |
| `target` | `str` | Hostname or service |
| `port` | `int \| None` | |
| `method` | `str \| None` | HTTP method (reverse proxy) |
| `path` | `str \| None` | Request path (reverse proxy) |
| `status` | `int \| None` | Upstream response status |
| `reason` | `str \| None` | Denial reason |

### Module-Level Function

#### start_proxy

```python
def start_proxy(config: ProxyConfig) -> ProxyHandle: ...
```

Creates a tokio runtime on a background thread, calls
`nono_proxy::start(config)`, blocks (with GIL released) until the proxy is
listening, and returns a `ProxyHandle`. The tokio runtime lives for the
lifetime of the handle and is shut down when `ProxyHandle.shutdown()` is
called or the handle is garbage collected.

### Tokio Runtime Strategy

The proxy server is async (tokio). The binding creates a
`tokio::runtime::Runtime` in `start_proxy()`, calls `runtime.block_on()` to
run the async `start()` and obtain the handle, then keeps the runtime alive
inside the `ProxyHandle` PyO3 wrapper so the proxy's background tasks
(connection handling, DNS resolution, credential injection) continue running.

The GIL is released during `block_on()` via `py.allow_threads()`, consistent
with how `sandboxed_exec` handles blocking operations.

### Integration with sandboxed_exec

`sandboxed_exec` already accepts `env: list[tuple[str, str]]`. The proxy
env vars slot in directly:

```python
proxy = start_proxy(config)
all_env = list(proxy.env_vars().items()) + list(proxy.credential_env_vars().items())
result = sandboxed_exec(caps, ["python", "agent.py"], env=all_env)
```

No changes to `sandboxed_exec` are required.

## Part 2: Undo/Snapshot Bindings

### Rust Types to Bind

All types originate from the `nono::undo` module (already a dependency).

#### SnapshotManager

Wraps `nono::undo::SnapshotManager`:

```python
mgr = SnapshotManager(
    session_dir="/path/to/session",
    tracked_paths=["/workspace"],
    exclusion=ExclusionConfig(...),
)

mgr.create_baseline()                # capture initial state
mgr.create_incremental()             # capture current state, return changes
mgr.restore_to(snapshot_number=0)    # roll back to baseline
mgr.compute_restore_diff(0)          # dry-run: show what restore would change
mgr.snapshot_count()                 # number of snapshots taken
```

#### ExclusionConfig

Wraps `nono::undo::ExclusionConfig`:

```python
exclusion = ExclusionConfig(
    use_gitignore=True,
    exclude_patterns=["node_modules", "__pycache__", "target"],
    exclude_globs=["*.pyc", "*.tmp.*"],
    force_include=[],
)
```

#### ContentHash

Wraps `nono::undo::ContentHash`. Frozen, hashable:

```python
hash.hex()       # 64-char hex string
repr(hash)       # "ContentHash(abcdef...)"
```

#### Change

Wraps `nono::undo::Change`. Frozen:

```python
change.path          # str — file path
change.change_type   # str — "created", "modified", "deleted", "permissions_changed"
```

#### SessionMetadata

Wraps `nono::undo::SessionMetadata`:

```python
meta = SessionMetadata(
    session_id="20260326-143000-12345",
    command=["python", "agent.py"],
    tracked_paths=["/workspace"],
)

meta.session_id          # str
meta.started             # str (ISO 8601)
meta.ended               # str | None
meta.command             # list[str]
meta.tracked_paths       # list[str]
meta.snapshot_count      # int
meta.exit_code           # int | None
meta.merkle_roots        # list[ContentHash]
meta.network_events      # list[dict]  (same schema as drain_audit_events)
```

`SessionMetadata.network_events` uses the same dict schema as
`ProxyHandle.drain_audit_events()`, since both represent
`NetworkAuditEvent`.

#### SnapshotManifest

Wraps `nono::undo::SnapshotManifest`. Read-only view:

```python
manifest.number        # int
manifest.timestamp     # str (ISO 8601)
manifest.parent        # int | None
manifest.merkle_root   # ContentHash
manifest.files         # dict[str, FileState]
```

#### FileState

Wraps `nono::undo::FileState`. Frozen:

```python
state.hash          # ContentHash
state.size          # int
state.mtime         # float (seconds since epoch)
state.permissions   # int (Unix mode bits)
```

## Part 3: Policy Schema Extension

Python policy resolution should follow the same `network` field naming as the
main nono profile format instead of introducing a nested `network.proxy`
object. The canonical host-allowlist key is `allow_domain`, with
`allow_proxy` and `proxy_allow` accepted as aliases for compatibility.

```json
"network": {
  "block": false,
  "allow_domain": ["api.openai.com", "*.anthropic.com"],
  "max_connections": 256
}
```

The Python binding resolves these fields into a `ProxyConfig` when
`Policy.resolve_proxy_config()` is called.

Current Python binding coverage:

- `block`
- `allow_domain` plus `allow_proxy` / `proxy_allow` aliases
- `max_connections`
- `custom_credentials`
- `upstream_proxy` / `external_proxy`
- `upstream_bypass` / `external_proxy_bypass`

Not yet implemented in `nono-py`:

- `network_profile`
- built-in credential service resolution via `credentials`

## Rust Source File Layout

```
src/
  lib.rs              # existing — add proxy + undo module declarations and registrations
  policy.rs           # existing
  sandboxed_exec.rs   # existing
  proxy.rs            # new — ProxyConfig, RouteConfig, InjectMode, ExternalProxyConfig,
                      #        ProxyHandle, start_proxy()
  undo.rs             # new — SnapshotManager, ExclusionConfig, ContentHash, Change,
                      #        SessionMetadata, SnapshotManifest, FileState
```

## Type Stub Updates

`python/nono_py/_nono_py.pyi` must be updated with all new classes and
functions. This file is the source of truth for IDE autocompletion and mypy.

## Supervisor Usage Example

```python
from nono_py import (
    CapabilitySet, AccessMode, ProxyConfig, RouteConfig,
    SnapshotManager, ExclusionConfig, SessionMetadata,
    start_proxy, sandboxed_exec,
)

# 1. Configure proxy with domain filtering and credential injection
config = ProxyConfig(
    allowed_hosts=["api.openai.com"],
    routes=[
        RouteConfig(
            prefix="/openai",
            upstream="https://api.openai.com",
            credential_key="openai-key",
        ),
    ],
)
proxy = start_proxy(config)

# 2. Set up filesystem snapshot tracking
exclusion = ExclusionConfig(
    use_gitignore=True,
    exclude_patterns=["node_modules", "__pycache__"],
)
mgr = SnapshotManager(
    session_dir="~/.nono/rollbacks/session-001",
    tracked_paths=["/workspace"],
    exclusion=exclusion,
)
mgr.create_baseline()

# 3. Build sandbox capabilities
caps = CapabilitySet()
caps.allow_path("/workspace", AccessMode.READ_WRITE)
caps.block_network()  # direct network blocked; proxy provides filtered access

# 4. Run sandboxed agent with proxy env vars
env = list(proxy.env_vars().items()) + list(proxy.credential_env_vars().items())
result = sandboxed_exec(caps, ["python", "agent.py"], env=env)

# 5. Capture incremental snapshot after agent finishes
changes = mgr.create_incremental()

# 6. Collect audit trail
audit_events = proxy.drain_audit_events()

# 7. Assemble session metadata
meta = SessionMetadata(
    session_id="20260326-143000-12345",
    command=["python", "agent.py"],
    tracked_paths=["/workspace"],
)
# ... populate meta with snapshot_count, merkle_roots, network_events, exit_code

# 8. Roll back if needed
mgr.restore_to(snapshot_number=0)

# 9. Shut down proxy
proxy.shutdown()
```

## Security Properties Preserved

All security properties from the Rust implementation carry through unchanged:

- **Cloud metadata deny list**: 169.254.169.254 and equivalents always blocked
- **DNS rebinding protection**: resolve-once, validate IPs, connect to resolved addresses
- **Credential isolation**: real secrets never reach the sandboxed process
- **Zeroizing memory**: credentials cleared on drop (Rust-side)
- **Constant-time token comparison**: prevents timing side-channels
- **Merkle commitment**: single root hash commits to entire filesystem state
- **Content-addressable dedup**: identical file content stored once
- **APFS clonefile**: copy-on-write on macOS for efficient snapshots
- **Atomic writes**: temp file + rename for all persistent state
- **Audit log cap**: 4096 events maximum, no sensitive data recorded

## Out of Scope

- Async Python API (asyncio) for the proxy — synchronous wrapper is sufficient
- Python-side credential management — credentials are loaded from OS keyring by
  the Rust proxy
- Changes to the `nono` or `nono-proxy` Rust crates
- External proxy authentication (not yet implemented in nono-proxy)
