<div align="center">

<img src="assets/nono-py.png" alt="nono logo" width="500"/>
</p>

<a href="https://discord.gg/pPcjYzGvbS">
  <img src="https://img.shields.io/badge/Chat-Join%20Discord-7289da?style=for-the-badge&logo=discord&logoColor=white" alt="Join Discord"/>
</a>

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

### Enums

#### `AccessMode`

File system access mode:
- `AccessMode.READ` - Read-only access
- `AccessMode.WRITE` - Write-only access
- `AccessMode.READ_WRITE` - Both read and write access

### Classes

#### `CapabilitySet`

A collection of capabilities that define sandbox permissions.

```python
caps = CapabilitySet()

# Add directory access (recursive)
caps.allow_path("/tmp", AccessMode.READ_WRITE)

# Add single file access
caps.allow_file("/etc/hosts", AccessMode.READ)

# Block network
caps.block_network()

# Add platform-specific rule (macOS Seatbelt)
caps.platform_rule("(allow mach-lookup (global-name \"com.apple.system.logger\"))")

# Utility methods
caps.deduplicate()  # Remove duplicates
caps.path_covered("/tmp/foo")  # Check if path is covered
caps.fs_capabilities()  # List all fs capabilities
caps.summary()  # Human-readable summary
```

#### `QueryContext`

Query permissions without applying the sandbox:

```python
caps = CapabilitySet()
caps.allow_path("/tmp", AccessMode.READ)

ctx = QueryContext(caps)

result = ctx.query_path("/tmp/file.txt", AccessMode.READ)
# {'status': 'allowed', 'reason': 'granted_path', 'granted_path': '/tmp', 'access': 'read'}

result = ctx.query_path("/var/log/test", AccessMode.READ)
# {'status': 'denied', 'reason': 'path_not_granted'}

result = ctx.query_network()
# {'status': 'allowed', 'reason': 'network_allowed'}
```

#### `SandboxState`

Serialize and restore capability sets:

```python
caps = CapabilitySet()
caps.allow_path("/tmp", AccessMode.READ)

# Serialize to JSON
state = SandboxState.from_caps(caps)
json_str = state.to_json()

# Restore from JSON
restored_state = SandboxState.from_json(json_str)
restored_caps = restored_state.to_caps()
```

#### `SupportInfo`

Platform support information:

```python
info = support_info()
print(info.is_supported)  # True/False
print(info.platform)      # "linux" or "macos"
print(info.details)       # Human-readable details
```

#### `Policy`

Load a `policy.json` document and resolve named groups into a `CapabilitySet`:

```python
from pathlib import Path

from nono_py import CapabilitySet, load_policy

policy = load_policy(Path("examples/policy_example.json").read_text())
caps = CapabilitySet()
resolved = policy.resolve_groups(["system_tmp_read", "deny_secrets"], caps)

print(resolved.names)
print(resolved.deny_paths)
print(caps.summary())
```

### Functions

#### `apply(caps: CapabilitySet) -> None`

Apply the sandbox. **This is irreversible.** Once applied, the current process and all children can only access resources granted by the capabilities.

#### `is_supported() -> bool`

Check if sandboxing is supported on this platform.

#### `support_info() -> SupportInfo`

Get detailed platform support information.

#### `load_policy(json: str) -> Policy`

Parse a `policy.json` document.

#### `load_embedded_policy() -> Policy`

Load the bundled nono policy shipped with the package.

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
