# nono-py Examples

These examples demonstrate various features of the nono-py sandboxing library.

## Examples

### 01_basic_sandbox.py

Basic sandbox usage: create capabilities, apply sandbox, verify restrictions.

**WARNING**: This example actually applies the sandbox, which is irreversible!

```bash
python examples/01_basic_sandbox.py
```

### 02_query_permissions.py

Test permissions without applying the sandbox using `QueryContext`. Safe to run
repeatedly - no sandbox is applied.

```bash
python examples/02_query_permissions.py
```

### 03_sandbox_state.py

Serialize sandbox configuration to JSON for cross-process transfer or
persistence. Demonstrates the `SandboxState` class.

```bash
python examples/03_sandbox_state.py
```

### 04_capability_inspection.py

Examine capability set contents including filesystem capabilities, access
modes, sources, and deduplication.

```bash
python examples/04_capability_inspection.py
```

### 05_subprocess_sandbox.py

Run untrusted code in a sandboxed subprocess. Shows the pattern for passing
sandbox configuration via environment variables.

**WARNING**: This example applies the sandbox in a subprocess!

```bash
python examples/05_subprocess_sandbox.py
```

### 06_capability_basics.py

Review the core `CapabilitySet` building blocks: filesystem grants, network
blocking, and readable summaries.

```bash
python examples/06_capability_basics.py
```

### 07_error_handling.py

Handle errors gracefully: path validation, serialization errors, and
platform support issues.

```bash
python examples/07_error_handling.py
```

### 08_sandboxed_exec.py

Run commands in sandboxed child processes while the parent remains unsandboxed.
Shows output capture, environment injection, timeout handling, repeated calls,
and the `max_processes` caveat for dedicated-UID deployments.

```bash
python examples/08_sandboxed_exec.py
```

### 09_policy_loading.py

Load a `policy.json` document, resolve named groups into a `CapabilitySet`,
and inspect the resulting filesystem and network permissions without applying
the sandbox.

The matching example policy file lives at `examples/policy_example.json`.

```bash
python examples/09_policy_loading.py
```

### 10_policy_enforced.py

Resolve a policy and enforce it in child processes using `sandboxed_exec()`.
This shows a permitted read, a denied read, and an allowed write inside a
granted directory.

```bash
python examples/10_policy_enforced.py
```

### 12_policy_proxy.py

Resolve a proxy allowlist from `policy_example.json`, start the proxy from
that JSON-derived config, and demonstrate one allowed HTTPS domain and one
blocked HTTPS domain.

```bash
python examples/12_policy_proxy.py
```

### 14_audit_to_s3.py

Stream both the proxy audit stream and the supervisor's on-disk
audit log (`audit-events.ndjson`) to an S3-compatible sink, gzipped
JSONL with a per-record source tag. Demonstrates command auditing,
filesystem capability decisions, URL opens, and network events end
to end. Verifies alpha-scheme chain/leaf/Merkle integrity of the
on-disk log at the end of the run.

Configurable via env vars (no defaults):

- Real S3: `NONO_S3_BUCKET` (+ `NONO_S3_KEY_PREFIX`, optional
  `NONO_S3_ENDPOINT_URL`, `NONO_S3_REGION`, ambient AWS credentials).
- Offline: `NONO_S3_FAKE=1` (in-memory sink, no infrastructure required).
- Tail an existing CLI session: set `NONO_AUDIT_SESSION_DIR=...`.
  Otherwise a representative synth log is produced for the demo.

```bash
NONO_S3_FAKE=1 NONO_S3_KEY_PREFIX=demo \
  python examples/14_audit_to_s3.py
```

## Running Examples

All examples can be run directly:

```bash
# From the repository root
cd examples
python 01_basic_sandbox.py

# Or from anywhere
python /path/to/nono-py/examples/02_query_permissions.py
```

## Platform Support

- **Linux**: Requires kernel 5.13+ with Landlock support
- **macOS**: Uses Seatbelt (App Sandbox)
- **Other**: Not supported

Check support programmatically:

```python
from nono_py import is_supported, support_info

if is_supported():
    info = support_info()
    print(f"Platform: {info.platform}")
else:
    print("Sandboxing not available")
```
