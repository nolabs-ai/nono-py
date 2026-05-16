# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

nono-py provides Python bindings for the [nono](https://github.com/always-further/nono) Rust capability-based sandboxing library. It uses PyO3/maturin to expose Rust code to Python, supporting Landlock (Linux) and Seatbelt (macOS).

## Build & Development Commands

```bash
uv sync                          # Install all dependencies (creates venv automatically)
uv run maturin develop           # Build native module (debug mode)
uv run maturin develop --release # Build native module (release mode)
```

## Testing

```bash
uv run pytest tests/ -v                        # All tests
uv run pytest tests/test_capability_set.py -v   # Single file
uv run pytest tests/test_query.py::TestQueryContextPathQueries -v  # Single class
```

## Linting & Formatting

```bash
cargo fmt                                    # Format Rust
cargo clippy -- -D warnings                  # Lint Rust
uv run ruff format python/ tests/            # Format Python
uv run ruff check --fix python/ tests/       # Lint Python (autofix)
uv run mypy python/nono_py                   # Type check (strict mode)
```

`make ci` runs the full suite: fmt-check, lint, test.

## Architecture

### Binding Layer

`src/lib.rs` is the main Rust source file. It wraps the `nono` crate's types using PyO3 `#[pyclass]`/`#[pymethods]` macros. Each Python class holds an inner Rust type (e.g., `CapabilitySet` wraps `RustCapabilitySet`). Rust `NonoError` variants map to Python exceptions: `FileNotFoundError`, `ValueError`, `OSError`, `RuntimeError`, `PermissionError`. Additional bindings live in `src/proxy.rs` (network proxy), `src/undo.rs` (snapshots), `src/policy.rs` (policy resolution), and `src/sandboxed_exec.rs`.

### Python Package

`python/nono_py/__init__.py` re-exports everything from the native `_nono_py` module. The underscore-prefixed native module is an internal implementation detail.

`python/nono_py/_nono_py.pyi` contains type stubs that must stay in sync with the Rust API. This file is the source of truth for IDE autocompletion and mypy.

### Key Classes

- **CapabilitySet** — mutable builder: `allow_path()`, `allow_file()`, `block_network()`, `proxy_only()`
- **QueryContext** — test permissions without applying: returns dicts with `status`/`reason` keys
- **SandboxState** — JSON-serializable snapshot of a CapabilitySet for cross-process transfer
- **AccessMode** — enum: `READ`, `WRITE`, `READ_WRITE` (frozen)
- **Policy** / **ResolvedPolicy** — load and resolve `policy.json` documents
- **ProxyConfig** / **RouteConfig** / **ProxyHandle** — network filtering proxy with credential injection
- **SnapshotManager** / **SessionMetadata** — content-addressable filesystem snapshots with Merkle trees
- **apply()** — module-level function, **irreversible** OS sandbox enforcement
- **sandboxed_exec()** — run a command in a sandboxed child process

### Pure-Python Audit Module

`python/nono_py/audit.py` provides the audit log reader/writer/verifier: `AlphaRecorder`, `iter_session`, `tail_session`, `verify_log`, and typed event builders. This is a pure-Python module (no Rust), re-exported as `nono_py.audit`.

### Nono Dependency

The nono library is pulled from crates.io (`nono = "0.55.0"`, `nono-proxy = "0.55.0"`).

## Conventions

- Python: ruff, line-length 100, target py310, strict mypy
- Rust: edition 2021, rust-version 1.95, clippy with `-D warnings`
- Frozen PyO3 classes for immutable types (AccessMode, FsCapability, SupportInfo, CapabilitySource)
- Path validation happens at add-time in Rust (fail fast)
- Tests use `conftest.py` fixtures `temp_dir` and `temp_file` for filesystem isolation
