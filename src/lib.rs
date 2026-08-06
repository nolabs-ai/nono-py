//! Python bindings for the nono capability-based sandboxing library.
//!
//! Provides Python access to OS-enforced sandboxing via Landlock (Linux)
//! and Seatbelt (macOS).

#[cfg(all(target_os = "linux", debug_assertions))]
mod raw_clone_allocator_guard {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::sync::atomic::{AtomicBool, Ordering};

    const ALLOCATION_EXIT_STATUS: i32 = 125;
    static ARMED: AtomicBool = AtomicBool::new(false);

    pub struct GuardedSystem;

    fn reject_if_armed() {
        if ARMED.load(Ordering::Relaxed) {
            // No formatting, unwinding, or allocator-backed diagnostics are
            // permitted in the raw-cloned child.
            unsafe {
                libc::syscall(libc::SYS_exit_group, ALLOCATION_EXIT_STATUS);
                core::hint::unreachable_unchecked();
            }
        }
    }

    unsafe impl GlobalAlloc for GuardedSystem {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            reject_if_armed();
            unsafe { System.alloc(layout) }
        }

        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            reject_if_armed();
            unsafe { System.alloc_zeroed(layout) }
        }

        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            reject_if_armed();
            unsafe { System.dealloc(ptr, layout) }
        }

        unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
            reject_if_armed();
            unsafe { System.realloc(ptr, layout, size) }
        }
    }

    pub fn arm() {
        ARMED.store(true, Ordering::SeqCst);
    }
}

#[cfg(all(target_os = "linux", debug_assertions))]
#[global_allocator]
static RAW_CLONE_ALLOCATOR: raw_clone_allocator_guard::GuardedSystem =
    raw_clone_allocator_guard::GuardedSystem;

#[cfg(all(target_os = "linux", debug_assertions))]
pub(crate) fn arm_raw_clone_allocator_guard() {
    raw_clone_allocator_guard::arm();
}

#[cfg(all(target_os = "linux", not(debug_assertions)))]
pub(crate) fn arm_raw_clone_allocator_guard() {}

use nono::{
    AccessMode as RustAccessMode, CapabilitySet as RustCapabilitySet,
    CapabilitySource as RustCapabilitySource, FsCapability as RustFsCapability, NonoError, Sandbox,
    SandboxState as RustSandboxState, SupportInfo as RustSupportInfo,
};
use pyo3::exceptions::{
    PyFileNotFoundError, PyOSError, PyPermissionError, PyRuntimeError, PyValueError,
};
use pyo3::prelude::*;
use std::path::Path;

mod diagnostic;
mod policy;
mod proxy;
mod sandboxed_exec;
mod stderr_observation;
mod undo;

// ---------------------------------------------------------------------------
// Error mapping
// ---------------------------------------------------------------------------

fn to_py_err(e: NonoError) -> PyErr {
    Python::attach(|py| {
        let py_err = match &e {
            NonoError::PathNotFound(_) => PyFileNotFoundError::new_err(e.to_string()),
            NonoError::ExpectedDirectory(_) | NonoError::ExpectedFile(_) => {
                PyValueError::new_err(e.to_string())
            }
            NonoError::PathCanonicalization { .. } => PyOSError::new_err(e.to_string()),
            NonoError::SandboxInit(_) | NonoError::UnsupportedPlatform(_) => {
                PyRuntimeError::new_err(e.to_string())
            }
            NonoError::BlockedCommand { .. } => PyPermissionError::new_err(e.to_string()),
            NonoError::ConfigParse(_) | NonoError::ProfileParse(_) => {
                PyValueError::new_err(e.to_string())
            }
            _ => PyRuntimeError::new_err(e.to_string()),
        };
        diagnostic::attach_nono_error_diagnostics(py, &py_err, &e);
        py_err
    })
}

// ---------------------------------------------------------------------------
// AccessMode
// ---------------------------------------------------------------------------

/// File system access mode.
///
/// Defines the type of access granted to a path:
/// - `READ`: Read-only access
/// - `WRITE`: Write-only access
/// - `READ_WRITE`: Both read and write access
#[pyclass(frozen, eq, hash, from_py_object)]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum AccessMode {
    #[pyo3(name = "READ")]
    Read,
    #[pyo3(name = "WRITE")]
    Write,
    #[pyo3(name = "READ_WRITE")]
    ReadWrite,
}

#[pymethods]
impl AccessMode {
    fn __repr__(&self) -> &'static str {
        match self {
            AccessMode::Read => "AccessMode.READ",
            AccessMode::Write => "AccessMode.WRITE",
            AccessMode::ReadWrite => "AccessMode.READ_WRITE",
        }
    }

    fn __str__(&self) -> &'static str {
        match self {
            AccessMode::Read => "read",
            AccessMode::Write => "write",
            AccessMode::ReadWrite => "read+write",
        }
    }
}

impl From<AccessMode> for RustAccessMode {
    fn from(mode: AccessMode) -> Self {
        match mode {
            AccessMode::Read => RustAccessMode::Read,
            AccessMode::Write => RustAccessMode::Write,
            AccessMode::ReadWrite => RustAccessMode::ReadWrite,
        }
    }
}

impl From<RustAccessMode> for AccessMode {
    fn from(mode: RustAccessMode) -> Self {
        match mode {
            RustAccessMode::Read => AccessMode::Read,
            RustAccessMode::Write => AccessMode::Write,
            RustAccessMode::ReadWrite => AccessMode::ReadWrite,
        }
    }
}

// ---------------------------------------------------------------------------
// CapabilitySource
// ---------------------------------------------------------------------------

/// Source/origin of a capability grant.
///
/// Tracks where a capability came from:
/// - `user()`: Added directly by the user
/// - `group(name)`: Resolved from a named policy group
/// - `system()`: System-level path required for execution
#[pyclass(frozen, skip_from_py_object)]
#[derive(Clone)]
pub struct CapabilitySource {
    inner: RustCapabilitySource,
}

#[pymethods]
impl CapabilitySource {
    /// Create a user-sourced capability.
    #[staticmethod]
    fn user() -> Self {
        Self {
            inner: RustCapabilitySource::User,
        }
    }

    /// Create a group-sourced capability.
    #[staticmethod]
    fn group(name: String) -> Self {
        Self {
            inner: RustCapabilitySource::Group(name),
        }
    }

    /// Create a system-sourced capability.
    #[staticmethod]
    fn system() -> Self {
        Self {
            inner: RustCapabilitySource::System,
        }
    }

    fn __repr__(&self) -> String {
        format!("CapabilitySource({})", self.inner)
    }

    fn __str__(&self) -> String {
        self.inner.to_string()
    }
}

// ---------------------------------------------------------------------------
// FsCapability (read-only view)
// ---------------------------------------------------------------------------

/// A filesystem capability grant.
///
/// Represents access granted to a specific path. This is a read-only view
/// of a capability that has been added to a CapabilitySet.
///
/// Attributes:
///     original: The original user-specified path
///     resolved: The canonicalized absolute path
///     access: The access mode granted (READ, WRITE, or READ_WRITE)
///     is_file: True if this grants access to a single file, False for directory
///     source: The origin of this capability
#[pyclass(frozen, skip_from_py_object)]
#[derive(Clone)]
pub struct FsCapability {
    inner: RustFsCapability,
}

#[pymethods]
impl FsCapability {
    /// The original user-specified path.
    #[getter]
    fn original(&self) -> String {
        self.inner.original.display().to_string()
    }

    /// The canonicalized absolute path.
    #[getter]
    fn resolved(&self) -> String {
        self.inner.resolved.display().to_string()
    }

    /// The access mode granted.
    #[getter]
    fn access(&self) -> AccessMode {
        self.inner.access.into()
    }

    /// True if this grants access to a single file.
    #[getter]
    fn is_file(&self) -> bool {
        self.inner.is_file
    }

    /// The origin of this capability.
    #[getter]
    fn source(&self) -> CapabilitySource {
        CapabilitySource {
            inner: self.inner.source.clone(),
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "FsCapability(path='{}', access={}, is_file={})",
            self.inner.resolved.display(),
            self.inner.access,
            self.inner.is_file
        )
    }

    fn __str__(&self) -> String {
        self.inner.to_string()
    }
}

// ---------------------------------------------------------------------------
// CapabilitySet
// ---------------------------------------------------------------------------

/// A collection of capabilities that define sandbox permissions.
///
/// Use this class to build up the set of permissions that will be granted
/// when the sandbox is applied. Capabilities include filesystem access
/// and network access control.
///
/// Example:
///     >>> caps = CapabilitySet()
///     >>> caps.allow_path("/tmp", AccessMode.READ_WRITE)
///     >>> caps.allow_file("/etc/hosts", AccessMode.READ)
///     >>> caps.block_network()
///     >>> apply(caps)  # Irreversible!
#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct CapabilitySet {
    inner: RustCapabilitySet,
}

#[pymethods]
impl CapabilitySet {
    /// Create a new empty capability set.
    #[new]
    fn new() -> Self {
        Self {
            inner: RustCapabilitySet::new(),
        }
    }

    /// Add directory access for the given path.
    ///
    /// The path is validated and canonicalized. Grants access to the directory
    /// and all its contents recursively.
    ///
    /// Args:
    ///     path: Path to the directory
    ///     mode: Access mode (READ, WRITE, or READ_WRITE)
    ///
    /// Raises:
    ///     FileNotFoundError: If the path does not exist
    ///     ValueError: If the path is not a directory
    fn allow_path(&mut self, path: &str, mode: AccessMode) -> PyResult<()> {
        let cap = RustFsCapability::new_dir(path, mode.into()).map_err(to_py_err)?;
        self.inner.add_fs(cap);
        Ok(())
    }

    /// Add single-file access for the given path.
    ///
    /// The path is validated and canonicalized. Grants access only to the
    /// specific file, not its parent directory.
    ///
    /// Args:
    ///     path: Path to the file
    ///     mode: Access mode (READ, WRITE, or READ_WRITE)
    ///
    /// Raises:
    ///     FileNotFoundError: If the path does not exist
    ///     ValueError: If the path is not a file
    fn allow_file(&mut self, path: &str, mode: AccessMode) -> PyResult<()> {
        let cap = RustFsCapability::new_file(path, mode.into()).map_err(to_py_err)?;
        self.inner.add_fs(cap);
        Ok(())
    }

    /// Block all outbound network access.
    ///
    /// Once applied, the sandboxed process cannot make any network connections.
    fn block_network(&mut self) {
        self.inner.set_network_blocked(true);
    }

    /// Restrict network to proxy-only mode.
    ///
    /// Blocks all outbound network at the kernel level (Landlock on Linux,
    /// Seatbelt on macOS) except localhost TCP to the proxy's port. This
    /// ensures the child process can only reach the network through the
    /// proxy, which enforces domain-level filtering.
    ///
    /// Use ``proxy.sandbox_env()`` to get the environment variables
    /// (HTTP_PROXY, HTTPS_PROXY, etc.) to pass to ``sandboxed_exec(env=...)``.
    ///
    /// Args:
    ///     proxy: A running ProxyHandle from ``start_proxy()``
    ///
    /// Example:
    ///     >>> proxy = start_proxy(ProxyConfig(allowed_hosts=["example.com"]))
    ///     >>> caps = CapabilitySet()
    ///     >>> caps.allow_path("/usr", AccessMode.READ)
    ///     >>> caps.proxy_only(proxy)
    ///     >>> env = proxy.sandbox_env()
    ///     >>> result = sandboxed_exec(caps, ["curl", "https://example.com"], env=env)
    ///     >>> proxy.shutdown()
    fn proxy_only(&mut self, proxy: &proxy::ProxyHandle) {
        use nono::NetworkMode;
        self.inner.set_network_mode_mut(NetworkMode::ProxyOnly {
            port: proxy.port_number(),
            bind_ports: Vec::new(),
        });
    }

    /// Allow bidirectional localhost TCP on a specific port.
    ///
    /// **Has no effect on its own.** This only takes effect when the set is also
    /// in blocked or proxy-only mode — i.e. you must also call
    /// ``block_network()`` (or ``proxy_only()``). In the default allow-all mode
    /// the localhost port list is ignored on *every* kernel and the child keeps
    /// full network access; calling this method alone restricts nothing and
    /// raises no error. When paired with ``block_network()`` the child may
    /// connect to and bind/listen on the given port(s) and nothing else.
    ///
    /// Enforcement:
    ///     - Linux Landlock ABI V4+ (kernel >= 6.7): per-port ConnectTcp +
    ///       BindTcp rules. NOTE: Landlock filters by PORT ONLY — the rule
    ///       permits the port on ANY address, not strictly ``127.0.0.1``.
    ///       Loopback-only scoping requires the seccomp supervisor path (the
    ///       kernel < V4 work, not yet implemented).
    ///     - macOS: per-port outbound; bind/inbound is blanket (all ports).
    ///     - Linux kernels < 6.7 (Landlock ABI < V4), incl. the common ECS 6.1
    ///       target: NOT YET enforceable with ``block_network()`` — the sandbox
    ///       fails closed at apply time (``apply()`` raises RuntimeError;
    ///       ``sandboxed_exec()`` exits non-zero without running the command).
    ///       Support is pending a crate seccomp-fallback change. Probe
    ///       ``detect_abi().has_network``.
    ///
    /// Only TCP is affected — UDP egress is not filtered by Landlock. Not
    /// serviced under ``proxy_only()`` on the < V4 seccomp path, and not
    /// preserved across ``SandboxState`` (from_caps raises rather than drop it).
    ///
    /// Args:
    ///     port: The localhost TCP port to allow. Port 0 is a wildcard meaning
    ///         all localhost outbound on macOS; rejected on Linux with block-net
    ///         (RuntimeError at apply() time, not when this method is called).
    fn allow_localhost_port(&mut self, port: u16) {
        self.inner.add_localhost_port(port);
    }

    /// Allow outbound TCP connect() to a specific port.
    ///
    /// Adds ``port`` to the connect allowlist. On Linux this switches the
    /// network to an allowlist model even without ``block_network()``: only the
    /// listed port(s) are reachable and all other outbound connections are
    /// blocked (e.g. allow 443 while blocking SSH/SMTP and high ports).
    ///
    /// Landlock filters by PORT ONLY, not by destination IP: the allowed port
    /// is reachable on ANY host, including the public internet — NOT only
    /// "approved hosts". For host/domain-level filtering use the nono proxy
    /// (``proxy_only()``).
    ///
    /// Only TCP is affected — UDP egress is not filtered by Landlock. Enforcement:
    /// Linux Landlock ABI V4+ only; fails closed at apply time on older kernels
    /// (see ``allow_localhost_port``). Not available on macOS — raises
    /// RuntimeError at apply()/sandboxed_exec() time, not when this method is
    /// called. Not preserved across ``SandboxState`` (from_caps raises).
    ///
    /// Args:
    ///     port: The TCP port to allow outbound connections to.
    fn allow_tcp_connect_port(&mut self, port: u16) {
        self.inner.add_tcp_connect_port(port);
    }

    /// Allow the sandboxed process to bind()/listen() on a specific TCP port.
    ///
    /// Lets an in-sandbox server (e.g. Streamlit/Gradio/Shiny) open a local
    /// listen port while outbound connections stay blocked. On Linux Landlock
    /// V4+ adding a bind port switches to an allowlist that blocks all outbound
    /// connect() on its own (the "implicit block"); pairing with
    /// ``block_network()`` is still recommended for clarity. Only TCP is
    /// affected — UDP egress is NOT blocked by Landlock.
    ///
    /// Enforcement: Linux Landlock ABI V4+ (per-port BindTcp); fails closed at
    /// apply time on older kernels, incl. the 6.1 target (support pending the
    /// crate seccomp change). Not available on macOS — raises RuntimeError at
    /// apply time, not when this method is called. Not preserved across
    /// ``SandboxState``.
    ///
    /// Args:
    ///     port: The TCP port to allow the child to bind/listen on.
    fn allow_bind_port(&mut self, port: u16) {
        self.inner.add_tcp_bind_port(port);
    }

    /// Add a raw platform-specific sandbox rule.
    ///
    /// On macOS, this is a Seatbelt S-expression string injected verbatim
    /// into the generated profile. Ignored on Linux.
    ///
    /// Args:
    ///     rule: Platform-specific rule string
    ///
    /// Raises:
    ///     ValueError: If the rule is malformed or grants dangerous access
    fn platform_rule(&mut self, rule: &str) -> PyResult<()> {
        self.inner
            .add_platform_rule(rule)
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }

    /// Remove duplicate filesystem capabilities.
    ///
    /// Keeps the highest access level when duplicates exist. User-granted
    /// capabilities take priority over system-granted ones.
    fn deduplicate(&mut self) {
        self.inner.deduplicate();
    }

    /// Check if the given path is covered by an existing directory capability.
    ///
    /// Args:
    ///     path: Path to check
    ///
    /// Returns:
    ///     True if the path is covered by an existing capability
    fn path_covered(&self, path: &str) -> bool {
        self.inner.path_covered(Path::new(path))
    }

    /// Get a list of all filesystem capabilities.
    ///
    /// Returns:
    ///     List of FsCapability objects
    fn fs_capabilities(&self) -> Vec<FsCapability> {
        self.inner
            .fs_capabilities()
            .iter()
            .map(|cap| FsCapability { inner: cap.clone() })
            .collect()
    }

    /// True if network access is blocked.
    #[getter]
    fn is_network_blocked(&self) -> bool {
        self.inner.is_network_blocked()
    }

    /// Get a plain-text summary of the capability set.
    ///
    /// Returns:
    ///     Human-readable summary string
    fn summary(&self) -> String {
        self.inner.summary()
    }

    fn __repr__(&self) -> String {
        let n_fs = self.inner.fs_capabilities().len();
        let net = format!("{}", self.inner.network_mode());
        format!("CapabilitySet(fs={}, network={})", n_fs, net)
    }
}

// ---------------------------------------------------------------------------
// SupportInfo
// ---------------------------------------------------------------------------

/// Information about sandbox support on the current platform.
///
/// Attributes:
///     is_supported: True if sandboxing is available
///     platform: Platform identifier (e.g., "linux", "macos")
///     details: Human-readable description of support status
#[pyclass(frozen)]
pub struct SupportInfo {
    info: RustSupportInfo,
}

#[pymethods]
impl SupportInfo {
    /// True if sandboxing is supported on this platform.
    #[getter]
    fn is_supported(&self) -> bool {
        self.info.is_supported
    }

    /// Platform identifier.
    #[getter]
    fn platform(&self) -> &str {
        self.info.platform
    }

    /// Human-readable support details.
    #[getter]
    fn details(&self) -> &str {
        &self.info.details
    }

    fn __repr__(&self) -> String {
        format!(
            "SupportInfo(supported={}, platform='{}')",
            self.info.is_supported, self.info.platform
        )
    }
}

// ---------------------------------------------------------------------------
// DetectedAbi
// ---------------------------------------------------------------------------

/// Detected Landlock ABI version and the feature set it supports (Linux only).
///
/// Obtain one via `detect_abi()`. Pass it to the `apply_*_with_abi` variants
/// to skip re-probing the kernel on repeated applications.
#[pyclass(frozen)]
pub struct DetectedAbi {
    #[cfg(target_os = "linux")]
    inner: nono::sandbox::DetectedAbi,
}

#[cfg(target_os = "linux")]
#[pymethods]
impl DetectedAbi {
    /// Landlock ABI version string (e.g. "V4").
    #[getter]
    fn version(&self) -> &'static str {
        self.inner.version_string()
    }

    /// Whether file rename across directories is supported (V2+).
    #[getter]
    fn has_refer(&self) -> bool {
        self.inner.has_refer()
    }

    /// Whether file truncation control is supported (V3+).
    #[getter]
    fn has_truncate(&self) -> bool {
        self.inner.has_truncate()
    }

    /// Whether execute access control is supported (V3+).
    #[getter]
    fn has_execute(&self) -> bool {
        self.inner.has_execute()
    }

    /// Whether TCP network filtering is supported (V4+).
    #[getter]
    fn has_network(&self) -> bool {
        self.inner.has_network()
    }

    /// Whether device ioctl filtering is supported (V5+).
    #[getter]
    fn has_ioctl_dev(&self) -> bool {
        self.inner.has_ioctl_dev()
    }

    /// Whether scoped signals and abstract UNIX sockets are supported (V6+).
    #[getter]
    fn has_scoping(&self) -> bool {
        self.inner.has_scoping()
    }

    /// Human-readable feature names available at this ABI level.
    #[getter]
    fn feature_names(&self) -> Vec<String> {
        self.inner.feature_names()
    }

    fn __repr__(&self) -> String {
        format!("DetectedAbi(version='{}')", self.inner.version_string())
    }
}

// ---------------------------------------------------------------------------
// SandboxState
// ---------------------------------------------------------------------------

/// Serializable snapshot of a CapabilitySet.
///
/// Use this to persist sandbox state to JSON and restore it later.
/// Useful for passing sandbox configuration across process boundaries.
///
/// **Limitation:** only filesystem grants, unix-socket grants, and the
/// blocked/allowed network flag are serialized. Per-port TCP allowlists set via
/// ``allow_localhost_port`` / ``allow_tcp_connect_port`` / ``allow_bind_port``
/// cannot be represented, and dropping them silently could widen a restored
/// sandbox (in the default allow-all mode a connect/bind allowlist becomes fully
/// open). To keep this fail-closed, ``from_caps`` **raises** ``ValueError`` if
/// the capability set carries any port allowlist, rather than silently dropping
/// it. Remove the port rules, or transfer the CapabilitySet without SandboxState,
/// until the underlying crate serializes the port vectors (tracked upstream).
///
/// Example:
///     >>> state = SandboxState.from_caps(caps)
///     >>> json_str = state.to_json()
///     >>> # Later...
///     >>> state = SandboxState.from_json(json_str)
///     >>> caps = state.to_caps()
#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct SandboxState {
    inner: RustSandboxState,
}

#[pymethods]
impl SandboxState {
    /// Create a SandboxState snapshot from a CapabilitySet.
    ///
    /// Args:
    ///     caps: The capability set to snapshot
    ///
    /// Returns:
    ///     A new SandboxState instance
    ///
    /// Raises:
    ///     ValueError: If the capability set carries a per-port TCP allowlist
    ///         (allow_localhost_port / allow_tcp_connect_port / allow_bind_port).
    ///         These cannot be serialized, and dropping them silently could widen
    ///         the restored sandbox, so this fails closed instead.
    #[staticmethod]
    fn from_caps(caps: &CapabilitySet) -> PyResult<Self> {
        if !caps.inner.tcp_connect_ports().is_empty()
            || !caps.inner.tcp_bind_ports().is_empty()
            || !caps.inner.localhost_ports().is_empty()
        {
            return Err(PyValueError::new_err(
                "SandboxState cannot represent per-port TCP allowlists \
                 (allow_localhost_port / allow_tcp_connect_port / allow_bind_port); \
                 serializing would silently drop them and could widen the restored \
                 sandbox. Remove the port rules or transfer the CapabilitySet without \
                 SandboxState.",
            ));
        }
        Ok(Self {
            inner: RustSandboxState::from_caps(&caps.inner),
        })
    }

    /// Serialize the state to a JSON string.
    ///
    /// Returns:
    ///     JSON string representation
    fn to_json(&self) -> PyResult<String> {
        self.inner.to_json().map_err(to_py_err)
    }

    /// Deserialize state from a JSON string.
    ///
    /// Args:
    ///     json: JSON string to parse
    ///
    /// Returns:
    ///     A new SandboxState instance
    ///
    /// Raises:
    ///     ValueError: If the JSON is invalid
    #[staticmethod]
    fn from_json(json: &str) -> PyResult<Self> {
        let state = RustSandboxState::from_json(json)
            .map_err(|e| PyValueError::new_err(format!("Invalid JSON: {}", e)))?;
        Ok(Self { inner: state })
    }

    /// Reconstruct a CapabilitySet from this state.
    ///
    /// May fail if referenced paths no longer exist.
    ///
    /// Returns:
    ///     A new CapabilitySet instance
    ///
    /// Raises:
    ///     FileNotFoundError: If a referenced path no longer exists
    fn to_caps(&self) -> PyResult<CapabilitySet> {
        let caps = self.inner.to_caps().map_err(to_py_err)?;
        Ok(CapabilitySet { inner: caps })
    }

    /// True if network access is blocked in this state.
    #[getter]
    fn net_blocked(&self) -> bool {
        self.inner.net_blocked
    }

    fn __repr__(&self) -> String {
        format!(
            "SandboxState(fs={}, net_blocked={})",
            self.inner.fs.len(),
            self.inner.net_blocked
        )
    }
}

// ---------------------------------------------------------------------------
// QueryContext and QueryResult
// ---------------------------------------------------------------------------

/// Context for querying permissions without applying the sandbox.
///
/// Use this to check whether operations would be permitted by a capability
/// set before actually applying the sandbox.
///
/// Example:
///     >>> ctx = QueryContext(caps)
///     >>> result = ctx.query_path("/etc/passwd", AccessMode.READ)
///     >>> if result["status"] == "allowed":
///     ...     print("Read access granted")
#[pyclass]
pub struct QueryContext {
    inner: nono::query::QueryContext,
}

#[pymethods]
impl QueryContext {
    /// Create a new query context from a capability set.
    ///
    /// Args:
    ///     caps: The capability set to query against
    #[new]
    fn new(caps: &CapabilitySet) -> Self {
        Self {
            inner: nono::query::QueryContext::new(caps.inner.clone()),
        }
    }

    /// Query whether a path operation is permitted.
    ///
    /// Args:
    ///     path: Path to check
    ///     mode: Requested access mode
    ///
    /// Returns:
    ///     Dict with 'status' ('allowed' or 'denied') and reason details:
    ///     - For allowed: 'reason', 'granted_path', 'access'
    ///     - For denied: 'reason' (and possibly 'granted', 'requested')
    fn query_path(&self, path: &str, mode: AccessMode) -> PyResult<Py<PyAny>> {
        let result = self.inner.query_path(Path::new(path), mode.into());
        Python::attach(|py| query_result_to_dict(py, &result))
    }

    /// Query whether network access is permitted.
    ///
    /// Returns:
    ///     Dict with 'status' ('allowed' or 'denied') and 'reason'
    fn query_network(&self) -> PyResult<Py<PyAny>> {
        let result = self.inner.query_network();
        Python::attach(|py| query_result_to_dict(py, &result))
    }
}

fn query_result_to_dict(py: Python<'_>, result: &nono::query::QueryResult) -> PyResult<Py<PyAny>> {
    let dict = pyo3::types::PyDict::new(py);
    match result {
        nono::query::QueryResult::Allowed(reason) => {
            dict.set_item("status", "allowed")?;
            match reason {
                nono::query::AllowReason::GrantedPath {
                    granted_path,
                    access,
                } => {
                    dict.set_item("reason", "granted_path")?;
                    dict.set_item("granted_path", granted_path)?;
                    dict.set_item("access", access)?;
                }
                nono::query::AllowReason::NetworkAllowed => {
                    dict.set_item("reason", "network_allowed")?;
                }
            }
        }
        nono::query::QueryResult::Denied(reason) => {
            dict.set_item("status", "denied")?;
            match reason {
                nono::query::DenyReason::PathNotGranted => {
                    dict.set_item("reason", "path_not_granted")?;
                }
                nono::query::DenyReason::InsufficientAccess { granted, requested } => {
                    dict.set_item("reason", "insufficient_access")?;
                    dict.set_item("granted", granted)?;
                    dict.set_item("requested", requested)?;
                }
                nono::query::DenyReason::NetworkBlocked => {
                    dict.set_item("reason", "network_blocked")?;
                }
            }
        }
    }
    Ok(dict.unbind().into_any())
}

// ---------------------------------------------------------------------------
// Module-level functions
// ---------------------------------------------------------------------------

/// Apply the sandbox with the given capabilities.
///
/// **This is irreversible.** Once applied, the current process and all children
/// can only access resources granted by the capabilities. There is no way to
/// expand permissions after this call.
///
/// Args:
///     caps: The capability set defining permitted operations
///
/// Raises:
///     RuntimeError: If the platform is not supported or sandbox initialization fails
#[pyfunction]
fn apply(caps: &CapabilitySet) -> PyResult<()> {
    Sandbox::apply_auto(&caps.inner).map_err(to_py_err)?;
    Ok(())
}

/// Detect the Landlock ABI supported by the running kernel (Linux only).
///
/// Returns:
///     A DetectedAbi describing the kernel's Landlock feature set.
///
/// Raises:
///     RuntimeError: On non-Linux platforms, or if Landlock is unavailable.
#[pyfunction]
fn detect_abi() -> PyResult<DetectedAbi> {
    #[cfg(target_os = "linux")]
    {
        let inner = Sandbox::detect_abi().map_err(to_py_err)?;
        Ok(DetectedAbi { inner })
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(PyRuntimeError::new_err(
            "detect_abi is only available on Linux",
        ))
    }
}

/// Apply Landlock-only sandboxing (Linux only). **Irreversible.**
///
/// Unlike `apply` (which falls back to seccomp), this errors if network
/// restrictions cannot be satisfied by Landlock alone (kernel ABI < V4).
///
/// Raises:
///     RuntimeError: On non-Linux platforms, or if application fails.
#[pyfunction]
fn apply_landlock(caps: &CapabilitySet) -> PyResult<()> {
    #[cfg(target_os = "linux")]
    {
        Sandbox::apply_landlock(&caps.inner).map_err(to_py_err)?;
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = caps;
        Err(PyRuntimeError::new_err(
            "apply_landlock is only available on Linux",
        ))
    }
}

/// Apply Landlock filesystem/process sandboxing plus the static seccomp
/// network baseline (Linux only). **Irreversible.**
///
/// Args:
///     caps: The capability set defining permitted operations.
///     external_tcp: When True, declare that TCP enforcement is handled
///         externally instead of by nono's seccomp baseline (default False).
///
/// Raises:
///     RuntimeError: On non-Linux platforms, or if application fails.
#[pyfunction]
#[pyo3(signature = (caps, external_tcp = false))]
fn apply_seccomp(caps: &CapabilitySet, external_tcp: bool) -> PyResult<()> {
    #[cfg(target_os = "linux")]
    {
        let opts = if external_tcp {
            nono::sandbox::SeccompOpts::external_tcp()
        } else {
            nono::sandbox::SeccompOpts::network_baseline()
        };
        Sandbox::apply_seccomp(&caps.inner, opts).map_err(to_py_err)?;
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (caps, external_tcp);
        Err(PyRuntimeError::new_err(
            "apply_seccomp is only available on Linux",
        ))
    }
}

/// Declare that TCP network enforcement is handled externally (Linux only).
///
/// This is a no-op marker; it must not be used as the whole sandbox —
/// filesystem/process sandboxing is applied separately.
///
/// Raises:
///     RuntimeError: On non-Linux platforms, or if application fails.
#[pyfunction]
fn apply_external() -> PyResult<()> {
    #[cfg(target_os = "linux")]
    {
        Sandbox::apply_external().map_err(to_py_err)?;
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(PyRuntimeError::new_err(
            "apply_external is only available on Linux",
        ))
    }
}

/// Apply automatic Landlock → seccomp fallback with a pre-detected ABI
/// (Linux only). **Irreversible.** See `apply` and `detect_abi`.
#[pyfunction]
fn apply_auto_with_abi(caps: &CapabilitySet, abi: &DetectedAbi) -> PyResult<()> {
    #[cfg(target_os = "linux")]
    {
        Sandbox::apply_auto_with_abi(&caps.inner, &abi.inner).map_err(to_py_err)?;
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (caps, abi);
        Err(PyRuntimeError::new_err(
            "apply_auto_with_abi is only available on Linux",
        ))
    }
}

/// Apply Landlock-only sandboxing with a pre-detected ABI (Linux only).
/// **Irreversible.** See `apply_landlock` and `detect_abi`.
#[pyfunction]
fn apply_landlock_with_abi(caps: &CapabilitySet, abi: &DetectedAbi) -> PyResult<()> {
    #[cfg(target_os = "linux")]
    {
        Sandbox::apply_landlock_with_abi(&caps.inner, &abi.inner).map_err(to_py_err)?;
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (caps, abi);
        Err(PyRuntimeError::new_err(
            "apply_landlock_with_abi is only available on Linux",
        ))
    }
}

/// Apply Landlock + the static seccomp baseline with a pre-detected ABI (Linux only).
/// **Irreversible.** See `apply_seccomp` and `detect_abi`.
#[pyfunction]
#[pyo3(signature = (caps, abi, external_tcp = false))]
fn apply_seccomp_with_abi(
    caps: &CapabilitySet,
    abi: &DetectedAbi,
    external_tcp: bool,
) -> PyResult<()> {
    #[cfg(target_os = "linux")]
    {
        let opts = if external_tcp {
            nono::sandbox::SeccompOpts::external_tcp()
        } else {
            nono::sandbox::SeccompOpts::network_baseline()
        };
        Sandbox::apply_seccomp_with_abi(&caps.inner, &abi.inner, opts).map_err(to_py_err)?;
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (caps, abi, external_tcp);
        Err(PyRuntimeError::new_err(
            "apply_seccomp_with_abi is only available on Linux",
        ))
    }
}

/// Check if sandboxing is supported on this platform.
///
/// Returns:
///     True if sandboxing is available (Linux with Landlock, or macOS)
#[pyfunction]
fn is_supported() -> bool {
    Sandbox::is_supported()
}

/// Get detailed information about sandbox support on this platform.
///
/// Returns:
///     SupportInfo object with platform details
#[pyfunction]
fn support_info() -> SupportInfo {
    SupportInfo {
        info: Sandbox::support_info(),
    }
}

/// Parse a policy.json document.
#[pyfunction]
fn load_policy(json: &str) -> PyResult<policy::Policy> {
    policy::load_policy(json).map_err(to_py_err)
}

/// Load the embedded nono policy bundled with this package.
#[pyfunction]
fn load_embedded_policy() -> PyResult<policy::Policy> {
    policy::load_embedded_policy().map_err(to_py_err)
}

/// Return the raw embedded policy.json string.
#[pyfunction]
fn embedded_policy_json() -> &'static str {
    include_str!("../data/policy.json")
}

/// Apply post-resolution unlink override rules for writable paths.
#[pyfunction]
fn apply_unlink_overrides(caps: &mut CapabilitySet) -> PyResult<()> {
    policy::apply_unlink_overrides(caps).map_err(to_py_err)
}

/// Validate deny.access paths against the final capability set.
#[pyfunction]
fn validate_deny_overlaps(deny_paths: Vec<String>, caps: &CapabilitySet) -> PyResult<()> {
    let deny_paths = deny_paths
        .into_iter()
        .map(std::path::PathBuf::from)
        .collect::<Vec<_>>();
    policy::validate_deny_overlaps(&deny_paths, caps).map_err(to_py_err)
}

// ---------------------------------------------------------------------------
// Module definition
// ---------------------------------------------------------------------------

/// nono: Capability-based sandboxing for Python.
///
/// This module provides OS-enforced sandboxing using Landlock (Linux) and
/// Seatbelt (macOS). Once a sandbox is applied, unauthorized operations are
/// structurally impossible.
///
/// Basic usage:
///     >>> from nono_py import CapabilitySet, AccessMode, apply
///     >>> caps = CapabilitySet()
///     >>> caps.allow_path("/tmp", AccessMode.READ_WRITE)
///     >>> caps.block_network()
///     >>> apply(caps)  # Irreversible!
#[pymodule]
fn _nono_py(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<AccessMode>()?;
    m.add_class::<CapabilitySource>()?;
    m.add_class::<FsCapability>()?;
    m.add_class::<CapabilitySet>()?;
    m.add_class::<policy::Policy>()?;
    m.add_class::<policy::ResolvedPolicy>()?;
    m.add_class::<SupportInfo>()?;
    m.add_class::<DetectedAbi>()?;
    m.add_class::<SandboxState>()?;
    m.add_class::<QueryContext>()?;
    m.add_class::<sandboxed_exec::ExecResult>()?;
    // Proxy classes
    m.add_class::<proxy::InjectMode>()?;
    m.add_class::<proxy::RouteConfig>()?;
    m.add_class::<proxy::ExternalProxyConfig>()?;
    m.add_class::<proxy::ProxyConfig>()?;
    m.add_class::<proxy::ProxyHandle>()?;
    // Undo/snapshot classes
    m.add_class::<undo::ContentHash>()?;
    m.add_class::<undo::FileState>()?;
    m.add_class::<undo::Change>()?;
    m.add_class::<undo::SnapshotManifest>()?;
    m.add_class::<undo::ExclusionConfig>()?;
    m.add_class::<undo::SessionMetadata>()?;
    m.add_class::<undo::SnapshotManager>()?;
    // Module functions
    m.add_function(wrap_pyfunction!(apply, m)?)?;
    m.add_function(wrap_pyfunction!(apply_landlock, m)?)?;
    m.add_function(wrap_pyfunction!(apply_seccomp, m)?)?;
    m.add_function(wrap_pyfunction!(apply_external, m)?)?;
    m.add_function(wrap_pyfunction!(apply_auto_with_abi, m)?)?;
    m.add_function(wrap_pyfunction!(apply_landlock_with_abi, m)?)?;
    m.add_function(wrap_pyfunction!(apply_seccomp_with_abi, m)?)?;
    m.add_function(wrap_pyfunction!(detect_abi, m)?)?;
    m.add_function(wrap_pyfunction!(apply_unlink_overrides, m)?)?;
    m.add_function(wrap_pyfunction!(embedded_policy_json, m)?)?;
    m.add_function(wrap_pyfunction!(is_supported, m)?)?;
    m.add_function(wrap_pyfunction!(load_embedded_policy, m)?)?;
    m.add_function(wrap_pyfunction!(load_policy, m)?)?;
    m.add_function(wrap_pyfunction!(support_info, m)?)?;
    m.add_function(wrap_pyfunction!(sandboxed_exec::sandboxed_exec, m)?)?;
    m.add_function(wrap_pyfunction!(validate_deny_overlaps, m)?)?;
    m.add_function(wrap_pyfunction!(
        diagnostic::build_session_diagnostic_report,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        diagnostic::merge_diagnostic_report_json,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(proxy::start_proxy, m)?)?;
    Ok(())
}
