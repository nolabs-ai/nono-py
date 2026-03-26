//! Python bindings for the nono capability-based sandboxing library.
//!
//! Provides Python access to OS-enforced sandboxing via Landlock (Linux)
//! and Seatbelt (macOS).

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

mod policy;
mod proxy;
mod sandboxed_exec;
mod undo;

// ---------------------------------------------------------------------------
// Error mapping
// ---------------------------------------------------------------------------

fn to_py_err(e: NonoError) -> PyErr {
    match &e {
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
    }
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
#[pyclass(frozen, eq, hash)]
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
#[pyclass(frozen)]
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
#[pyclass(frozen)]
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
#[pyclass]
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
        let net = if self.inner.is_network_blocked() {
            "blocked"
        } else {
            "allowed"
        };
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
// SandboxState
// ---------------------------------------------------------------------------

/// Serializable snapshot of a CapabilitySet.
///
/// Use this to persist sandbox state to JSON and restore it later.
/// Useful for passing sandbox configuration across process boundaries.
///
/// Example:
///     >>> state = SandboxState.from_caps(caps)
///     >>> json_str = state.to_json()
///     >>> # Later...
///     >>> state = SandboxState.from_json(json_str)
///     >>> caps = state.to_caps()
#[pyclass]
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
    #[staticmethod]
    fn from_caps(caps: &CapabilitySet) -> Self {
        Self {
            inner: RustSandboxState::from_caps(&caps.inner),
        }
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
    fn query_path(&self, path: &str, mode: AccessMode) -> PyResult<PyObject> {
        let result = self.inner.query_path(Path::new(path), mode.into());
        Python::with_gil(|py| query_result_to_dict(py, &result))
    }

    /// Query whether network access is permitted.
    ///
    /// Returns:
    ///     Dict with 'status' ('allowed' or 'denied') and 'reason'
    fn query_network(&self) -> PyResult<PyObject> {
        let result = self.inner.query_network();
        Python::with_gil(|py| query_result_to_dict(py, &result))
    }
}

fn query_result_to_dict(py: Python<'_>, result: &nono::query::QueryResult) -> PyResult<PyObject> {
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
    Ok(dict.into())
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
    Sandbox::apply(&caps.inner).map_err(to_py_err)
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
    m.add_function(wrap_pyfunction!(apply_unlink_overrides, m)?)?;
    m.add_function(wrap_pyfunction!(embedded_policy_json, m)?)?;
    m.add_function(wrap_pyfunction!(is_supported, m)?)?;
    m.add_function(wrap_pyfunction!(load_embedded_policy, m)?)?;
    m.add_function(wrap_pyfunction!(load_policy, m)?)?;
    m.add_function(wrap_pyfunction!(support_info, m)?)?;
    m.add_function(wrap_pyfunction!(sandboxed_exec::sandboxed_exec, m)?)?;
    m.add_function(wrap_pyfunction!(validate_deny_overlaps, m)?)?;
    m.add_function(wrap_pyfunction!(proxy::start_proxy, m)?)?;
    Ok(())
}
