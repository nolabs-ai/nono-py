//! Python bindings for the nono undo/snapshot system.
//!
//! Provides content-addressable filesystem snapshots, incremental change
//! tracking, Merkle-committed state, and rollback for sandboxed sessions.

use crate::to_py_err;
use nono::undo::{
    Change as RustChange, ChangeType as RustChangeType, ContentHash as RustContentHash,
    ExclusionConfig as RustExclusionConfig, ExclusionFilter, FileState as RustFileState,
    NetworkAuditDecision, NetworkAuditMode, SessionMetadata as RustSessionMetadata,
    SnapshotManager as RustSnapshotManager, SnapshotManifest as RustSnapshotManifest, WalkBudget,
};
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// ContentHash
// ---------------------------------------------------------------------------

/// SHA-256 content hash for content-addressable storage.
///
/// Immutable and hashable. Use `hex()` to get the 64-character hex string.
#[pyclass(frozen)]
#[derive(Clone)]
pub struct ContentHash {
    inner: RustContentHash,
}

#[pymethods]
impl ContentHash {
    /// Return the hash as a 64-character hex string.
    fn hex(&self) -> String {
        self.inner.to_string()
    }

    fn __repr__(&self) -> String {
        let hex = self.inner.to_string();
        if hex.len() > 16 {
            format!("ContentHash({}...)", &hex[..16])
        } else {
            format!("ContentHash({})", hex)
        }
    }

    fn __str__(&self) -> String {
        self.inner.to_string()
    }

    fn __hash__(&self) -> u64 {
        let bytes = self.inner.as_bytes();
        u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ])
    }

    fn __eq__(&self, other: &ContentHash) -> bool {
        self.inner.as_bytes() == other.inner.as_bytes()
    }
}

// ---------------------------------------------------------------------------
// FileState
// ---------------------------------------------------------------------------

/// Filesystem state of a single file within a snapshot.
#[pyclass(frozen)]
#[derive(Clone)]
pub struct FileState {
    inner: RustFileState,
}

#[pymethods]
impl FileState {
    /// SHA-256 content hash of the file.
    #[getter]
    fn hash(&self) -> ContentHash {
        ContentHash {
            inner: self.inner.hash,
        }
    }

    /// File size in bytes.
    #[getter]
    fn size(&self) -> u64 {
        self.inner.size
    }

    /// Modification time as seconds since epoch.
    #[getter]
    fn mtime(&self) -> i64 {
        self.inner.mtime
    }

    /// Unix permission bits (masked to 0o0777).
    #[getter]
    fn permissions(&self) -> u32 {
        self.inner.permissions
    }

    fn __repr__(&self) -> String {
        format!(
            "FileState(size={}, permissions={:o})",
            self.inner.size, self.inner.permissions
        )
    }
}

// ---------------------------------------------------------------------------
// Change
// ---------------------------------------------------------------------------

/// A filesystem change detected between snapshots.
#[pyclass(frozen)]
#[derive(Clone)]
pub struct Change {
    inner: RustChange,
}

#[pymethods]
impl Change {
    /// Path of the changed file.
    #[getter]
    fn path(&self) -> String {
        self.inner.path.display().to_string()
    }

    /// Type of change: "created", "modified", "deleted", or "permissions_changed".
    #[getter]
    fn change_type(&self) -> &'static str {
        match self.inner.change_type {
            RustChangeType::Created => "created",
            RustChangeType::Modified => "modified",
            RustChangeType::Deleted => "deleted",
            RustChangeType::PermissionsChanged => "permissions_changed",
        }
    }

    /// Size difference in bytes, if applicable.
    #[getter]
    fn size_delta(&self) -> Option<i64> {
        self.inner.size_delta
    }

    fn __repr__(&self) -> String {
        format!(
            "Change(path='{}', type={})",
            self.inner.path.display(),
            self.change_type()
        )
    }
}

// ---------------------------------------------------------------------------
// SnapshotManifest
// ---------------------------------------------------------------------------

/// A snapshot manifest recording the state of all tracked files.
#[pyclass]
#[derive(Clone)]
pub struct SnapshotManifest {
    inner: RustSnapshotManifest,
}

#[pymethods]
impl SnapshotManifest {
    /// Snapshot sequence number (0 = baseline).
    #[getter]
    fn number(&self) -> u32 {
        self.inner.number
    }

    /// ISO 8601 timestamp of when the snapshot was created.
    #[getter]
    fn timestamp(&self) -> &str {
        &self.inner.timestamp
    }

    /// Parent snapshot number, or None for the baseline.
    #[getter]
    fn parent(&self) -> Option<u32> {
        self.inner.parent
    }

    /// Merkle root hash committing to the entire filesystem state.
    #[getter]
    fn merkle_root(&self) -> ContentHash {
        ContentHash {
            inner: self.inner.merkle_root,
        }
    }

    /// Dict mapping file paths to their FileState.
    #[getter]
    fn files(&self) -> PyResult<PyObject> {
        Python::with_gil(|py| {
            let dict = pyo3::types::PyDict::new(py);
            for (path, state) in &self.inner.files {
                dict.set_item(
                    path.display().to_string(),
                    FileState {
                        inner: state.clone(),
                    }
                    .into_pyobject(py)?,
                )?;
            }
            Ok(dict.into())
        })
    }

    fn __repr__(&self) -> String {
        format!(
            "SnapshotManifest(number={}, files={})",
            self.inner.number,
            self.inner.files.len()
        )
    }
}

// ---------------------------------------------------------------------------
// ExclusionConfig
// ---------------------------------------------------------------------------

/// Configuration for excluding files from snapshot tracking.
#[pyclass]
#[derive(Clone)]
pub struct ExclusionConfig {
    inner: RustExclusionConfig,
}

#[pymethods]
impl ExclusionConfig {
    #[new]
    #[pyo3(signature = (
        use_gitignore = true,
        exclude_patterns = vec![],
        exclude_globs = vec![],
        force_include = vec![],
    ))]
    fn new(
        use_gitignore: bool,
        exclude_patterns: Vec<String>,
        exclude_globs: Vec<String>,
        force_include: Vec<String>,
    ) -> Self {
        Self {
            inner: RustExclusionConfig {
                use_gitignore,
                exclude_patterns,
                exclude_globs,
                force_include,
            },
        }
    }

    #[getter]
    fn use_gitignore(&self) -> bool {
        self.inner.use_gitignore
    }

    #[getter]
    fn exclude_patterns(&self) -> Vec<String> {
        self.inner.exclude_patterns.clone()
    }

    #[getter]
    fn exclude_globs(&self) -> Vec<String> {
        self.inner.exclude_globs.clone()
    }

    #[getter]
    fn force_include(&self) -> Vec<String> {
        self.inner.force_include.clone()
    }

    fn __repr__(&self) -> String {
        format!(
            "ExclusionConfig(gitignore={}, patterns={}, globs={})",
            self.inner.use_gitignore,
            self.inner.exclude_patterns.len(),
            self.inner.exclude_globs.len()
        )
    }
}

// ---------------------------------------------------------------------------
// SessionMetadata
// ---------------------------------------------------------------------------

/// Metadata for a sandboxed session including snapshots and audit trail.
#[pyclass]
#[derive(Clone)]
pub struct SessionMetadata {
    inner: RustSessionMetadata,
}

#[pymethods]
impl SessionMetadata {
    #[new]
    #[pyo3(signature = (session_id, command, tracked_paths))]
    fn new(session_id: String, command: Vec<String>, tracked_paths: Vec<String>) -> Self {
        Self {
            inner: RustSessionMetadata {
                session_id,
                started: chrono_now_iso8601(),
                ended: None,
                command,
                executable_identity: None,
                tracked_paths: tracked_paths.into_iter().map(PathBuf::from).collect(),
                snapshot_count: 0,
                exit_code: None,
                merkle_roots: Vec::new(),
                network_events: Vec::new(),
                audit_event_count: 0,
                audit_integrity: None,
                audit_attestation: None,
            },
        }
    }

    #[getter]
    fn session_id(&self) -> &str {
        &self.inner.session_id
    }

    #[getter]
    fn started(&self) -> &str {
        &self.inner.started
    }

    #[getter]
    fn ended(&self) -> Option<&str> {
        self.inner.ended.as_deref()
    }

    #[setter]
    fn set_ended(&mut self, value: Option<String>) {
        self.inner.ended = value;
    }

    #[getter]
    fn command(&self) -> Vec<String> {
        self.inner.command.clone()
    }

    #[getter]
    fn tracked_paths(&self) -> Vec<String> {
        self.inner
            .tracked_paths
            .iter()
            .map(|p| p.display().to_string())
            .collect()
    }

    #[getter]
    fn snapshot_count(&self) -> u32 {
        self.inner.snapshot_count
    }

    #[setter]
    fn set_snapshot_count(&mut self, value: u32) {
        self.inner.snapshot_count = value;
    }

    #[getter]
    fn exit_code(&self) -> Option<i32> {
        self.inner.exit_code
    }

    #[setter]
    fn set_exit_code(&mut self, value: Option<i32>) {
        self.inner.exit_code = value;
    }

    #[getter]
    fn merkle_roots(&self) -> Vec<ContentHash> {
        self.inner
            .merkle_roots
            .iter()
            .map(|h| ContentHash { inner: *h })
            .collect()
    }

    /// Add a Merkle root to the chain.
    fn add_merkle_root(&mut self, root: &ContentHash) {
        self.inner.merkle_roots.push(root.inner);
    }

    /// Canonical executable identity hashed by the supervisor before launch.
    ///
    /// Returns `{"resolved_path": str, "sha256": str}` or `None` if the
    /// session was not launched through a supervisor that captured it.
    #[getter]
    fn executable_identity(&self) -> PyResult<Option<PyObject>> {
        let Some(id) = self.inner.executable_identity.as_ref() else {
            return Ok(None);
        };
        Python::with_gil(|py| {
            let dict = pyo3::types::PyDict::new(py);
            dict.set_item("resolved_path", id.resolved_path.display().to_string())?;
            dict.set_item("sha256", id.sha256.to_string())?;
            Ok(Some(dict.into()))
        })
    }

    /// Number of audit events captured for this session.
    #[getter]
    fn audit_event_count(&self) -> u64 {
        self.inner.audit_event_count
    }

    /// Optional integrity summary for the append-only audit log.
    ///
    /// Returns `{"hash_algorithm": str, "event_count": int,
    /// "chain_head": str, "merkle_root": str}` or `None` if integrity
    /// recording was disabled for this session.
    #[getter]
    fn audit_integrity(&self) -> PyResult<Option<PyObject>> {
        let Some(s) = self.inner.audit_integrity.as_ref() else {
            return Ok(None);
        };
        Python::with_gil(|py| {
            let dict = pyo3::types::PyDict::new(py);
            dict.set_item("hash_algorithm", &s.hash_algorithm)?;
            dict.set_item("event_count", s.event_count)?;
            dict.set_item("chain_head", s.chain_head.to_string())?;
            dict.set_item("merkle_root", s.merkle_root.to_string())?;
            Ok(Some(dict.into()))
        })
    }

    /// Optional keyed signature over the audit Merkle root and session context.
    ///
    /// Returns `{"predicate_type": str, "key_id": str, "public_key": str,
    /// "bundle_filename": str}` or `None` if the session was not signed.
    #[getter]
    fn audit_attestation(&self) -> PyResult<Option<PyObject>> {
        let Some(s) = self.inner.audit_attestation.as_ref() else {
            return Ok(None);
        };
        Python::with_gil(|py| {
            let dict = pyo3::types::PyDict::new(py);
            dict.set_item("predicate_type", &s.predicate_type)?;
            dict.set_item("key_id", &s.key_id)?;
            dict.set_item("public_key", &s.public_key)?;
            dict.set_item("bundle_filename", &s.bundle_filename)?;
            Ok(Some(dict.into()))
        })
    }

    /// Network audit events recorded during the session.
    ///
    /// Returns a list of dicts with the same schema as
    /// `ProxyHandle.drain_audit_events()`.
    #[getter]
    fn network_events(&self) -> PyResult<PyObject> {
        Python::with_gil(|py| {
            let list = pyo3::types::PyList::empty(py);
            for event in &self.inner.network_events {
                let dict = crate::proxy::audit_event_to_py_dict(py, event)?;
                list.append(dict)?;
            }
            Ok(list.into())
        })
    }

    /// Set network events from a list of dicts (as returned by
    /// `ProxyHandle.drain_audit_events()`).
    fn set_network_events(&mut self, events: Vec<PyObject>) -> PyResult<()> {
        Python::with_gil(|py| {
            let mut rust_events = Vec::with_capacity(events.len());
            for obj in &events {
                let dict = obj.downcast_bound::<pyo3::types::PyDict>(py)?;
                rust_events.push(nono::undo::NetworkAuditEvent {
                    timestamp_unix_ms: dict
                        .get_item("timestamp_unix_ms")?
                        .ok_or_else(|| PyValueError::new_err("missing timestamp_unix_ms"))?
                        .extract()?,
                    mode: match dict
                        .get_item("mode")?
                        .ok_or_else(|| PyValueError::new_err("missing mode"))?
                        .extract::<String>()?
                        .as_str()
                    {
                        "connect" => NetworkAuditMode::Connect,
                        "connect_intercept" => NetworkAuditMode::ConnectIntercept,
                        "reverse" => NetworkAuditMode::Reverse,
                        "external" => NetworkAuditMode::External,
                        other => {
                            return Err(PyValueError::new_err(format!("invalid mode: {}", other)))
                        }
                    },
                    decision: match dict
                        .get_item("decision")?
                        .ok_or_else(|| PyValueError::new_err("missing decision"))?
                        .extract::<String>()?
                        .as_str()
                    {
                        "allow" => NetworkAuditDecision::Allow,
                        "deny" => NetworkAuditDecision::Deny,
                        other => {
                            return Err(PyValueError::new_err(format!(
                                "invalid decision: {}",
                                other
                            )))
                        }
                    },
                    target: dict
                        .get_item("target")?
                        .ok_or_else(|| PyValueError::new_err("missing target"))?
                        .extract()?,
                    port: dict.get_item("port")?.and_then(|v| v.extract().ok()),
                    method: dict.get_item("method")?.and_then(|v| v.extract().ok()),
                    path: dict.get_item("path")?.and_then(|v| v.extract().ok()),
                    status: dict.get_item("status")?.and_then(|v| v.extract().ok()),
                    reason: dict.get_item("reason")?.and_then(|v| v.extract().ok()),
                    route_id: dict.get_item("route_id")?.and_then(|v| v.extract().ok()),
                    auth_mechanism: dict
                        .get_item("auth_mechanism")?
                        .and_then(|v| v.extract::<String>().ok())
                        .map(|s| match s.as_str() {
                            "proxy_authorization" => {
                                nono::undo::NetworkAuditAuthMechanism::ProxyAuthorization
                            }
                            "phantom_header" => {
                                nono::undo::NetworkAuditAuthMechanism::PhantomHeader
                            }
                            "phantom_path" => nono::undo::NetworkAuditAuthMechanism::PhantomPath,
                            "phantom_query" => nono::undo::NetworkAuditAuthMechanism::PhantomQuery,
                            _ => nono::undo::NetworkAuditAuthMechanism::ProxyAuthorization,
                        }),
                    auth_outcome: dict
                        .get_item("auth_outcome")?
                        .and_then(|v| v.extract::<String>().ok())
                        .map(|s| match s.as_str() {
                            "succeeded" => nono::undo::NetworkAuditAuthOutcome::Succeeded,
                            "failed" => nono::undo::NetworkAuditAuthOutcome::Failed,
                            _ => nono::undo::NetworkAuditAuthOutcome::Failed,
                        }),
                    managed_credential_active: dict
                        .get_item("managed_credential_active")?
                        .and_then(|v| v.extract().ok()),
                    injection_mode: dict
                        .get_item("injection_mode")?
                        .and_then(|v| v.extract::<String>().ok())
                        .map(|s| match s.as_str() {
                            "header" => nono::undo::NetworkAuditInjectionMode::Header,
                            "url_path" => nono::undo::NetworkAuditInjectionMode::UrlPath,
                            "query_param" => nono::undo::NetworkAuditInjectionMode::QueryParam,
                            "basic_auth" => nono::undo::NetworkAuditInjectionMode::BasicAuth,
                            "oauth2" => nono::undo::NetworkAuditInjectionMode::OAuth2,
                            _ => nono::undo::NetworkAuditInjectionMode::Header,
                        }),
                    denial_category: dict
                        .get_item("denial_category")?
                        .and_then(|v| v.extract::<String>().ok())
                        .map(|s| match s.as_str() {
                            "authentication_failed" => {
                                nono::undo::NetworkAuditDenialCategory::AuthenticationFailed
                            }
                            "endpoint_policy" => {
                                nono::undo::NetworkAuditDenialCategory::EndpointPolicy
                            }
                            "managed_credential_unavailable" => {
                                nono::undo::NetworkAuditDenialCategory::ManagedCredentialUnavailable
                            }
                            "host_denied" => nono::undo::NetworkAuditDenialCategory::HostDenied,
                            "intercept_handshake_failed" => {
                                nono::undo::NetworkAuditDenialCategory::InterceptHandshakeFailed
                            }
                            "upstream_connect_failed" => {
                                nono::undo::NetworkAuditDenialCategory::UpstreamConnectFailed
                            }
                            "connect_bypasses_l7" => {
                                nono::undo::NetworkAuditDenialCategory::ConnectBypassesL7
                            }
                            "external_proxy_rejected" => {
                                nono::undo::NetworkAuditDenialCategory::ExternalProxyRejected
                            }
                            _ => nono::undo::NetworkAuditDenialCategory::HostDenied,
                        }),
                });
            }
            self.inner.network_events = rust_events;
            Ok(())
        })
    }

    /// Serialize to JSON string.
    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string_pretty(&self.inner)
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to serialize: {}", e)))
    }

    /// Deserialize from JSON string.
    #[staticmethod]
    fn from_json(json: &str) -> PyResult<Self> {
        let inner: RustSessionMetadata = serde_json::from_str(json)
            .map_err(|e| PyValueError::new_err(format!("Invalid JSON: {}", e)))?;
        Ok(Self { inner })
    }

    fn __repr__(&self) -> String {
        format!(
            "SessionMetadata(id='{}', snapshots={})",
            self.inner.session_id, self.inner.snapshot_count
        )
    }
}

/// Scan the session directory for existing snapshot manifests and load the latest.
///
/// SnapshotManager::new() initializes snapshot_count to 0 and latest_manifest
/// is a Python-side field. When re-creating the wrapper for an existing session,
/// we need to recover the latest manifest from disk so create_incremental() works.
fn find_latest_manifest_on_disk(
    mgr: &RustSnapshotManager,
    session_dir: &std::path::Path,
) -> PyResult<Option<RustSnapshotManifest>> {
    let snapshots_dir = session_dir.join("snapshots");
    if !snapshots_dir.exists() {
        return Ok(None);
    }

    // Find the highest-numbered snapshot manifest on disk
    let mut max_number: Option<u32> = None;
    if let Ok(entries) = std::fs::read_dir(&snapshots_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if let Some(stem) = name_str.strip_suffix(".json") {
                if let Ok(num) = stem.parse::<u32>() {
                    max_number = Some(max_number.map_or(num, |m: u32| m.max(num)));
                }
            }
        }
    }

    match max_number {
        Some(n) => {
            let manifest = mgr.load_manifest(n).map_err(to_py_err)?;
            Ok(Some(manifest))
        }
        None => Ok(None),
    }
}

/// Build per-root exclusion filters for each tracked path.
///
/// Each tracked root gets its own `ExclusionFilter` constructed with that
/// root as context, so `.gitignore` rules are interpreted relative to their
/// own root directory.
fn build_per_root_filters(
    config: RustExclusionConfig,
    tracked: &[PathBuf],
) -> PyResult<Vec<(PathBuf, ExclusionFilter)>> {
    tracked
        .iter()
        .map(|root| {
            let filter = ExclusionFilter::new(config.clone(), root).map_err(to_py_err)?;
            Ok((root.clone(), filter))
        })
        .collect()
}

/// Generate an ISO 8601 timestamp without pulling in the chrono crate.
fn chrono_now_iso8601() -> String {
    use std::time::SystemTime;
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    // Format as YYYY-MM-DDTHH:MM:SSZ using basic arithmetic
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Days since epoch to Y-M-D (simplified, handles leap years)
    let mut y = 1970i64;
    let mut remaining = days as i64;
    loop {
        let days_in_year = if is_leap_year(y) { 366 } else { 365 };
        if remaining < days_in_year {
            break;
        }
        remaining -= days_in_year;
        y += 1;
    }
    let month_days: [i64; 12] = if is_leap_year(y) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let mut m = 0usize;
    for (i, &d) in month_days.iter().enumerate() {
        if remaining < d {
            m = i;
            break;
        }
        remaining -= d;
    }
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y,
        m + 1,
        remaining + 1,
        hours,
        minutes,
        seconds
    )
}

fn is_leap_year(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

// ---------------------------------------------------------------------------
// SnapshotManager
// ---------------------------------------------------------------------------

/// Manages content-addressable filesystem snapshots for a session.
///
/// Creates baseline and incremental snapshots, computes diffs, and
/// restores filesystem state to any previous snapshot.
#[pyclass]
pub struct SnapshotManager {
    inner: RustSnapshotManager,
    latest_manifest: Option<RustSnapshotManifest>,
    /// Snapshot count recovered from disk when resuming an existing session.
    /// The upstream `inner.snapshot_count()` starts at 0 on construction,
    /// so we track the true count here and keep it in sync.
    resumed_count: u32,
}

#[pymethods]
impl SnapshotManager {
    /// Create a new snapshot manager.
    ///
    /// Args:
    ///     session_dir: Directory for storing session data (snapshots, objects)
    ///     tracked_paths: Directories to track for changes
    ///     exclusion: Exclusion configuration for filtering files
    ///     max_entries: Maximum number of files to track (default: 300000)
    ///     max_bytes: Maximum total bytes to track (default: 2 GiB)
    #[new]
    #[pyo3(signature = (session_dir, tracked_paths, exclusion = None, max_entries = 300_000, max_bytes = 2_147_483_648))]
    fn new(
        session_dir: String,
        tracked_paths: Vec<String>,
        exclusion: Option<&ExclusionConfig>,
        max_entries: usize,
        max_bytes: u64,
    ) -> PyResult<Self> {
        let session_path = PathBuf::from(&session_dir);
        let tracked: Vec<PathBuf> = tracked_paths.iter().map(PathBuf::from).collect();

        let config = exclusion.map(|e| e.inner.clone()).unwrap_or_default();

        // Build per-root exclusion filters so each tracked path's .gitignore
        // is interpreted relative to its own root directory.
        let roots = build_per_root_filters(config, &tracked)?;

        let budget = WalkBudget {
            max_entries,
            max_bytes,
        };

        let session_path_ref = session_path.clone();
        let inner =
            RustSnapshotManager::new_per_root(session_path, roots, budget).map_err(to_py_err)?;

        // If snapshots already exist on disk, load the latest manifest
        // so that create_incremental() works after re-creating the wrapper.
        let latest_manifest = find_latest_manifest_on_disk(&inner, &session_path_ref)?;

        // Derive the true snapshot count from the manifest on disk.
        // inner.snapshot_count() always starts at 0 on fresh construction.
        let resumed_count = latest_manifest
            .as_ref()
            .map(|m| m.number.saturating_add(1))
            .unwrap_or(0);

        Ok(Self {
            inner,
            latest_manifest,
            resumed_count,
        })
    }

    /// Create a baseline snapshot of the current filesystem state.
    ///
    /// Must be called before any incremental snapshots. Captures the
    /// initial state of all tracked files.
    ///
    /// Returns:
    ///     SnapshotManifest for the baseline
    fn create_baseline(&mut self) -> PyResult<SnapshotManifest> {
        let manifest = self.inner.create_baseline().map_err(to_py_err)?;
        self.latest_manifest = Some(manifest.clone());
        Ok(SnapshotManifest { inner: manifest })
    }

    /// Create an incremental snapshot capturing changes since the last snapshot.
    ///
    /// Returns:
    ///     Tuple of (SnapshotManifest, list[Change])
    fn create_incremental(&mut self) -> PyResult<(SnapshotManifest, Vec<Change>)> {
        let previous = self.latest_manifest.as_ref().ok_or_else(|| {
            PyRuntimeError::new_err("No previous snapshot. Call create_baseline() first.")
        })?;

        let (manifest, changes) = self.inner.create_incremental(previous).map_err(to_py_err)?;
        self.latest_manifest = Some(manifest.clone());

        let py_changes = changes.into_iter().map(|c| Change { inner: c }).collect();

        Ok((SnapshotManifest { inner: manifest }, py_changes))
    }

    /// Compute what changes would be needed to restore to a given snapshot.
    ///
    /// This is a dry-run that does not modify the filesystem.
    ///
    /// Args:
    ///     snapshot_number: Snapshot number to diff against
    ///
    /// Returns:
    ///     List of changes that restore_to would apply
    fn compute_restore_diff(&self, snapshot_number: u32) -> PyResult<Vec<Change>> {
        let manifest = self
            .inner
            .load_manifest(snapshot_number)
            .map_err(to_py_err)?;
        let changes = self
            .inner
            .compute_restore_diff(&manifest)
            .map_err(to_py_err)?;
        Ok(changes.into_iter().map(|c| Change { inner: c }).collect())
    }

    /// Restore the filesystem to the state captured in a snapshot.
    ///
    /// Args:
    ///     snapshot_number: Snapshot number to restore to (0 = baseline)
    ///
    /// Returns:
    ///     List of changes that were applied
    fn restore_to(&self, snapshot_number: u32) -> PyResult<Vec<Change>> {
        let manifest = self
            .inner
            .load_manifest(snapshot_number)
            .map_err(to_py_err)?;
        let changes = self.inner.restore_to(&manifest).map_err(to_py_err)?;
        Ok(changes.into_iter().map(|c| Change { inner: c }).collect())
    }

    /// Load a snapshot manifest by number.
    fn load_manifest(&self, number: u32) -> PyResult<SnapshotManifest> {
        let manifest = self.inner.load_manifest(number).map_err(to_py_err)?;
        Ok(SnapshotManifest { inner: manifest })
    }

    /// Save session metadata to the session directory.
    fn save_session_metadata(&self, meta: &SessionMetadata) -> PyResult<()> {
        self.inner
            .save_session_metadata(&meta.inner)
            .map_err(to_py_err)
    }

    /// Number of snapshots taken in this session.
    ///
    /// Returns the correct count even when resuming an existing session
    /// where the upstream `inner.snapshot_count()` starts at 0.
    fn snapshot_count(&self) -> u32 {
        let inner_count = self.inner.snapshot_count();
        // After create_baseline/create_incremental, inner catches up.
        // Before that, use the resumed count from disk.
        inner_count.max(self.resumed_count)
    }

    /// Load session metadata from a session directory.
    #[staticmethod]
    fn load_session_metadata(session_dir: &str) -> PyResult<SessionMetadata> {
        let meta = RustSnapshotManager::load_session_metadata(PathBuf::from(session_dir).as_path())
            .map_err(to_py_err)?;
        Ok(SessionMetadata { inner: meta })
    }

    fn __repr__(&self) -> String {
        format!("SnapshotManager(snapshots={})", self.inner.snapshot_count())
    }
}
