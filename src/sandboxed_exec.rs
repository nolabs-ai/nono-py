//! Sandboxed command execution via fork + sandbox + exec.
//!
//! Provides `sandboxed_exec()` which forks the current process, applies
//! OS-level sandbox restrictions in the child, then exec's a command.
//! The parent captures stdout/stderr and waits for exit. The calling
//! process remains unsandboxed and can call this repeatedly.

use crate::CapabilitySet;
use nono::Sandbox;
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use std::collections::BTreeMap;
#[cfg(target_os = "linux")]
use std::collections::BTreeSet;
use std::ffi::CString;
use std::io::{Read, Result as IoResult};
#[cfg(target_os = "linux")]
use std::os::fd::OwnedFd;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::sync::Mutex;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

/// Which OS enforcement mechanism `sandboxed_exec` applies in the child.
///
/// Mirrors the module-level `apply_landlock` / `apply_seccomp` selectors for the
/// in-process path, letting callers pin subprocess enforcement instead of relying
/// on auto-detection.
#[derive(Clone, Copy, PartialEq, Eq)]
enum EnforcementMode {
    /// Auto-detect the best mechanism (Landlock, falling back to seccomp).
    Auto,
    /// Landlock only. Errors if network restrictions need the seccomp fallback.
    Landlock,
    /// Landlock filesystem/process sandboxing plus the seccomp TCP fallback.
    Seccomp,
}

fn parse_enforcement_mode(mode: &str) -> PyResult<EnforcementMode> {
    match mode {
        "auto" => Ok(EnforcementMode::Auto),
        "landlock" => Ok(EnforcementMode::Landlock),
        "seccomp" => Ok(EnforcementMode::Seccomp),
        other => Err(PyValueError::new_err(format!(
            "enforcement_mode must be 'auto', 'landlock', or 'seccomp', got '{}'",
            other
        ))),
    }
}

/// The user/group identity the child should end up with. `None` = leave untouched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ResolvedIds {
    uid: Option<u32>,
    gid: Option<u32>,
}

/// Work out (and sanity-check) the uid/gid the child should drop to. This is
/// pure policy — no syscalls, no fork, no privilege — so it can be unit-tested
/// on its own. The rules:
///
///   * A uid/gid of 0 is root: "dropping" to it does nothing and would leave the
///     child fully privileged, so we reject it as almost certainly a mistake.
///   * If the caller sets a uid but no gid, the gid defaults to the uid. Without
///     this the child would keep the parent's group (group 0 when the parent is
///     root), quietly handing back access the uid drop is meant to remove.
///   * An explicit gid always wins, and if no uid is given the gid is left as-is.
///
/// The zero-checks run before the defaulting so `resolve_ids(Some(0), None)` is
/// rejected rather than turned into `gid = 0`.
fn resolve_ids(uid: Option<u32>, gid: Option<u32>) -> Result<ResolvedIds, String> {
    if uid == Some(0) {
        return Err("uid must be non-zero (0 is root; dropping to it is a no-op)".to_string());
    }
    if gid == Some(0) {
        return Err(
            "gid must be non-zero (0 is the root group; dropping to it is a no-op)".to_string(),
        );
    }
    let gid = if uid.is_some() { gid.or(uid) } else { gid };
    Ok(ResolvedIds { uid, gid })
}

/// Clamp a u64 resource-limit value into the platform's `rlim_t`.
fn clamp_rlim(value: u64) -> libc::rlim_t {
    #[cfg(target_pointer_width = "64")]
    {
        value
    }
    #[cfg(not(target_pointer_width = "64"))]
    {
        value.min(libc::rlim_t::MAX as u64) as libc::rlim_t
    }
}

/// `setrlimit`'s resource argument type differs across libc implementations:
/// `c_uint` on glibc, `c_int` on musl and macOS. This alias lets `set_rlimit`
/// take the `libc::RLIMIT_*` constants directly, with no cast at the call sites.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
type RlimitResource = libc::c_uint;
#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
type RlimitResource = libc::c_int;

/// Apply a single `setrlimit` cap (soft == hard) before exec.
fn set_rlimit(resource: RlimitResource, value: u64) -> IoResult<()> {
    let rlim = clamp_rlim(value);
    let limit = libc::rlimit {
        rlim_cur: rlim,
        rlim_max: rlim,
    };
    // SAFETY: setrlimit reads the provided rlimit and changes only this
    // process's resource limits before exec.
    let ret = unsafe { libc::setrlimit(resource, &limit) };
    if ret == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Write a diagnostic to stderr and exit the child with code 126. Never returns.
///
/// Used only after fork, where returning a `PyErr` to the parent is impossible.
fn child_die(detail: &str) -> ! {
    let msg = detail.as_bytes();
    // SAFETY: write() to STDERR and _exit() are valid in the forked child.
    unsafe {
        libc::write(
            libc::STDERR_FILENO,
            msg.as_ptr().cast::<libc::c_void>(),
            msg.len(),
        );
        libc::_exit(126);
    }
}

/// Result of a sandboxed command execution.
///
/// Attributes:
///     stdout: Raw bytes from the child's stdout
///     stderr: Raw bytes from the child's stderr
///     exit_code: Process exit code (0 = success, -N = killed by signal N)
#[pyclass(frozen)]
pub struct ExecResult {
    #[pyo3(get)]
    pub stdout: Vec<u8>,
    #[pyo3(get)]
    pub stderr: Vec<u8>,
    #[pyo3(get)]
    pub exit_code: i32,
    session_report: nono::SessionDiagnosticReport,
}

#[pymethods]
impl ExecResult {
    fn __repr__(&self) -> String {
        format!(
            "ExecResult(exit_code={}, stdout_len={}, stderr_len={})",
            self.exit_code,
            self.stdout.len(),
            self.stderr.len()
        )
    }

    /// Structured session diagnostic report for this execution.
    ///
    /// Parses stderr for sandbox-related path/network hints and attaches
    /// structured remediations based on the capability set used for the run.
    fn session_diagnostics(&self) -> PyResult<Py<PyAny>> {
        Python::attach(|py| crate::diagnostic::session_report_to_py(py, &self.session_report))
    }

    /// JSON session diagnostic report (see ``session_diagnostics()``).
    fn session_diagnostics_json(&self) -> PyResult<String> {
        self.session_report
            .to_json()
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))
    }
}

/// Pre-fork data prepared in the parent (where allocation is safe).
struct ForkContext {
    caps: nono::CapabilitySet,
    program_c: CString,
    argv_c: Vec<CString>,
    env_c: Vec<CString>,
    cwd_c: Option<CString>,
    cwd: Option<PathBuf>,
    timeout_secs: Option<f64>,
    max_processes: Option<u64>,
    max_cpu_seconds: Option<u64>,
    max_file_size_bytes: Option<u64>,
    max_open_files: Option<u64>,
    uid: Option<u32>,
    gid: Option<u32>,
    #[cfg(target_os = "linux")]
    enforcement_mode: EnforcementMode,
    #[cfg(target_os = "linux")]
    proxy_handoff: ProxyHandoff,
    #[cfg(target_os = "linux")]
    prepared_landlock: Option<nono::sandbox::PreparedLandlockSandbox>,
    #[cfg(target_os = "linux")]
    prepared_proxy_filter: Option<nono::sandbox::PreparedSeccompNotifyFilter>,
    #[cfg(all(target_os = "linux", debug_assertions))]
    clone_files_test_fault: CloneFilesTestFault,
}

/// Pipe file descriptors for stdout or stderr.
struct PipeFds {
    read_fd: i32,
    write_fd: i32,
}

#[cfg(target_os = "linux")]
#[derive(Clone)]
struct ProxyOnlyPolicy {
    proxy_port: u16,
    bind_ports: Vec<u16>,
}

#[cfg(target_os = "linux")]
struct ProxySupervisor {
    sock: Option<nono::SupervisorSocket>,
    notify_fd: Option<ProxyNotifyFd>,
    policy: ProxyOnlyPolicy,
    child_pid: i32,
}

/// A supervisor listener whose slot cannot disappear during another shared
/// fd-table bootstrap. This keeps the before/after listener snapshot immune to
/// descriptor-number reuse as older sandboxed targets finish concurrently.
#[cfg(target_os = "linux")]
struct ProxyNotifyFd {
    fd: Option<OwnedFd>,
}

#[cfg(target_os = "linux")]
impl ProxyNotifyFd {
    fn new(fd: OwnedFd) -> Self {
        Self { fd: Some(fd) }
    }
}

#[cfg(target_os = "linux")]
impl AsRawFd for ProxyNotifyFd {
    fn as_raw_fd(&self) -> i32 {
        match self.fd.as_ref() {
            Some(fd) => fd.as_raw_fd(),
            None => -1,
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for ProxyNotifyFd {
    fn drop(&mut self) {
        let guard = SHARED_BOOTSTRAP_MUTEX
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        drop(self.fd.take());
        drop(guard);
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProxyHandoff {
    CloneFiles,
    Pidfd,
}

#[cfg(all(target_os = "linux", debug_assertions))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CloneFilesTestFault {
    None,
    BeforeListener,
    AfterListener,
    AfterFdReport,
    AfterUnshare,
    AfterDetached,
    AfterAck,
}

#[cfg(target_os = "linux")]
static SHARED_BOOTSTRAP_MUTEX: Mutex<()> = Mutex::new(());

#[cfg(target_os = "linux")]
const CLOSE_RANGE_UNSHARE: u32 = 1 << 1;
#[cfg(target_os = "linux")]
const HANDSHAKE_DETACHED: u8 = 0xd7;
#[cfg(target_os = "linux")]
const HANDSHAKE_ACK: u8 = 0xa7;

/// Execute a command in a sandboxed child process.
///
/// Forks the current process, applies capability-based sandbox restrictions
/// (Landlock on Linux, Seatbelt on macOS) in the child, then exec's the
/// command. The parent captures stdout/stderr via pipes and waits for exit.
///
/// The calling process remains unsandboxed and can call this repeatedly
/// with different capabilities.
///
/// Args:
///     caps: Capability set defining the child's permitted operations
///     command: List of command + arguments (e.g., ["bash", "-c", "ls /"])
///     cwd: Working directory for the child (defaults to current directory)
///     timeout_secs: Maximum execution time in seconds (None = no limit)
///     env: Optional list of (key, value) tuples for environment variables.
///         These variables become the child's environment. The parent
///         environment is not inherited unless inherit_env=True.
///     inherit_env: If True, start from the parent environment and apply env
///         as overrides. Dangerous dynamic loader variables are rejected.
///     max_processes: Optional RLIMIT_NPROC value for the child. This is
///         enforced by the OS per real UID, not per sandbox process tree, and
///         is useful only when sandboxed executions run as a dedicated Unix
///         user. It is a best-effort cap that a child can escape (e.g. via
///         setsid). For a hard, unescapable per-tree process cap use
///         `nono_py.limited.run(max_processes=...)` (cgroup v2 pids.max); prefer
///         that where cgroup v2 delegation is available, and use max_processes
///         for the in-process path or as a fallback when it is not.
///     max_cpu_seconds: Optional RLIMIT_CPU value (seconds of CPU time). The
///         soft and hard limits are set equal, so reaching the cap terminates
///         the child with SIGKILL (SIGXCPU is not reliably deliverable).
///     max_file_size_bytes: Optional RLIMIT_FSIZE value (max bytes the child
///         may write to any single file). A write past the limit fails with
///         EFBIG and raises SIGXFSZ, which terminates the child if unhandled.
///     max_open_files: Optional RLIMIT_NOFILE value (max open file descriptors).
///     uid: Optional real+effective UID to drop the child to before exec.
///         Requires the calling process to be privileged (root or CAP_SETUID).
///         A distinct UID makes the kernel reject the child's kill() against the
///         same-UID parent with EPERM. Must be non-zero.
///     gid: Optional real+effective GID to drop the child to before exec. Applied
///         before uid, and supplementary groups are cleared. Requires privilege.
///         If uid is set and gid is omitted, gid defaults to uid so the child
///         does not retain the parent's (possibly privileged) group. Must be
///         non-zero.
///     enforcement_mode: Linux network enforcement rollout mode. "auto"
///         (default) preserves the compatibility-oriented Landlock-first
///         behavior for this release; "seccomp" layers a static seccomp
///         baseline under Landlock to deny UDP, raw/non-IP sockets, and
///         io_uring; "landlock" requests Landlock only. "landlock"/"seccomp"
///         are Linux-only.
///
/// Returns:
///     ExecResult with stdout, stderr, and exit_code
///
/// Raises:
///     RuntimeError: If fork fails, sandbox cannot be applied, or the
///         command cannot be executed
///     ValueError: If the command list is empty, timeout is negative,
///         max_processes/max_cpu_seconds/max_open_files is zero, uid/gid is
///         set on an unsupported platform, or enforcement_mode is invalid
#[pyfunction]
#[pyo3(signature = (caps, command, cwd=None, timeout_secs=None, env=None, inherit_env=false, max_processes=None, max_cpu_seconds=None, max_file_size_bytes=None, max_open_files=None, uid=None, gid=None, enforcement_mode="auto"))]
#[allow(clippy::too_many_arguments)]
pub fn sandboxed_exec(
    py: Python<'_>,
    caps: &CapabilitySet,
    command: Vec<String>,
    cwd: Option<String>,
    timeout_secs: Option<f64>,
    env: Option<Vec<(String, String)>>,
    inherit_env: bool,
    max_processes: Option<u64>,
    max_cpu_seconds: Option<u64>,
    max_file_size_bytes: Option<u64>,
    max_open_files: Option<u64>,
    uid: Option<u32>,
    gid: Option<u32>,
    enforcement_mode: &str,
) -> PyResult<ExecResult> {
    if command.is_empty() {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "command must not be empty",
        ));
    }

    // Validate timeout before passing to Duration::from_secs_f64,
    // which panics on negative or NaN values.
    if let Some(t) = timeout_secs
        && (t < 0.0 || t.is_nan())
    {
        return Err(pyo3::exceptions::PyValueError::new_err(format!(
            "timeout_secs must be non-negative, got {}",
            t
        )));
    }

    if let Some(limit) = max_processes
        && limit == 0
    {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "max_processes must be positive",
        ));
    }

    // A zero CPU-time or open-file cap kills the child before it can do useful
    // work, which is almost certainly a mistake. A zero file-size cap is a valid
    // "no writes" policy, so it is allowed.
    if max_cpu_seconds == Some(0) {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "max_cpu_seconds must be positive",
        ));
    }
    if max_open_files == Some(0) {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "max_open_files must be positive",
        ));
    }

    // Validate and resolve the drop identity (pure policy; see resolve_ids).
    let ResolvedIds { uid, gid } =
        resolve_ids(uid, gid).map_err(pyo3::exceptions::PyValueError::new_err)?;

    let enforcement_mode = parse_enforcement_mode(enforcement_mode)?;

    #[cfg(not(target_os = "linux"))]
    if enforcement_mode != EnforcementMode::Auto {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "enforcement_mode 'landlock' and 'seccomp' are only available on Linux",
        ));
    }

    #[cfg(not(target_os = "linux"))]
    if uid.is_some() || gid.is_some() {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "uid/gid dropping is only available on Unix platforms other than macOS",
        ));
    }

    // Proxy-only enforcement needs the seccomp fallback supervisor, which only
    // the auto and seccomp paths install. Landlock-only cannot service it.
    #[cfg(target_os = "linux")]
    if enforcement_mode == EnforcementMode::Landlock
        && matches!(
            caps.inner.network_mode(),
            nono::NetworkMode::ProxyOnly { .. }
        )
    {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "enforcement_mode='landlock' cannot enforce proxy_only network mode; \
             use 'auto' or 'seccomp'",
        ));
    }

    // Prepare all data before fork (allocation-safe zone)
    let mut ctx = prepare_fork_context(
        &caps.inner,
        &command,
        cwd,
        timeout_secs,
        env,
        inherit_env,
        max_processes,
        max_cpu_seconds,
        max_file_size_bytes,
        max_open_files,
        uid,
        gid,
        enforcement_mode,
    )?;

    #[cfg(target_os = "linux")]
    prepare_linux_proxy_bootstrap(&mut ctx)?;

    // Keep the ordinary fork path's Landlock ABI cache warm. Proxy-only
    // preparation already performs this probe, so this is a cheap cache read
    // there and preserves the pre-existing child-allocation mitigation for all
    // other Linux launches.
    #[cfg(target_os = "linux")]
    let _ = Sandbox::detect_abi();

    // The regular and legacy pidfd paths still use libc fork and therefore
    // retain the conservative thread-count guard.  The CLONE_FILES path is
    // specifically allocation-free and lock-free in the child, so it supports
    // multithreaded embedders and the fd-churn stress case from its design.
    #[cfg(target_os = "linux")]
    if ctx.prepared_proxy_filter.is_none() {
        let thread_count = get_thread_count()
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to check thread count: {}", e)))?;
        if thread_count > 32 {
            return Err(PyRuntimeError::new_err(format!(
                "Too many threads ({}) for safe fork. \
                 Reduce thread count before calling sandboxed_exec.",
                thread_count
            )));
        }
    }

    #[cfg(target_os = "linux")]
    let proxy_supervisor_pair = create_proxy_supervisor_pair(&ctx)?;

    // Create pipes for stdout and stderr
    let stdout_pipe = create_pipe()?;
    let stderr_pipe = match create_pipe() {
        Ok(pipe) => pipe,
        Err(error) => {
            unsafe {
                libc::close(stdout_pipe.read_fd);
                libc::close(stdout_pipe.write_fd);
            }
            return Err(error);
        }
    };

    // Release the GIL during fork+wait so other Python threads can proceed
    py.detach(|| {
        #[cfg(target_os = "linux")]
        {
            do_fork_sandbox_exec(&mut ctx, &stdout_pipe, &stderr_pipe, proxy_supervisor_pair)
        }
        #[cfg(not(target_os = "linux"))]
        {
            do_fork_sandbox_exec(&mut ctx, &stdout_pipe, &stderr_pipe)
        }
    })
}

/// Prepare all data needed for fork+exec while allocation is safe.
#[allow(clippy::too_many_arguments)]
fn prepare_fork_context(
    caps: &nono::CapabilitySet,
    command: &[String],
    cwd: Option<String>,
    timeout_secs: Option<f64>,
    env: Option<Vec<(String, String)>>,
    inherit_env: bool,
    max_processes: Option<u64>,
    max_cpu_seconds: Option<u64>,
    max_file_size_bytes: Option<u64>,
    max_open_files: Option<u64>,
    uid: Option<u32>,
    gid: Option<u32>,
    #[cfg_attr(not(target_os = "linux"), allow(unused_variables))]
    enforcement_mode: EnforcementMode,
) -> PyResult<ForkContext> {
    let resolved_program = resolve_program(&command[0])?;
    let program_c = CString::new(resolved_program.as_os_str().as_bytes())
        .map_err(|_| PyRuntimeError::new_err("Program path contains null byte"))?;

    let mut argv_c: Vec<CString> = Vec::with_capacity(command.len());
    for arg in command {
        argv_c.push(
            CString::new(arg.as_bytes())
                .map_err(|_| PyRuntimeError::new_err("Argument contains null byte"))?,
        );
    }

    let env_c = build_env_cstrings(env.as_deref(), inherit_env)?;

    let cwd = match &cwd {
        Some(d) => {
            let canonical = std::fs::canonicalize(d).map_err(|e| {
                PyRuntimeError::new_err(format!("Cannot resolve working directory '{}': {}", d, e))
            })?;
            Some(canonical)
        }
        None => std::env::current_dir().ok(),
    };

    let cwd_c = cwd
        .as_ref()
        .map(|path| {
            CString::new(path.as_os_str().as_bytes())
                .map_err(|_| PyRuntimeError::new_err("Working directory contains null byte"))
        })
        .transpose()?;

    Ok(ForkContext {
        caps: caps.clone(),
        program_c,
        argv_c,
        env_c,
        cwd_c,
        cwd,
        timeout_secs,
        max_processes,
        max_cpu_seconds,
        max_file_size_bytes,
        max_open_files,
        uid,
        gid,
        #[cfg(target_os = "linux")]
        enforcement_mode,
        #[cfg(target_os = "linux")]
        proxy_handoff: ProxyHandoff::CloneFiles,
        #[cfg(target_os = "linux")]
        prepared_landlock: None,
        #[cfg(target_os = "linux")]
        prepared_proxy_filter: None,
        #[cfg(all(target_os = "linux", debug_assertions))]
        clone_files_test_fault: CloneFilesTestFault::None,
    })
}

#[cfg(target_os = "linux")]
fn prepare_linux_proxy_bootstrap(ctx: &mut ForkContext) -> PyResult<()> {
    ctx.proxy_handoff = match std::env::var("NONO_PY_PROXY_HANDOFF") {
        Ok(value) if value == "pidfd" => ProxyHandoff::Pidfd,
        Ok(value) if value == "clone_files" => ProxyHandoff::CloneFiles,
        Ok(value) => {
            return Err(PyValueError::new_err(format!(
                "NONO_PY_PROXY_HANDOFF must be 'clone_files' or 'pidfd', got '{}'",
                value
            )));
        }
        Err(std::env::VarError::NotPresent) => ProxyHandoff::CloneFiles,
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err(PyValueError::new_err(
                "NONO_PY_PROXY_HANDOFF is not valid UTF-8",
            ));
        }
    };

    let Some(policy) = proxy_only_policy(&ctx.caps) else {
        return Ok(());
    };

    let abi = Sandbox::detect_abi()
        .map_err(|e| PyRuntimeError::new_err(format!("Landlock ABI detection failed: {}", e)))?;
    if abi.has_network() || ctx.proxy_handoff == ProxyHandoff::Pidfd {
        return Ok(());
    }

    #[cfg(debug_assertions)]
    {
        ctx.clone_files_test_fault = match std::env::var("NONO_PY_TEST_CLONE_FILES_FAULT") {
            Err(std::env::VarError::NotPresent) => CloneFilesTestFault::None,
            Ok(value) if value == "before_listener" => CloneFilesTestFault::BeforeListener,
            Ok(value) if value == "after_listener" => CloneFilesTestFault::AfterListener,
            Ok(value) if value == "after_fd_report" => CloneFilesTestFault::AfterFdReport,
            Ok(value) if value == "after_unshare" => CloneFilesTestFault::AfterUnshare,
            Ok(value) if value == "after_detached" => CloneFilesTestFault::AfterDetached,
            Ok(value) if value == "after_ack" => CloneFilesTestFault::AfterAck,
            Ok(value) => {
                return Err(PyValueError::new_err(format!(
                    "NONO_PY_TEST_CLONE_FILES_FAULT has unknown phase '{}'",
                    value
                )));
            }
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err(PyValueError::new_err(
                    "NONO_PY_TEST_CLONE_FILES_FAULT is not valid UTF-8",
                ));
            }
        };
    }

    let prepared_landlock = Sandbox::prepare_seccomp_with_abi(
        &ctx.caps,
        &abi,
        nono::sandbox::SeccompOpts::preinstalled_tcp_filter(),
    )
    .map_err(|e| PyRuntimeError::new_err(format!("Failed to prepare child sandbox: {}", e)))?;
    ctx.prepared_proxy_filter = Some(nono::sandbox::prepare_seccomp_proxy_filter(
        !policy.bind_ports.is_empty(),
    ));
    ctx.prepared_landlock = Some(prepared_landlock);
    Ok(())
}

#[cfg(target_os = "linux")]
fn create_proxy_supervisor_pair(
    ctx: &ForkContext,
) -> PyResult<Option<(nono::SupervisorSocket, nono::SupervisorSocket)>> {
    if proxy_only_policy(&ctx.caps).is_none()
        || (ctx.prepared_proxy_filter.is_none() && ctx.proxy_handoff != ProxyHandoff::Pidfd)
    {
        return Ok(None);
    }

    let pair = nono::SupervisorSocket::pair().map_err(|e| {
        PyRuntimeError::new_err(format!("Failed to create proxy supervisor: {}", e))
    })?;
    set_cloexec(pair.0.as_raw_fd())
        .and_then(|_| set_cloexec(pair.1.as_raw_fd()))
        .map_err(|e| {
            PyRuntimeError::new_err(format!(
                "Failed to protect proxy supervisor descriptors: {}",
                e
            ))
        })?;
    Ok(Some(pair))
}

/// Build child environment CStrings.
///
/// By default, the child receives only env vars explicitly supplied by the
/// caller. Parent environment inheritance is an explicit opt-in because env
/// vars can carry API keys, proxy tokens, and dynamic-loader control state.
fn build_env_cstrings(
    overrides: Option<&[(String, String)]>,
    inherit_env: bool,
) -> PyResult<Vec<CString>> {
    let mut env = BTreeMap::new();

    if inherit_env {
        for (key, value) in std::env::vars_os() {
            insert_env_var(
                &mut env,
                key.as_os_str().as_bytes().to_vec(),
                value.as_os_str().as_bytes().to_vec(),
            )?;
        }
    }

    if let Some(ovr) = overrides {
        for (key, value) in ovr {
            insert_env_var(&mut env, key.as_bytes().to_vec(), value.as_bytes().to_vec())?;
        }
    }

    let mut env_c: Vec<CString> = Vec::new();
    for (mut key, value) in env {
        key.reserve(1 + value.len());
        key.push(b'=');
        key.extend_from_slice(&value);

        env_c.push(
            CString::new(key)
                .map_err(|_| PyValueError::new_err("environment contains null byte"))?,
        );
    }

    Ok(env_c)
}

pub(crate) fn sanitize_env_pairs(pairs: Vec<(String, String)>) -> PyResult<Vec<(String, String)>> {
    let mut env = BTreeMap::new();
    for (key, value) in pairs {
        insert_env_var(&mut env, key.as_bytes().to_vec(), value.as_bytes().to_vec())?;
    }

    let mut sanitized = Vec::with_capacity(env.len());
    for (key, value) in env {
        let key = String::from_utf8(key)
            .map_err(|_| PyValueError::new_err("environment name is not valid UTF-8"))?;
        let value = String::from_utf8(value)
            .map_err(|_| PyValueError::new_err("environment value is not valid UTF-8"))?;
        sanitized.push((key, value));
    }
    Ok(sanitized)
}

fn insert_env_var(
    env: &mut BTreeMap<Vec<u8>, Vec<u8>>,
    key: Vec<u8>,
    value: Vec<u8>,
) -> PyResult<()> {
    validate_env_var(&key, &value)?;
    env.insert(key, value);
    Ok(())
}

fn validate_env_var(key: &[u8], value: &[u8]) -> PyResult<()> {
    if key.is_empty() {
        return Err(PyValueError::new_err(
            "environment variable name must not be empty",
        ));
    }
    if key.contains(&b'=') {
        return Err(PyValueError::new_err(format!(
            "environment variable name '{}' must not contain '='",
            display_env_key(key)
        )));
    }
    if key.contains(&0) {
        return Err(PyValueError::new_err(
            "environment variable name contains null byte",
        ));
    }
    if value.contains(&0) {
        return Err(PyValueError::new_err(format!(
            "environment variable value for '{}' contains null byte",
            display_env_key(key)
        )));
    }
    if is_dangerous_loader_env(key) {
        return Err(PyValueError::new_err(format!(
            "environment variable '{}' is not allowed in sandboxed_exec",
            display_env_key(key)
        )));
    }
    Ok(())
}

fn is_dangerous_loader_env(key: &[u8]) -> bool {
    key.starts_with(b"LD_")
        || key.starts_with(b"DYLD_")
        || matches!(key, b"LIBPATH" | b"SHLIB_PATH")
}

fn display_env_key(key: &[u8]) -> String {
    String::from_utf8_lossy(key).into_owned()
}

/// Create a pipe, returning a PipeFds struct.
fn create_pipe() -> PyResult<PipeFds> {
    let mut fds = [0i32; 2];

    #[cfg(target_os = "linux")]
    {
        // SAFETY: pipe2() is safe with a valid 2-element array. O_CLOEXEC
        // prevents accidental descriptor inheritance across execve().
        let ret = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
        if ret == 0 {
            return Ok(PipeFds {
                read_fd: fds[0],
                write_fd: fds[1],
            });
        }

        let err = std::io::Error::last_os_error();
        if !matches!(
            err.raw_os_error(),
            Some(code) if code == libc::ENOSYS || code == libc::EINVAL
        ) {
            return Err(PyRuntimeError::new_err(format!("pipe2() failed: {}", err)));
        }
    }

    // SAFETY: pipe() is safe with a valid 2-element array.
    let ret = unsafe { libc::pipe(fds.as_mut_ptr()) };
    if ret != 0 {
        return Err(PyRuntimeError::new_err(format!(
            "pipe() failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    if let Err(e) = set_cloexec(fds[0]).and_then(|_| set_cloexec(fds[1])) {
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
        return Err(PyRuntimeError::new_err(format!(
            "fcntl(FD_CLOEXEC) failed: {}",
            e
        )));
    }

    Ok(PipeFds {
        read_fd: fds[0],
        write_fd: fds[1],
    })
}

fn set_cloexec(fd: i32) -> IoResult<()> {
    // SAFETY: fcntl() is safe for a valid fd and does not take ownership.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }

    // SAFETY: fcntl(F_SETFD) updates only descriptor flags for this fd.
    let ret = unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Fork, apply sandbox in child, exec command, capture output in parent.
fn do_fork_sandbox_exec(
    ctx: &mut ForkContext,
    stdout_pipe: &PipeFds,
    stderr_pipe: &PipeFds,
    #[cfg(target_os = "linux")] proxy_supervisor_pair: Option<(
        nono::SupervisorSocket,
        nono::SupervisorSocket,
    )>,
) -> PyResult<ExecResult> {
    let argv_ptrs: Vec<*const libc::c_char> = ctx
        .argv_c
        .iter()
        .map(|s| s.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();

    let envp_ptrs: Vec<*const libc::c_char> = ctx
        .env_c
        .iter()
        .map(|s| s.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();

    #[cfg(target_os = "linux")]
    if ctx.prepared_proxy_filter.is_some() {
        return do_clone_files_sandbox_exec(
            ctx,
            &argv_ptrs,
            &envp_ptrs,
            stdout_pipe,
            stderr_pipe,
            proxy_supervisor_pair,
        );
    }

    // SAFETY: fork() creates a child process. Only the forking thread
    // continues in the child, so any lock held by another parent thread at
    // fork time (e.g. a malloc arena lock) stays held forever in the child.
    // The thread-count guard above bounds the exposure but cannot remove it;
    // the child path therefore keeps allocation to a minimum (ABI detection
    // is pre-warmed in the parent) though Sandbox apply is not allocation-free.
    let pid = unsafe { libc::fork() };

    if pid < 0 {
        unsafe {
            libc::close(stdout_pipe.read_fd);
            libc::close(stdout_pipe.write_fd);
            libc::close(stderr_pipe.read_fd);
            libc::close(stderr_pipe.write_fd);
        }
        return Err(PyRuntimeError::new_err(format!(
            "fork() failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    if pid == 0 {
        // === CHILD PROCESS ===
        child_process(
            ctx,
            &argv_ptrs,
            &envp_ptrs,
            stdout_pipe,
            stderr_pipe,
            #[cfg(target_os = "linux")]
            proxy_supervisor_pair.as_ref(),
        );
    }

    // Put the child in a dedicated process group as early as possible.
    // The child does the same after fork; doing it from both sides narrows
    // the race before exec and makes timeout cleanup target the whole group.
    set_child_process_group(pid);

    // === PARENT PROCESS ===
    #[cfg(target_os = "linux")]
    let proxy_supervisor =
        create_proxy_supervisor(proxy_supervisor_pair, proxy_only_policy(&ctx.caps), pid);

    parent_process(
        pid,
        stdout_pipe,
        stderr_pipe,
        ctx,
        #[cfg(target_os = "linux")]
        proxy_supervisor,
    )
}

#[cfg(target_os = "linux")]
struct SignalMaskGuard {
    old_mask: libc::sigset_t,
    restored: bool,
}

#[cfg(target_os = "linux")]
impl SignalMaskGuard {
    fn block_all() -> IoResult<Self> {
        // SAFETY: both sigset pointers are valid and only the calling thread's
        // mask is changed.  SIGKILL/SIGSTOP are silently left unblocked.
        unsafe {
            let mut all = std::mem::zeroed::<libc::sigset_t>();
            let mut old_mask = std::mem::zeroed::<libc::sigset_t>();
            libc::sigfillset(&mut all);
            let err = libc::pthread_sigmask(libc::SIG_SETMASK, &all, &mut old_mask);
            if err != 0 {
                return Err(std::io::Error::from_raw_os_error(err));
            }
            Ok(Self {
                old_mask,
                restored: false,
            })
        }
    }

    fn restore(&mut self) -> IoResult<()> {
        if self.restored {
            return Ok(());
        }
        // SAFETY: old_mask was initialized by pthread_sigmask above.
        let err = unsafe {
            libc::pthread_sigmask(libc::SIG_SETMASK, &self.old_mask, std::ptr::null_mut())
        };
        if err != 0 {
            return Err(std::io::Error::from_raw_os_error(err));
        }
        self.restored = true;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl Drop for SignalMaskGuard {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

#[cfg(target_os = "linux")]
fn do_clone_files_sandbox_exec(
    ctx: &mut ForkContext,
    argv_ptrs: &[*const libc::c_char],
    envp_ptrs: &[*const libc::c_char],
    stdout_pipe: &PipeFds,
    stderr_pipe: &PipeFds,
    proxy_supervisor_pair: Option<(nono::SupervisorSocket, nono::SupervisorSocket)>,
) -> PyResult<ExecResult> {
    let bootstrap_guard = SHARED_BOOTSTRAP_MUTEX
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let listener_snapshot = match seccomp_notify_fds() {
        Ok(snapshot) => snapshot,
        Err(e) => {
            close_all_pipe_fds(stdout_pipe, stderr_pipe);
            return Err(PyRuntimeError::new_err(format!(
                "Failed to snapshot seccomp listener fds: {}",
                e
            )));
        }
    };
    let mut signal_guard = match SignalMaskGuard::block_all() {
        Ok(guard) => guard,
        Err(e) => {
            close_all_pipe_fds(stdout_pipe, stderr_pipe);
            return Err(PyRuntimeError::new_err(format!(
                "Failed to block signals before clone: {}",
                e
            )));
        }
    };
    let original_parent_pid = unsafe { libc::getpid() };

    // SAFETY: CLONE_FILES shares only the descriptor table.  No VM, signal
    // handlers, TLS, parent/child tid pointers, or namespaces are shared.
    let clone_result = unsafe {
        libc::syscall(
            libc::SYS_clone,
            libc::CLONE_FILES | libc::SIGCHLD,
            0,
            0,
            0,
            0,
        )
    };

    if clone_result == 0 {
        crate::arm_raw_clone_allocator_guard();
        child_process_clone_files(CloneFilesChildArgs {
            ctx,
            argv_ptrs,
            envp_ptrs,
            stdout_pipe,
            stderr_pipe,
            proxy_supervisor_pair: proxy_supervisor_pair.as_ref(),
            original_parent_pid,
            intended_signal_mask: &signal_guard.old_mask,
        });
    }

    if clone_result < 0 {
        close_all_pipe_fds(stdout_pipe, stderr_pipe);
        return Err(PyRuntimeError::new_err(format!(
            "clone(CLONE_FILES) failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    let child_pid = clone_result as i32;

    if let Err(e) = signal_guard.restore() {
        cleanup_failed_shared_bootstrap(
            child_pid,
            None,
            &listener_snapshot,
            stdout_pipe,
            stderr_pipe,
        );
        return Err(PyRuntimeError::new_err(format!(
            "Failed to restore parent signal mask: {}",
            e
        )));
    }
    set_child_process_group(child_pid);

    let Some((supervisor_sock, child_sock)) = proxy_supervisor_pair else {
        kill_and_reap_bootstrap_child(child_pid);
        close_all_pipe_fds(stdout_pipe, stderr_pipe);
        return Err(PyRuntimeError::new_err(
            "clone-files proxy bootstrap is missing its supervisor socket",
        ));
    };

    let mut raw_listener = None;
    let handshake = (|| -> PyResult<i32> {
        let mut fd_bytes = [0_u8; std::mem::size_of::<i32>()];
        read_bootstrap_exact(supervisor_sock.as_raw_fd(), child_pid, &mut fd_bytes)?;
        let listener = i32::from_ne_bytes(fd_bytes);
        if listener < 0 {
            return Err(PyRuntimeError::new_err(
                "child reported an invalid seccomp listener slot",
            ));
        }
        raw_listener = Some(listener);

        let mut detached = [0_u8; 1];
        read_bootstrap_exact(supervisor_sock.as_raw_fd(), child_pid, &mut detached)?;
        if detached[0] != HANDSHAKE_DETACHED {
            return Err(PyRuntimeError::new_err(
                "invalid DETACHED marker in proxy bootstrap",
            ));
        }
        Ok(listener)
    })();

    let listener = match handshake {
        Ok(listener) => listener,
        Err(error) => {
            cleanup_failed_shared_bootstrap(
                child_pid,
                raw_listener,
                &listener_snapshot,
                stdout_pipe,
                stderr_pipe,
            );
            drop(child_sock);
            drop(supervisor_sock);
            return Err(error);
        }
    };

    // The child's table is private now.  Parent RAII may safely close its copy
    // of the child endpoint and all parent copies of prepared path fds.
    drop(child_sock);
    drop(ctx.prepared_landlock.take());
    drop(ctx.prepared_proxy_filter.take());

    if let Err(error) = validate_seccomp_notify_fd(listener, &listener_snapshot) {
        cleanup_failed_shared_bootstrap(
            child_pid,
            Some(listener),
            &listener_snapshot,
            stdout_pipe,
            stderr_pipe,
        );
        drop(supervisor_sock);
        return Err(error);
    }

    // SAFETY: DETACHED proves the parent now privately owns this table slot.
    let listener = unsafe { OwnedFd::from_raw_fd(listener) };
    if let Err(e) = write_all_raw(supervisor_sock.as_raw_fd(), &[HANDSHAKE_ACK]) {
        kill_and_reap_bootstrap_child(child_pid);
        close_all_pipe_fds(stdout_pipe, stderr_pipe);
        return Err(PyRuntimeError::new_err(format!(
            "proxy supervisor ACK failed: {}",
            e
        )));
    }
    drop(supervisor_sock);
    let listener = ProxyNotifyFd::new(listener);
    drop(bootstrap_guard);

    let proxy_supervisor = Some(ProxySupervisor {
        sock: None,
        notify_fd: Some(listener),
        policy: proxy_only_policy(&ctx.caps)
            .expect("prepared proxy bootstrap always has proxy policy"),
        child_pid,
    });

    parent_process(child_pid, stdout_pipe, stderr_pipe, ctx, proxy_supervisor)
}

#[cfg(target_os = "linux")]
struct CloneFilesChildArgs<'a> {
    ctx: &'a ForkContext,
    argv_ptrs: &'a [*const libc::c_char],
    envp_ptrs: &'a [*const libc::c_char],
    stdout_pipe: &'a PipeFds,
    stderr_pipe: &'a PipeFds,
    proxy_supervisor_pair: Option<&'a (nono::SupervisorSocket, nono::SupervisorSocket)>,
    original_parent_pid: libc::pid_t,
    intended_signal_mask: &'a libc::sigset_t,
}

#[cfg(target_os = "linux")]
fn child_process_clone_files(args: CloneFilesChildArgs<'_>) -> ! {
    let CloneFilesChildArgs {
        ctx,
        argv_ptrs,
        envp_ptrs,
        stdout_pipe,
        stderr_pipe,
        proxy_supervisor_pair,
        original_parent_pid,
        intended_signal_mask,
    } = args;
    let Some((supervisor_sock, child_sock)) = proxy_supervisor_pair else {
        child_die_raw(b"nono: missing clone-files supervisor socket\n", 126);
    };
    let Some(filter) = ctx.prepared_proxy_filter.as_ref() else {
        child_die_raw(b"nono: missing prepared proxy filter\n", 126);
    };
    let Some(landlock) = ctx.prepared_landlock.as_ref() else {
        child_die_raw(b"nono: missing prepared Landlock policy\n", 126);
    };

    unsafe {
        if libc::syscall(
            libc::SYS_prctl,
            libc::PR_SET_PDEATHSIG,
            libc::SIGKILL,
            0,
            0,
            0,
        ) < 0
            || libc::syscall(libc::SYS_getppid) as libc::pid_t != original_parent_pid
        {
            child_die_raw(b"nono: parent died during proxy bootstrap\n", 126);
        }
        libc::syscall(libc::SYS_setpgid, 0, 0);
    }

    #[cfg(debug_assertions)]
    if ctx.clone_files_test_fault == CloneFilesTestFault::BeforeListener {
        child_die_raw(b"nono: injected failure before listener creation\n", 126);
    }

    let listener = match filter.install_raw() {
        Ok(fd) => fd,
        Err(_) => child_die_raw(b"nono: failed to install prepared proxy filter\n", 126),
    };
    #[cfg(debug_assertions)]
    if ctx.clone_files_test_fault == CloneFilesTestFault::AfterListener {
        child_die_raw(b"nono: injected failure after listener creation\n", 126);
    }
    if !raw_write_all(child_sock.as_raw_fd(), &listener.to_ne_bytes()) {
        child_die_raw(b"nono: failed to report proxy listener slot\n", 126);
    }
    #[cfg(debug_assertions)]
    if ctx.clone_files_test_fault == CloneFilesTestFault::AfterFdReport {
        child_die_raw(b"nono: injected failure after listener report\n", 126);
    }

    // Empty range: unshare the table but close nothing.
    let detached = unsafe {
        libc::syscall(
            libc::SYS_close_range,
            u32::MAX,
            u32::MAX,
            CLOSE_RANGE_UNSHARE,
        )
    };
    if detached < 0 {
        child_die_raw(b"nono: close_range fd-table detach failed\n", 126);
    }
    #[cfg(debug_assertions)]
    if ctx.clone_files_test_fault == CloneFilesTestFault::AfterUnshare {
        child_die_raw(b"nono: injected failure after fd-table detach\n", 126);
    }

    raw_close(supervisor_sock.as_raw_fd());
    if !raw_write_all(child_sock.as_raw_fd(), &[HANDSHAKE_DETACHED]) {
        child_die_raw(b"nono: failed to send DETACHED marker\n", 126);
    }
    #[cfg(debug_assertions)]
    if ctx.clone_files_test_fault == CloneFilesTestFault::AfterDetached {
        child_die_raw(b"nono: injected failure after DETACHED\n", 126);
    }
    let mut ack = [0_u8; 1];
    if !raw_read_exact(child_sock.as_raw_fd(), &mut ack) || ack[0] != HANDSHAKE_ACK {
        child_die_raw(b"nono: parent did not ACK proxy handoff\n", 126);
    }
    #[cfg(debug_assertions)]
    if ctx.clone_files_test_fault == CloneFilesTestFault::AfterAck {
        child_die_raw(b"nono: injected failure after ACK\n", 126);
    }

    // The handshake endpoint is no longer needed. Close it before dup3 so a
    // socket originally allocated into a closed stdout/stderr slot cannot be
    // mistaken for the newly wired pipe later in bootstrap.
    raw_close(child_sock.as_raw_fd());

    raw_close(stdout_pipe.read_fd);
    raw_close(stderr_pipe.read_fd);
    if !raw_dup2(stdout_pipe.write_fd, libc::STDOUT_FILENO)
        || !raw_dup2(stderr_pipe.write_fd, libc::STDERR_FILENO)
    {
        child_die_raw(b"nono: failed to wire child stdio\n", 126);
    }
    if stdout_pipe.write_fd != libc::STDOUT_FILENO {
        raw_close(stdout_pipe.write_fd);
    }
    if stderr_pipe.write_fd != libc::STDERR_FILENO {
        raw_close(stderr_pipe.write_fd);
    }

    if let Some(dir) = ctx.cwd_c.as_ref()
        && unsafe { libc::syscall(libc::SYS_chdir, dir.as_ptr()) } < 0
    {
        child_die_raw(b"nono: failed to chdir\n", 126);
    }
    if !drop_privileges_raw(ctx.uid, ctx.gid) {
        child_die_raw(b"nono: failed to drop privileges\n", 126);
    }
    if landlock.apply_raw().is_err() {
        child_die_raw(b"nono: prepared sandbox apply failed\n", 126);
    }
    if !apply_resource_limits_raw(ctx) {
        child_die_raw(b"nono: failed to set resource limit\n", 126);
    }

    if unsafe { libc::syscall(libc::SYS_close_range, 3_u32, u32::MAX, 0_u32) } < 0 {
        child_die_raw(b"nono: final fd scrub failed\n", 126);
    }
    if !restore_signal_mask_raw(intended_signal_mask) {
        child_die_raw(b"nono: failed to restore child signal mask\n", 126);
    }

    unsafe {
        libc::syscall(
            libc::SYS_execve,
            ctx.program_c.as_ptr(),
            argv_ptrs.as_ptr(),
            envp_ptrs.as_ptr(),
        );
    }
    child_die_raw(b"nono: exec failed\n", 127)
}

#[cfg(target_os = "linux")]
fn close_all_pipe_fds(stdout_pipe: &PipeFds, stderr_pipe: &PipeFds) {
    unsafe {
        libc::close(stdout_pipe.read_fd);
        libc::close(stdout_pipe.write_fd);
        libc::close(stderr_pipe.read_fd);
        libc::close(stderr_pipe.write_fd);
    }
}

#[cfg(target_os = "linux")]
fn read_bootstrap_exact(fd: i32, child_pid: i32, buf: &mut [u8]) -> PyResult<()> {
    let mut filled = 0;
    while filled < buf.len() {
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
            revents: 0,
        };
        // SAFETY: pfd points to one initialized pollfd.
        let poll_result = unsafe { libc::poll(&mut pfd, 1, 10) };
        if poll_result < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(PyRuntimeError::new_err(format!(
                "proxy bootstrap poll failed: {}",
                error
            )));
        }

        if poll_result > 0 && pfd.revents & libc::POLLIN != 0 {
            // SAFETY: the destination slice is valid and the socket remains
            // protected by the bootstrap owner.
            let read = unsafe {
                libc::read(
                    fd,
                    buf[filled..].as_mut_ptr().cast::<libc::c_void>(),
                    buf.len() - filled,
                )
            };
            if read > 0 {
                filled += read as usize;
                continue;
            }
            if read < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(PyRuntimeError::new_err(format!(
                    "proxy bootstrap read failed: {}",
                    error
                )));
            }
        }

        let mut status = 0_i32;
        // Socket EOF is not meaningful before DETACHED because the parent
        // still holds both endpoints.  waitpid is the liveness oracle.
        let waited = unsafe { libc::waitpid(child_pid, &mut status, libc::WNOHANG) };
        if waited == child_pid {
            return Err(PyRuntimeError::new_err(
                "sandbox child exited before proxy fd-table detach",
            ));
        }
        if waited < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                return Err(PyRuntimeError::new_err(format!(
                    "waitpid during proxy bootstrap failed: {}",
                    error
                )));
            }
        }
        if poll_result > 0 && pfd.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
            return Err(PyRuntimeError::new_err(
                "proxy bootstrap socket failed before handoff completed",
            ));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn is_seccomp_notify_target(target: &std::ffi::OsStr) -> bool {
    target == std::ffi::OsStr::new("anon_inode:seccomp notify")
        || target == std::ffi::OsStr::new("anon_inode:[seccomp notify]")
}

#[cfg(target_os = "linux")]
fn seccomp_notify_fds() -> IoResult<BTreeSet<i32>> {
    let mut listeners = BTreeSet::new();
    for entry in std::fs::read_dir("/proc/self/fd")? {
        let entry = entry?;
        let Ok(fd) = entry.file_name().to_string_lossy().parse::<i32>() else {
            continue;
        };
        if let Ok(target) = std::fs::read_link(entry.path())
            && is_seccomp_notify_target(target.as_os_str())
        {
            listeners.insert(fd);
        }
    }
    Ok(listeners)
}

#[cfg(target_os = "linux")]
fn validate_seccomp_notify_fd(fd: i32, listener_snapshot: &BTreeSet<i32>) -> PyResult<()> {
    if listener_snapshot.contains(&fd) {
        return Err(PyRuntimeError::new_err(format!(
            "child reported pre-existing seccomp listener slot {}",
            fd
        )));
    }

    let target = std::fs::read_link(format!("/proc/self/fd/{}", fd)).map_err(|e| {
        PyRuntimeError::new_err(format!(
            "cannot inspect proxy listener slot {} after DETACHED: {}",
            fd, e
        ))
    })?;
    if !is_seccomp_notify_target(target.as_os_str()) {
        return Err(PyRuntimeError::new_err(format!(
            "fd {} is not a seccomp notification listener after DETACHED (target: {})",
            fd,
            target.display()
        )));
    }
    // NEW_LISTENER is specified to return O_CLOEXEC.  Treat a missing flag as
    // a bootstrap integrity failure rather than allowing target inheritance.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 || flags & libc::FD_CLOEXEC == 0 {
        return Err(PyRuntimeError::new_err(format!(
            "seccomp listener slot {} is missing FD_CLOEXEC",
            fd
        )));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn cleanup_failed_shared_bootstrap(
    child_pid: i32,
    known_listener: Option<i32>,
    listener_snapshot: &BTreeSet<i32>,
    stdout_pipe: &PipeFds,
    stderr_pipe: &PipeFds,
) {
    // Establish that the child can no longer mutate or detach the table before
    // closing any raw listener slot inherited through CLONE_FILES.
    kill_and_reap_bootstrap_child(child_pid);

    let mut to_close = seccomp_notify_fds()
        .unwrap_or_default()
        .difference(listener_snapshot)
        .copied()
        .collect::<BTreeSet<_>>();
    if let Some(fd) = known_listener
        && !listener_snapshot.contains(&fd)
    {
        to_close.insert(fd);
    }
    for fd in to_close {
        unsafe {
            libc::close(fd);
        }
    }
    close_all_pipe_fds(stdout_pipe, stderr_pipe);
}

#[cfg(target_os = "linux")]
fn kill_and_reap_bootstrap_child(child_pid: i32) {
    unsafe {
        libc::kill(child_pid, libc::SIGKILL);
    }
    loop {
        let waited = unsafe { libc::waitpid(child_pid, std::ptr::null_mut(), 0) };
        if waited == child_pid {
            return;
        }
        if waited < 0 {
            let errno = unsafe { *libc::__errno_location() };
            if errno == libc::ECHILD {
                // A prior WNOHANG probe already reaped the child.
                return;
            }
            // EINTR is expected under signal stress. Other errors are not
            // expected for a direct child and valid wait arguments; retry so
            // protected shared-table descriptors are never closed before the
            // child is known unable to mutate them.
        }
    }
}

#[cfg(target_os = "linux")]
fn raw_errno() -> i32 {
    unsafe { *libc::__errno_location() }
}

#[cfg(target_os = "linux")]
fn raw_write_all(fd: i32, buf: &[u8]) -> bool {
    let mut written = 0;
    while written < buf.len() {
        let count = unsafe {
            libc::syscall(
                libc::SYS_write,
                fd,
                buf[written..].as_ptr(),
                buf.len() - written,
            )
        };
        if count > 0 {
            written += count as usize;
        } else if count < 0 && raw_errno() == libc::EINTR {
            continue;
        } else {
            return false;
        }
    }
    true
}

#[cfg(target_os = "linux")]
fn raw_read_exact(fd: i32, buf: &mut [u8]) -> bool {
    let mut filled = 0;
    while filled < buf.len() {
        let count = unsafe {
            libc::syscall(
                libc::SYS_read,
                fd,
                buf[filled..].as_mut_ptr(),
                buf.len() - filled,
            )
        };
        if count > 0 {
            filled += count as usize;
        } else if count < 0 && raw_errno() == libc::EINTR {
            continue;
        } else {
            return false;
        }
    }
    true
}

#[cfg(target_os = "linux")]
fn raw_close(fd: i32) {
    unsafe {
        libc::syscall(libc::SYS_close, fd);
    }
}

#[cfg(target_os = "linux")]
fn raw_dup2(from: i32, to: i32) -> bool {
    if from != to {
        return unsafe { libc::syscall(libc::SYS_dup3, from, to, 0_u32) } >= 0;
    }

    // dup2(fd, fd) is a no-op, so explicitly clear the pipe2 O_CLOEXEC flag
    // when an originally closed stdio slot was reused as the pipe source.
    let flags = unsafe { libc::syscall(libc::SYS_fcntl, from, libc::F_GETFD) };
    flags >= 0
        && unsafe {
            libc::syscall(
                libc::SYS_fcntl,
                from,
                libc::F_SETFD,
                flags & !(libc::FD_CLOEXEC as libc::c_long),
            )
        } >= 0
}

#[cfg(target_os = "linux")]
fn raw_set_rlimit(resource: RlimitResource, value: u64) -> bool {
    let rlim = clamp_rlim(value);
    let limit = libc::rlimit {
        rlim_cur: rlim,
        rlim_max: rlim,
    };
    unsafe {
        libc::syscall(
            libc::SYS_prlimit64,
            0,
            resource,
            &limit as *const libc::rlimit,
            std::ptr::null::<libc::rlimit>(),
        ) >= 0
    }
}

#[cfg(target_os = "linux")]
fn apply_resource_limits_raw(ctx: &ForkContext) -> bool {
    ctx.max_cpu_seconds
        .is_none_or(|value| raw_set_rlimit(libc::RLIMIT_CPU, value))
        && ctx
            .max_file_size_bytes
            .is_none_or(|value| raw_set_rlimit(libc::RLIMIT_FSIZE, value))
        && ctx
            .max_processes
            .is_none_or(|value| raw_set_rlimit(libc::RLIMIT_NPROC, value))
        && ctx
            .max_open_files
            .is_none_or(|value| raw_set_rlimit(libc::RLIMIT_NOFILE, value))
}

#[cfg(target_os = "linux")]
fn drop_privileges_raw(uid: Option<u32>, gid: Option<u32>) -> bool {
    if uid.is_none() && gid.is_none() {
        return true;
    }
    if unsafe { libc::syscall(libc::SYS_setgroups, 0, std::ptr::null::<libc::gid_t>()) } < 0 {
        return false;
    }
    if let Some(gid) = gid
        && (unsafe { libc::syscall(libc::SYS_setresgid, gid, gid, gid) } < 0
            || unsafe { libc::syscall(libc::SYS_getgid) } as u32 != gid
            || unsafe { libc::syscall(libc::SYS_getegid) } as u32 != gid)
    {
        return false;
    }
    if let Some(uid) = uid
        && (unsafe { libc::syscall(libc::SYS_setresuid, uid, uid, uid) } < 0
            || unsafe { libc::syscall(libc::SYS_getuid) } as u32 != uid
            || unsafe { libc::syscall(libc::SYS_geteuid) } as u32 != uid)
    {
        return false;
    }
    true
}

#[cfg(target_os = "linux")]
fn restore_signal_mask_raw(mask: &libc::sigset_t) -> bool {
    // The kernel rt_sigprocmask ABI uses _NSIG / 8 bytes (8 on supported
    // x86_64 and arm64 Linux), rather than libc's padded sigset_t size.
    unsafe {
        libc::syscall(
            libc::SYS_rt_sigprocmask,
            libc::SIG_SETMASK,
            mask as *const libc::sigset_t,
            std::ptr::null_mut::<libc::sigset_t>(),
            8_usize,
        ) >= 0
    }
}

#[cfg(target_os = "linux")]
fn child_die_raw(message: &'static [u8], code: i32) -> ! {
    let _ = raw_write_all(libc::STDERR_FILENO, message);
    unsafe {
        libc::syscall(libc::SYS_exit_group, code);
        core::hint::unreachable_unchecked();
    }
}

/// Child process: set up pipes, apply sandbox, chdir, exec.
/// This function never returns.
fn child_process(
    ctx: &ForkContext,
    argv_ptrs: &[*const libc::c_char],
    envp_ptrs: &[*const libc::c_char],
    stdout_pipe: &PipeFds,
    stderr_pipe: &PipeFds,
    #[cfg(target_os = "linux")] proxy_supervisor_pair: Option<&(
        nono::SupervisorSocket,
        nono::SupervisorSocket,
    )>,
) -> ! {
    // Create a process group rooted at this child before any sandboxed command
    // can fork descendants. Descendants inherit the group unless they
    // explicitly create a new session/process group.
    set_own_process_group();

    #[cfg(target_os = "linux")]
    let proxy_child_fd = proxy_supervisor_pair.map(|(_, child_sock)| child_sock.as_raw_fd());

    #[cfg(target_os = "linux")]
    if let Some((supervisor_sock, _)) = proxy_supervisor_pair {
        unsafe {
            libc::close(supervisor_sock.as_raw_fd());
        }
    }

    // Close read ends (parent reads, child writes)
    unsafe {
        libc::close(stdout_pipe.read_fd);
        libc::close(stderr_pipe.read_fd);
    }

    // Redirect stdout and stderr to pipe write ends
    unsafe {
        libc::dup2(stdout_pipe.write_fd, libc::STDOUT_FILENO);
        libc::dup2(stderr_pipe.write_fd, libc::STDERR_FILENO);
        libc::close(stdout_pipe.write_fd);
        libc::close(stderr_pipe.write_fd);
    }

    #[cfg(target_os = "linux")]
    let keep_fds: Vec<i32> = proxy_child_fd.into_iter().collect();
    #[cfg(not(target_os = "linux"))]
    let keep_fds: Vec<i32> = Vec::new();

    if let Err(e) = close_untrusted_fds(&keep_fds) {
        child_die(&format!(
            "nono: failed to close inherited file descriptors: {}\n",
            e
        ));
    }

    // Apply resource-limit caps (RLIMIT_*) after untrusted fds are closed so the
    // NOFILE cap does not truncate the fd-closing sweep.
    if let Err(e) = apply_resource_limits(ctx) {
        child_die(&format!("nono: failed to set resource limit ({})\n", e));
    }

    // Change working directory if specified
    if let Some(ref dir) = ctx.cwd_c {
        // SAFETY: chdir with a valid NUL-terminated path in the forked child.
        if unsafe { libc::chdir(dir.as_ptr()) } != 0 {
            child_die("nono: failed to chdir\n");
        }
    }

    // Drop to the requested UID/GID after chdir (cwd may need the original
    // privileges) and before applying the sandbox and exec'ing user code.
    if let Err(e) = drop_privileges(ctx.uid, ctx.gid) {
        child_die(&format!("nono: failed to drop privileges: {}\n", e));
    }

    #[cfg(target_os = "linux")]
    {
        let applied = match ctx.enforcement_mode {
            EnforcementMode::Auto => Sandbox::apply_auto(&ctx.caps).map(Some),
            EnforcementMode::Seccomp => {
                Sandbox::apply_seccomp(&ctx.caps, nono::sandbox::SeccompOpts::network_baseline())
                    .map(Some)
            }
            EnforcementMode::Landlock => Sandbox::apply_landlock(&ctx.caps).map(|()| None),
        };
        match applied {
            Ok(fallback) => {
                if let Some(fallback) = fallback
                    && let Err(e) =
                        install_proxy_fallback_if_needed(&ctx.caps, fallback, proxy_child_fd)
                {
                    child_die(&format!(
                        "nono: proxy-only supervisor setup failed: {}\n",
                        e
                    ));
                }
            }
            Err(e) => child_die(&format!("nono: sandbox apply failed: {}\n", e)),
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        if let Err(e) = Sandbox::apply_auto(&ctx.caps) {
            child_die(&format!("nono: sandbox apply failed: {}\n", e));
        }
    }

    #[cfg(target_os = "linux")]
    if let Some(fd) = proxy_child_fd {
        unsafe {
            libc::close(fd);
        }
    }

    // Exec the command
    unsafe {
        libc::execve(
            ctx.program_c.as_ptr(),
            argv_ptrs.as_ptr(),
            envp_ptrs.as_ptr(),
        );

        // execve only returns on error
        let detail = format!("nono: exec failed: {}\n", std::io::Error::last_os_error());
        let msg = detail.as_bytes();
        libc::write(
            libc::STDERR_FILENO,
            msg.as_ptr().cast::<libc::c_void>(),
            msg.len(),
        );
        libc::_exit(127);
    }
}

#[cfg(target_os = "linux")]
fn install_proxy_fallback_if_needed(
    caps: &nono::CapabilitySet,
    fallback: nono::sandbox::SeccompNetFallback,
    proxy_child_fd: Option<i32>,
) -> Result<(), String> {
    let nono::sandbox::SeccompNetFallback::ProxyOnly { .. } = fallback else {
        return Ok(());
    };

    let Some(sock_fd) = proxy_child_fd else {
        return Err("missing proxy supervisor socket".to_string());
    };

    let has_bind_ports = match caps.network_mode() {
        nono::NetworkMode::ProxyOnly { bind_ports, .. } => !bind_ports.is_empty(),
        _ => false,
    };

    let notify_fd =
        nono::sandbox::install_seccomp_proxy_filter(has_bind_ports).map_err(|e| e.to_string())?;

    // The filter just installed traps sendmsg(), so the notify fd cannot be
    // transferred with SCM_RIGHTS: that sendmsg would itself block on the
    // not-yet-serviced notify fd. Instead, write the raw fd *number* with
    // plain write(2) (not trapped) and let the parent clone the fd out of
    // this process with pidfd_getfd(2).
    let fd_bytes = notify_fd.as_raw_fd().to_ne_bytes();
    write_all_raw(sock_fd, &fd_bytes).map_err(|e| format!("notify fd handoff write: {}", e))?;

    // Hold the notify fd open until the parent confirms it has cloned it;
    // exec/close before that would tear the listener down (trapped syscalls
    // would fail with ENOSYS instead of being mediated). EOF means the
    // parent went away or gave up — fail closed.
    let mut ack = [0u8; 1];
    read_exact_raw(sock_fd, &mut ack).map_err(|e| format!("notify fd handoff ack: {}", e))?;

    Ok(())
}

/// write(2) a full buffer to a raw fd, retrying on EINTR/partial writes.
#[cfg(target_os = "linux")]
fn write_all_raw(fd: i32, buf: &[u8]) -> IoResult<()> {
    let mut written = 0;
    while written < buf.len() {
        // SAFETY: fd is a valid open socket; the pointer/len describe `buf`.
        let n = unsafe {
            libc::write(
                fd,
                buf[written..].as_ptr().cast::<libc::c_void>(),
                buf.len() - written,
            )
        };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        written += n as usize;
    }
    Ok(())
}

/// read(2) an exact number of bytes from a raw fd, retrying on EINTR.
/// Returns an error on EOF (peer closed).
#[cfg(target_os = "linux")]
fn read_exact_raw(fd: i32, buf: &mut [u8]) -> IoResult<()> {
    let mut filled = 0;
    while filled < buf.len() {
        // SAFETY: fd is a valid open socket; the pointer/len describe `buf`.
        let n = unsafe {
            libc::read(
                fd,
                buf[filled..].as_mut_ptr().cast::<libc::c_void>(),
                buf.len() - filled,
            )
        };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "peer closed during notify fd handoff",
            ));
        }
        filled += n as usize;
    }
    Ok(())
}

/// Close every inherited fd except stdin/stdout/stderr in the forked child.
///
/// Open descriptors are capabilities: a sandbox cannot revoke access that was
/// already represented by an fd before `Sandbox::apply()`. This must run after
/// stdout/stderr are wired to the capture pipes and before applying the sandbox.
fn close_untrusted_fds(keep_fds: &[i32]) -> IoResult<()> {
    #[cfg(target_os = "linux")]
    {
        if keep_fds.is_empty() && close_range_from(3).is_ok() {
            return Ok(());
        }
    }

    close_fds_by_rlimit(3, keep_fds);
    Ok(())
}

#[cfg(target_os = "linux")]
fn close_range_from(first_fd: u32) -> IoResult<()> {
    // SAFETY: close_range closes descriptors in the requested numeric range.
    // Starting at fd 3 preserves stdin/stdout/stderr.
    let ret = unsafe { libc::syscall(libc::SYS_close_range, first_fd, u32::MAX, 0u32) };
    if ret == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn close_fds_by_rlimit(first_fd: i32, keep_fds: &[i32]) {
    let max_fd = open_fd_limit();
    for fd in first_fd..max_fd {
        if keep_fds.contains(&fd) {
            continue;
        }
        // SAFETY: closing an invalid fd is harmless; EBADF is ignored.
        unsafe {
            libc::close(fd);
        }
    }
}

fn open_fd_limit() -> i32 {
    let mut rlimit = std::mem::MaybeUninit::<libc::rlimit>::uninit();
    // SAFETY: getrlimit initializes the provided rlimit on success.
    let ret = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, rlimit.as_mut_ptr()) };
    if ret == 0 {
        // SAFETY: ret == 0 means getrlimit initialized rlimit.
        let rlimit = unsafe { rlimit.assume_init() };
        if rlimit.rlim_cur != libc::RLIM_INFINITY {
            return rlimit.rlim_cur.min(i32::MAX as libc::rlim_t) as i32;
        }
    }

    // SAFETY: sysconf reads a process limit and has no ownership effects.
    let open_max = unsafe { libc::sysconf(libc::_SC_OPEN_MAX) };
    if open_max > 0 {
        open_max.min(i64::from(i32::MAX)) as i32
    } else {
        1024
    }
}

fn set_own_process_group() {
    // SAFETY: setpgid(0, 0) affects only the current child process.
    unsafe {
        libc::setpgid(0, 0);
    }
}

fn set_child_process_group(child_pid: i32) {
    // SAFETY: setpgid(child, child) is allowed while the child is still ours
    // and has not performed an exec that prevents the parent-side update. This
    // is best-effort; the child also calls setpgid(0, 0), and timeout cleanup
    // falls back to killing the direct child if group kill fails.
    unsafe {
        libc::setpgid(child_pid, child_pid);
    }
}

/// Apply the requested `setrlimit` caps in the forked child before exec.
///
/// Each cap sets both the soft and hard limit to the requested value. Returns a
/// human-readable error string identifying which limit failed (the child cannot
/// propagate a `PyErr` back to the parent).
fn apply_resource_limits(ctx: &ForkContext) -> Result<(), String> {
    if let Some(v) = ctx.max_cpu_seconds {
        set_rlimit(libc::RLIMIT_CPU, v).map_err(|e| format!("max_cpu_seconds: {}", e))?;
    }
    if let Some(v) = ctx.max_file_size_bytes {
        set_rlimit(libc::RLIMIT_FSIZE, v).map_err(|e| format!("max_file_size_bytes: {}", e))?;
    }
    // RLIMIT_NPROC is enforced by the OS per real UID, not per sandbox tree.
    if let Some(v) = ctx.max_processes {
        set_rlimit(libc::RLIMIT_NPROC, v).map_err(|e| format!("max_processes: {}", e))?;
    }
    if let Some(v) = ctx.max_open_files {
        set_rlimit(libc::RLIMIT_NOFILE, v).map_err(|e| format!("max_open_files: {}", e))?;
    }
    Ok(())
}

/// Hand the child a less-powerful user/group identity before it runs.
///
/// The parent may be running as root. We don't want the untrusted command to
/// inherit that power, so just before exec we switch the child to the requested
/// user (uid) and group (gid). This only works if the parent is privileged
/// enough to hand out identities; if it isn't, the switch fails and the child
/// aborts rather than running with the wrong privileges.
///
/// Order matters: drop the group first, then the user. Once you give up the
/// powerful user you also lose the right to change groups, so doing it the other
/// way around would leave the group half-changed.
fn drop_privileges(uid: Option<u32>, gid: Option<u32>) -> Result<(), String> {
    // Nothing requested — leave the child's identity untouched.
    if uid.is_none() && gid.is_none() {
        return Ok(());
    }

    forget_inherited_groups()?;

    if let Some(gid) = gid {
        switch_group(gid)?;
    }
    if let Some(uid) = uid {
        switch_user(uid)?;
    }

    Ok(())
}

/// Drop every "extra" group the parent belonged to so the child can't ride in
/// on the parent's group memberships. Must run while still privileged.
fn forget_inherited_groups() -> Result<(), String> {
    // SAFETY: setgroups(0, NULL) clears the supplementary group list for this
    // process only and touches nothing else.
    if unsafe { libc::setgroups(0, std::ptr::null::<libc::gid_t>()) } != 0 {
        return Err(format!("setgroups: {}", std::io::Error::last_os_error()));
    }
    Ok(())
}

/// Switch the child to group `gid`, then read the identity back to make sure it
/// actually changed. We don't trust "the call returned success" alone — if the
/// group didn't fully change we abort instead of running with the wrong group.
fn switch_group(gid: u32) -> Result<(), String> {
    // SAFETY: setgid changes only this process's group identity.
    if unsafe { libc::setgid(gid as libc::gid_t) } != 0 {
        return Err(format!(
            "setgid({}): {}",
            gid,
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: getgid/getegid just read the current ids; no side effects.
    let real = unsafe { libc::getgid() };
    let effective = unsafe { libc::getegid() };
    if real != gid as libc::gid_t || effective != gid as libc::gid_t {
        return Err(format!("setgid({}) did not fully take effect", gid));
    }
    Ok(())
}

/// Switch the child to user `uid`, then read it back to confirm. Same paranoia
/// as switch_group: a successful-looking call that didn't really drop the user
/// would leave the child with the parent's power, so we verify and abort if not.
fn switch_user(uid: u32) -> Result<(), String> {
    // SAFETY: setuid changes only this process's user identity.
    if unsafe { libc::setuid(uid as libc::uid_t) } != 0 {
        return Err(format!(
            "setuid({}): {}",
            uid,
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: getuid/geteuid just read the current ids; no side effects.
    let real = unsafe { libc::getuid() };
    let effective = unsafe { libc::geteuid() };
    if real != uid as libc::uid_t || effective != uid as libc::uid_t {
        return Err(format!("setuid({}) did not fully take effect", uid));
    }
    Ok(())
}

fn set_nonblocking(fd: i32) -> IoResult<()> {
    // SAFETY: fcntl() is safe for a valid fd and does not take ownership.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }

    // SAFETY: fcntl(F_SETFL) updates status flags for this fd.
    let ret = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn read_pipe_until_eof_or_cancel(fd: i32, cancel: Arc<AtomicBool>) -> IoResult<Vec<u8>> {
    // SAFETY: This thread owns the read fd passed by the parent.
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];

    loop {
        if cancel.load(Ordering::Relaxed) {
            return Ok(buf);
        }

        match file.read(&mut chunk) {
            Ok(0) => return Ok(buf),
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if cancel.load(Ordering::Relaxed) {
                    return Ok(buf);
                }
                poll_readable(file.as_raw_fd(), Duration::from_millis(10))?;
            }
            Err(e) => return Err(e),
        }
    }
}

fn poll_readable(fd: i32, timeout: Duration) -> IoResult<()> {
    let timeout_ms = timeout.as_millis().min(i32::MAX as u128) as i32;
    loop {
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
            revents: 0,
        };
        // SAFETY: poll is safe with a valid pointer to one pollfd.
        let ret = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
        if ret >= 0 {
            return Ok(());
        }

        let err = std::io::Error::last_os_error();
        if err.kind() != std::io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

/// Parent process: close write ends, read output, wait for child.
fn parent_process(
    child_pid: i32,
    stdout_pipe: &PipeFds,
    stderr_pipe: &PipeFds,
    ctx: &ForkContext,
    #[cfg(target_os = "linux")] mut proxy_supervisor: Option<ProxySupervisor>,
) -> PyResult<ExecResult> {
    // Close write ends (child writes, parent reads)
    unsafe {
        libc::close(stdout_pipe.write_fd);
        libc::close(stderr_pipe.write_fd);
    }

    // Capture read fds before spawning threads (moved into closures)
    let stdout_read = stdout_pipe.read_fd;
    let stderr_read = stderr_pipe.read_fd;
    if let Err(e) = set_nonblocking(stdout_read).and_then(|_| set_nonblocking(stderr_read)) {
        unsafe {
            libc::close(stdout_read);
            libc::close(stderr_read);
        }
        return Err(PyRuntimeError::new_err(format!(
            "fcntl(O_NONBLOCK) failed: {}",
            e
        )));
    }
    let cancel_readers = Arc::new(AtomicBool::new(false));

    // Spawn reader threads to drain pipes concurrently.
    // Prevents deadlock when child output exceeds pipe buffer.
    let stdout_cancel = Arc::clone(&cancel_readers);
    let stdout_handle = std::thread::spawn(move || {
        read_pipe_until_eof_or_cancel(stdout_read, stdout_cancel).unwrap_or_default()
    });

    let stderr_cancel = Arc::clone(&cancel_readers);
    let stderr_handle = std::thread::spawn(move || {
        read_pipe_until_eof_or_cancel(stderr_read, stderr_cancel).unwrap_or_default()
    });

    let exit_code = match wait_for_child(
        child_pid,
        ctx.timeout_secs,
        &cancel_readers,
        #[cfg(target_os = "linux")]
        proxy_supervisor.as_mut(),
    ) {
        Ok(code) => code,
        Err(e) => {
            // wait_for_child bailed before reaping (e.g. a proxy notify-fd
            // handshake failure). Kill and reap the child so it does not
            // linger as a zombie, and unblock+join the reader threads, before
            // propagating the error.
            cancel_readers.store(true, Ordering::Relaxed);
            // SAFETY: valid child pid; kill the group then reap the child.
            unsafe {
                kill_process_group_or_child(child_pid);
                let mut status: i32 = 0;
                libc::waitpid(child_pid, &mut status, 0);
            }
            let _ = stdout_handle.join();
            let _ = stderr_handle.join();
            return Err(e);
        }
    };

    let stdout_buf = stdout_handle.join().unwrap_or_default();
    let stderr_buf = stderr_handle.join().unwrap_or_default();
    let session_report = crate::diagnostic::build_session_report_from_exec(
        exit_code,
        &stderr_buf,
        ctx.cwd.as_deref(),
        &ctx.caps,
    );

    Ok(ExecResult {
        stdout: stdout_buf,
        stderr: stderr_buf,
        exit_code,
        session_report,
    })
}

#[cfg(target_os = "linux")]
fn create_proxy_supervisor(
    proxy_supervisor_pair: Option<(nono::SupervisorSocket, nono::SupervisorSocket)>,
    proxy_policy: Option<ProxyOnlyPolicy>,
    child_pid: i32,
) -> Option<ProxySupervisor> {
    let (supervisor_sock, child_sock) = proxy_supervisor_pair?;
    drop(child_sock);
    Some(ProxySupervisor {
        sock: Some(supervisor_sock),
        notify_fd: None,
        policy: proxy_policy?,
        child_pid,
    })
}

/// Wait for child process, with optional timeout.
/// Returns the exit code, or -signal_number if killed by signal.
fn wait_for_child(
    child_pid: i32,
    timeout_secs: Option<f64>,
    cancel_readers: &AtomicBool,
    #[cfg(target_os = "linux")] mut proxy_supervisor: Option<&mut ProxySupervisor>,
) -> PyResult<i32> {
    let deadline = timeout_secs.map(|t| Instant::now() + Duration::from_secs_f64(t));

    // A blocking waitpid() would starve the proxy notify fd: the child's
    // first trapped syscall (and the notify fd handshake itself) would then
    // wedge forever. Poll whenever there is a supervisor to service, not
    // only when a timeout deadline exists.
    #[cfg(target_os = "linux")]
    let must_poll = deadline.is_some() || proxy_supervisor.is_some();
    #[cfg(not(target_os = "linux"))]
    let must_poll = deadline.is_some();

    loop {
        #[cfg(target_os = "linux")]
        service_proxy_supervisor(proxy_supervisor.as_deref_mut())?;

        let mut status: i32 = 0;
        // SAFETY: waitpid is safe with a valid pid.
        let ret = unsafe {
            libc::waitpid(
                child_pid,
                &mut status,
                if must_poll { libc::WNOHANG } else { 0 },
            )
        };

        if ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(PyRuntimeError::new_err(format!(
                "waitpid() failed: {}",
                err
            )));
        }

        if ret == 0 {
            // Child still running (WNOHANG returned 0)
            if let Some(dl) = deadline
                && Instant::now() >= dl
            {
                cancel_readers.store(true, Ordering::Relaxed);
                unsafe {
                    kill_process_group_or_child(child_pid);
                    libc::waitpid(child_pid, &mut status, 0);
                }
                #[cfg(target_os = "linux")]
                service_proxy_supervisor(proxy_supervisor.as_deref_mut())?;
                return Ok(124);
            }
            std::thread::sleep(Duration::from_millis(10));
            continue;
        }

        // Child exited — extract status
        #[allow(unused_unsafe)]
        if unsafe { libc::WIFEXITED(status) } {
            #[allow(unused_unsafe)]
            return Ok(unsafe { libc::WEXITSTATUS(status) });
        }
        #[allow(unused_unsafe)]
        if unsafe { libc::WIFSIGNALED(status) } {
            #[allow(unused_unsafe)]
            return Ok(-(unsafe { libc::WTERMSIG(status) }));
        }

        return Err(PyRuntimeError::new_err(
            "Child process exited with unexpected status",
        ));
    }
}

unsafe fn kill_process_group_or_child(child_pid: i32) {
    // Negative pid targets the process group whose id is child_pid. If the
    // process-group setup raced or failed, fall back to the direct child.
    let group_ret = unsafe { libc::kill(-child_pid, libc::SIGKILL) };
    if group_ret != 0 {
        unsafe {
            libc::kill(child_pid, libc::SIGKILL);
        }
    }
}

#[cfg(target_os = "linux")]
fn service_proxy_supervisor(proxy_supervisor: Option<&mut ProxySupervisor>) -> PyResult<()> {
    let Some(supervisor) = proxy_supervisor else {
        return Ok(());
    };

    if supervisor.notify_fd.is_none() {
        try_receive_proxy_notify_fd(supervisor)?;
    }

    let Some(fd) = supervisor.notify_fd.as_ref() else {
        return Ok(());
    };

    loop {
        let mut pfd = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: poll is safe with a valid pointer to one pollfd.
        let ret = unsafe { libc::poll(&mut pfd, 1, 0) };
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(PyRuntimeError::new_err(format!(
                "proxy supervisor poll() failed: {}",
                err
            )));
        }
        if ret == 0 || pfd.revents & libc::POLLIN == 0 {
            return Ok(());
        }

        handle_proxy_notification(fd.as_raw_fd(), &supervisor.policy)?;
    }
}

#[cfg(target_os = "linux")]
fn try_receive_proxy_notify_fd(supervisor: &mut ProxySupervisor) -> PyResult<()> {
    let Some(sock) = supervisor.sock.as_ref() else {
        return Ok(());
    };

    let mut pfd = libc::pollfd {
        fd: sock.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: poll is safe with a valid pointer to one pollfd.
    let ret = unsafe { libc::poll(&mut pfd, 1, 0) };
    if ret < 0 {
        let err = std::io::Error::last_os_error();
        if err.kind() == std::io::ErrorKind::Interrupted {
            return Ok(());
        }
        return Err(PyRuntimeError::new_err(format!(
            "proxy supervisor socket poll() failed: {}",
            err
        )));
    }
    if ret == 0 {
        return Ok(());
    }

    if pfd.revents & libc::POLLIN != 0 {
        // The child writes the notify fd *number* with plain write(2)
        // (SCM_RIGHTS would be trapped by the proxy filter it just
        // installed). This function is reached only by the explicitly selected
        // NONO_PY_PROXY_HANDOFF=pidfd rollback path.
        let remote_fd = match sock.recv_raw_fd_number() {
            Ok(fd) => fd,
            Err(_) => {
                supervisor.sock = None;
                return Ok(());
            }
        };

        // Serialize legacy listener insertion into the parent table with the
        // clone-files before/after snapshot. Once wrapped, its eventual close
        // is protected by the same mutex.
        let bootstrap_guard = SHARED_BOOTSTRAP_MUTEX
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match clone_fd_from_child(supervisor.child_pid, remote_fd) {
            Ok(local_fd) => {
                supervisor.notify_fd = Some(ProxyNotifyFd::new(local_fd));
                drop(bootstrap_guard);
                let ack = [1u8];
                // SAFETY: sock is a valid open socketpair fd; 1-byte write.
                let ret = unsafe { libc::write(sock.as_raw_fd(), ack.as_ptr().cast(), 1) };
                supervisor.sock = None;
                if ret != 1 {
                    return Err(PyRuntimeError::new_err(format!(
                        "proxy supervisor handshake ack failed: {}",
                        std::io::Error::last_os_error()
                    )));
                }
            }
            Err(e) => {
                drop(bootstrap_guard);
                // Drop the socket so the child's ack read sees EOF and it
                // fails closed instead of waiting forever.
                supervisor.sock = None;
                // Keep this hint scoped to the explicitly selected rollback
                // path.  The default clone-files handoff needs no capability.
                let hint = if e.raw_os_error() == Some(libc::EPERM) {
                    " — pidfd_getfd is blocked by the container seccomp profile. \
                     NONO_PY_PROXY_HANDOFF=pidfd selected the legacy rollback \
                     implementation; unset it to use the capability-free \
                     clone-files handoff. Older releases on ECS-EC2/EKS can \
                     instead use a custom profile allowing only pidfd_getfd"
                } else {
                    " — requires kernel >= 5.6 and ptrace access to the child"
                };
                return Err(PyRuntimeError::new_err(format!(
                    "proxy-only notify fd handoff failed (pidfd_getfd): {}{}",
                    e, hint
                )));
            }
        }
        return Ok(());
    }

    if pfd.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
        supervisor.sock = None;
    }

    Ok(())
}

/// Legacy rollback: clone a file descriptor out of the child via pidfd_getfd(2).
///
/// Requires kernel >= 5.6 and PTRACE_MODE_ATTACH_REALCREDS permission over
/// the child (a direct parent has this under default Yama settings).
///
/// Caveat: a container seccomp profile can still block the pidfd_getfd
/// syscall itself even when ptrace permission is granted. The Docker /
/// containerd / ECS default profile allows pidfd_getfd only with
/// CAP_SYS_PTRACE, so the explicitly selected rollback path returns EPERM
/// there. The default CLONE_FILES handoff does not call either pidfd syscall.
#[cfg(target_os = "linux")]
fn clone_fd_from_child(child_pid: i32, remote_fd: i32) -> IoResult<OwnedFd> {
    // SAFETY: pidfd_open has no libc wrapper; arguments are a valid pid and
    // zero flags. On success it returns a new pidfd owned by us.
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, child_pid, 0u32) };
    if pidfd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let pidfd = pidfd as i32;

    // SAFETY: pidfd_getfd duplicates remote_fd from the target into our fd
    // table; zero flags. The returned fd (if >= 0) is owned by us.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_getfd, pidfd, remote_fd, 0u32) };
    let getfd_err = std::io::Error::last_os_error();
    // SAFETY: pidfd is a valid fd we own; closing it does not affect the child.
    unsafe {
        libc::close(pidfd);
    }
    if fd < 0 {
        return Err(getfd_err);
    }
    // SAFETY: fd is a fresh descriptor returned by pidfd_getfd, owned by us.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
}

#[cfg(target_os = "linux")]
fn handle_proxy_notification(notify_fd: i32, policy: &ProxyOnlyPolicy) -> PyResult<()> {
    use nono::sandbox::{
        SYS_BIND, SYS_CONNECT, SYS_SENDMMSG, SYS_SENDMSG, SYS_SENDTO, continue_notif, deny_notif,
        notif_id_valid, recv_notif, respond_notif_errno,
    };

    let notif = recv_notif(notify_fd).map_err(proxy_supervisor_err)?;
    let pid = notif.pid;
    let args = notif.data.args;

    // Destination-less sends (NULL sockaddr) go to a peer the socket is
    // already connected to; that connect() was itself mediated, so they are
    // allowed. Everything else must name the proxy (or an allowed bind port).
    let allow = match notif.data.nr {
        SYS_CONNECT => sockaddr_allowed(pid, args[1], args[2], policy, false),
        SYS_BIND => sockaddr_allowed(pid, args[1], args[2], policy, true),
        // sendto(fd, buf, len, flags, dest_addr, addrlen)
        SYS_SENDTO => {
            if args[4] == 0 || args[5] == 0 {
                Some(true)
            } else {
                sockaddr_allowed(pid, args[4], args[5], policy, false)
            }
        }
        // sendmsg(fd, msghdr*, flags): destination is msghdr.msg_name
        SYS_SENDMSG => match nono::sandbox::read_msghdr_dest(pid, args[1]) {
            Ok(None) => Some(true),
            Ok(Some((addr_ptr, addrlen))) => {
                sockaddr_allowed(pid, addr_ptr, addrlen, policy, false)
            }
            Err(_) => None,
        },
        // sendmmsg(fd, msgvec, vlen, flags): every message may carry its own
        // destination; all of them must be allowed.
        SYS_SENDMMSG => match nono::sandbox::read_mmsghdr_dests(pid, args[1], args[2]) {
            Ok(dests) => dests.into_iter().try_fold(true, |acc, dest| match dest {
                None => Some(acc),
                Some((addr_ptr, addrlen)) => {
                    sockaddr_allowed(pid, addr_ptr, addrlen, policy, false).map(|a| acc && a)
                }
            }),
            Err(_) => None,
        },
        _ => Some(false),
    };

    // A parse failure means the child's memory could not be read coherently;
    // deny without classifying.
    let Some(allow) = allow else {
        let _ = deny_notif(notify_fd, notif.id);
        return Ok(());
    };

    if !notif_id_valid(notify_fd, notif.id).map_err(proxy_supervisor_err)? {
        return Ok(());
    }

    if allow {
        continue_notif(notify_fd, notif.id).map_err(proxy_supervisor_err)
    } else {
        respond_notif_errno(notify_fd, notif.id, libc::EACCES).map_err(proxy_supervisor_err)
    }
}

/// Read a sockaddr from the child's memory and evaluate it against the
/// proxy-only policy. `for_bind` selects the bind-port allowlist instead of
/// the proxy destination check. Returns `None` if the sockaddr cannot be read.
#[cfg(target_os = "linux")]
fn sockaddr_allowed(
    pid: u32,
    addr_ptr: u64,
    addrlen: u64,
    policy: &ProxyOnlyPolicy,
    for_bind: bool,
) -> Option<bool> {
    let sockaddr = nono::sandbox::read_notif_sockaddr(pid, addr_ptr, addrlen).ok()?;
    Some(if for_bind {
        policy.bind_ports.contains(&sockaddr.port)
    } else {
        sockaddr.is_loopback && sockaddr.port == policy.proxy_port
    })
}

#[cfg(target_os = "linux")]
fn proxy_supervisor_err(e: nono::NonoError) -> PyErr {
    PyRuntimeError::new_err(format!("proxy supervisor failed: {}", e))
}

#[cfg(target_os = "linux")]
fn proxy_only_policy(caps: &nono::CapabilitySet) -> Option<ProxyOnlyPolicy> {
    match caps.network_mode() {
        nono::NetworkMode::ProxyOnly { port, bind_ports } => Some(ProxyOnlyPolicy {
            proxy_port: *port,
            bind_ports: bind_ports.clone(),
        }),
        _ => None,
    }
}

/// Resolve a program name to its absolute, canonical path by searching PATH.
///
/// Canonicalization matters on macOS: Seatbelt `file-map-executable` rules are
/// emitted for resolved grant paths, so execve must use the symlink target path
/// (e.g. uv-managed interpreters under `~/.local/share/uv/python/...`).
fn resolve_program(program: &str) -> PyResult<PathBuf> {
    let path = Path::new(program);

    if program.contains('/') {
        return canonicalize_existing_program(path, program);
    }

    if let Ok(path_var) = std::env::var("PATH") {
        for dir in path_var.split(':') {
            let candidate = Path::new(dir).join(program);
            if candidate.is_file() {
                return canonicalize_existing_program(&candidate, program);
            }
        }
    }

    Err(PyRuntimeError::new_err(format!(
        "Program not found in PATH: {}",
        program
    )))
}

fn canonicalize_existing_program(path: &Path, display: &str) -> PyResult<PathBuf> {
    if !path.exists() {
        return Err(PyRuntimeError::new_err(format!(
            "Program not found: {}",
            display
        )));
    }

    std::fs::canonicalize(path).map_err(|e| {
        PyRuntimeError::new_err(format!("Cannot resolve program path '{}': {}", display, e))
    })
}

/// Get the number of threads in the current process (Linux only).
#[cfg(target_os = "linux")]
fn get_thread_count() -> Result<usize, String> {
    let status = std::fs::read_to_string("/proc/self/status")
        .map_err(|e| format!("Cannot read /proc/self/status: {}", e))?;
    for line in status.lines() {
        if let Some(count_str) = line.strip_prefix("Threads:") {
            return count_str
                .trim()
                .parse()
                .map_err(|_| "Cannot parse thread count".to_string());
        }
    }
    Err("Threads field not found in /proc/self/status".to_string())
}

#[cfg(test)]
mod tests {
    use super::{ResolvedIds, resolve_ids};

    #[test]
    fn nothing_requested_is_left_untouched() {
        assert_eq!(
            resolve_ids(None, None).unwrap(),
            ResolvedIds {
                uid: None,
                gid: None
            }
        );
    }

    #[test]
    fn uid_only_defaults_gid_to_uid() {
        assert_eq!(
            resolve_ids(Some(1000), None).unwrap(),
            ResolvedIds {
                uid: Some(1000),
                gid: Some(1000)
            }
        );
    }

    #[test]
    fn explicit_gid_wins_over_default() {
        assert_eq!(
            resolve_ids(Some(1000), Some(2000)).unwrap(),
            ResolvedIds {
                uid: Some(1000),
                gid: Some(2000)
            }
        );
    }

    #[test]
    fn gid_only_leaves_uid_none() {
        assert_eq!(
            resolve_ids(None, Some(2000)).unwrap(),
            ResolvedIds {
                uid: None,
                gid: Some(2000)
            }
        );
    }

    #[test]
    fn matching_uid_gid_pass_through() {
        assert_eq!(
            resolve_ids(Some(1000), Some(1000)).unwrap(),
            ResolvedIds {
                uid: Some(1000),
                gid: Some(1000)
            }
        );
    }

    #[test]
    fn zero_uid_is_rejected() {
        assert!(
            resolve_ids(Some(0), None)
                .unwrap_err()
                .contains("uid must be non-zero")
        );
    }

    #[test]
    fn zero_gid_is_rejected() {
        assert!(
            resolve_ids(Some(1000), Some(0))
                .unwrap_err()
                .contains("gid must be non-zero")
        );
    }

    #[test]
    fn zero_gid_alone_is_rejected() {
        assert!(
            resolve_ids(None, Some(0))
                .unwrap_err()
                .contains("gid must be non-zero")
        );
    }

    #[test]
    fn zero_uid_rejected_before_defaulting() {
        // Must reject rather than quietly turn into gid = 0.
        assert!(resolve_ids(Some(0), None).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn close_range_empty_unshare_detaches_fd_table() {
        let mut sockets = [-1_i32; 2];
        assert_eq!(
            unsafe {
                libc::socketpair(
                    libc::AF_UNIX,
                    libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
                    0,
                    sockets.as_mut_ptr(),
                )
            },
            0
        );
        let mut flag_probe = [-1_i32; 2];
        assert_eq!(
            unsafe { libc::pipe2(flag_probe.as_mut_ptr(), libc::O_CLOEXEC) },
            0
        );

        let pid = unsafe {
            libc::syscall(
                libc::SYS_clone,
                libc::CLONE_FILES | libc::SIGCHLD,
                0,
                0,
                0,
                0,
            )
        };
        assert!(pid >= 0);
        if pid == 0 {
            let detached = unsafe {
                libc::syscall(
                    libc::SYS_close_range,
                    u32::MAX,
                    u32::MAX,
                    super::CLOSE_RANGE_UNSHARE,
                )
            };
            if detached < 0 {
                unsafe { libc::_exit(10) };
            }
            super::raw_close(sockets[0]);
            let child_cleared_cloexec =
                unsafe { libc::syscall(libc::SYS_fcntl, flag_probe[0], libc::F_SETFD, 0) };
            let child_fd = unsafe {
                libc::syscall(
                    libc::SYS_memfd_create,
                    c"nono-child-private".as_ptr(),
                    libc::MFD_CLOEXEC,
                ) as i32
            };
            let mut child_stat: libc::stat = unsafe { std::mem::zeroed() };
            let child_stat_ok = child_fd >= 0
                && unsafe { libc::syscall(libc::SYS_fstat, child_fd, &raw mut child_stat) == 0 };
            let mut child_identity = [0_u8; 20];
            child_identity[..4].copy_from_slice(&child_fd.to_ne_bytes());
            child_identity[4..12].copy_from_slice(&(child_stat.st_dev as u64).to_ne_bytes());
            child_identity[12..].copy_from_slice(&(child_stat.st_ino as u64).to_ne_bytes());
            if child_cleared_cloexec < 0
                || child_fd < 0
                || !child_stat_ok
                || !super::raw_write_all(sockets[1], &[super::HANDSHAKE_DETACHED])
                || !super::raw_write_all(sockets[1], &child_identity)
            {
                unsafe { libc::_exit(11) };
            }
            let mut parent_identity = [0_u8; 20];
            if !super::raw_read_exact(sockets[1], &mut parent_identity) {
                unsafe { libc::_exit(12) };
            }
            let parent_fd = i32::from_ne_bytes(parent_identity[..4].try_into().unwrap());
            let parent_dev = u64::from_ne_bytes(parent_identity[4..12].try_into().unwrap());
            let parent_ino = u64::from_ne_bytes(parent_identity[12..].try_into().unwrap());
            let mut observed_parent_stat: libc::stat = unsafe { std::mem::zeroed() };
            let parent_visible =
                unsafe { libc::syscall(libc::SYS_fstat, parent_fd, &raw mut observed_parent_stat) }
                    == 0;
            let ok = !parent_visible
                || observed_parent_stat.st_dev as u64 != parent_dev
                || observed_parent_stat.st_ino as u64 != parent_ino;
            let child_flags =
                unsafe { libc::syscall(libc::SYS_fcntl, flag_probe[1], libc::F_GETFD) };
            let ok = ok && child_flags >= 0 && child_flags & libc::FD_CLOEXEC as libc::c_long != 0;
            let _ = super::raw_write_all(sockets[1], &[u8::from(ok)]);
            unsafe { libc::_exit(if ok { 0 } else { 13 }) };
        }

        let mut detached = [0_u8; 1];
        super::read_exact_raw(sockets[0], &mut detached).unwrap();
        assert_eq!(detached[0], super::HANDSHAKE_DETACHED);
        assert_ne!(
            unsafe { libc::fcntl(flag_probe[0], libc::F_GETFD) } & libc::FD_CLOEXEC,
            0,
            "the child's descriptor-flag change reached the parent table"
        );
        unsafe { libc::close(sockets[1]) };
        let mut child_identity = [0_u8; 20];
        super::read_exact_raw(sockets[0], &mut child_identity).unwrap();
        let child_fd = i32::from_ne_bytes(child_identity[..4].try_into().unwrap());
        let child_dev = u64::from_ne_bytes(child_identity[4..12].try_into().unwrap());
        let child_ino = u64::from_ne_bytes(child_identity[12..].try_into().unwrap());
        let mut observed_child_stat: libc::stat = unsafe { std::mem::zeroed() };
        let child_visible = unsafe { libc::fstat(child_fd, &raw mut observed_child_stat) } == 0;
        assert!(
            !child_visible
                || observed_child_stat.st_dev as u64 != child_dev
                || observed_child_stat.st_ino as u64 != child_ino,
            "the child's newly opened file reached the parent table"
        );

        let parent_fd = unsafe {
            libc::syscall(
                libc::SYS_memfd_create,
                c"nono-parent-private".as_ptr(),
                libc::MFD_CLOEXEC,
            ) as i32
        };
        assert!(parent_fd >= 0);
        let mut parent_stat: libc::stat = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::fstat(parent_fd, &raw mut parent_stat) }, 0);
        let mut parent_identity = [0_u8; 20];
        parent_identity[..4].copy_from_slice(&parent_fd.to_ne_bytes());
        parent_identity[4..12].copy_from_slice(&(parent_stat.st_dev as u64).to_ne_bytes());
        parent_identity[12..].copy_from_slice(&(parent_stat.st_ino as u64).to_ne_bytes());
        assert_eq!(unsafe { libc::fcntl(flag_probe[1], libc::F_SETFD, 0) }, 0);
        super::write_all_raw(sockets[0], &parent_identity).unwrap();
        let mut result = [0_u8; 1];
        super::read_exact_raw(sockets[0], &mut result).unwrap();
        assert_eq!(result[0], 1);

        let mut status = 0;
        assert_eq!(
            unsafe { libc::waitpid(pid as i32, &mut status, 0) },
            pid as i32
        );
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
        unsafe {
            libc::close(parent_fd);
            libc::close(sockets[0]);
            libc::close(flag_probe[0]);
            libc::close(flag_probe[1]);
        }
    }

    #[cfg(all(target_os = "linux", debug_assertions))]
    #[test]
    fn raw_clone_allocator_guard_terminates_allocating_child() {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            crate::arm_raw_clone_allocator_guard();
            let allocation = vec![0_u8; 4096];
            std::hint::black_box(allocation);
            unsafe { libc::_exit(1) };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 125);
    }
}
