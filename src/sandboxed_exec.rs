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
use std::ffi::CString;
use std::io::{Read, Result as IoResult};
use std::os::fd::FromRawFd;
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

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
    notify_fd: Option<OwnedFd>,
    policy: ProxyOnlyPolicy,
}

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
///
/// Returns:
///     ExecResult with stdout, stderr, and exit_code
///
/// Raises:
///     RuntimeError: If fork fails, sandbox cannot be applied, or the
///         command cannot be executed
///     ValueError: If the command list is empty or timeout is negative
#[pyfunction]
#[pyo3(signature = (caps, command, cwd=None, timeout_secs=None, env=None, inherit_env=false))]
pub fn sandboxed_exec(
    py: Python<'_>,
    caps: &CapabilitySet,
    command: Vec<String>,
    cwd: Option<String>,
    timeout_secs: Option<f64>,
    env: Option<Vec<(String, String)>>,
    inherit_env: bool,
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

    // Verify threading before fork on Linux.
    #[cfg(target_os = "linux")]
    {
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

    // Prepare all data before fork (allocation-safe zone)
    let ctx = prepare_fork_context(&caps.inner, &command, cwd, timeout_secs, env, inherit_env)?;

    #[cfg(target_os = "linux")]
    let proxy_supervisor_pair = create_proxy_supervisor_pair(&ctx)?;

    // Create pipes for stdout and stderr
    let stdout_pipe = create_pipe()?;
    let stderr_pipe = create_pipe()?;

    // Release the GIL during fork+wait so other Python threads can proceed
    py.detach(|| {
        #[cfg(target_os = "linux")]
        {
            do_fork_sandbox_exec(&ctx, &stdout_pipe, &stderr_pipe, proxy_supervisor_pair)
        }
        #[cfg(not(target_os = "linux"))]
        {
            do_fork_sandbox_exec(&ctx, &stdout_pipe, &stderr_pipe)
        }
    })
}

/// Prepare all data needed for fork+exec while allocation is safe.
fn prepare_fork_context(
    caps: &nono::CapabilitySet,
    command: &[String],
    cwd: Option<String>,
    timeout_secs: Option<f64>,
    env: Option<Vec<(String, String)>>,
    inherit_env: bool,
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
    })
}

#[cfg(target_os = "linux")]
fn create_proxy_supervisor_pair(
    ctx: &ForkContext,
) -> PyResult<Option<(nono::SupervisorSocket, nono::SupervisorSocket)>> {
    if proxy_only_policy(&ctx.caps).is_none() {
        return Ok(None);
    }

    nono::SupervisorSocket::pair()
        .map(Some)
        .map_err(|e| PyRuntimeError::new_err(format!("Failed to create proxy supervisor: {}", e)))
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
    ctx: &ForkContext,
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

    // SAFETY: fork() creates a child process. We validated threading
    // context above. Sandbox::apply() allocates in the child, which is
    // safe because only the forking thread continues after fork.
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

    // === PARENT PROCESS ===
    parent_process(
        pid,
        stdout_pipe,
        stderr_pipe,
        ctx,
        #[cfg(target_os = "linux")]
        proxy_supervisor_pair,
        #[cfg(target_os = "linux")]
        proxy_only_policy(&ctx.caps),
    )
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
        let detail = format!("nono: failed to close inherited file descriptors: {}\n", e);
        let msg = detail.as_bytes();
        unsafe {
            libc::write(
                libc::STDERR_FILENO,
                msg.as_ptr().cast::<libc::c_void>(),
                msg.len(),
            );
            libc::_exit(126);
        }
    }

    // Change working directory if specified
    if let Some(ref dir) = ctx.cwd_c {
        unsafe {
            if libc::chdir(dir.as_ptr()) != 0 {
                let msg = b"nono: failed to chdir\n";
                libc::write(
                    libc::STDERR_FILENO,
                    msg.as_ptr().cast::<libc::c_void>(),
                    msg.len(),
                );
                libc::_exit(126);
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        match Sandbox::apply(&ctx.caps) {
            Ok(fallback) => {
                if let Err(e) =
                    install_proxy_fallback_if_needed(&ctx.caps, fallback, proxy_child_fd)
                {
                    let detail = format!("nono: proxy-only supervisor setup failed: {}\n", e);
                    let msg = detail.as_bytes();
                    unsafe {
                        libc::write(
                            libc::STDERR_FILENO,
                            msg.as_ptr().cast::<libc::c_void>(),
                            msg.len(),
                        );
                        libc::_exit(126);
                    }
                }
            }
            Err(e) => {
                let detail = format!("nono: sandbox apply failed: {}\n", e);
                let msg = detail.as_bytes();
                unsafe {
                    libc::write(
                        libc::STDERR_FILENO,
                        msg.as_ptr().cast::<libc::c_void>(),
                        msg.len(),
                    );
                    libc::_exit(126);
                }
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        if let Err(e) = Sandbox::apply(&ctx.caps) {
            let detail = format!("nono: sandbox apply failed: {}\n", e);
            let msg = detail.as_bytes();
            unsafe {
                libc::write(
                    libc::STDERR_FILENO,
                    msg.as_ptr().cast::<libc::c_void>(),
                    msg.len(),
                );
                libc::_exit(126);
            }
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
    nono::supervisor::socket::send_fd_via_socket(sock_fd, notify_fd.as_raw_fd())
        .map_err(|e| e.to_string())
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

/// Parent process: close write ends, read output, wait for child.
fn parent_process(
    child_pid: i32,
    stdout_pipe: &PipeFds,
    stderr_pipe: &PipeFds,
    ctx: &ForkContext,
    #[cfg(target_os = "linux")] proxy_supervisor_pair: Option<(
        nono::SupervisorSocket,
        nono::SupervisorSocket,
    )>,
    #[cfg(target_os = "linux")] proxy_policy: Option<ProxyOnlyPolicy>,
) -> PyResult<ExecResult> {
    // Close write ends (child writes, parent reads)
    unsafe {
        libc::close(stdout_pipe.write_fd);
        libc::close(stderr_pipe.write_fd);
    }

    #[cfg(target_os = "linux")]
    let mut proxy_supervisor = create_proxy_supervisor(proxy_supervisor_pair, proxy_policy);

    // Capture read fds before spawning threads (moved into closures)
    let stdout_read = stdout_pipe.read_fd;
    let stderr_read = stderr_pipe.read_fd;

    // Spawn reader threads to drain pipes concurrently.
    // Prevents deadlock when child output exceeds pipe buffer.
    let stdout_handle = std::thread::spawn(move || {
        // SAFETY: We own this fd and it is a valid pipe read end.
        let mut file = unsafe { std::fs::File::from_raw_fd(stdout_read) };
        let mut buf = Vec::new();
        let _ = file.read_to_end(&mut buf);
        buf
    });

    let stderr_handle = std::thread::spawn(move || {
        // SAFETY: We own this fd and it is a valid pipe read end.
        let mut file = unsafe { std::fs::File::from_raw_fd(stderr_read) };
        let mut buf = Vec::new();
        let _ = file.read_to_end(&mut buf);
        buf
    });

    let exit_code = wait_for_child(
        child_pid,
        ctx.timeout_secs,
        #[cfg(target_os = "linux")]
        proxy_supervisor.as_mut(),
    )?;

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
) -> Option<ProxySupervisor> {
    let (supervisor_sock, child_sock) = proxy_supervisor_pair?;
    drop(child_sock);
    Some(ProxySupervisor {
        sock: Some(supervisor_sock),
        notify_fd: None,
        policy: proxy_policy?,
    })
}

/// Wait for child process, with optional timeout.
/// Returns the exit code, or -signal_number if killed by signal.
fn wait_for_child(
    child_pid: i32,
    timeout_secs: Option<f64>,
    #[cfg(target_os = "linux")] mut proxy_supervisor: Option<&mut ProxySupervisor>,
) -> PyResult<i32> {
    let deadline = timeout_secs.map(|t| Instant::now() + Duration::from_secs_f64(t));

    loop {
        #[cfg(target_os = "linux")]
        service_proxy_supervisor(proxy_supervisor.as_deref_mut())?;

        let mut status: i32 = 0;
        // SAFETY: waitpid is safe with a valid pid.
        let ret = unsafe {
            libc::waitpid(
                child_pid,
                &mut status,
                if deadline.is_some() { libc::WNOHANG } else { 0 },
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
                unsafe {
                    libc::kill(child_pid, libc::SIGKILL);
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
        supervisor.notify_fd = sock.recv_fd().ok();
        supervisor.sock = None;
        return Ok(());
    }

    if pfd.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
        supervisor.sock = None;
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn handle_proxy_notification(notify_fd: i32, policy: &ProxyOnlyPolicy) -> PyResult<()> {
    use nono::sandbox::{
        SYS_BIND, SYS_CONNECT, continue_notif, deny_notif, notif_id_valid, read_notif_sockaddr,
        recv_notif, respond_notif_errno,
    };

    let notif = recv_notif(notify_fd).map_err(proxy_supervisor_err)?;
    let sockaddr = match read_notif_sockaddr(notif.pid, notif.data.args[1], notif.data.args[2]) {
        Ok(info) => info,
        Err(_) => {
            let _ = deny_notif(notify_fd, notif.id);
            return Ok(());
        }
    };

    if !notif_id_valid(notify_fd, notif.id).map_err(proxy_supervisor_err)? {
        return Ok(());
    }

    let allow = match notif.data.nr {
        SYS_CONNECT => sockaddr.is_loopback && sockaddr.port == policy.proxy_port,
        SYS_BIND => policy.bind_ports.contains(&sockaddr.port),
        _ => false,
    };

    if allow {
        continue_notif(notify_fd, notif.id).map_err(proxy_supervisor_err)
    } else {
        respond_notif_errno(notify_fd, notif.id, libc::EACCES).map_err(proxy_supervisor_err)
    }
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
