//! Sandboxed command execution via fork + sandbox + exec.
//!
//! Provides `sandboxed_exec()` which forks the current process, applies
//! OS-level sandbox restrictions in the child, then exec's a command.
//! The parent captures stdout/stderr and waits for exit. The calling
//! process remains unsandboxed and can call this repeatedly.

use crate::CapabilitySet;
use nono::Sandbox;
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use std::ffi::CString;
use std::io::Read;
use std::os::fd::FromRawFd;
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
}

/// Pre-fork data prepared in the parent (where allocation is safe).
struct ForkContext {
    caps: nono::CapabilitySet,
    program_c: CString,
    argv_c: Vec<CString>,
    env_c: Vec<CString>,
    cwd_c: Option<CString>,
    timeout_secs: Option<f64>,
}

/// Pipe file descriptors for stdout or stderr.
struct PipeFds {
    read_fd: i32,
    write_fd: i32,
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
///         When provided, the child inherits the current environment with
///         these variables added or overridden.
///
/// Returns:
///     ExecResult with stdout, stderr, and exit_code
///
/// Raises:
///     RuntimeError: If fork fails, sandbox cannot be applied, or the
///         command cannot be executed
///     ValueError: If the command list is empty or timeout is negative
#[pyfunction]
#[pyo3(signature = (caps, command, cwd=None, timeout_secs=None, env=None))]
pub fn sandboxed_exec(
    py: Python<'_>,
    caps: &CapabilitySet,
    command: Vec<String>,
    cwd: Option<String>,
    timeout_secs: Option<f64>,
    env: Option<Vec<(String, String)>>,
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
    let ctx = prepare_fork_context(&caps.inner, &command, cwd, timeout_secs, env)?;

    // Create pipes for stdout and stderr
    let stdout_pipe = create_pipe()?;
    let stderr_pipe = create_pipe()?;

    // Release the GIL during fork+wait so other Python threads can proceed
    py.allow_threads(|| do_fork_sandbox_exec(&ctx, &stdout_pipe, &stderr_pipe))
}

/// Prepare all data needed for fork+exec while allocation is safe.
fn prepare_fork_context(
    caps: &nono::CapabilitySet,
    command: &[String],
    cwd: Option<String>,
    timeout_secs: Option<f64>,
    env: Option<Vec<(String, String)>>,
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

    let env_c = build_env_cstrings(env.as_deref())?;

    let cwd_c = match &cwd {
        Some(d) => {
            let canonical = std::fs::canonicalize(d).map_err(|e| {
                PyRuntimeError::new_err(format!("Cannot resolve working directory '{}': {}", d, e))
            })?;
            Some(
                CString::new(canonical.as_os_str().as_bytes())
                    .map_err(|_| PyRuntimeError::new_err("Working directory contains null byte"))?,
            )
        }
        None => None,
    };

    Ok(ForkContext {
        caps: caps.clone(),
        program_c,
        argv_c,
        env_c,
        cwd_c,
        timeout_secs,
    })
}

/// Build environment CStrings from current env + overrides.
fn build_env_cstrings(overrides: Option<&[(String, String)]>) -> PyResult<Vec<CString>> {
    let mut env_c: Vec<CString> = Vec::new();

    let override_keys: std::collections::HashSet<&str> = overrides
        .map(|ovr| ovr.iter().map(|(k, _)| k.as_str()).collect())
        .unwrap_or_default();

    for (key, value) in std::env::vars() {
        if !override_keys.contains(key.as_str())
            && let Ok(cstr) = CString::new(format!("{}={}", key, value))
        {
            env_c.push(cstr);
        }
    }

    if let Some(ovr) = overrides {
        for (key, value) in ovr {
            if let Ok(cstr) = CString::new(format!("{}={}", key, value)) {
                env_c.push(cstr);
            }
        }
    }

    Ok(env_c)
}

/// Create a pipe, returning a PipeFds struct.
fn create_pipe() -> PyResult<PipeFds> {
    let mut fds = [0i32; 2];
    // SAFETY: pipe() is safe with a valid 2-element array.
    let ret = unsafe { libc::pipe(fds.as_mut_ptr()) };
    if ret != 0 {
        return Err(PyRuntimeError::new_err(format!(
            "pipe() failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(PipeFds {
        read_fd: fds[0],
        write_fd: fds[1],
    })
}

/// Fork, apply sandbox in child, exec command, capture output in parent.
fn do_fork_sandbox_exec(
    ctx: &ForkContext,
    stdout_pipe: &PipeFds,
    stderr_pipe: &PipeFds,
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
        child_process(ctx, &argv_ptrs, &envp_ptrs, stdout_pipe, stderr_pipe);
    }

    // === PARENT PROCESS ===
    parent_process(pid, stdout_pipe, stderr_pipe, ctx.timeout_secs)
}

/// Child process: set up pipes, apply sandbox, chdir, exec.
/// This function never returns.
fn child_process(
    ctx: &ForkContext,
    argv_ptrs: &[*const libc::c_char],
    envp_ptrs: &[*const libc::c_char],
    stdout_pipe: &PipeFds,
    stderr_pipe: &PipeFds,
) -> ! {
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

    // Apply sandbox restrictions
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

/// Parent process: close write ends, read output, wait for child.
fn parent_process(
    child_pid: i32,
    stdout_pipe: &PipeFds,
    stderr_pipe: &PipeFds,
    timeout_secs: Option<f64>,
) -> PyResult<ExecResult> {
    // Close write ends (child writes, parent reads)
    unsafe {
        libc::close(stdout_pipe.write_fd);
        libc::close(stderr_pipe.write_fd);
    }

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

    let exit_code = wait_for_child(child_pid, timeout_secs)?;

    let stdout_buf = stdout_handle.join().unwrap_or_default();
    let stderr_buf = stderr_handle.join().unwrap_or_default();

    Ok(ExecResult {
        stdout: stdout_buf,
        stderr: stderr_buf,
        exit_code,
    })
}

/// Wait for child process, with optional timeout.
/// Returns the exit code, or -signal_number if killed by signal.
fn wait_for_child(child_pid: i32, timeout_secs: Option<f64>) -> PyResult<i32> {
    let deadline = timeout_secs.map(|t| Instant::now() + Duration::from_secs_f64(t));

    loop {
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

/// Resolve a program name to its absolute path by searching PATH.
fn resolve_program(program: &str) -> PyResult<PathBuf> {
    let path = Path::new(program);

    if program.contains('/') {
        if path.exists() {
            return Ok(path.to_path_buf());
        }
        return Err(PyRuntimeError::new_err(format!(
            "Program not found: {}",
            program
        )));
    }

    if let Ok(path_var) = std::env::var("PATH") {
        for dir in path_var.split(':') {
            let candidate = Path::new(dir).join(program);
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }

    Err(PyRuntimeError::new_err(format!(
        "Program not found in PATH: {}",
        program
    )))
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
