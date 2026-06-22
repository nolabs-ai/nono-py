//! Structured diagnostics for Python clients (PyO3 → nono / nono-proxy).

use crate::stderr_observation::{ErrorObservation, ObservedPathHint, analyze_error_output};
use nono::diagnostic::{
    NonoDiagnostic, NonoDiagnosticCode, NonoRemediation, SessionDiagnosticReport,
    diagnostic_application_failure, diagnostic_likely_sandbox_path, diagnostic_missing_path,
    diagnostic_network_blocked, diagnostic_protected_file_write, follow_up_diagnostics,
};
use nono::{AccessMode, CapabilitySet, NonoError, try_canonicalize};
use nono_proxy::ProxyDiagnostic;
use pyo3::prelude::*;
use std::path::Path;

pub(crate) fn diagnostic_code_label(code: NonoDiagnosticCode) -> &'static str {
    match code {
        NonoDiagnosticCode::SandboxDeniedPath => "sandbox_denied_path",
        NonoDiagnosticCode::SandboxDeniedNetwork => "sandbox_denied_network",
        NonoDiagnosticCode::SandboxDeniedUnixSocket => "sandbox_denied_unix_socket",
        NonoDiagnosticCode::CommandNotFound => "command_not_found",
        NonoDiagnosticCode::CommandFailedLikelySandbox => "command_failed_likely_sandbox",
        NonoDiagnosticCode::CommandFailedApplication => "command_failed_application",
        NonoDiagnosticCode::CredentialNotFound => "credential_not_found",
        NonoDiagnosticCode::CredentialUnavailable => "credential_unavailable",
        NonoDiagnosticCode::UnsupportedPlatformFeature => "unsupported_platform_feature",
        NonoDiagnosticCode::RollbackBudgetExceeded => "rollback_budget_exceeded",
        NonoDiagnosticCode::CwdAccessRequired => "cwd_access_required",
        NonoDiagnosticCode::ConfigurationError => "configuration_error",
        NonoDiagnosticCode::TrustVerificationFailed => "trust_verification_failed",
        NonoDiagnosticCode::IoError => "io_error",
        NonoDiagnosticCode::Cancelled => "cancelled",
        NonoDiagnosticCode::Other => "other",
        _ => "other",
    }
}

pub(crate) fn attach_nono_error_diagnostics(py: Python<'_>, err: &PyErr, error: &NonoError) {
    let value = err.value(py);
    let _ = value.setattr(
        "diagnostic_code",
        diagnostic_code_label(error.diagnostic_code()),
    );
    if let Some(remediation) = error.remediation()
        && let Ok(rem) = remediation_to_py(py, &remediation)
    {
        let _ = value.setattr("remediation", rem);
    }
}

pub(crate) fn remediation_to_py(
    py: Python<'_>,
    remediation: &NonoRemediation,
) -> PyResult<Py<PyAny>> {
    let json = serde_json::to_string(remediation).map_err(|e| {
        pyo3::exceptions::PyRuntimeError::new_err(format!("serialize remediation JSON: {e}"))
    })?;
    json_to_py(py, &json)
}

pub(crate) fn proxy_diagnostics_to_py(
    py: Python<'_>,
    diagnostics: &[ProxyDiagnostic],
) -> PyResult<Py<PyAny>> {
    let json = serde_json::to_string(diagnostics).map_err(|e| {
        pyo3::exceptions::PyRuntimeError::new_err(format!("serialize proxy diagnostics JSON: {e}"))
    })?;
    json_to_py(py, &json)
}

pub(crate) fn session_report_to_py(
    py: Python<'_>,
    report: &SessionDiagnosticReport,
) -> PyResult<Py<PyAny>> {
    let json = report.to_json().map_err(|e| {
        pyo3::exceptions::PyRuntimeError::new_err(format!(
            "serialize session diagnostic report JSON: {e}"
        ))
    })?;
    json_to_py(py, &json)
}

pub(crate) fn json_to_py(py: Python<'_>, json: &str) -> PyResult<Py<PyAny>> {
    let json_mod = py.import("json")?;
    Ok(json_mod.call_method1("loads", (json,))?.unbind())
}

/// Build a session diagnostic report from exec output and capability context.
#[must_use]
pub(crate) fn build_session_report_from_exec(
    exit_code: i32,
    stderr: &[u8],
    cwd: Option<&Path>,
    caps: &CapabilitySet,
) -> SessionDiagnosticReport {
    let stderr_text = String::from_utf8_lossy(stderr);
    let observation = analyze_error_output(&stderr_text, &[], cwd);
    let mut report =
        SessionDiagnosticReport::from_merged_session(exit_code, Vec::new(), Vec::new(), Vec::new());
    append_stderr_observations(caps, cwd, &observation, &mut report.diagnostics);
    report.diagnostics.extend(follow_up_diagnostics());
    report
}

fn append_stderr_observations(
    caps: &CapabilitySet,
    cwd: Option<&Path>,
    observation: &ErrorObservation,
    diagnostics: &mut Vec<NonoDiagnostic>,
) {
    if let Some(ref file) = observation.blocked_protected_file {
        push_unique_diagnostic(diagnostics, diagnostic_protected_file_write(file.clone()));
    }
    for path in &observation.missing_paths {
        push_unique_diagnostic(diagnostics, diagnostic_missing_path(path.clone()));
    }
    if let Some(ref message) = observation.non_sandbox_failure {
        push_unique_diagnostic(diagnostics, diagnostic_application_failure(message.clone()));
    }
    if observation.network_blocked_hint && caps.is_network_blocked() {
        push_unique_diagnostic(diagnostics, diagnostic_network_blocked());
    }
    for hint in actionable_observed_path_hints(caps, observation) {
        if observation_path_already_logged(diagnostics, &hint.path) {
            continue;
        }
        let remediation = remediation_for_observed_hint(caps, cwd, &hint);
        push_unique_diagnostic(
            diagnostics,
            diagnostic_likely_sandbox_path(hint.path, hint.access, remediation),
        );
    }
}

fn actionable_observed_path_hints(
    caps: &CapabilitySet,
    observation: &ErrorObservation,
) -> Vec<ObservedPathHint> {
    observation
        .path_hints
        .iter()
        .filter_map(|hint| {
            actionable_observed_access(caps, &hint.path, hint.access).map(|access| {
                ObservedPathHint {
                    path: hint.path.clone(),
                    access,
                }
            })
        })
        .collect()
}

fn actionable_observed_access(
    caps: &CapabilitySet,
    path: &Path,
    inferred: AccessMode,
) -> Option<AccessMode> {
    let Some(cap) = closest_covering_capability(caps, path) else {
        return Some(inferred);
    };

    if cap.access.contains(inferred) {
        return None;
    }

    Some(match (cap.access, inferred) {
        (AccessMode::Read, AccessMode::ReadWrite) => AccessMode::Write,
        (AccessMode::Write, AccessMode::ReadWrite) => AccessMode::Read,
        _ => inferred,
    })
}

fn closest_covering_capability<'a>(
    caps: &'a CapabilitySet,
    path: &Path,
) -> Option<&'a nono::FsCapability> {
    let canonical = try_canonicalize(path);
    let mut best_covering: Option<&nono::FsCapability> = None;
    let mut best_covering_score = 0usize;

    for cap in caps.fs_capabilities() {
        let covers = if cap.is_file {
            cap.resolved == canonical
        } else {
            canonical.starts_with(&cap.resolved)
        };

        if !covers {
            continue;
        }

        let score = cap.resolved.as_os_str().len();
        if score >= best_covering_score {
            best_covering = Some(cap);
            best_covering_score = score;
        }
    }

    best_covering
}

fn remediation_for_observed_hint(
    caps: &CapabilitySet,
    cwd: Option<&Path>,
    hint: &ObservedPathHint,
) -> NonoRemediation {
    if observed_hint_points_to_ungranted_cwd(caps, cwd, &hint.path) {
        return NonoRemediation::AllowCwd;
    }
    if let Some(cap) = closest_covering_capability(caps, &hint.path) {
        let access = match (cap.access, hint.access) {
            (AccessMode::Read, AccessMode::ReadWrite) => AccessMode::Write,
            (AccessMode::Write, AccessMode::ReadWrite) => AccessMode::Read,
            _ => hint.access,
        };
        return NonoRemediation::GrantPath {
            is_file: cap.is_file,
            path: cap.resolved.clone(),
            access,
        };
    }
    NonoRemediation::GrantPath {
        is_file: hint.path.is_file() || hint.path.file_name().is_some_and(|_| !hint.path.is_dir()),
        path: hint.path.clone(),
        access: hint.access,
    }
}

fn observed_hint_points_to_ungranted_cwd(
    caps: &CapabilitySet,
    cwd: Option<&Path>,
    path: &Path,
) -> bool {
    let Some(current_dir) = cwd else {
        return false;
    };

    if !path.starts_with(current_dir) {
        return false;
    }

    closest_covering_capability(caps, current_dir).is_none()
}

fn push_unique_diagnostic(diagnostics: &mut Vec<NonoDiagnostic>, diagnostic: NonoDiagnostic) {
    if diagnostics.iter().any(|existing| existing == &diagnostic) {
        return;
    }
    diagnostics.push(diagnostic);
}

fn observation_path_already_logged(diagnostics: &[NonoDiagnostic], path: &Path) -> bool {
    diagnostics
        .iter()
        .any(|diagnostic| diagnostic.path.as_deref() == Some(path))
}

/// Build a minimal session diagnostic report for a sandboxed child exit.
///
/// Uses empty denial/violation lists and appends standard follow-up hints.
#[pyfunction]
#[pyo3(signature = (exit_code))]
pub fn build_session_diagnostic_report(exit_code: i32) -> PyResult<Py<PyAny>> {
    Python::attach(|py| {
        let mut report = SessionDiagnosticReport::from_merged_session(
            exit_code,
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        report.diagnostics.extend(follow_up_diagnostics());
        session_report_to_py(py, &report)
    })
}

/// Merge session diagnostic JSON with optional proxy diagnostics JSON.
///
/// ``proxy_diagnostics_json`` must be a JSON array when provided (the shape
/// returned by ``ProxyHandle.diagnostics_json()``).
#[pyfunction]
#[pyo3(signature = (session_report_json, proxy_diagnostics_json=None))]
pub fn merge_diagnostic_report_json(
    session_report_json: &str,
    proxy_diagnostics_json: Option<&str>,
) -> PyResult<Py<PyAny>> {
    Python::attach(|py| {
        let merged = SessionDiagnosticReport::merge_with_proxy_json(
            session_report_json,
            proxy_diagnostics_json,
        )
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
        json_to_py(py, &merged)
    })
}
