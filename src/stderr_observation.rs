//! Stderr parsing for exec failure diagnostics (ported from nono-cli formatter).

use nono::AccessMode;
use std::path::{Path, PathBuf};

/// Path-level hint extracted from a command's own error output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedPathHint {
    /// The path mentioned in the error output.
    pub path: PathBuf,
    /// Best-effort access mode inferred from the error text.
    pub access: AccessMode,
}

/// Primary classification derived from a command's own error output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorVerdict {
    /// The command likely hit a sandbox-relevant path access issue.
    LikelySandbox(ObservedPathHint),
    /// The command reported a missing path, which is not itself a sandbox denial.
    MissingPath(PathBuf),
    /// The command reported an application-level failure unrelated to permissions.
    NonSandboxFailure(String),
}

/// Best-effort observations extracted from a command's stderr output.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ErrorObservation {
    /// Primary diagnosis extracted from the command output.
    pub primary_verdict: Option<ErrorVerdict>,
    /// Name of a protected file referenced in the error output, if any.
    pub blocked_protected_file: Option<String>,
    /// Paths that look like sandbox-denied accesses from stderr.
    pub path_hints: Vec<ObservedPathHint>,
    /// Paths that look missing according to stderr output.
    pub missing_paths: Vec<PathBuf>,
    /// Error text that strongly suggests a non-sandbox application failure.
    pub non_sandbox_failure: Option<String>,
    /// Stderr suggests network access may have been blocked.
    pub network_blocked_hint: bool,
}

/// Parse best-effort denial hints from a command's stderr output.
#[must_use]
pub fn analyze_error_output(
    error_output: &str,
    protected_paths: &[PathBuf],
    current_dir: Option<&Path>,
) -> ErrorObservation {
    let mut blocked_protected_file = None;
    let mut observed = std::collections::BTreeMap::<PathBuf, AccessMode>::new();
    let mut missing = std::collections::BTreeSet::<PathBuf>::new();
    let mut pending_relative_write: Option<PathBuf> = None;
    let mut pending_structured_access_denial = false;
    let mut pending_structured_access: Option<AccessMode> = None;
    let mut non_sandbox_failure = None;
    let mut network_blocked_hint = false;

    for line in error_output.lines() {
        if !network_blocked_hint && looks_like_network_denial(line) {
            network_blocked_hint = true;
        }
        if blocked_protected_file.is_none() {
            blocked_protected_file = detect_protected_file_in_error_line(protected_paths, line);
        }

        if non_sandbox_failure.is_none() {
            non_sandbox_failure = detect_non_sandbox_failure_line(line);
        }

        if let Some(path) =
            current_dir.and_then(|cwd| extract_relative_write_path_from_line(line, cwd))
        {
            pending_relative_write = Some(path);
        }

        if looks_like_structured_access_denial_code(line) {
            pending_structured_access_denial = true;
        }

        if pending_structured_access_denial {
            if let Some(access) = infer_access_from_structured_syscall_line(line) {
                pending_structured_access = Some(access);
            }

            if let (Some(path), Some(access)) = (
                extract_structured_path_property(line),
                pending_structured_access,
            ) {
                observed
                    .entry(path)
                    .and_modify(|existing| *existing = merge_access_modes(*existing, access))
                    .or_insert(access);
                pending_structured_access_denial = false;
                pending_structured_access = None;
                continue;
            }
        }

        if looks_like_missing_path(line) {
            if let Some(path) = extract_denied_path_from_error_line(line) {
                missing.insert(path);
            }
            continue;
        }

        if !looks_like_access_denial(line) {
            continue;
        }

        let from_line = extract_denied_path_from_error_line(line);
        let path_from_line = from_line.is_some();
        let Some(path) = from_line.or_else(|| pending_relative_write.clone()) else {
            continue;
        };
        let access = if path_from_line {
            infer_access_from_error_line(line, &path)
        } else {
            AccessMode::Write
        };

        observed
            .entry(path)
            .and_modify(|existing| *existing = merge_access_modes(*existing, access))
            .or_insert(access);
        pending_relative_write = None;
    }

    let path_hints = observed
        .into_iter()
        .map(|(path, access)| ObservedPathHint { path, access })
        .collect::<Vec<_>>();
    let primary_verdict = missing
        .iter()
        .next()
        .cloned()
        .map(ErrorVerdict::MissingPath)
        .or_else(|| {
            non_sandbox_failure
                .clone()
                .map(ErrorVerdict::NonSandboxFailure)
        })
        .or_else(|| path_hints.first().cloned().map(ErrorVerdict::LikelySandbox));

    ErrorObservation {
        primary_verdict,
        blocked_protected_file,
        path_hints,
        missing_paths: missing.into_iter().collect(),
        non_sandbox_failure,
        network_blocked_hint,
    }
}

fn detect_non_sandbox_failure_line(line: &str) -> Option<String> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }
    let lower = trimmed.to_ascii_lowercase();
    if lower.contains("eexist")
        || lower.contains("file already exists")
        || lower.contains("already exists")
    {
        return Some(trimmed.to_string());
    }

    // Version requirement errors are never sandbox-related
    if lower.contains("version must be at least")
        || lower.contains("requires version")
        || lower.contains("minimum version")
        || lower.contains("upgrade your")
    {
        return Some(trimmed.to_string());
    }

    None
}

fn detect_protected_file_in_error_line(
    protected_paths: &[PathBuf],
    error_line: &str,
) -> Option<String> {
    for path in protected_paths {
        if let Some(name) = path.file_name().and_then(|n| n.to_str())
            && error_line.contains(name)
        {
            return Some(name.to_string());
        }
    }
    None
}

fn looks_like_network_denial(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    (lower.contains("network") || lower.contains("socket") || lower.contains("connect"))
        && (lower.contains("not permitted")
            || lower.contains("permission denied")
            || lower.contains("operation not permitted")
            || lower.contains("connection refused")
            || lower.contains("unreachable"))
}

fn looks_like_access_denial(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    lower.contains("operation not permitted")
        || lower.contains("permission denied")
        || lower.contains("read-only file system")
}

fn looks_like_structured_access_denial_code(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    (lower.contains("eperm") || lower.contains("eacces")) && looks_like_access_denial(line)
}

fn looks_like_missing_path(line: &str) -> bool {
    line.to_ascii_lowercase()
        .contains("no such file or directory")
}

fn extract_denied_path_from_error_line(line: &str) -> Option<PathBuf> {
    if let Some(path) = extract_path_after_syscall_word(line) {
        return Some(path);
    }

    let denial_markers = [
        "Operation not permitted",
        "Permission denied",
        "Read-only file system",
    ];

    let prefix = denial_markers
        .iter()
        .find_map(|marker| line.find(marker).map(|idx| &line[..idx]))
        .unwrap_or(line);

    for segment in prefix.rsplit(':') {
        if let Some(path) = extract_path_from_segment(segment) {
            return Some(path);
        }
    }

    extract_path_from_segment(prefix).or_else(|| extract_path_from_segment(line))
}

fn extract_path_after_syscall_word(line: &str) -> Option<PathBuf> {
    const MARKERS: &[&str] = &["mkdir", "mkdtemp", "open", "copyfile", "rename", "unlink"];

    let lower = line.to_ascii_lowercase();
    for marker in MARKERS {
        let needle = format!("{marker} ");
        let Some(idx) = lower.find(&needle) else {
            continue;
        };
        let segment = line.get(idx + needle.len()..)?;
        if let Some(path) = extract_path_from_segment(segment) {
            return Some(path);
        }
    }

    None
}

fn infer_access_from_structured_syscall_line(line: &str) -> Option<AccessMode> {
    let syscall = extract_structured_string_property(line, "syscall")?;
    Some(match syscall.to_ascii_lowercase().as_str() {
        "mkdir" | "mkdtemp" | "rmdir" | "unlink" | "rename" | "write" | "copyfile" | "chmod"
        | "chown" | "utimes" => AccessMode::Write,
        _ => AccessMode::ReadWrite,
    })
}

fn extract_structured_path_property(line: &str) -> Option<PathBuf> {
    extract_structured_string_property(line, "path").map(PathBuf::from)
}

fn extract_structured_string_property(line: &str, key: &str) -> Option<String> {
    let trimmed = line.trim();
    let after_key = trimmed
        .strip_prefix(key)
        .or_else(|| trimmed.strip_prefix(&format!("\"{key}\"")))
        .or_else(|| trimmed.strip_prefix(&format!("'{key}'")))?;
    let after_colon = after_key.trim_start().strip_prefix(':')?.trim_start();
    let quote = after_colon.chars().next()?;
    if quote != '\'' && quote != '"' {
        return None;
    }
    let after_quote = after_colon.get(quote.len_utf8()..)?;
    let mut value = String::new();
    let mut escaped = false;
    let mut found_end = false;

    for ch in after_quote.chars() {
        if escaped {
            if ch == quote || ch == '\\' {
                value.push(ch);
            } else {
                value.push('\\');
                value.push(ch);
            }
            escaped = false;
            continue;
        }

        if ch == '\\' {
            escaped = true;
            continue;
        }

        if ch == quote {
            found_end = true;
            break;
        }

        value.push(ch);
    }

    if !found_end {
        return None;
    }

    let value = value.trim();
    if value.is_empty() || value.chars().any(char::is_control) {
        return None;
    }
    Some(value.to_string())
}

fn extract_relative_write_path_from_line(line: &str, current_dir: &Path) -> Option<PathBuf> {
    let lower = line.to_ascii_lowercase();
    let markers = ["creating empty ", "creating ", "create ", "writing "];

    let marker = markers.iter().find(|marker| lower.contains(**marker))?;
    let start = lower.find(marker)? + marker.len();
    let candidate = line.get(start..)?.split_whitespace().next()?;
    let candidate = candidate
        .trim_matches(|c: char| {
            matches!(
                c,
                '\'' | '"' | '`' | ',' | ':' | ';' | '(' | ')' | '[' | ']'
            )
        })
        .trim_end_matches('.')
        .trim();

    if candidate.is_empty()
        || candidate.starts_with('/')
        || candidate.starts_with('~')
        || candidate.starts_with('-')
        || candidate.chars().any(char::is_control)
    {
        return None;
    }

    Some(current_dir.join(candidate))
}

fn extract_path_from_segment(segment: &str) -> Option<PathBuf> {
    let trimmed = segment.trim();
    if trimmed.is_empty() {
        return None;
    }

    // Strip a leading quote if the path is quoted (e.g. '/bin/ls' or "/bin/ls")
    let (unquoted, closing_quote) = if trimmed.starts_with('\'') || trimmed.starts_with('"') {
        let quote = trimmed.as_bytes()[0] as char;
        (&trimmed[1..], Some(quote))
    } else {
        (trimmed, None)
    };

    let tilde_idx = unquoted.find("~/");
    let slash_idx = unquoted.find('/');
    let start = match (tilde_idx, slash_idx) {
        (Some(a), Some(b)) => Some(std::cmp::min(a, b)),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }?;

    let after_start = &unquoted[start..];

    // Terminate the path at the closing quote (if we stripped an opening one)
    // or at any character that cannot appear in a filesystem path.
    let end = if let Some(q) = closing_quote {
        after_start.find(q).unwrap_or(after_start.len())
    } else {
        path_segment_end(after_start)
    };

    let candidate = after_start[..end].trim();
    if candidate.is_empty() || candidate.chars().any(char::is_control) {
        return None;
    }

    Some(PathBuf::from(candidate))
}

fn path_segment_end(after_start: &str) -> usize {
    let mut end = after_start
        .find(['\'', '"', '`', ')', '(', '<', '>'])
        .unwrap_or(after_start.len());
    for suffix in [
        ": Permission denied",
        ": Operation not permitted",
        ": Read-only file system",
    ] {
        if let Some(idx) = after_start.find(suffix) {
            end = end.min(idx);
        }
    }
    end
}

fn infer_access_from_error_line(line: &str, path: &Path) -> AccessMode {
    let lower = line.to_ascii_lowercase();

    if let Some(name) = path.file_name().and_then(|n| n.to_str())
        && matches!(
            name,
            ".profile" | ".bash_profile" | ".bashrc" | ".zprofile" | ".zshrc" | ".zlogin"
        )
    {
        return AccessMode::Read;
    }

    if lower.contains("cannot create")
        || lower.contains("can't create")
        || lower.contains("write error")
        || lower.contains("read-only file system")
        || lower.contains("operation not permitted, mkdir ")
        || lower.contains("permission denied, mkdir ")
        || lower.contains("eperm") && lower.contains("mkdir ")
        || lower.contains("eacces") && lower.contains("mkdir ")
        || lower.starts_with("tee:")
        || lower.starts_with("touch:")
        || lower.starts_with("mkdir:")
        || lower.starts_with("mktemp:")
        || lower.starts_with("install:")
        || lower.starts_with("cp:")
        || lower.starts_with("mv:")
        || lower.starts_with("rm:")
        || lower.starts_with("ln:")
        || lower.starts_with("chmod:")
        || lower.starts_with("chown:")
        || lower.starts_with("truncate:")
    {
        return AccessMode::Write;
    }

    if lower.contains("cannot open")
        || lower.contains("can't open")
        || lower.starts_with("cat:")
        || lower.starts_with("grep:")
        || lower.starts_with("sed:")
        || lower.starts_with("awk:")
        || lower.starts_with("head:")
        || lower.starts_with("tail:")
        || lower.starts_with("less:")
        || lower.starts_with("more:")
        || lower.starts_with("find:")
        || lower.starts_with("ls:")
    {
        return AccessMode::Read;
    }

    AccessMode::ReadWrite
}

fn merge_access_modes(existing: AccessMode, new: AccessMode) -> AccessMode {
    if existing == new {
        existing
    } else {
        AccessMode::ReadWrite
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn analyze_error_output_detects_read_path() {
        let observation =
            analyze_error_output("cat: /etc/hosts: Operation not permitted\n", &[], None);
        assert_eq!(
            observation.path_hints,
            vec![ObservedPathHint {
                path: PathBuf::from("/etc/hosts"),
                access: AccessMode::Read,
            }]
        );
    }

    #[test]
    fn analyze_error_output_detects_shell_redirect_read_path() {
        let observation = analyze_error_output(
            "/bin/sh: 1: cannot open /etc/hosts: Permission denied\n",
            &[],
            None,
        );
        assert_eq!(
            observation.path_hints,
            vec![ObservedPathHint {
                path: PathBuf::from("/etc/hosts"),
                access: AccessMode::Read,
            }]
        );
    }

    #[test]
    fn analyze_error_output_detects_missing_path() {
        let observation = analyze_error_output(
            "python: can't open file '/tmp/missing.py': [Errno 2] No such file or directory\n",
            &[],
            None,
        );
        assert_eq!(
            observation.missing_paths,
            vec![PathBuf::from("/tmp/missing.py")]
        );
    }
}
