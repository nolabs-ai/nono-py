use crate::{proxy::ProxyConfig, CapabilitySet};
use nono::{AccessMode, CapabilitySource, FsCapability, NonoError, Result as NonoResult};
use nono_proxy::config::{
    EndpointRule as RustEndpointRule, InjectMode as RustInjectMode, RouteConfig as RustRouteConfig,
};
use nono_proxy::ProxyConfig as RustProxyConfig;
use pyo3::prelude::*;
use serde::Deserialize;
use std::collections::HashMap;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

const EMBEDDED_POLICY_JSON: &str = include_str!("../data/policy.json");

#[derive(Debug, Clone, Deserialize)]
pub struct RustPolicy {
    pub groups: HashMap<String, Group>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Group {
    #[allow(dead_code)]
    pub description: String,
    #[serde(default)]
    pub platform: Option<String>,
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub allow: Option<AllowOps>,
    #[serde(default)]
    pub deny: Option<DenyOps>,
    #[serde(default)]
    pub symlink_pairs: Option<HashMap<String, String>>,
    #[serde(default)]
    pub network: Option<NetworkOps>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct AllowOps {
    #[serde(default)]
    pub read: Vec<String>,
    #[serde(default)]
    pub write: Vec<String>,
    #[serde(default)]
    pub readwrite: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct DenyOps {
    #[serde(default)]
    pub access: Vec<String>,
    #[serde(default)]
    pub unlink: bool,
    #[serde(default)]
    pub unlink_override_for_user_writable: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct NetworkOps {
    #[serde(default)]
    pub block: bool,
    #[serde(
        default,
        rename = "allow_domain",
        alias = "allow_proxy",
        alias = "proxy_allow"
    )]
    pub allow_domain: Vec<String>,
    #[serde(default)]
    pub credentials: Vec<String>,
    #[serde(default)]
    pub custom_credentials: HashMap<String, PolicyRouteConfig>,
    #[serde(default, rename = "upstream_proxy", alias = "external_proxy")]
    pub upstream_proxy: Option<String>,
    #[serde(default, rename = "upstream_bypass", alias = "external_proxy_bypass")]
    pub upstream_bypass: Vec<String>,
    #[serde(default)]
    pub max_connections: Option<usize>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PolicyRouteConfig {
    pub prefix: String,
    pub upstream: String,
    #[serde(default)]
    pub credential_key: Option<String>,
    #[serde(default)]
    pub inject_mode: PolicyInjectMode,
    #[serde(default = "default_inject_header")]
    pub inject_header: String,
    #[serde(default = "default_credential_format")]
    pub credential_format: String,
    #[serde(default)]
    pub path_pattern: Option<String>,
    #[serde(default)]
    pub path_replacement: Option<String>,
    #[serde(default)]
    pub query_param_name: Option<String>,
    #[serde(default)]
    pub env_var: Option<String>,
    #[serde(default)]
    pub endpoint_rules: Vec<PolicyEndpointRule>,
    #[serde(default)]
    pub tls_ca: Option<String>,
    #[serde(default)]
    pub tls_client_cert: Option<String>,
    #[serde(default)]
    pub tls_client_key: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PolicyEndpointRule {
    pub method: String,
    pub path: String,
}

impl From<PolicyEndpointRule> for RustEndpointRule {
    fn from(rule: PolicyEndpointRule) -> Self {
        Self {
            method: rule.method,
            path: rule.path,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyInjectMode {
    #[default]
    Header,
    UrlPath,
    QueryParam,
    BasicAuth,
}

#[pyclass(name = "Policy")]
#[derive(Clone)]
pub struct Policy {
    pub(crate) inner: RustPolicy,
}

#[pyclass]
#[derive(Clone)]
pub struct ResolvedPolicy {
    pub(crate) names: Vec<String>,
    pub(crate) needs_unlink_overrides: bool,
    pub(crate) deny_paths: Vec<PathBuf>,
}

#[pymethods]
impl Policy {
    fn group_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.inner.groups.keys().cloned().collect();
        names.sort();
        names
    }

    fn group_description(&self, name: &str) -> Option<String> {
        self.inner
            .groups
            .get(name)
            .map(|group| group.description.clone())
    }

    fn resolve_groups(
        &self,
        group_names: Vec<String>,
        caps: &mut CapabilitySet,
    ) -> PyResult<ResolvedPolicy> {
        resolve_groups_impl(&self.inner, &group_names, caps).map_err(crate::to_py_err)
    }

    fn resolve_deny_paths(&self, group_names: Vec<String>) -> PyResult<Vec<String>> {
        let paths =
            resolve_deny_paths_for_groups(&self.inner, &group_names).map_err(crate::to_py_err)?;
        Ok(paths
            .into_iter()
            .map(|path| path.display().to_string())
            .collect())
    }

    fn resolve_proxy_config(&self, group_names: Vec<String>) -> PyResult<Option<ProxyConfig>> {
        resolve_proxy_config_impl(&self.inner, &group_names)
            .map(|config| config.map(ProxyConfig::from_inner))
            .map_err(crate::to_py_err)
    }

    fn validate_group_exclusions(&self, excluded_groups: Vec<String>) -> PyResult<()> {
        validate_group_exclusions(&self.inner, &excluded_groups).map_err(crate::to_py_err)
    }

    fn __repr__(&self) -> String {
        format!("Policy(groups={})", self.inner.groups.len())
    }
}

#[pymethods]
impl ResolvedPolicy {
    #[getter]
    fn names(&self) -> Vec<String> {
        self.names.clone()
    }

    #[getter]
    fn needs_unlink_overrides(&self) -> bool {
        self.needs_unlink_overrides
    }

    #[getter]
    fn deny_paths(&self) -> Vec<String> {
        self.deny_paths
            .iter()
            .map(|path| path.display().to_string())
            .collect()
    }

    fn __repr__(&self) -> String {
        format!(
            "ResolvedPolicy(names={}, deny_paths={}, needs_unlink_overrides={})",
            self.names.len(),
            self.deny_paths.len(),
            self.needs_unlink_overrides
        )
    }
}

pub fn load_policy(json: &str) -> NonoResult<Policy> {
    let policy = serde_json::from_str(json)
        .map_err(|e| NonoError::ConfigParse(format!("Failed to parse policy.json: {}", e)))?;
    Ok(Policy { inner: policy })
}

pub fn load_embedded_policy() -> NonoResult<Policy> {
    load_policy(EMBEDDED_POLICY_JSON)
}

pub fn resolve_groups_impl(
    policy: &RustPolicy,
    group_names: &[String],
    caps: &mut CapabilitySet,
) -> NonoResult<ResolvedPolicy> {
    let mut resolved_groups = Vec::new();
    let mut needs_unlink_overrides = false;
    let mut deny_paths = Vec::new();

    for name in group_names {
        let group = policy
            .groups
            .get(name)
            .ok_or_else(|| NonoError::ConfigParse(format!("Unknown policy group: '{}'", name)))?;

        if !group_matches_platform(group) {
            continue;
        }

        if resolve_single_group(name, group, caps, &mut deny_paths)? {
            needs_unlink_overrides = true;
        }
        resolved_groups.push(name.clone());
    }

    Ok(ResolvedPolicy {
        names: resolved_groups,
        needs_unlink_overrides,
        deny_paths,
    })
}

pub fn resolve_deny_paths_for_groups(
    policy: &RustPolicy,
    group_names: &[String],
) -> NonoResult<Vec<PathBuf>> {
    let mut tmp_caps = CapabilitySet {
        inner: nono::CapabilitySet::new(),
    };
    let resolved = resolve_groups_impl(policy, group_names, &mut tmp_caps)?;
    Ok(resolved.deny_paths)
}

pub fn resolve_proxy_config_impl(
    policy: &RustPolicy,
    group_names: &[String],
) -> NonoResult<Option<RustProxyConfig>> {
    let mut allowed_hosts = Vec::new();
    let mut seen_hosts = HashSet::new();
    let mut routes = Vec::new();
    let mut upstream_proxy: Option<String> = None;
    let mut upstream_proxy_group: Option<String> = None;
    let mut upstream_bypass = Vec::new();
    let mut seen_bypass = HashSet::new();
    let mut max_connections: Option<usize> = None;

    for name in group_names {
        let group = policy
            .groups
            .get(name)
            .ok_or_else(|| NonoError::ConfigParse(format!("Unknown policy group: '{}'", name)))?;

        if !group_matches_platform(group) {
            continue;
        }

        let Some(network) = &group.network else {
            continue;
        };

        for host in &network.allow_domain {
            if seen_hosts.insert(host.clone()) {
                allowed_hosts.push(host.clone());
            }
        }

        if !network.credentials.is_empty() {
            return Err(NonoError::ConfigParse(
                "network.credentials requires built-in network-policy resolution, which nono-py does not expose yet".to_string(),
            ));
        }

        routes.extend(network.custom_credentials.values().cloned().map(Into::into));

        if let Some(proxy) = &network.upstream_proxy {
            if let Some(existing) = &upstream_proxy {
                if existing != proxy {
                    return Err(NonoError::ConfigParse(format!(
                        "Conflicting upstream_proxy values in policy groups: '{}' sets '{}', but '{}' sets '{}'",
                        upstream_proxy_group.as_deref().unwrap_or("<unknown>"),
                        existing,
                        name,
                        proxy
                    )));
                }
            } else {
                upstream_proxy = Some(proxy.clone());
                upstream_proxy_group = Some(name.clone());
            }
        }

        for host in &network.upstream_bypass {
            if seen_bypass.insert(host.clone()) {
                upstream_bypass.push(host.clone());
            }
        }

        if let Some(limit) = network.max_connections {
            max_connections = Some(match max_connections {
                Some(current) => current.min(limit),
                None => limit,
            });
        }
    }

    if allowed_hosts.is_empty()
        && routes.is_empty()
        && upstream_proxy.is_none()
        && upstream_bypass.is_empty()
        && max_connections.is_none()
    {
        return Ok(None);
    }

    let mut config = RustProxyConfig {
        allowed_hosts,
        routes,
        ..Default::default()
    };
    if let Some(address) = upstream_proxy {
        config.external_proxy = Some(nono_proxy::config::ExternalProxyConfig {
            address,
            auth: None,
            bypass_hosts: upstream_bypass,
        });
    }
    if let Some(limit) = max_connections {
        config.max_connections = limit;
    }
    Ok(Some(config))
}

pub fn validate_deny_overlaps(deny_paths: &[PathBuf], caps: &CapabilitySet) -> NonoResult<()> {
    if cfg!(target_os = "macos") {
        return Ok(());
    }

    let mut fatal_conflicts = Vec::new();

    for deny_path in deny_paths {
        for cap in caps.inner.fs_capabilities() {
            if cap.is_file {
                continue;
            }
            if deny_path.starts_with(&cap.resolved)
                && *deny_path != cap.resolved
                && cap.source.is_user_intent()
            {
                fatal_conflicts.push(format!(
                    "deny '{}' overlaps allowed parent '{}' (source: {})",
                    deny_path.display(),
                    cap.resolved.display(),
                    cap.source
                ));
            }
        }
    }

    if fatal_conflicts.is_empty() {
        return Ok(());
    }

    fatal_conflicts.sort();
    fatal_conflicts.dedup();

    Err(NonoError::SandboxInit(format!(
        "Landlock deny-overlap is not enforceable on Linux. Refusing to start with conflicting policy.\n{}",
        fatal_conflicts.join("\n")
    )))
}

pub fn apply_unlink_overrides(caps: &mut CapabilitySet) -> NonoResult<()> {
    if cfg!(target_os = "linux") {
        return Ok(());
    }

    let writable_paths: Vec<PathBuf> = caps
        .inner
        .fs_capabilities()
        .iter()
        .filter(|cap| matches!(cap.access, AccessMode::Write | AccessMode::ReadWrite))
        .filter(|cap| !cap.is_file)
        .map(|cap| cap.resolved.clone())
        .collect();

    for path in writable_paths {
        let path_str = path_to_utf8(&path)?;
        let escaped = escape_seatbelt_path(path_str)?;
        caps.inner.add_platform_rule(format!(
            "(allow file-write-unlink (subpath \"{}\"))",
            escaped
        ))?;
    }

    Ok(())
}

pub fn validate_group_exclusions(
    policy: &RustPolicy,
    excluded_groups: &[String],
) -> NonoResult<()> {
    let violations: Vec<&String> = excluded_groups
        .iter()
        .filter(|name| policy.groups.get(name.as_str()).is_some_and(|g| g.required))
        .collect();

    if violations.is_empty() {
        return Ok(());
    }

    let names = violations
        .iter()
        .map(|name| format!("'{}'", name))
        .collect::<Vec<_>>()
        .join(", ");

    Err(NonoError::ConfigParse(format!(
        "Cannot exclude required groups: {}",
        names
    )))
}

fn resolve_single_group(
    group_name: &str,
    group: &Group,
    caps: &mut CapabilitySet,
    deny_paths: &mut Vec<PathBuf>,
) -> NonoResult<bool> {
    let source = CapabilitySource::Group(group_name.to_string());
    let mut needs_unlink_overrides = false;

    if let Some(allow) = &group.allow {
        for path in &allow.read {
            add_fs_capability(path, AccessMode::Read, &source, caps)?;
        }
        for path in &allow.write {
            add_fs_capability(path, AccessMode::Write, &source, caps)?;
        }
        for path in &allow.readwrite {
            add_fs_capability(path, AccessMode::ReadWrite, &source, caps)?;
        }
    }

    if let Some(deny) = &group.deny {
        for path in &deny.access {
            add_deny_access_rules(path, caps, deny_paths)?;
        }

        if deny.unlink && cfg!(target_os = "macos") {
            caps.inner.add_platform_rule("(deny file-write-unlink)")?;
        }

        if deny.unlink_override_for_user_writable {
            needs_unlink_overrides = true;
        }
    }

    if let Some(network) = &group.network {
        if network.block {
            caps.inner.set_network_blocked(true);
        }
    }

    if cfg!(target_os = "macos") {
        if let Some(pairs) = &group.symlink_pairs {
            for symlink in pairs.keys() {
                let expanded = expand_path(symlink)?;
                let escaped = escape_seatbelt_path(path_to_utf8(&expanded)?)?;
                caps.inner
                    .add_platform_rule(format!("(allow file-read* (subpath \"{}\"))", escaped))?;
            }
        }
    }

    Ok(needs_unlink_overrides)
}

fn add_fs_capability(
    path_str: &str,
    mode: AccessMode,
    source: &CapabilitySource,
    caps: &mut CapabilitySet,
) -> NonoResult<()> {
    let path = expand_path(path_str)?;

    if !path.exists() {
        return Ok(());
    }

    let capability = if path.is_dir() {
        FsCapability::new_dir(&path, mode)
    } else {
        FsCapability::new_file(&path, mode)
    };

    if let Ok(mut capability) = capability {
        capability.source = source.clone();
        caps.inner.add_fs(capability);
    }

    Ok(())
}

fn add_deny_access_rules(
    path_str: &str,
    caps: &mut CapabilitySet,
    deny_paths: &mut Vec<PathBuf>,
) -> NonoResult<()> {
    let path = expand_path(path_str)?;
    deny_paths.push(path.clone());

    let canonical = match path.canonicalize() {
        Ok(p) => Some(p),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            return Err(NonoError::PathCanonicalization {
                path: path.to_path_buf(),
                source: e,
            });
        }
    };
    if let Some(ref canonical) = canonical {
        if *canonical != path {
            deny_paths.push(canonical.clone());
        }
    }

    let parent_resolved = if canonical.is_none() {
        resolve_parent_symlinks(&path)?
    } else {
        None
    };
    if let Some(ref resolved) = parent_resolved {
        deny_paths.push(resolved.clone());
    }

    if cfg!(target_os = "macos") {
        emit_deny_rules(&path, caps)?;

        if let Some(ref canonical) = canonical {
            if *canonical != path {
                emit_deny_rules(canonical, caps)?;
            }
        }

        if let Some(ref resolved) = parent_resolved {
            emit_deny_rules(resolved, caps)?;
        }
    }

    Ok(())
}

fn emit_deny_rules(path: &Path, caps: &mut CapabilitySet) -> NonoResult<()> {
    let escaped = escape_seatbelt_path(path_to_utf8(path)?)?;
    let filter = if path.exists() && path.is_file() {
        format!("literal \"{}\"", escaped)
    } else {
        format!("subpath \"{}\"", escaped)
    };

    caps.inner
        .add_platform_rule(format!("(allow file-read-metadata ({}))", filter))?;
    caps.inner
        .add_platform_rule(format!("(deny file-read-data ({}))", filter))?;
    caps.inner
        .add_platform_rule(format!("(deny file-write* ({}))", filter))?;
    caps.inner
        .add_platform_rule(format!("(deny network-outbound (path \"{}\"))", escaped))?;
    Ok(())
}

fn resolve_parent_symlinks(path: &Path) -> NonoResult<Option<PathBuf>> {
    let mut suffix = Vec::new();
    let mut current = path;

    loop {
        if current.exists() {
            break;
        }
        let name = current.file_name().ok_or_else(|| {
            NonoError::ConfigParse(format!(
                "cannot resolve parent symlinks for {}",
                path.display()
            ))
        })?;
        suffix.push(name.to_os_string());
        current = current.parent().ok_or_else(|| {
            NonoError::ConfigParse(format!(
                "cannot resolve parent symlinks for {}",
                path.display()
            ))
        })?;
    }

    let mut resolved = current.canonicalize().map_err(|e| {
        NonoError::ConfigParse(format!("canonicalize {}: {}", current.display(), e))
    })?;
    for part in suffix.iter().rev() {
        resolved.push(part);
    }

    Ok((resolved != path).then_some(resolved))
}

fn current_platform() -> &'static str {
    if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else {
        "unknown"
    }
}

fn group_matches_platform(group: &Group) -> bool {
    match &group.platform {
        Some(platform) => platform == current_platform(),
        None => true,
    }
}

fn expand_path(path_str: &str) -> NonoResult<PathBuf> {
    let expanded = if let Some(rest) = path_str.strip_prefix("~/") {
        let home = validated_env_path("HOME")?;
        format!("{}/{}", home, rest)
    } else if path_str == "~" || path_str == "$HOME" {
        validated_env_path("HOME")?
    } else if let Some(rest) = path_str.strip_prefix("$HOME/") {
        let home = validated_env_path("HOME")?;
        format!("{}/{}", home, rest)
    } else if path_str == "$TMPDIR" {
        validated_env_path("TMPDIR")?
    } else if let Some(rest) = path_str.strip_prefix("$TMPDIR/") {
        let tmpdir = validated_env_path("TMPDIR")?;
        format!("{}/{}", tmpdir, rest)
    } else {
        path_str.to_string()
    };

    Ok(PathBuf::from(expanded))
}

fn validated_env_path(name: &str) -> NonoResult<String> {
    let value =
        std::env::var(name).map_err(|_| NonoError::ConfigParse(format!("{} is not set", name)))?;
    if !Path::new(&value).is_absolute() {
        return Err(NonoError::ConfigParse(format!(
            "{} must be an absolute path, got: {}",
            name, value
        )));
    }
    Ok(value)
}

fn path_to_utf8(path: &Path) -> NonoResult<&str> {
    path.to_str().ok_or_else(|| {
        NonoError::ConfigParse(format!("Path contains non-UTF-8 bytes: {}", path.display()))
    })
}

fn escape_seatbelt_path(path: &str) -> NonoResult<String> {
    let mut result = String::with_capacity(path.len());
    for c in path.chars() {
        if c.is_control() {
            return Err(NonoError::ConfigParse(format!(
                "Path contains control character: {:?}",
                path
            )));
        }
        match c {
            '\\' => result.push_str("\\\\"),
            '"' => result.push_str("\\\""),
            _ => result.push(c),
        }
    }
    Ok(result)
}

fn default_inject_header() -> String {
    String::from("Authorization")
}

fn default_credential_format() -> String {
    String::from("Bearer {}")
}

impl From<PolicyInjectMode> for RustInjectMode {
    fn from(mode: PolicyInjectMode) -> Self {
        match mode {
            PolicyInjectMode::Header => RustInjectMode::Header,
            PolicyInjectMode::UrlPath => RustInjectMode::UrlPath,
            PolicyInjectMode::QueryParam => RustInjectMode::QueryParam,
            PolicyInjectMode::BasicAuth => RustInjectMode::BasicAuth,
        }
    }
}

impl From<PolicyRouteConfig> for RustRouteConfig {
    fn from(route: PolicyRouteConfig) -> Self {
        Self {
            prefix: route.prefix,
            upstream: route.upstream,
            credential_key: route.credential_key,
            inject_mode: route.inject_mode.into(),
            inject_header: route.inject_header,
            credential_format: route.credential_format,
            path_pattern: route.path_pattern,
            path_replacement: route.path_replacement,
            query_param_name: route.query_param_name,
            proxy: None,
            env_var: route.env_var,
            oauth2: None,
            endpoint_rules: route.endpoint_rules.into_iter().map(Into::into).collect(),
            tls_ca: route.tls_ca,
            tls_client_cert: route.tls_client_cert,
            tls_client_key: route.tls_client_key,
        }
    }
}
