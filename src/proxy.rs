//! Python bindings for the nono-proxy network filtering proxy.
//!
//! Provides `ProxyConfig`, `RouteConfig`, `InjectMode`, `ExternalProxyConfig`,
//! `ProxyHandle`, and the `start_proxy()` function. The proxy runs on a
//! background tokio runtime and is controlled synchronously from Python.

use nono_proxy::config::{
    EndpointRule as RustEndpointRule, ExternalProxyConfig as RustExternalProxyConfig,
    InjectMode as RustInjectMode, RouteConfig as RustRouteConfig,
};
use nono_proxy::ProxyConfig as RustProxyConfig;
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use std::net::IpAddr;
use std::sync::Mutex;

// ---------------------------------------------------------------------------
// InjectMode
// ---------------------------------------------------------------------------

/// Credential injection method for reverse proxy routes.
#[pyclass(frozen, eq, hash)]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum InjectMode {
    /// Inject credential as an HTTP header (default).
    #[pyo3(name = "HEADER")]
    Header,
    /// Replace a pattern in the URL path with the credential.
    #[pyo3(name = "URL_PATH")]
    UrlPath,
    /// Add the credential as a query parameter.
    #[pyo3(name = "QUERY_PARAM")]
    QueryParam,
    /// Use HTTP Basic Authentication.
    #[pyo3(name = "BASIC_AUTH")]
    BasicAuth,
}

#[pymethods]
impl InjectMode {
    fn __repr__(&self) -> &'static str {
        match self {
            InjectMode::Header => "InjectMode.HEADER",
            InjectMode::UrlPath => "InjectMode.URL_PATH",
            InjectMode::QueryParam => "InjectMode.QUERY_PARAM",
            InjectMode::BasicAuth => "InjectMode.BASIC_AUTH",
        }
    }

    fn __str__(&self) -> &'static str {
        match self {
            InjectMode::Header => "header",
            InjectMode::UrlPath => "url_path",
            InjectMode::QueryParam => "query_param",
            InjectMode::BasicAuth => "basic_auth",
        }
    }
}

impl From<InjectMode> for RustInjectMode {
    fn from(mode: InjectMode) -> Self {
        match mode {
            InjectMode::Header => RustInjectMode::Header,
            InjectMode::UrlPath => RustInjectMode::UrlPath,
            InjectMode::QueryParam => RustInjectMode::QueryParam,
            InjectMode::BasicAuth => RustInjectMode::BasicAuth,
        }
    }
}

impl From<RustInjectMode> for InjectMode {
    fn from(mode: RustInjectMode) -> Self {
        match mode {
            RustInjectMode::Header => InjectMode::Header,
            RustInjectMode::UrlPath => InjectMode::UrlPath,
            RustInjectMode::QueryParam => InjectMode::QueryParam,
            RustInjectMode::BasicAuth => InjectMode::BasicAuth,
        }
    }
}

// ---------------------------------------------------------------------------
// RouteConfig
// ---------------------------------------------------------------------------

/// Configuration for a reverse proxy credential injection route.
#[pyclass]
#[derive(Clone)]
pub struct RouteConfig {
    inner: RustRouteConfig,
}

#[pymethods]
impl RouteConfig {
    #[new]
    #[pyo3(signature = (
        prefix,
        upstream,
        credential_key = None,
        inject_mode = InjectMode::Header,
        inject_header = String::from("Authorization"),
        credential_format = String::from("Bearer {}"),
        path_pattern = None,
        path_replacement = None,
        query_param_name = None,
        env_var = None,
        endpoint_rules = vec![],
        tls_ca = None,
        tls_client_cert = None,
        tls_client_key = None,
    ))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        prefix: String,
        upstream: String,
        credential_key: Option<String>,
        inject_mode: InjectMode,
        inject_header: String,
        credential_format: String,
        path_pattern: Option<String>,
        path_replacement: Option<String>,
        query_param_name: Option<String>,
        env_var: Option<String>,
        endpoint_rules: Vec<(String, String)>,
        tls_ca: Option<String>,
        tls_client_cert: Option<String>,
        tls_client_key: Option<String>,
    ) -> Self {
        Self {
            inner: RustRouteConfig {
                prefix,
                upstream,
                credential_key,
                inject_mode: inject_mode.into(),
                inject_header,
                credential_format,
                path_pattern,
                path_replacement,
                query_param_name,
                proxy: None,
                env_var,
                endpoint_rules: endpoint_rules
                    .into_iter()
                    .map(|(method, path)| RustEndpointRule { method, path })
                    .collect(),
                tls_ca,
                tls_client_cert,
                tls_client_key,
            },
        }
    }

    #[getter]
    fn prefix(&self) -> &str {
        &self.inner.prefix
    }

    #[getter]
    fn upstream(&self) -> &str {
        &self.inner.upstream
    }

    #[getter]
    fn credential_key(&self) -> Option<&str> {
        self.inner.credential_key.as_deref()
    }

    #[getter]
    fn inject_mode(&self) -> InjectMode {
        self.inner.inject_mode.clone().into()
    }

    #[getter]
    fn inject_header(&self) -> &str {
        &self.inner.inject_header
    }

    #[getter]
    fn credential_format(&self) -> &str {
        &self.inner.credential_format
    }

    #[getter]
    fn path_pattern(&self) -> Option<&str> {
        self.inner.path_pattern.as_deref()
    }

    #[getter]
    fn path_replacement(&self) -> Option<&str> {
        self.inner.path_replacement.as_deref()
    }

    #[getter]
    fn query_param_name(&self) -> Option<&str> {
        self.inner.query_param_name.as_deref()
    }

    #[getter]
    fn env_var(&self) -> Option<&str> {
        self.inner.env_var.as_deref()
    }

    #[getter]
    fn endpoint_rules(&self) -> Vec<(String, String)> {
        self.inner
            .endpoint_rules
            .iter()
            .map(|r| (r.method.clone(), r.path.clone()))
            .collect()
    }

    #[getter]
    fn tls_ca(&self) -> Option<&str> {
        self.inner.tls_ca.as_deref()
    }

    #[getter]
    fn tls_client_cert(&self) -> Option<&str> {
        self.inner.tls_client_cert.as_deref()
    }

    #[getter]
    fn tls_client_key(&self) -> Option<&str> {
        self.inner.tls_client_key.as_deref()
    }

    fn __repr__(&self) -> String {
        format!(
            "RouteConfig(prefix='{}', upstream='{}')",
            self.inner.prefix, self.inner.upstream
        )
    }
}

// ---------------------------------------------------------------------------
// ExternalProxyConfig
// ---------------------------------------------------------------------------

/// Configuration for enterprise proxy passthrough.
#[pyclass]
#[derive(Clone)]
pub struct ExternalProxyConfig {
    inner: RustExternalProxyConfig,
}

#[pymethods]
impl ExternalProxyConfig {
    #[new]
    #[pyo3(signature = (address, bypass_hosts = vec![]))]
    fn new(address: String, bypass_hosts: Vec<String>) -> Self {
        Self {
            inner: RustExternalProxyConfig {
                address,
                auth: None,
                bypass_hosts,
            },
        }
    }

    #[getter]
    fn address(&self) -> &str {
        &self.inner.address
    }

    #[getter]
    fn bypass_hosts(&self) -> Vec<String> {
        self.inner.bypass_hosts.clone()
    }

    fn __repr__(&self) -> String {
        format!("ExternalProxyConfig(address='{}')", self.inner.address)
    }
}

// ---------------------------------------------------------------------------
// ProxyConfig
// ---------------------------------------------------------------------------

/// Configuration for the nono network filtering proxy.
#[pyclass]
#[derive(Clone)]
pub struct ProxyConfig {
    pub(crate) inner: RustProxyConfig,
}

impl ProxyConfig {
    pub(crate) fn from_inner(inner: RustProxyConfig) -> Self {
        Self { inner }
    }
}

#[pymethods]
impl ProxyConfig {
    #[new]
    #[pyo3(signature = (
        allowed_hosts = vec![],
        routes = vec![],
        external_proxy = None,
        bind_addr = String::from("127.0.0.1"),
        bind_port = 0,
        max_connections = 256,
    ))]
    fn new(
        allowed_hosts: Vec<String>,
        routes: Vec<RouteConfig>,
        external_proxy: Option<ExternalProxyConfig>,
        bind_addr: String,
        bind_port: u16,
        max_connections: usize,
    ) -> PyResult<Self> {
        let addr: IpAddr = bind_addr
            .parse()
            .map_err(|e| PyValueError::new_err(format!("Invalid bind address: {}", e)))?;

        Ok(Self {
            inner: RustProxyConfig {
                bind_addr: addr,
                bind_port,
                allowed_hosts,
                routes: routes.into_iter().map(|r| r.inner).collect(),
                external_proxy: external_proxy.map(|e| e.inner),
                max_connections,
            },
        })
    }

    #[getter]
    fn bind_addr(&self) -> String {
        self.inner.bind_addr.to_string()
    }

    #[getter]
    fn bind_port(&self) -> u16 {
        self.inner.bind_port
    }

    #[getter]
    fn allowed_hosts(&self) -> Vec<String> {
        self.inner.allowed_hosts.clone()
    }

    #[getter]
    fn routes(&self) -> Vec<RouteConfig> {
        self.inner
            .routes
            .iter()
            .map(|r| RouteConfig { inner: r.clone() })
            .collect()
    }

    #[getter]
    fn max_connections(&self) -> usize {
        self.inner.max_connections
    }

    fn __repr__(&self) -> String {
        format!(
            "ProxyConfig(hosts={}, routes={}, bind={}:{})",
            self.inner.allowed_hosts.len(),
            self.inner.routes.len(),
            self.inner.bind_addr,
            self.inner.bind_port,
        )
    }
}

// ---------------------------------------------------------------------------
// ProxyHandle
// ---------------------------------------------------------------------------

/// Handle to a running nono proxy instance.
///
/// Returned by `start_proxy()`. Provides access to environment variables
/// for the sandboxed child, audit event draining, and shutdown.
#[pyclass]
pub struct ProxyHandle {
    handle: nono_proxy::ProxyHandle,
    config: RustProxyConfig,
    runtime: Mutex<Option<tokio::runtime::Runtime>>,
}

#[pymethods]
impl ProxyHandle {
    /// The port the proxy is listening on.
    #[getter]
    fn port(&self) -> u16 {
        self.handle.port
    }

    /// Environment variables to inject into the sandboxed child process.
    ///
    /// Returns a dict containing HTTP_PROXY, HTTPS_PROXY, NO_PROXY,
    /// NONO_PROXY_TOKEN, and their lowercase variants.
    fn env_vars(&self) -> PyResult<PyObject> {
        let vars = self.handle.env_vars();
        Python::with_gil(|py| {
            let dict = pyo3::types::PyDict::new(py);
            for (k, v) in vars {
                dict.set_item(k, v)?;
            }
            Ok(dict.into())
        })
    }

    /// Environment variables for reverse proxy credential routes.
    ///
    /// Returns a dict containing base URL overrides and phantom tokens
    /// for routes where credentials were successfully loaded.
    fn credential_env_vars(&self) -> PyResult<PyObject> {
        let vars = self.handle.credential_env_vars(&self.config);
        Python::with_gil(|py| {
            let dict = pyo3::types::PyDict::new(py);
            for (k, v) in vars {
                dict.set_item(k, v)?;
            }
            Ok(dict.into())
        })
    }

    /// Drain and return collected network audit events.
    ///
    /// Returns a list of dicts, each representing a network request
    /// observed by the proxy. Events are removed from the internal
    /// buffer once drained.
    fn drain_audit_events(&self) -> PyResult<PyObject> {
        let events = self.handle.drain_audit_events();
        Python::with_gil(|py| {
            let list = pyo3::types::PyList::empty(py);
            for event in events {
                let dict = pyo3::types::PyDict::new(py);
                dict.set_item("timestamp_unix_ms", event.timestamp_unix_ms)?;
                dict.set_item(
                    "mode",
                    match event.mode {
                        nono::undo::NetworkAuditMode::Connect => "connect",
                        nono::undo::NetworkAuditMode::Reverse => "reverse",
                        nono::undo::NetworkAuditMode::External => "external",
                    },
                )?;
                dict.set_item(
                    "decision",
                    match event.decision {
                        nono::undo::NetworkAuditDecision::Allow => "allow",
                        nono::undo::NetworkAuditDecision::Deny => "deny",
                    },
                )?;
                dict.set_item("target", &event.target)?;
                dict.set_item("port", event.port)?;
                dict.set_item("method", event.method.as_deref())?;
                dict.set_item("path", event.path.as_deref())?;
                dict.set_item("status", event.status)?;
                dict.set_item("reason", event.reason.as_deref())?;
                list.append(dict)?;
            }
            Ok(list.into())
        })
    }

    /// Signal the proxy to shut down gracefully.
    fn shutdown(&self) {
        self.handle.shutdown();
        if let Ok(mut rt) = self.runtime.lock() {
            rt.take();
        }
    }

    fn __repr__(&self) -> String {
        format!("ProxyHandle(port={})", self.handle.port)
    }
}

// ---------------------------------------------------------------------------
// start_proxy
// ---------------------------------------------------------------------------

/// Start the nono network filtering proxy.
///
/// Creates a tokio runtime, starts the proxy server, and returns a
/// `ProxyHandle` for interacting with it. The proxy runs on a background
/// thread and is shut down when `ProxyHandle.shutdown()` is called.
///
/// Args:
///     config: Proxy configuration
///
/// Returns:
///     ProxyHandle for the running proxy
///
/// Raises:
///     RuntimeError: If the proxy fails to start
#[pyfunction]
pub fn start_proxy(py: Python<'_>, config: &ProxyConfig) -> PyResult<ProxyHandle> {
    let rust_config = config.inner.clone();
    let config_copy = config.inner.clone();

    py.allow_threads(|| {
        let runtime = tokio::runtime::Runtime::new()
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to create runtime: {}", e)))?;

        let handle = runtime
            .block_on(nono_proxy::start(rust_config))
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to start proxy: {}", e)))?;

        Ok(ProxyHandle {
            handle,
            config: config_copy,
            runtime: Mutex::new(Some(runtime)),
        })
    })
}
