"""Tests for structured diagnostics bindings."""

from __future__ import annotations

import json

import pytest
from conftest import add_minimal_exec_paths

from nono_py import (
    AccessMode,
    CapabilitySet,
    ProxyConfig,
    RouteConfig,
    build_session_diagnostic_report,
    merge_diagnostic_report_json,
    sandboxed_exec,
    start_proxy,
)


def test_build_session_diagnostic_report_shape() -> None:
    report = build_session_diagnostic_report(1)
    assert report["exit_code"] == 1
    assert report["denials"] == []
    assert report["ipc_denials"] == []
    assert report["violations"] == []
    assert isinstance(report["diagnostics"], list)
    assert len(report["diagnostics"]) >= 2
    codes = {item["code"] for item in report["diagnostics"]}
    assert "command_failed_likely_sandbox" in codes
    assert "command_failed_application" in codes


def test_merge_diagnostic_report_json() -> None:
    session = json.dumps(
        {
            "exit_code": 0,
            "denials": [],
            "ipc_denials": [],
            "violations": [],
            "diagnostics": [],
        }
    )
    proxy = json.dumps(
        [
            {
                "code": "credential_not_found",
                "severity": "warning",
                "route_prefix": "openai",
                "message": "Credential not found",
            }
        ]
    )
    merged = merge_diagnostic_report_json(session, proxy)
    assert merged["session"]["exit_code"] == 0
    assert merged["proxy"][0]["code"] == "credential_not_found"


@pytest.mark.usefixtures("require_sandboxed_exec")
def test_exec_result_session_diagnostics(temp_dir) -> None:
    caps = CapabilitySet()
    add_minimal_exec_paths(caps)
    caps.allow_path(str(temp_dir), AccessMode.READ_WRITE)
    caps.block_network()
    result = sandboxed_exec(
        caps,
        # Shell redirection keeps the denial on /etc/hosts (not loader paths) and
        # avoids relying on an external cat binary + shared libraries on Linux.
        ["/bin/sh", "-c", "read -r _ </etc/hosts"],
        cwd=str(temp_dir),
    )
    assert result.exit_code != 0
    report = result.session_diagnostics()
    assert report["exit_code"] == result.exit_code
    sandbox_paths = [
        d.get("path")
        for d in report["diagnostics"]
        if d.get("code") == "command_failed_likely_sandbox" and d.get("path")
    ]
    assert "/etc/hosts" in sandbox_paths


def test_proxy_handle_diagnostics(monkeypatch: pytest.MonkeyPatch) -> None:
    missing_env = "NONO_PY_TEST_MISSING_CREDENTIAL"
    monkeypatch.delenv(missing_env, raising=False)
    proxy = start_proxy(
        ProxyConfig(
            allowed_hosts=["example.com"],
            routes=[
                RouteConfig(
                    prefix="missing",
                    upstream="https://api.example.com",
                    credential_key=f"env://{missing_env}",
                )
            ],
        )
    )
    try:
        diagnostics = proxy.diagnostics()
        assert isinstance(diagnostics, list)
        assert diagnostics[0]["code"] == "credential_not_found"
        assert diagnostics[0]["route_prefix"] == "missing"
        payload = json.loads(proxy.diagnostics_json())
        assert payload[0]["code"] == "credential_not_found"
    finally:
        proxy.shutdown()
