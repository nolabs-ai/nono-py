#!/usr/bin/env python3
"""Proxy basics with a sandboxed child process.

Demonstrates starting the nono proxy, injecting its environment into a
sandboxed child, and showing both an allowed and denied outbound request.

The child still runs under OS-enforced sandboxing for filesystem/process
isolation, while the proxy handles domain-level allow/deny behavior.
"""

import contextlib
import os
import sys
import tempfile

from nono_py import (
    AccessMode,
    CapabilitySet,
    InjectMode,
    ProxyConfig,
    RouteConfig,
    is_supported,
    sandboxed_exec,
    start_proxy,
)


def build_caps(workdir: str) -> CapabilitySet:
    """Build sandbox capabilities for a child that uses the proxy."""
    caps = CapabilitySet()

    for sys_path in ["/usr", "/bin", "/sbin", "/lib"]:
        with contextlib.suppress(FileNotFoundError):
            caps.allow_path(sys_path, AccessMode.READ)

    for sys_path in ["/private", "/Library/Frameworks", "/dev"]:
        with contextlib.suppress(FileNotFoundError):
            caps.allow_path(sys_path, AccessMode.READ)

    caps.allow_path(workdir, AccessMode.READ_WRITE)

    runtime_paths = {
        sys.prefix,
        sys.base_prefix,
        os.path.dirname(sys.executable),
    }
    real_executable = os.path.realpath(sys.executable)
    runtime_paths.add(os.path.dirname(real_executable))
    runtime_paths.add(os.path.dirname(os.path.dirname(real_executable)))
    runtime_paths.add(os.path.normpath(os.path.join(os.path.dirname(real_executable), "..", "lib")))

    for runtime_path in runtime_paths:
        with contextlib.suppress(FileNotFoundError):
            caps.allow_path(runtime_path, AccessMode.READ)

    import nono_py

    module_file = nono_py.__file__
    if module_file is None:
        raise RuntimeError("nono_py.__file__ is unavailable")
    caps.allow_path(os.path.dirname(module_file), AccessMode.READ)

    return caps


def main() -> None:
    if not is_supported():
        print("Sandboxing not supported on this platform")
        sys.exit(1)

    print("1. Creating proxy config with domain filtering\n")
    config = ProxyConfig(
        allowed_hosts=["example.com"],
    )
    print(f"   Config: {config!r}")
    print(f"   Allowed hosts: {config.allowed_hosts}")

    print("\n2. Starting proxy...")
    proxy = start_proxy(config)
    print(f"   Proxy listening on port {proxy.port}")

    try:
        print("\n3. Environment variables for the sandboxed child:")
        env = proxy.env_vars()
        for key in sorted(env):
            value = env[key]
            if len(value) > 80:
                value = value[:60] + "..."
            print(f"   {key}={value}")

        print("\n4. Running a sandboxed child through the proxy:")
        with tempfile.TemporaryDirectory() as workdir:
            caps = build_caps(workdir)
            child_env = list(env.items()) + list(proxy.credential_env_vars().items())
            child_code = """
import os
import urllib.request

proxy_url = os.environ["HTTP_PROXY"]
opener = urllib.request.build_opener(
    urllib.request.ProxyHandler({
        "http": proxy_url,
        "https": os.environ["HTTPS_PROXY"],
    })
)

targets = [
    ("allowed", "https://example.com"),
    ("denied", "https://evil.com"),
]

for label, url in targets:
    try:
        with opener.open(url, timeout=5) as response:
            print(f"{label}: status={response.status} url={url}")
    except Exception as exc:
        print(f"{label}: error={type(exc).__name__}: {exc}")
"""
            result = sandboxed_exec(
                caps,
                [sys.executable, "-c", child_code],
                cwd=workdir,
                env=child_env,
                timeout_secs=10.0,
            )
            print(f"   exit_code: {result.exit_code}")
            stdout = result.stdout.decode().strip()
            stderr = result.stderr.decode().strip()
            if stdout:
                print("   child stdout:")
                for line in stdout.splitlines():
                    print(f"     {line}")
            if stderr:
                print("   child stderr:")
                for line in stderr.splitlines():
                    print(f"     {line}")

        print("\n5. Audit events from the proxy:")
        events = proxy.drain_audit_events()
        print(f"   {len(events)} event(s) recorded")
        for event in events:
            decision = event["decision"]
            target = event["target"]
            mode = event["mode"]
            reason = event.get("reason")
            suffix = f" ({reason})" if reason else ""
            print(f"   [{decision}] {mode} -> {target}{suffix}")

        print("\n6. Credential environment variables:")
        cred_env = proxy.credential_env_vars()
        if cred_env:
            for key, value in sorted(cred_env.items()):
                print(f"   {key}={value}")
        else:
            print("   (none - no credential routes configured)")

    finally:
        proxy.shutdown()
        print("\n7. Proxy shut down.")

    print("\n8. Route config examples:")
    header_route = RouteConfig(
        prefix="/openai",
        upstream="https://api.openai.com",
        credential_key="openai-key",
        inject_mode=InjectMode.HEADER,
        inject_header="Authorization",
        credential_format="Bearer {}",
    )
    print(f"   Header injection: {header_route!r}")
    print(f"     inject_mode={header_route.inject_mode}")
    print(f"     credential_key={header_route.credential_key}")

    query_route = RouteConfig(
        prefix="/maps",
        upstream="https://maps.googleapis.com",
        credential_key="google-maps-key",
        inject_mode=InjectMode.QUERY_PARAM,
        query_param_name="key",
    )
    print(f"   Query param injection: {query_route!r}")
    print(f"     inject_mode={query_route.inject_mode}")
    print(f"     query_param_name={query_route.query_param_name}")

    print("\nAll examples completed.")


if __name__ == "__main__":
    main()
