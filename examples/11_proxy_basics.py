#!/usr/bin/env python3
"""Proxy basics with a sandboxed child process.

Demonstrates starting the nono proxy, injecting its environment into a
    sandboxed child, and showing both an allowed and blocked outbound request.

The child still runs under OS-enforced sandboxing for filesystem/process
isolation, while the proxy handles domain-level allow/deny behavior.
"""

import sys
import tempfile

from proxy_demo_support import PROXY_DEMO_CHILD_CODE, build_proxy_child_caps

from nono_py import (
    InjectMode,
    ProxyConfig,
    RouteConfig,
    is_supported,
    sandboxed_exec,
    start_proxy,
)


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
            caps = build_proxy_child_caps(workdir)
            child_env = list(env.items()) + list(proxy.credential_env_vars().items())
            result = sandboxed_exec(
                caps,
                [sys.executable, "-c", PROXY_DEMO_CHILD_CODE],
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
