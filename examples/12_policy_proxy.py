#!/usr/bin/env python3
"""Load proxy domain policy from JSON and demonstrate allow/deny behavior.

This example resolves a proxy configuration from `policy_example.json`,
starts the proxy, and runs a sandboxed child that makes one allowed HTTPS
request and one blocked HTTPS request through the proxy.
"""

import contextlib
import os
import sys
import tempfile
from pathlib import Path

from nono_py import (
    AccessMode,
    CapabilitySet,
    is_supported,
    load_policy,
    sandboxed_exec,
    start_proxy,
)


def build_caps(workdir: str) -> CapabilitySet:
    """Build sandbox capabilities for the child process."""
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

    policy_path = Path(__file__).parent / "policy_example.json"
    policy = load_policy(policy_path.read_text())
    proxy_config = policy.resolve_proxy_config(["proxy_web_demo"])
    if proxy_config is None:
        raise RuntimeError("proxy_web_demo did not resolve a proxy config")

    print(f"Loaded policy from: {policy_path}")
    print(f"Allowed hosts from JSON: {proxy_config.allowed_hosts}")
    print("Blocked domains are denied by omission from that allowlist.\n")

    proxy = start_proxy(proxy_config)
    print(f"Proxy listening on 127.0.0.1:{proxy.port}\n")

    try:
        with tempfile.TemporaryDirectory() as workdir:
            caps = build_caps(workdir)
            child_env = list(proxy.env_vars().items()) + list(proxy.credential_env_vars().items())
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
    ("blocked", "https://evil.com"),
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
            print(f"Child exit_code: {result.exit_code}")
            if result.stdout:
                print("Child stdout:")
                for line in result.stdout.decode().strip().splitlines():
                    print(f"  {line}")
            if result.stderr:
                print("Child stderr:")
                for line in result.stderr.decode().strip().splitlines():
                    print(f"  {line}")
            print()

        print("Proxy audit events:")
        for event in proxy.drain_audit_events():
            reason = event.get("reason")
            suffix = f" ({reason})" if reason else ""
            print(f"  [{event['decision']}] {event['mode']} -> {event['target']}{suffix}")

    finally:
        proxy.shutdown()
        print("\nProxy shut down.")


if __name__ == "__main__":
    main()
