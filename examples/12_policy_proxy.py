#!/usr/bin/env python3
"""Load proxy domain policy from JSON and demonstrate allow/deny behavior.

This example resolves a proxy configuration from `policy_example.json`,
starts the proxy, and runs a sandboxed child that makes one allowed HTTPS
request and one blocked HTTPS request through the proxy.
"""

import sys
import tempfile
from pathlib import Path

from nono_py import (
    is_supported,
    load_policy,
    sandboxed_exec,
    start_proxy,
)
from proxy_demo_support import PROXY_DEMO_CHILD_CODE, build_proxy_child_caps


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
            caps = build_proxy_child_caps(workdir)
            child_env = list(proxy.env_vars().items()) + list(proxy.credential_env_vars().items())
            result = sandboxed_exec(
                caps,
                [sys.executable, "-c", PROXY_DEMO_CHILD_CODE],
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
