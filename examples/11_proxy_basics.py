#!/usr/bin/env python3
"""Network proxy with domain filtering and credential injection.

Demonstrates starting the nono proxy, inspecting the environment variables
it generates for sandboxed children, and shutting it down.

The proxy runs on localhost and provides:
- Domain filtering (allowlist of hosts the child can reach)
- Credential injection (phantom tokens swapped for real keys from OS keyring)
- Audit logging (every network request recorded)

Manual testing steps:

    1. Run this script:
       uv run python examples/11_proxy_basics.py

    2. While the proxy is running, you can test it with curl in another terminal:
       # This should succeed (example.com is in the allowlist):
       curl -x http://nono:<token>@127.0.0.1:<port> https://example.com

       # This should be denied (not in the allowlist):
       curl -x http://nono:<token>@127.0.0.1:<port> https://evil.com

       (Replace <token> and <port> with values printed by the script)
"""

from nono_py import (
    InjectMode,
    ProxyConfig,
    RouteConfig,
    start_proxy,
)


def main() -> None:
    # --- 1. Configure proxy with domain filtering ---
    print("1. Creating proxy config with domain filtering\n")

    config = ProxyConfig(
        allowed_hosts=["example.com", "*.anthropic.com", "api.openai.com"],
    )
    print(f"   Config: {config!r}")
    print(f"   Allowed hosts: {config.allowed_hosts}")

    # --- 2. Start the proxy ---
    print("\n2. Starting proxy...")
    proxy = start_proxy(config)
    print(f"   Proxy listening on port {proxy.port}")

    # --- 3. Inspect environment variables ---
    print("\n3. Environment variables for the sandboxed child:")
    env = proxy.env_vars()
    for key in sorted(env):
        value = env[key]
        # Truncate long token values for display
        if len(value) > 80:
            value = value[:60] + "..."
        print(f"   {key}={value}")

    # --- 4. Show credential env vars (empty since no routes with credentials) ---
    print("\n4. Credential environment variables:")
    cred_env = proxy.credential_env_vars()
    if cred_env:
        for key, value in sorted(cred_env.items()):
            print(f"   {key}={value}")
    else:
        print("   (none - no credential routes configured)")

    # --- 5. Check audit events (empty since no requests made) ---
    print("\n5. Audit events:")
    events = proxy.drain_audit_events()
    print(f"   {len(events)} events recorded")

    # --- 6. Shutdown ---
    proxy.shutdown()
    print("\n6. Proxy shut down.")

    # --- 7. Show route config construction ---
    print("\n7. Route config examples:")
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
