"""Tests for proxy_only network mode on CapabilitySet."""

import socket
import sys

import pytest
from conftest import add_system_paths

from nono_py import (
    AccessMode,
    CapabilitySet,
    ProxyConfig,
    RouteConfig,
    sandboxed_exec,
    start_proxy,
)


@pytest.fixture
def proxy():
    p = start_proxy(ProxyConfig(allowed_hosts=["example.com"]))
    yield p
    p.shutdown()


class TestProxyOnlyCapabilitySet:
    """Unit tests for proxy_only on CapabilitySet."""

    def test_proxy_only_blocks_network(self, proxy) -> None:
        """proxy_only sets proxy-only network mode."""
        caps = CapabilitySet()
        caps.proxy_only(proxy)
        assert "proxy-only" in repr(caps)

    def test_proxy_only_repr(self, proxy) -> None:
        """repr shows proxy-only mode."""
        caps = CapabilitySet()
        caps.proxy_only(proxy)
        r = repr(caps)
        assert "proxy-only" in r

    def test_block_network_repr(self) -> None:
        """repr shows blocked for block_network."""
        caps = CapabilitySet()
        caps.block_network()
        assert "blocked" in repr(caps)

    def test_default_repr(self) -> None:
        """repr shows allowed by default."""
        caps = CapabilitySet()
        assert "allowed" in repr(caps)

    def test_proxy_only_overrides_block_network(self, proxy) -> None:
        """proxy_only can be called after block_network."""
        caps = CapabilitySet()
        caps.block_network()
        caps.proxy_only(proxy)
        assert "proxy-only" in repr(caps)

    def test_block_network_overrides_proxy_only(self, proxy) -> None:
        """block_network can be called after proxy_only."""
        caps = CapabilitySet()
        caps.proxy_only(proxy)
        caps.block_network()
        assert "blocked" in repr(caps)
        assert "proxy-only" not in repr(caps)

    def test_sandbox_env_merges_per_child_env(self, proxy) -> None:
        """sandbox_env merges current proxy vars with explicit session vars."""
        proxy_vars = proxy.env_vars()
        env = dict(
            proxy.sandbox_env(
                extra_env=[
                    ("NONO_SESSION_ID", "session-123"),
                    ("HTTP_PROXY", "http://127.0.0.1:1"),
                ]
            )
        )

        assert env["NONO_SESSION_ID"] == "session-123"
        assert env["HTTP_PROXY"] == proxy_vars["HTTP_PROXY"]

    def test_sandbox_env_rejects_loader_env(self, proxy) -> None:
        """sandbox_env should not package loader-control env vars."""
        with pytest.raises(ValueError, match="LD_PRELOAD"):
            proxy.sandbox_env(extra_env=[("LD_PRELOAD", "blocked-loader.so")])

    def test_allowed_hosts_and_allow_all_hosts_conflict(self) -> None:
        """Transparent CONNECT allow-all requires an explicit, unambiguous opt-in."""
        with pytest.raises(ValueError, match="allow_all_hosts"):
            ProxyConfig(allowed_hosts=["example.com"], allow_all_hosts=True)

    def test_route_only_proxy_denies_non_route_connect(self) -> None:
        """Routes alone must not make transparent CONNECT allow-all."""
        proxy = start_proxy(
            ProxyConfig(
                routes=[
                    RouteConfig(
                        prefix="openai",
                        upstream="https://api.openai.com",
                    )
                ]
            )
        )
        try:
            with socket.create_connection(("127.0.0.1", proxy.port), timeout=3) as s:
                s.sendall(
                    b"CONNECT google.com:443 HTTP/1.1\r\n"
                    b"Host: google.com:443\r\n"
                    b"\r\n"
                )
                response = s.recv(4096)
        finally:
            proxy.shutdown()

        assert response.startswith(b"HTTP/1.1 403"), response


class TestProxyOnlySandboxedExec:
    """Integration tests for proxy_only with sandboxed_exec."""

    def _make_caps(self, temp_dir, proxy):
        caps = CapabilitySet()
        add_system_paths(caps)
        caps.allow_path(str(temp_dir), AccessMode.READ_WRITE)
        caps.proxy_only(proxy)
        return caps

    def test_child_can_connect_to_proxy(self, proxy, temp_dir) -> None:
        """Child process can reach the proxy on localhost."""
        caps = self._make_caps(temp_dir, proxy)
        env = proxy.sandbox_env()

        result = sandboxed_exec(
            caps,
            [
                sys.executable,
                "-c",
                f"import socket; s = socket.socket(); s.settimeout(3); "
                f"s.connect(('127.0.0.1', {proxy.port})); "
                f"print('CONNECTED'); s.close()",
            ],
            cwd=str(temp_dir),
            env=env,
            timeout_secs=10.0,
        )
        stderr = result.stderr.decode(errors="replace")
        assert result.exit_code == 0, f"exit={result.exit_code} stderr={stderr!r}"
        assert b"CONNECTED" in result.stdout, f"stderr={stderr!r}"

    def test_child_cannot_connect_direct(self, proxy, temp_dir) -> None:
        """Child process cannot bypass the proxy and connect directly."""
        caps = self._make_caps(temp_dir, proxy)

        result = sandboxed_exec(
            caps,
            [
                sys.executable,
                "-c",
                "import socket\n"
                "s = socket.socket()\n"
                "s.settimeout(3)\n"
                "try:\n"
                "    s.connect(('192.0.2.1', 80))\n"
                "    print('BYPASSED')\n"
                "except (PermissionError, OSError) as e:\n"
                "    print(f'BLOCKED:{type(e).__name__}')\n"
                "finally:\n"
                "    s.close()\n",
            ],
            cwd=str(temp_dir),
            timeout_secs=10.0,
        )
        stderr = result.stderr.decode(errors="replace")
        assert b"BLOCKED" in result.stdout, f"stderr={stderr!r}"
        assert b"BYPASSED" not in result.stdout

    def test_child_cannot_bypass_proxy_to_local_listener_after_env_removal(
        self, proxy, temp_dir
    ) -> None:
        """Proxy-only still blocks direct TCP if the child removes proxy env vars."""
        caps = self._make_caps(temp_dir, proxy)
        env = proxy.sandbox_env()

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            direct_port = listener.getsockname()[1]

            result = sandboxed_exec(
                caps,
                [
                    sys.executable,
                    "-c",
                    "import os, socket\n"
                    "for key in ('HTTP_PROXY', 'HTTPS_PROXY', 'http_proxy', 'https_proxy'):\n"
                    "    os.environ.pop(key, None)\n"
                    "def probe(label, port):\n"
                    "    s = socket.socket()\n"
                    "    s.settimeout(3)\n"
                    "    try:\n"
                    "        s.connect(('127.0.0.1', port))\n"
                    "        print(f'{label}:CONNECTED')\n"
                    "    except (PermissionError, OSError) as e:\n"
                    "        print(f'{label}:BLOCKED:{type(e).__name__}')\n"
                    "    finally:\n"
                    "        s.close()\n"
                    f"probe('PROXY', {proxy.port})\n"
                    f"probe('DIRECT', {direct_port})\n",
                ],
                cwd=str(temp_dir),
                env=env,
                timeout_secs=10.0,
            )

        stderr = result.stderr.decode(errors="replace")
        assert result.exit_code == 0, f"exit={result.exit_code} stderr={stderr!r}"
        assert b"PROXY:CONNECTED" in result.stdout, f"stderr={stderr!r}"
        assert b"DIRECT:BLOCKED" in result.stdout, f"stderr={stderr!r}"
        assert b"DIRECT:CONNECTED" not in result.stdout

    def test_proxy_filters_blocked_domain(self, proxy, temp_dir) -> None:
        """Proxy denies connections to domains not in the allowlist."""
        caps = self._make_caps(temp_dir, proxy)
        env = proxy.sandbox_env()

        result = sandboxed_exec(
            caps,
            [
                sys.executable,
                "-c",
                "import urllib.request, ssl, os\n"
                "ctx = ssl.create_default_context()\n"
                "ctx.check_hostname = False\n"
                "ctx.verify_mode = ssl.CERT_NONE\n"
                "try:\n"
                "    r = urllib.request.urlopen('https://google.com', timeout=5, context=ctx)\n"
                "    print(f'ALLOWED:{r.status}')\n"
                "except Exception as e:\n"
                "    s = str(e)\n"
                "    if 'not in the allowlist' in s:\n"
                "        print('PROXY-DENIED')\n"
                "    else:\n"
                "        print(f'ERROR:{s[:120]}')\n",
            ],
            cwd=str(temp_dir),
            env=env,
            timeout_secs=10.0,
        )
        stderr = result.stderr.decode(errors="replace")
        assert b"PROXY-DENIED" in result.stdout, f"stderr={stderr!r}"

    def test_audit_events_recorded(self, proxy, temp_dir) -> None:
        """Proxy records audit events for connection attempts."""
        caps = self._make_caps(temp_dir, proxy)
        env = proxy.sandbox_env()

        sandboxed_exec(
            caps,
            [
                sys.executable,
                "-c",
                "import urllib.request, ssl\n"
                "ctx = ssl.create_default_context()\n"
                "ctx.check_hostname = False\n"
                "ctx.verify_mode = ssl.CERT_NONE\n"
                "try:\n"
                "    urllib.request.urlopen('https://google.com', timeout=5, context=ctx)\n"
                "except Exception:\n"
                "    pass\n",
            ],
            cwd=str(temp_dir),
            env=env,
            timeout_secs=10.0,
        )

        events = proxy.drain_audit_events()
        assert len(events) >= 1, "no audit events recorded"
        deny_events = [e for e in events if e["decision"] == "deny"]
        assert len(deny_events) >= 1, f"all events: {events}"
        assert any("google.com" in e["target"] for e in deny_events)

    def test_block_network_prevents_proxy_access(self, proxy, temp_dir) -> None:
        """Contrast: block_network() prevents reaching the proxy entirely."""
        caps = CapabilitySet()
        add_system_paths(caps)
        caps.allow_path(str(temp_dir), AccessMode.READ_WRITE)
        caps.block_network()

        result = sandboxed_exec(
            caps,
            [
                sys.executable,
                "-c",
                "import socket\n"
                "s = socket.socket()\n"
                "s.settimeout(3)\n"
                f"try:\n"
                f"    s.connect(('127.0.0.1', {proxy.port}))\n"
                f"    print('CONNECTED')\n"
                f"except (PermissionError, OSError):\n"
                f"    print('BLOCKED')\n"
                f"finally:\n"
                f"    s.close()\n",
            ],
            cwd=str(temp_dir),
            timeout_secs=10.0,
        )
        stderr = result.stderr.decode(errors="replace")
        assert b"BLOCKED" in result.stdout, f"stderr={stderr!r}"
