"""Shared helpers for proxy + sandbox examples."""

import contextlib
import os
import sys

from nono_py import AccessMode, CapabilitySet

PROXY_DEMO_CHILD_CODE = """
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


def build_proxy_child_caps(workdir: str) -> CapabilitySet:
    """Build sandbox capabilities for a child process that uses the proxy."""
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
    runtime_paths.add(
        os.path.normpath(os.path.join(os.path.dirname(real_executable), "..", "lib"))
    )

    for runtime_path in runtime_paths:
        with contextlib.suppress(FileNotFoundError):
            caps.allow_path(runtime_path, AccessMode.READ)

    import nono_py

    module_file = nono_py.__file__
    if module_file is None:
        raise RuntimeError("nono_py.__file__ is unavailable")
    caps.allow_path(os.path.dirname(module_file), AccessMode.READ)

    return caps
