#!/usr/bin/env python3
"""Sandbox subprocess execution.

This example demonstrates sandboxing untrusted code by running it
in a subprocess with restricted capabilities. The subprocess
receives the sandbox configuration via an environment variable.

NOTE: This is a demonstration pattern. In production, you would
typically have a separate worker script that applies the sandbox.
"""

import os
import subprocess
import sys
import tempfile

from nono_py import AccessMode, CapabilitySet, SandboxState, is_supported


def create_worker_script(workdir: str) -> str:
    """Create a Python script that runs inside the sandbox."""
    script = f'''
import os
import sys

# Add parent to path for imports
sys.path.insert(0, "{os.path.dirname(os.path.dirname(os.path.abspath(__file__)))}")

from nono_py import SandboxState, apply

def main():
    # Reconstruct sandbox from environment
    json_str = os.environ.get("NONO_STATE")
    if not json_str:
        print("ERROR: No NONO_STATE environment variable")
        sys.exit(1)

    state = SandboxState.from_json(json_str)
    caps = state.to_caps()

    print("Worker: Applying sandbox...")
    apply(caps)
    print("Worker: Sandbox active!")

    # Now do work within the sandbox
    workdir = "{workdir}"

    # This should succeed (workdir is allowed)
    test_file = os.path.join(workdir, "output.txt")
    with open(test_file, "w") as f:
        f.write("Written from sandboxed worker!")
    print(f"Worker: Wrote to {{test_file}}")

    # Read it back
    with open(test_file) as f:
        print(f"Worker: Content: {{f.read()}}")

    # Try to access forbidden paths (would fail)
    # with open("/etc/passwd") as f:
    #     pass  # PermissionError!

    print("Worker: Done!")

if __name__ == "__main__":
    main()
'''
    return script


def main() -> None:
    if not is_supported():
        print("Sandboxing not supported on this platform")
        sys.exit(1)

    with tempfile.TemporaryDirectory() as workdir:
        print(f"Work directory: {workdir}")

        # Create sandbox configuration
        caps = CapabilitySet()
        caps.allow_path(workdir, AccessMode.READ_WRITE)
        # Allow read access to Python and system libraries
        caps.allow_path("/usr", AccessMode.READ)
        caps.allow_path(sys.prefix, AccessMode.READ)
        # Allow read access to the nono_py package
        import nono_py

        module_file = nono_py.__file__
        if module_file is None:
            raise RuntimeError("nono_py.__file__ is unavailable")
        pkg_dir = os.path.dirname(module_file)
        caps.allow_path(pkg_dir, AccessMode.READ)
        caps.block_network()

        print("\nSandbox configuration for worker:")
        print(caps.summary())

        # Serialize state
        state = SandboxState.from_caps(caps)
        json_str = state.to_json()

        # Create worker script
        worker_script = create_worker_script(workdir)
        worker_path = os.path.join(workdir, "worker.py")
        with open(worker_path, "w") as f:
            f.write(worker_script)

        print("\nLaunching sandboxed subprocess...")
        print("-" * 50)

        # Run the worker in a subprocess
        env = os.environ.copy()
        env["NONO_STATE"] = json_str

        result = subprocess.run(  # noqa: S603
            [sys.executable, worker_path],
            env=env,
            capture_output=True,
            text=True,
            shell=False
        )

        print(result.stdout)
        if result.stderr:
            print("STDERR:", result.stderr)

        print("-" * 50)
        print(f"Worker exit code: {result.returncode}")

        # Verify the worker's output
        output_file = os.path.join(workdir, "output.txt")
        if os.path.exists(output_file):
            with open(output_file) as f:
                print(f"Parent verified output: {f.read()}")


if __name__ == "__main__":
    main()
