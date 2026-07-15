#!/usr/bin/env python3
"""Resource limiting example.

This example demonstrates running a command under a memory ceiling and under a
process-count cap using ``nono_py.limited``, which drives the tested ``nono``
CLI. A memory breach is OOM-killed (exit 137); a process-count breach makes the
kernel refuse new forks with ``EAGAIN`` — nothing is killed, the command just
fails to spawn and surfaces its own non-zero status.

Unlike ``apply()`` (which sandboxes the current process irreversibly), this
runs the command as a child of the ``nono`` supervisor, so it is safe to run
repeatedly. It requires the ``nono`` binary on ``PATH`` (or via ``NONO_BIN``),
and enforcement needs Linux with cgroup v2 delegation.
"""

import sys
import tempfile

from nono_py import AccessMode, CapabilitySet, limited


def main() -> None:
    # The nono binary does the enforcement; bail early with a clear message if
    # it is not installed.
    try:
        binary = limited.find_nono_binary()
    except FileNotFoundError as exc:
        print(f"nono binary not found: {exc}")
        print("Install nono, put it on PATH, or set NONO_BIN.")
        sys.exit(1)
    print(f"Using nono binary: {binary}")

    with tempfile.TemporaryDirectory() as tmpdir:
        caps = CapabilitySet()
        caps.allow_path(tmpdir, AccessMode.READ_WRITE)
        caps.block_network()

        # A trivial command well under a generous cap: expected to succeed.
        print("\nRunning `true` under a 128M memory cap...")
        result = limited.run(caps, ["true"], memory="128M", cwd=tmpdir)
        print(f"  command: {' '.join(result.argv)}")
        print(f"  returncode={result.returncode} ok={result.ok}")

        if not result.ok:
            # On hosts without cgroup v2 delegation, nono fails closed rather
            # than running with an unenforced ceiling.
            print(f"  (enforcement unavailable here) stderr: {result.stderr!r}")
            return

        # A command that allocates far more than its cap: expected to be
        # OOM-killed (exit 137) rather than run to completion.
        print("\nRunning a memory hog under a 32M cap (expect OOM kill)...")
        hog = "a = bytearray(256 * 1024 * 1024)"  # allocate 256 MiB
        result = limited.run(caps, [sys.executable, "-c", hog], memory="32M", cwd=tmpdir)
        print(f"  returncode={result.returncode} oom_killed={result.oom_killed}")
        if result.oom_killed:
            print("  process exceeded its memory cap and was killed, as expected.")

        # A command that spawns far more threads than its process cap allows:
        # thread creation hits pids.max, the kernel returns EAGAIN, and Python
        # raises "can't start new thread" and exits non-zero. Nothing is killed.
        print("\nRunning a thread hog under a 32-process cap (expect non-zero exit)...")
        thread_hog = (
            "import threading, time\n"
            "for _ in range(500):\n"
            "    threading.Thread(target=time.sleep, args=(30,), daemon=True).start()\n"
        )
        result = limited.run(caps, [sys.executable, "-c", thread_hog], max_processes=32, cwd=tmpdir)
        print(f"  returncode={result.returncode} ok={result.ok}")
        if not result.ok:
            print("  process hit its fork/thread cap and could not spawn, as expected.")


if __name__ == "__main__":
    main()
