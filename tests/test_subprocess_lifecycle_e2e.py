"""Executable, subprocess-level checks for the OpenCLI transport boundary.

These tests deliberately use a real executable rather than monkeypatching
``subprocess.run``.  They are deterministic and do not invoke a live model.
"""

from __future__ import annotations

import stat
import os
import re
import shutil
import subprocess
import sys
import textwrap
import time

import pytest

from reviewer.opencli import OpenCLITransport


@pytest.fixture
def fake_opencli(tmp_path):
    script = tmp_path / "fake-opencli.py"
    script.write_text(
        textwrap.dedent(
            """
            import json, os, signal, subprocess, sys, time

            mode = sys.argv[1]
            command = sys.argv[3] if len(sys.argv) > 3 else ""
            if mode == "valid":
                if command == "ask":
                    print(json.dumps([{"response": "ask-snapshot", "conversationId": "c"}]))
                elif command == "detail":
                    print(json.dumps([{"Index": 1, "Role": "Assistant", "Text": "{\\"status\\":\\"PASS\\"}", "Generating": False, "StableSeconds": 6}]))
                else:
                    raise SystemExit(2)
            elif mode == "malformed":
                print("not-json")
            elif mode == "empty":
                pass
            elif mode == "nonzero":
                print("failure", file=sys.stderr)
                raise SystemExit(7)
            elif mode == "partial":
                print("[{\\"response\\":", end="", flush=True)
                time.sleep(2)
            elif mode == "hang":
                time.sleep(2)
            elif mode == "child-holds-pipe":
                # The child inherits stdout and keeps communicate() from
                # completing after the parent is terminated.
                subprocess.Popen([sys.executable, "-c", "import time; time.sleep(2)"])
                print("[{\\"response\\":", end="", flush=True)
                time.sleep(2)
            elif mode == "ignore-term":
                signal.signal(signal.SIGTERM, signal.SIG_IGN)
                time.sleep(2)
            elif mode == "version":
                print("1.8.6")
            else:
                raise SystemExit(2)
            """
        ).lstrip()
    )
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return script


def transport(fake_opencli, mode, *, process_timeout=5):
    # The transport appends the OpenCLI arguments, so the fake receives its
    # mode from the prompt position (the first positional argument after the
    # executable in this test-specific command wrapper).
    wrapper = fake_opencli.parent / f"run-{mode}.sh"
    wrapper.write_text(f"#!/bin/sh\nexec {sys.executable} {fake_opencli} {mode} \"$@\"\n")
    wrapper.chmod(wrapper.stat().st_mode | stat.S_IXUSR)
    return OpenCLITransport(executable=str(wrapper), timeout=0, process_timeout=process_timeout)


@pytest.mark.parametrize("mode", ["valid", "malformed", "empty", "nonzero"])
def test_real_executable_terminal_outcomes(fake_opencli, mode):
    result = transport(fake_opencli, mode).invoke("prompt")
    if mode == "valid":
        assert result.status == "REVIEW_COMPLETED"
        assert result.raw == '{"status":"PASS"}'
        assert result.envelope["conversationId"] == "c"
    else:
        assert result.status == "OPENCLI_PROCESS_FAILURE"


@pytest.mark.parametrize("mode", ["hang", "partial", "ignore-term"])
def test_timeout_is_unknown_and_fail_closed(fake_opencli, mode):
    started = time.monotonic()
    result = transport(fake_opencli, mode, process_timeout=0.25).invoke("prompt")
    elapsed = time.monotonic() - started
    assert result.status == "OPENCLI_OUTCOME_UNKNOWN"
    assert result.outcome_unknown is True
    assert result.retry_safe is False
    assert elapsed < 3, f"timeout path exceeded bound: {elapsed:.2f}s"


def test_descendant_pipe_holder_is_bounded(fake_opencli):
    """A child inheriting stdout must not make the caller hang indefinitely."""
    started = time.monotonic()
    result = transport(fake_opencli, "child-holds-pipe", process_timeout=0.25).invoke("prompt")
    elapsed = time.monotonic() - started
    assert result.status == "OPENCLI_OUTCOME_UNKNOWN"
    assert result.outcome_unknown is True
    assert elapsed < 4, f"descendant pipe path exceeded bound: {elapsed:.2f}s"


def test_installed_opencli_version_is_observation_only():
    executable = os.environ.get("OPENCLI_EXECUTABLE") or shutil.which("opencli")
    if not executable:
        pytest.skip("OpenCLI is not installed")
    completed = subprocess.run(
        [executable, "--version"],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert completed.returncode == 0
    assert re.fullmatch(r"v?\d+\.\d+\.\d+", completed.stdout.strip())
