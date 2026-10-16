"""Issue #85: the action must verify the vendored wheel against provenance before install."""
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "verify_vendored_wheel.py"
WHEEL = "repository_intelligence_engine-0.1.0-py3-none-any.whl"


def _run(vendor):
    return subprocess.run([sys.executable, str(SCRIPT), str(vendor)], capture_output=True, text=True)


def test_pristine_vendored_wheel_verifies(tmp_path):
    r = _run(ROOT / "vendor")
    assert r.returncode == 0, r.stderr


def test_tampered_vendored_wheel_is_rejected(tmp_path):
    vendor = tmp_path / "vendor"
    shutil.copytree(ROOT / "vendor", vendor)
    with zipfile.ZipFile(vendor / WHEEL, "a") as z:
        z.writestr("repository_intelligence/_tampered.py", "TAMPERED = True\n")
    r = _run(vendor)
    assert r.returncode != 0
    assert "VENDOR_WHEEL_SHA256_MISMATCH" in r.stderr


def test_missing_wheel_is_rejected(tmp_path):
    vendor = tmp_path / "vendor"
    shutil.copytree(ROOT / "vendor", vendor)
    (vendor / WHEEL).unlink()
    assert _run(vendor).returncode != 0


def test_action_verifies_before_installing():
    text = (ROOT / "action.yml").read_text(encoding="utf-8")
    verify = text.index("verify_vendored_wheel.py")
    install = text.index("python3 -m pip install")
    assert verify < install  # set -euo pipefail aborts the step on verifier failure
    assert "set -euo pipefail" in text[:verify]


# --- R85-A: install exactly the wheel whose sha256 was verified ---------------
import hashlib
import json
import re

PROV = "repository-intelligence-engine.provenance.json"


def _run_block():
    text = (ROOT / "action.yml").read_text(encoding="utf-8")
    block = text.split("run: |\n", 1)[1]
    lines = []
    for line in block.splitlines():
        if line.startswith("        "):
            lines.append(line[8:])
        else:
            break
    script = "\n".join(lines)
    script = script.split("args=(", 1)[0]  # stop before running reviewer code
    return re.sub(r"python3 -m pip install", "echo PIP_INSTALL", script)


def _dry_run(tmp_path, mutate):
    root = tmp_path / "action"
    (root / "scripts").mkdir(parents=True)
    shutil.copy(SCRIPT, root / "scripts" / SCRIPT.name)
    shutil.copytree(ROOT / "vendor", root / "vendor")
    mutate(root / "vendor")
    env = {"GITHUB_ACTION_PATH": str(root), "PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin"}
    r = subprocess.run(["bash", "-c", _run_block()], capture_output=True, text=True, env=env)
    return root, r


def _decoy_with_tampered_hardcoded(vendor):
    shutil.copy(vendor / WHEEL, vendor / "decoy-0.1.0-py3-none-any.whl")
    prov = json.loads((vendor / PROV).read_text())
    prov["wheel_filename"] = "decoy-0.1.0-py3-none-any.whl"
    (vendor / PROV).write_text(json.dumps(prov))
    with zipfile.ZipFile(vendor / WHEEL, "a") as z:
        z.writestr("evil.py", "x=1")


def test_action_dry_run_genuine_installs_verified_wheel(tmp_path):
    root, r = _dry_run(tmp_path, lambda v: None)
    assert r.returncode == 0, r.stderr
    assert Path(r.stdout.strip().split()[-1]).resolve() == (root / "vendor" / WHEEL).resolve()


def test_action_never_installs_unverified_hardcoded_wheel_when_provenance_is_decoy(tmp_path):
    root, r = _dry_run(tmp_path, _decoy_with_tampered_hardcoded)
    tampered = (root / "vendor" / WHEEL).resolve()
    for line in r.stdout.splitlines():
        if "PIP_INSTALL" in line:
            installed = Path(line.split()[-1])
            assert installed.resolve() != tampered
            expected = json.loads((root / "vendor" / PROV).read_text())["wheel_sha256"]
            assert hashlib.sha256(installed.read_bytes()).hexdigest() == expected


def test_action_dry_run_fails_step_when_verifier_fails(tmp_path):
    def tamper(v):
        with zipfile.ZipFile(v / WHEEL, "a") as z:
            z.writestr("evil.py", "x=1")

    _root, r = _dry_run(tmp_path, tamper)
    assert r.returncode != 0
    assert "PIP_INSTALL" not in r.stdout


def test_verifier_prints_only_verified_wheel_path_on_stdout():
    r = _run(ROOT / "vendor")
    assert r.stdout.strip() == str((ROOT / "vendor" / WHEEL).resolve())
