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
