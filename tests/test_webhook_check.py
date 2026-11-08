"""Smoke tests for the free webhook-check tool.

Run: python3 tests/test_webhook_check.py   (script-mode; pytest optional)
"""
from __future__ import annotations

import contextlib
import io
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "webhook_check.py"

import webhook_check as wc  # noqa: E402

SECRET = b"test-key"


def _status(rows, rid):
    return next(r["status"] for r in rows if r["id"] == rid)


def test_fixed_reference_passes_all():
    rows = wc.evaluate(wc.probe(wc.reference_fixed, SECRET))
    assert all(r["status"] == wc.PASS for r in rows)


def test_vulnerable_reference_fails_length_and_timing():
    # The hand-rolled index loop raises IndexError on a truncated valid sig
    # (VT-D-052) and is not constant-time (VT-D-053), but still accepts valid
    # and rejects tampered.
    rows = wc.evaluate(wc.probe(wc.reference_vulnerable, SECRET))
    assert _status(rows, "VT-D-050") == wc.PASS
    assert _status(rows, "VT-D-051") == wc.PASS
    assert _status(rows, "VT-D-052") == wc.FAIL
    assert _status(rows, "VT-D-053") == wc.FAIL


def test_equality_verifier_is_length_safe_but_not_constant_time():
    # '==' does not index, so it is length-safe (052 PASS) but leaks via timing
    # (053 FAIL). Confirms the two bug shapes are distinguished.
    def eq_verify(secret, body, header):
        import hashlib, hmac
        provided = header.split("=", 1)[1]
        expected = hmac.new(secret, body, hashlib.sha256).hexdigest()
        return provided == expected

    rows = wc.evaluate(wc.probe(eq_verify, SECRET))
    assert _status(rows, "VT-D-052") == wc.PASS
    assert _status(rows, "VT-D-053") == wc.FAIL


def test_cli_exit_codes():
    assert wc.main(["--verifier", "examples.fixed_verifier:verify", "--no-cta"]) == 0
    assert wc.main(["--verifier", "examples.vulnerable_verifier:verify", "--no-cta"]) == 1


def _run_cli(*extra: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *extra],
        capture_output=True, text=True, cwd=str(ROOT),
    )


def _assert_pure_json_line(stdout: str) -> Any:
    """stdout must be exactly one line of pure, parseable JSON.

    Shape: verifier mode emits one {verifier, rows} object; demo mode emits
    a two-element array of such objects (vulnerable block, then fixed).
    """
    lines = stdout.splitlines()
    assert len(lines) == 1, f"expected exactly 1 stdout line, got {len(lines)}: {lines!r}"
    payload = json.loads(lines[0])  # raises if not pure JSON
    blocks = payload if isinstance(payload, list) else [payload]
    for b in blocks:
        assert isinstance(b, dict)
        assert set(b.keys()) == {"verifier", "rows"}
        assert isinstance(b["verifier"], str)
        assert isinstance(b["rows"], list)
        for r in b["rows"]:
            assert set(r.keys()) == {"id", "title", "status", "detail"}
            assert isinstance(r["id"], str) and isinstance(r["title"], str)
            assert r["status"] in ("PASS", "FAIL", "SKIP")
            assert isinstance(r["detail"], str)
    return payload


def test_json_demo_output_is_machine_readable():
    # --demo --no-cta --json: one JSON line, no funnel/CTA/decoration.
    # Demo shape: a two-element array — one block per built-in reference,
    # vulnerable then fixed (r1 shape: one object per verifier).
    proc = _run_cli("--demo", "--no-cta", "--json")
    # Built-in vulnerable reference FAILs 052/053 -> exit code 1.
    assert proc.returncode == 1, proc.stderr
    payload = _assert_pure_json_line(proc.stdout)
    assert isinstance(payload, list), f"demo must be a 2-element array: {payload!r}"
    assert [b["verifier"] for b in payload] == [
        "webhook_check:reference_vulnerable",
        "webhook_check:reference_fixed",
    ]
    ids = ["VT-D-050", "VT-D-051", "VT-D-052", "VT-D-053"]
    vuln, fixed = payload[0]["rows"], payload[1]["rows"]
    assert [r["id"] for r in vuln] == ids
    assert [r["id"] for r in fixed] == ids
    assert all(r["status"] == "PASS" for r in fixed)
    assert sum(1 for r in vuln if r["status"] == "FAIL") == 2
    # No funnel / decorative text leaks into the JSON line.
    assert "gumroad" not in proc.stdout and "leanpub" not in proc.stdout
    assert "─" not in proc.stdout and "RESULT:" not in proc.stdout


def test_json_fixed_verifier_output_all_pass_exit_zero():
    # reference_fixed target: exit code 0, 4 rows, verifier echoes the spec.
    spec = "examples.fixed_verifier:verify"
    proc = _run_cli("--verifier", spec, "--json")
    assert proc.returncode == 0, proc.stderr
    payload = _assert_pure_json_line(proc.stdout)
    assert payload["verifier"] == spec
    assert len(payload["rows"]) == 4
    assert all(r["status"] == "PASS" for r in payload["rows"])


def test_json_vulnerable_verifier_exit_one():
    spec = "examples.vulnerable_verifier:verify"
    proc = _run_cli("--verifier", spec, "--json")
    assert proc.returncode == 1, proc.stderr
    payload = _assert_pure_json_line(proc.stdout)
    assert payload["verifier"] == spec
    assert len(payload["rows"]) == 4


def test_json_unresolvable_verifier_exit_two_no_stdout():
    proc = _run_cli("--verifier", "no.such.module:verify", "--json")
    assert proc.returncode == 2
    assert proc.stdout == ""


def test_json_mode_in_process_prints_only_json():
    buf_out, buf_err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(buf_out), contextlib.redirect_stderr(buf_err):
        code = wc.main(["--demo", "--no-cta", "--json"])
    assert code == 1
    payload = _assert_pure_json_line(buf_out.getvalue())
    assert isinstance(payload, list) and len(payload) == 2
    assert buf_err.getvalue() == ""


def test_default_funnel_urls_are_live_not_placeholders():
    assert wc.BOOK_URL == "https://leanpub.com/agent-security"
    assert wc.KIT_URL == (
        "https://0xshugo.gumroad.com/l/AI-Agent?utm_source=github&utm_medium=tool"
        "&utm_campaign=agent_security_funnel&utm_content=cli_output"
    )
    assert wc.LIST_URL == "https://dispatch.aoifuture.com/s/security"
    assert "TBD" not in wc.KIT_URL


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"ok  {name}")
    print("all passed")
