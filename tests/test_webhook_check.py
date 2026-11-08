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


# --- --json-pretty -----------------------------------------------------------

def test_json_pretty_demo_is_parseable_indented_multiline():
    # (a) --demo --json-pretty: parseable JSON, multi-line, with indent=2
    # indentation; no funnel/CTA leaking in.
    proc = _run_cli("--demo", "--json-pretty")
    assert proc.returncode == 1, proc.stderr
    stdout = proc.stdout
    payload = json.loads(stdout)  # raises if not pure JSON
    assert isinstance(payload, list) and len(payload) == 2
    lines = stdout.rstrip("\n").splitlines()
    assert len(lines) > 1, "--json-pretty output must be multi-line"
    # indent=2 evidence: nested openers and members sit on 2-space multiples.
    assert lines[0] == "["
    assert any(ln == "  {" for ln in lines), lines[:6]
    assert any(ln.startswith('    "verifier": ') for ln in lines), lines[:8]
    assert any(ln.startswith('        "id": "VT-D-050"') for ln in lines)
    # Exact formatting contract: byte-identical to json.dumps(indent=2).
    assert stdout.rstrip("\n") == json.dumps(payload, ensure_ascii=False, indent=2)


def test_json_pretty_structure_identical_to_json():
    # (b) parsed structure of --json-pretty equals --json in both modes.
    demo_pretty = _run_cli("--demo", "--json-pretty")
    demo_json = _run_cli("--demo", "--json")
    assert demo_pretty.returncode == demo_json.returncode == 1
    pretty_payload = json.loads(demo_pretty.stdout)
    json_payload = json.loads(demo_json.stdout)
    assert pretty_payload == json_payload
    assert [b["verifier"] for b in pretty_payload] == [
        "webhook_check:reference_vulnerable",
        "webhook_check:reference_fixed",
    ]

    spec = "examples.fixed_verifier:verify"
    pretty_v = _run_cli("--verifier", spec, "--json-pretty")
    json_v = _run_cli("--verifier", spec, "--json")
    assert pretty_v.returncode == json_v.returncode == 0
    assert json.loads(pretty_v.stdout) == json.loads(json_v.stdout)


def test_json_still_exactly_one_compact_line():
    # (c) --json remains exactly one compact line for compatibility.
    proc = _run_cli("--demo", "--json")
    assert proc.returncode == 1, proc.stderr
    _assert_pure_json_line(proc.stdout)
    assert "\n" not in proc.stdout.rstrip("\n")

    spec = "examples.fixed_verifier:verify"
    proc = _run_cli("--verifier", spec, "--json")
    assert proc.returncode == 0, proc.stderr
    _assert_pure_json_line(proc.stdout)


def test_json_pretty_suppresses_funnel_and_cta():
    # (d) --json-pretty prints no funnel/CTA or decorative text on stdout
    # (run WITHOUT --no-cta: machine-readable mode must suppress it itself).
    proc = _run_cli("--demo", "--json-pretty")
    stdout = proc.stdout
    for needle in ("gumroad", "leanpub", "dispatch.aoifuture",
                   "RESULT:", "webhook-check —", "─", "•"):
        assert needle not in stdout, f"{needle!r} leaked into stdout"
    # And it is still pure JSON end-to-end.
    json.loads(stdout)


def test_json_pretty_exit_codes_match_json():
    # (e) exit-code convention unchanged vs --json: all PASS -> 0,
    # any FAIL -> 1, verifier resolution failure -> 2 (stdout empty).
    cases = [
        ["--demo"],
        ["--verifier", "examples.fixed_verifier:verify"],
        ["--verifier", "examples.vulnerable_verifier:verify"],
        ["--verifier", "no.such.module:verify"],
    ]
    for base in cases:
        pretty = _run_cli(*base, "--json-pretty")
        compact = _run_cli(*base, "--json")
        assert pretty.returncode == compact.returncode, (base, pretty.returncode)
    assert _run_cli("--demo", "--json-pretty").returncode == 1
    assert _run_cli("--verifier", "examples.fixed_verifier:verify",
                    "--json-pretty").returncode == 0
    proc = _run_cli("--verifier", "no.such.module:verify", "--json-pretty")
    assert proc.returncode == 2
    assert proc.stdout == ""


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
