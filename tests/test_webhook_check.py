"""Smoke tests for the free webhook-check tool.

Run: python3 -m pytest tests/ -q   (pytest optional; also runnable as a script)
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

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


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"ok  {name}")
    print("all passed")
