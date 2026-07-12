#!/usr/bin/env python3
"""webhook-check — a free, single-file webhook signature verifier auditor.

This is the free carve-out of one case from the AI-Agent Security Verification
Kit: the webhook signature verifier. A webhook is the callback that lets an
external system trigger an agent action — a refund, a deploy, a message send —
so a verifier that accepts a forged signature hands an attacker the agent's
hands. It is the single highest-frequency real bug we see in agent tool
callbacks, which is why it is the one we give away.

It runs FOUR executable checks against a verifier and prints PASS/FAIL:

  VT-D-050  accepts a genuinely signed body
  VT-D-051  rejects a tampered body under the old signature
  VT-D-052  is length-safe on a forged short signature (no crash / DoS)
  VT-D-053  compares in constant time (no timing side channel)

What this free tool does NOT do — and what the paid kit does — is produce the
sealed evidence you hand a CISO or an auditor: a single machine-readable +
human-readable artifact whose hash is countersigned by an RFC 3161 timestamp
authority, proving *what* you tested and *when*, without any secret leaving the
machine. This tool explains and executes; the kit executes and *proves*.

    Explanation and a single check are free. Execution across the whole
    attack surface, and the evidence you can defend, are the paid kit.

Usage
-----
    # See it find a real bug with zero setup (runs the two built-in references):
    python3 webhook_check.py --demo

    # Audit your own verifier in place:
    python3 webhook_check.py --verifier yourmodule:verify

A verifier is any callable ``verify(secret: bytes, body: bytes, header: str)
-> bool`` that returns True iff ``header`` is a valid signature of ``body``
under ``secret``. It MUST NOT raise on malformed input; it MUST return False.

Stdlib only. No network. No dependencies. MIT-licensed — run it, read it,
share it.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import importlib
import inspect
import os
import sys

# --- Where to go next (the funnel) ------------------------------------------
# Overridable by environment so the tool can be re-pointed without editing
# source. Defaults point to the live product funnel.
BOOK_URL = os.environ.get("AGENTKIT_BOOK_URL", "https://leanpub.com/agent-security")
KIT_URL = os.environ.get("AGENTKIT_KIT_URL", "https://0xshugo.gumroad.com/l/AI-Agent")
LIST_URL = os.environ.get("AGENTKIT_LIST_URL", "https://dispatch.aoifuture.com/s/security")


# --- The signature primitive and reference verifiers ------------------------

def sign(secret: bytes, body: bytes) -> str:
    """Produce the canonical ``sha256=<hex>`` signature header for a body."""
    mac = hmac.new(secret, body, hashlib.sha256).hexdigest()
    return f"sha256={mac}"


def reference_fixed(secret: bytes, body: bytes, header: str) -> bool:
    """Correct verifier: constant-time and length-safe.

    ``hmac.compare_digest`` is constant-time over its comparison and tolerates
    unequal lengths without raising. Any malformed header returns False.
    """
    if not isinstance(header, str) or not header.startswith("sha256="):
        return False
    provided = header[len("sha256="):]
    expected = hmac.new(secret, body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(provided, expected)


def reference_vulnerable(secret: bytes, body: bytes, header: str) -> bool:
    """Deliberately broken verifier — the bug this tool is built to catch.

    Two defects, both seen in the wild:
      * a hand-rolled byte loop is not constant-time (a timing side channel
        that leaks the valid HMAC one byte at a time), and
      * it indexes ``provided[i]`` with no length guard, so a short forged
        signature runs off the end and raises IndexError — a forged header
        that crashes the handler (denial of service).
    """
    provided = header.split("=", 1)[1]  # naive parse
    expected = hmac.new(secret, body, hashlib.sha256).hexdigest()
    # BUG: length-unsafe, non-constant-time comparison.
    for i in range(len(expected)):
        if expected[i] != provided[i]:   # IndexError if provided is shorter
            return False
    return True


# --- The probe --------------------------------------------------------------

def _source_uses_compare_digest(verify) -> bool | None:
    try:
        src = inspect.getsource(verify)
    except (OSError, TypeError):
        return None  # cannot inspect (e.g. a C function); unknown, not a fail
    return "compare_digest" in src


def probe(verify, secret: bytes) -> dict:
    """Exercise a verifier against valid, tampered, and malformed inputs.

    Returns a dict of observed behaviors. No exception escapes: a raise on
    malformed input is itself a finding (``length_safe = False``).
    """
    body = b'{"event":"refund","amount":100}'
    tampered = b'{"event":"refund","amount":1000000}'
    valid_header = sign(secret, body)

    obs: dict = {}

    # 1. Accepts a valid signature.
    try:
        obs["accepts_valid"] = bool(verify(secret, body, valid_header))
    except Exception as e:
        obs["accepts_valid"] = False
        obs["accepts_valid_error"] = type(e).__name__

    # 2. Rejects a tampered body under the old (now invalid) signature.
    try:
        obs["rejects_tampered"] = not bool(verify(secret, tampered, valid_header))
    except Exception as e:
        obs["rejects_tampered"] = False
        obs["rejects_tampered_error"] = type(e).__name__

    # 3. Length-safe: a too-short signature must return False, not raise. The
    #    adversarial input is a *truncated valid* signature — its bytes match
    #    the expected value on every position compared, so a hand-rolled loop
    #    runs off the end of the shorter string (IndexError -> DoS). A random
    #    short string usually mismatches on the first byte and returns False
    #    before the length bug is ever reached, hiding the defect.
    short_header = valid_header[: len("sha256=") + 8]
    try:
        obs["length_safe"] = not bool(verify(secret, body, short_header))
    except Exception as e:
        obs["length_safe"] = False
        obs["length_safe_error"] = type(e).__name__

    # 4. Uses the stdlib constant-time comparator. White-box signal, detected
    #    by source inspection, so we can tell "correct by construction" from
    #    "passed the black-box probes by luck".
    obs["uses_compare_digest"] = _source_uses_compare_digest(verify)

    return obs


# --- Turning observations into PASS/FAIL rows -------------------------------

PASS, FAIL, SKIP = "PASS", "FAIL", "SKIP"


def evaluate(obs: dict) -> list[dict]:
    """Map raw observations to the four VT-D rows with a human detail line."""
    rows: list[dict] = []

    rows.append({
        "id": "VT-D-050",
        "title": "Accepts a valid signature",
        "status": PASS if obs.get("accepts_valid") else FAIL,
        "detail": "valid signature accepted"
        if obs.get("accepts_valid")
        else "valid signature rejected or handler raised "
             f"({obs.get('accepts_valid_error', 'returned False')})",
    })

    rows.append({
        "id": "VT-D-051",
        "title": "Rejects a tampered body",
        "status": PASS if obs.get("rejects_tampered") else FAIL,
        "detail": "tampered body rejected"
        if obs.get("rejects_tampered")
        else "tampered body accepted or handler raised; signature not enforced",
    })

    length_safe = obs.get("length_safe")
    rows.append({
        "id": "VT-D-052",
        "title": "Length-safe on a forged short signature",
        "status": PASS if length_safe else FAIL,
        "detail": "short forged signature rejected without raising"
        if length_safe
        else f"forged short signature raised {obs.get('length_safe_error', 'an error')}; "
             "a forged header crashes the handler (denial of service)",
    })

    uses_ct = obs.get("uses_compare_digest")
    if uses_ct is None:
        status, detail = SKIP, "verifier source not inspectable (cannot confirm)"
    elif uses_ct:
        status, detail = PASS, "uses hmac.compare_digest (constant-time)"
    else:
        status, detail = FAIL, (
            "no constant-time comparator; signature comparison is a timing "
            "side channel that leaks the valid HMAC"
        )
    rows.append({
        "id": "VT-D-053",
        "title": "Constant-time signature comparison (SHOULD)",
        "status": status,
        "detail": detail,
    })

    return rows


# --- Rendering --------------------------------------------------------------

def render(rows: list[dict], *, label: str) -> str:
    lines = [f"webhook-check — {label}", ""]
    id_w = max(len(r["id"]) for r in rows)
    title_w = max(len(r["title"]) for r in rows)
    for r in rows:
        lines.append(f"  [{r['status']:<4}] {r['id']:<{id_w}}  "
                     f"{r['title']:<{title_w}}  — {r['detail']}")
    fails = sum(1 for r in rows if r["status"] == FAIL)
    lines.append("")
    if fails:
        lines.append(f"  RESULT: FAIL ({fails} of {len(rows)} checks failed). "
                     "The fix is hmac.compare_digest with a startswith/length guard.")
    else:
        lines.append(f"  RESULT: PASS (all {len(rows)} checks passed).")
    return "\n".join(lines)


def cta() -> str:
    return "\n".join([
        "",
        "─" * 68,
        "This is ONE check from the full AI-Agent Security Verification Kit.",
        "",
        f"  • The book — what to verify across the whole agent attack surface,",
        f"    and why (free / pay-what-you-want): {BOOK_URL}",
        f"  • The kit — every check (identity, tools, untrusted content, MCP,",
        f"    EMA), run in one command, sealed into a timestamped evidence",
        f"    artifact you can hand an auditor: {KIT_URL}",
        f"  • Get the next case + update when the standards move: {LIST_URL}",
        "",
        "The free tool tells you PASS or FAIL. The kit gives you the signed",
        "proof — a report whose hash is countersigned by an RFC 3161 timestamp",
        "authority, with no secret ever leaving your machine.",
        "─" * 68,
    ])


# --- CLI --------------------------------------------------------------------

def _resolve(spec: str):
    if ":" not in spec:
        raise ValueError(f"--verifier must be 'module:function', got {spec!r}")
    mod_name, func_name = spec.split(":", 1)
    mod = importlib.import_module(mod_name)
    return getattr(mod, func_name)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="webhook_check.py",
        description="Audit a webhook signature verifier for the four bugs that "
                    "let a forged callback drive an agent.",
    )
    g = p.add_mutually_exclusive_group()
    g.add_argument("--verifier", metavar="module:function",
                   help="Your verifier callable verify(secret, body, header)->bool")
    g.add_argument("--demo", action="store_true",
                   help="Run the built-in vulnerable and fixed references so you "
                        "can see the tool find a real bug with no setup.")
    p.add_argument("--no-cta", action="store_true", help=argparse.SUPPRESS)
    args = p.parse_args(argv)

    # A fixed, non-secret test key: not a credential, only so a valid signature
    # can be computed for comparison. Deterministic so runs are reproducible.
    test_secret = b"webhook-check-test-key-not-a-real-secret"

    blocks: list[str] = []
    exit_code = 0

    if args.verifier:
        try:
            verify = _resolve(args.verifier)
        except Exception as e:
            print(f"could not resolve verifier {args.verifier!r}: "
                  f"{type(e).__name__}: {e}", file=sys.stderr)
            return 2
        rows = evaluate(probe(verify, test_secret))
        blocks.append(render(rows, label=f"target = {args.verifier}"))
        if any(r["status"] == FAIL for r in rows):
            exit_code = 1
    else:
        # Default and --demo behave the same: show the contrast.
        vuln_rows = evaluate(probe(reference_vulnerable, test_secret))
        fixed_rows = evaluate(probe(reference_fixed, test_secret))
        blocks.append(render(vuln_rows,
                             label="built-in VULNERABLE reference (what a bug looks like)"))
        blocks.append(render(fixed_rows,
                             label="built-in FIXED reference (what correct looks like)"))
        if not args.demo:
            blocks.insert(0, "No --verifier given; showing the built-in demo. "
                             "Point --verifier module:function at your own to audit it.\n")

    print("\n\n".join(blocks))
    if not args.no_cta:
        print(cta())
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
