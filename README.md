# webhook-check

**A free, single-file auditor for webhook signature verifiers — the highest-frequency real bug in AI-agent tool callbacks.**

A webhook is the callback that lets an external system trigger an agent action: a refund, a deploy, a message send, a fund movement. If the verifier that checks the webhook's signature can be fooled by a forged one, an attacker gets to drive the agent's hands. This tool audits that verifier for the four ways it commonly fails.

It is the free carve-out of one case from the full **AI-Agent Security Verification Kit**. No dependencies, no network, stdlib only. Run it, read it, share it.

## Quick start

See it find a real bug with zero setup:

```bash
python3 webhook_check.py --demo
```

That runs two built-in reference verifiers — one deliberately broken, one correct — so you can see PASS and FAIL side by side.

Audit your own verifier in place:

```bash
python3 webhook_check.py --verifier yourmodule:verify
```

`yourmodule:verify` is any callable with the signature:

```python
def verify(secret: bytes, body: bytes, header: str) -> bool:
    """Return True iff `header` is a valid signature of `body` under `secret`.
    Must NOT raise on malformed input; must return False."""
```

Exit code is `0` if every check passes, `1` if any fails — so you can drop it into CI.

Try it against the worked examples in `examples/`:

```bash
python3 webhook_check.py --verifier examples.vulnerable_verifier:verify   # fails
python3 webhook_check.py --verifier examples.fixed_verifier:verify        # passes
```

## What it checks

| ID | Check | The bug it catches |
|----|-------|--------------------|
| VT-D-050 | Accepts a valid signature | Verifier is so strict it rejects genuine traffic (a broken control is not a secure one). |
| VT-D-051 | Rejects a tampered body | Old signature is accepted for a mutated payload — the signature isn't actually binding the body. |
| VT-D-052 | Length-safe on a forged short signature | A too-short signature runs a hand-rolled loop off the end and raises `IndexError`: a forged header **crashes the handler** (denial of service). |
| VT-D-053 | Constant-time comparison | `==` or a byte loop leaks the valid HMAC through response **timing** — an attacker recovers the signature one byte at a time. |

The fix for both real defects is one line: **`hmac.compare_digest`**, behind a `startswith("sha256=")` / length guard. See `examples/fixed_verifier.py`.

Note the two example bugs are genuinely different: `==` on the digest (`vulnerable_verifier.py`) is length-safe but *not* constant-time, so it fails only VT-D-053; a hand-rolled index loop (the built-in `--demo` reference) fails *both* VT-D-052 and VT-D-053. Real code has both shapes.

## What this does not do — and where the rest is

This free tool tells you **PASS or FAIL** for one case. The full **AI-Agent Security Verification Kit** does two things it does not:

1. **Covers the whole attack surface** — agent identity and delegation, tool and action safety, untrusted content and memory, the MCP supply chain, and Enterprise-Managed Authorization (EMA) — run in one command against your config.
2. **Produces evidence you can defend.** Every run seals into a single artifact — machine-readable JSON plus a human-readable PDF — whose hash is countersigned by an [RFC 3161](https://www.rfc-editor.org/rfc/rfc3161) timestamp authority. It proves *what* you tested and *when*, and **no secret ever leaves your machine** — only a hash and a nonce go to the timestamp server.

> Explanation and a single check are free. Execution across the whole surface, and the signed proof, are the kit.

- **The book — _AI Agent Security_ (free with a Leanpub membership / name your price)** — what to verify across the agent attack surface and why. **Live now** — <https://leanpub.com/agent-security>.
- **The verification kit** — every check plus the timestamped evidence artifact. **Available now** — <https://0xshugo.gumroad.com/l/wbvgfb>.
- **Get the next free case** and a heads-up when the standards move — [join the Security list](https://dispatch.aoifuture.com/s/security).

The three URLs the CLI prints can also be set from the environment (`AGENTKIT_BOOK_URL`, `AGENTKIT_KIT_URL`, `AGENTKIT_LIST_URL`) without editing source.

## License

MIT — see [LICENSE](LICENSE). This free tool is deliberately permissive so it can spread. The paid kit is separately licensed.
