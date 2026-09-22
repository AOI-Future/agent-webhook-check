"""A realistic *broken* webhook verifier — the kind this tool exists to catch.

Run it:
    python3 webhook_check.py --verifier examples.vulnerable_verifier:verify

You should see VT-D-053 (constant-time) FAIL and VT-D-052 (length-safe) PASS.
Comparing digests with ``==`` is not constant-time (timing side channel), but
unlike a hand-rolled index loop it does not crash on a short forged signature.
"""

from __future__ import annotations

import hashlib
import hmac


def verify(secret: bytes, body: bytes, header: str) -> bool:
    # Naive parse: assumes the header is well-formed 'sha256=<hex>'.
    provided = header.split("=", 1)[1]
    expected = hmac.new(secret, body, hashlib.sha256).hexdigest()
    return provided == expected
