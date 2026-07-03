"""A realistic *broken* webhook verifier — the kind this tool exists to catch.

Run it:
    python3 webhook_check.py --verifier examples.vulnerable_verifier:verify

You should see VT-D-052 (length-safe) and VT-D-053 (constant-time) FAIL. The
'==' on the digest is not constant-time, and slicing to len(expected) with no
length check means a short forged signature is silently mishandled.
"""

from __future__ import annotations

import hashlib
import hmac


def verify(secret: bytes, body: bytes, header: str) -> bool:
    # Naive parse: assumes the header is well-formed 'sha256=<hex>'.
    provided = header.split("=", 1)[1]
    expected = hmac.new(secret, body, hashlib.sha256).hexdigest()
    # BUG: '==' on strings is not constant-time (timing side channel), and
    # comparing raw like this gives no length safety guarantee.
    return provided == expected
