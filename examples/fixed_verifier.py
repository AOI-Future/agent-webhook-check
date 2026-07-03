"""A correct webhook verifier — what your code should look like.

Run it:
    python3 webhook_check.py --verifier examples.fixed_verifier:verify

All four checks should PASS. The two things that make it correct:
  * hmac.compare_digest — constant-time, and tolerant of unequal lengths so a
    short forged signature returns False instead of raising, and
  * a startswith guard so a malformed header is rejected, never parsed blindly.
"""

from __future__ import annotations

import hashlib
import hmac


def verify(secret: bytes, body: bytes, header: str) -> bool:
    if not isinstance(header, str) or not header.startswith("sha256="):
        return False
    provided = header[len("sha256="):]
    expected = hmac.new(secret, body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(provided, expected)
