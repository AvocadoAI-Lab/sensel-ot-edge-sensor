"""HMAC verification for signed OT feed artifacts (D8, edge side).

The Control Plane signs every rule / listfile feed body with a key derived from
the shared OT edge bearer secret (``OT_EDGE_SENSOR_API_KEY`` /
``OT_SECURITY_INGEST_SECRET`` server-side; the edge already holds the same value
as ``SENSEL_API_KEY``). The edge MUST verify ``X-Signature`` over the *exact*
response bytes before applying any artifact so a tampered feed is rejected.

This mirrors ``sensel_control_plane/services/ot_security/signing.py``; keep the
two in lockstep.
"""

from __future__ import annotations

import base64
import hashlib
import hmac

DEV_FALLBACK_SECRET = "sensel-ot-feed-dev-secret"


def derive_feed_key(tenant_id: str, base_secret: str) -> bytes:
    secret = base_secret or DEV_FALLBACK_SECRET
    return hashlib.sha256(f"{secret}:{tenant_id}:ot-feed".encode("utf-8")).digest()


def sha256_hex(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def sign_artifact(body: bytes, *, tenant_id: str, base_secret: str) -> str:
    key = derive_feed_key(tenant_id, base_secret)
    return base64.b64encode(hmac.new(key, body, hashlib.sha256).digest()).decode("ascii")


def verify_artifact(body: bytes, signature: str, *, tenant_id: str, base_secret: str) -> bool:
    """Constant-time compare of the recomputed signature against ``X-Signature``."""
    if not signature:
        return False
    expected = sign_artifact(body, tenant_id=tenant_id, base_secret=base_secret)
    return hmac.compare_digest(expected, signature)
