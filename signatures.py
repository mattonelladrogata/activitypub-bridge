"""
HTTP Signatures — the draft-cavage-http-signatures scheme Mastodon and
the rest of the Fediverse actually require for federation. This is
not decorative: a real Mastodon instance will silently drop (or
reject with 401) any inbox delivery that isn't signed correctly with
the actor's registered public key. Getting this wrong means "it looks
like it should work" while nothing actually federates.

WHAT GETS SIGNED: a canonical string built from specific HTTP headers
(by convention: the pseudo-header "(request-target)", plus "host",
"date", and "digest" for POST requests with a body), signed with the
actor's RSA private key using RSA-SHA256. The receiving server
recomputes the same string and verifies it against the actor's public
key (fetched from the actor document referenced by keyId).
"""

import base64
import hashlib
from datetime import datetime, timezone
from urllib.parse import urlparse

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature


def compute_digest(body: bytes) -> str:
    """The Digest header: SHA-256 of the request body, base64-encoded."""
    digest = hashlib.sha256(body).digest()
    return "SHA-256=" + base64.b64encode(digest).decode("ascii")


def build_signing_string(method: str, path: str, headers: dict) -> str:
    """
    Builds the exact string that gets signed. Header order matters —
    it must match the order later declared in the `headers=` field of
    the Signature header, since the verifier reconstructs the same
    string from the same declared order.
    """
    lines = [f"(request-target): {method.lower()} {path}"]
    for name in ["host", "date", "digest"]:
        if name in headers:
            lines.append(f"{name}: {headers[name]}")
    return "\n".join(lines)


def sign_request(private_key, key_id: str, method: str, url: str, body: bytes) -> dict:
    """
    Returns the full set of headers a real HTTP POST to a Fediverse
    inbox needs: Host, Date, Digest, and Signature.
    """
    parsed = urlparse(url)
    host = parsed.netloc
    path = parsed.path or "/"
    date = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")
    digest = compute_digest(body)

    headers = {"host": host, "date": date, "digest": digest}
    signing_string = build_signing_string(method, path, headers)

    signature_bytes = private_key.sign(
        signing_string.encode("utf-8"),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    signature_b64 = base64.b64encode(signature_bytes).decode("ascii")

    sig_header = (
        f'keyId="{key_id}",algorithm="rsa-sha256",'
        f'headers="(request-target) host date digest",signature="{signature_b64}"'
    )

    return {
        "Host": host,
        "Date": date,
        "Digest": digest,
        "Signature": sig_header,
        "Content-Type": "application/activity+json",
    }


def verify_signature(public_key, method: str, url: str, headers: dict, body: bytes) -> bool:
    """
    Independent verification path — deliberately NOT reusing
    sign_request's internals, so a bug shared between signing and
    verifying can't hide a real mismatch from this test.
    """
    parsed = urlparse(url)
    path = parsed.path or "/"

    sig_header = headers.get("Signature", "")
    parts = dict(
        item.split("=", 1) for item in sig_header.split(",")
        if "=" in item
    )
    signature_b64 = parts.get("signature", "").strip('"')
    if not signature_b64:
        return False

    lowered = {k.lower(): v for k, v in headers.items()}
    signing_string = build_signing_string(method, path, lowered)

    expected_digest = compute_digest(body)
    if lowered.get("digest") != expected_digest:
        return False  # body was tampered with after signing

    try:
        public_key.verify(
            base64.b64decode(signature_b64),
            signing_string.encode("utf-8"),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False
