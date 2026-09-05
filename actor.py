"""
Actor & WebFinger — the two documents that make a magazine
discoverable and followable from real Mastodon.

WebFinger answers "who is @myzine@example.com" by pointing at the
Actor document. The Actor document is the actual ActivityPub identity:
name, inbox/outbox URLs, and the public key other servers use to
verify signed activities coming from this actor (see signatures.py).

Both formats are specified (WebFinger: RFC 7033; Actor: ActivityPub
W3C Recommendation) — this isn't a custom format, it's what a real
Mastodon server expects to parse.
"""

from typing import Optional


def build_actor_document(
    domain: str,
    username: str,
    display_name: str,
    summary: str,
    public_key_pem: str,
    actor_type: str = "Organization",
) -> dict:
    """
    An "Organization" or "Service" actor type fits a literary magazine
    better than "Person" — Mastodon renders both as normal followable
    accounts, the type is metadata, not a restriction on capability.
    """
    base = f"https://{domain}/{username}"
    return {
        "@context": [
            "https://www.w3.org/ns/activitystreams",
            "https://w3id.org/security/v1",
        ],
        "id": base,
        "type": actor_type,
        "preferredUsername": username,
        "name": display_name,
        "summary": summary,
        "inbox": f"{base}/inbox",
        "outbox": f"{base}/outbox",
        "followers": f"{base}/followers",
        "following": f"{base}/following",
        "publicKey": {
            "id": f"{base}#main-key",
            "owner": base,
            "publicKeyPem": public_key_pem,
        },
    }


def build_webfinger_response(domain: str, username: str) -> dict:
    base = f"https://{domain}/{username}"
    return {
        "subject": f"acct:{username}@{domain}",
        "aliases": [base],
        "links": [
            {
                "rel": "self",
                "type": "application/activity+json",
                "href": base,
            },
            {
                "rel": "http://webfinger.net/rel/profile-page",
                "type": "text/html",
                "href": base,
            },
        ],
    }


def validate_actor_document(doc: dict) -> Optional[str]:
    """
    Returns None if valid, or a description of what's missing.
    A minimal but real check against the fields a receiving server
    (Mastodon included) actually requires to accept a Follow.
    """
    required = ["@context", "id", "type", "inbox", "publicKey"]
    for field in required:
        if field not in doc:
            return f"missing required field: {field}"
    if "publicKeyPem" not in doc.get("publicKey", {}):
        return "publicKey is missing publicKeyPem"
    if "https://www.w3.org/ns/activitystreams" not in doc["@context"]:
        return "@context must include the ActivityStreams namespace"
    return None
