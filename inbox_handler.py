"""
Inbox handler — processes incoming Follow/Undo activities.

CRITICAL ORDERING: signature verification happens FIRST, before any
activity content is trusted or acted on. An unverified "Follow" is
just a claim by whoever sent the HTTP request — verifying it against
the sender's own published public key (fetched from their actor
document) is what makes it trustworthy. Skipping this step would let
anyone add themselves as a follower by forging a request.
"""

import json
import urllib.request
from typing import Optional, Callable, Dict

from cryptography.hazmat.primitives.serialization import load_pem_public_key

from .signatures import verify_signature


def fetch_remote_actor(actor_url: str, opener: Optional[Callable] = None) -> dict:
    opener_fn = opener or urllib.request.urlopen
    req = urllib.request.Request(actor_url, headers={"Accept": "application/activity+json"})
    with opener_fn(req, timeout=10) as resp:
        return json.loads(resp.read())


def verify_incoming_request(method: str, url: str, headers: dict, body: bytes,
                             opener: Optional[Callable] = None) -> bool:
    """Fetches the sender's actor document via the signature's keyId,
    extracts their public key, and verifies the request against it."""
    sig_header = headers.get("Signature", "")
    parts = dict(item.split("=", 1) for item in sig_header.split(",") if "=" in item)
    key_id = parts.get("keyId", "").strip('"')
    if not key_id:
        return False
    actor_url = key_id.split("#")[0]
    try:
        actor_doc = fetch_remote_actor(actor_url, opener=opener)
        pub_pem = actor_doc["publicKey"]["publicKeyPem"]
        pub_key = load_pem_public_key(pub_pem.encode("utf-8"))
    except Exception:
        return False
    return verify_signature(pub_key, method, url, headers, body)


def handle_incoming_activity(
    raw_body: bytes,
    headers: dict,
    my_actor_url: str,
    follower_store,
    request_url: str,
    opener: Optional[Callable] = None,
) -> Dict[str, Optional[dict]]:
    """
    Processes one POST to /inbox. Returns {"type": ..., "response_activity": ...}.
    "rejected" means the signature didn't verify — the activity is
    never even parsed for content in that case, by design.
    """
    if not verify_incoming_request("POST", request_url, headers, raw_body, opener=opener):
        return {"type": "rejected", "response_activity": None}

    activity = json.loads(raw_body)
    activity_type = activity.get("type")

    if activity_type == "Follow":
        follower_actor = activity.get("actor")
        inbox = None
        try:
            remote_doc = fetch_remote_actor(follower_actor, opener=opener)
            inbox = remote_doc.get("inbox")
        except Exception:
            pass
        if follower_actor and inbox:
            follower_store.add(follower_actor, inbox)
        accept = {
            "@context": "https://www.w3.org/ns/activitystreams",
            "type": "Accept",
            "actor": my_actor_url,
            "object": activity,
        }
        return {"type": "Follow", "response_activity": accept}

    if activity_type == "Undo":
        inner = activity.get("object", {})
        if inner.get("type") == "Follow":
            follower_store.remove(activity.get("actor"))
        return {"type": "Undo", "response_activity": None}

    return {"type": "unknown", "response_activity": None}
