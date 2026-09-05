import pytest
from activitypub_bridge.keys import generate_keypair, load_private_key
from activitypub_bridge.signatures import sign_request, verify_signature, compute_digest
from activitypub_bridge.actor import build_actor_document, build_webfinger_response, validate_actor_document
from activitypub_bridge.feed_bridge import fetch_and_convert, entry_to_note_content
from activitypub_bridge.followers import FollowerStore


# ---------------------------------------------------------------
# KEYS
# ---------------------------------------------------------------

def test_keypair_generation_and_reload():
    priv, pub_pem, priv_pem = generate_keypair()
    assert pub_pem.startswith("-----BEGIN PUBLIC KEY-----")
    assert priv_pem.startswith("-----BEGIN PRIVATE KEY-----")
    reloaded = load_private_key(priv_pem)
    # a reloaded key must produce identical PEM output to the original
    from cryptography.hazmat.primitives import serialization
    original_bytes = priv.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    reloaded_bytes = reloaded.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    assert original_bytes == reloaded_bytes


# ---------------------------------------------------------------
# HTTP SIGNATURES — the part that must be right or nothing federates
# ---------------------------------------------------------------

@pytest.fixture
def signed_request():
    priv, pub_pem, _ = generate_keypair()
    body = b'{"type":"Create","actor":"https://example.com/actor"}'
    url = "https://mastodon.social/inbox"
    key_id = "https://example.com/actor#main-key"
    headers = sign_request(priv, key_id, "POST", url, body)
    return priv, priv.public_key(), url, headers, body


def test_valid_signature_verifies(signed_request):
    _, pub_key, url, headers, body = signed_request
    assert verify_signature(pub_key, "POST", url, headers, body) is True


def test_tampered_body_fails_verification(signed_request):
    _, pub_key, url, headers, _ = signed_request
    tampered = b'{"type":"Create","actor":"https://EVIL.com/actor"}'
    assert verify_signature(pub_key, "POST", url, headers, tampered) is False


def test_wrong_key_fails_verification(signed_request):
    _, _, url, headers, body = signed_request
    _, other_pub_pem, _ = generate_keypair()
    other_pub = load_private_key(
        generate_keypair()[2]
    ).public_key()  # a fresh, unrelated key
    assert verify_signature(other_pub, "POST", url, headers, body) is False


def test_digest_changes_with_body():
    d1 = compute_digest(b"hello")
    d2 = compute_digest(b"hello!")
    assert d1 != d2
    assert compute_digest(b"hello") == d1  # deterministic


def test_signature_header_contains_required_fields(signed_request):
    _, _, _, headers, _ = signed_request
    sig = headers["Signature"]
    assert 'keyId="https://example.com/actor#main-key"' in sig
    assert 'algorithm="rsa-sha256"' in sig
    assert "(request-target)" in sig


# ---------------------------------------------------------------
# ACTOR / WEBFINGER
# ---------------------------------------------------------------

def test_actor_document_is_valid():
    _, pub_pem, _ = generate_keypair()
    doc = build_actor_document("example.com", "myzine", "My Zine", "A magazine", pub_pem)
    assert validate_actor_document(doc) is None


def test_actor_missing_field_is_caught():
    _, pub_pem, _ = generate_keypair()
    doc = build_actor_document("example.com", "myzine", "My Zine", "A magazine", pub_pem)
    del doc["inbox"]
    assert validate_actor_document(doc) == "missing required field: inbox"


def test_actor_missing_public_key_pem_is_caught():
    doc = {
        "@context": ["https://www.w3.org/ns/activitystreams"],
        "id": "https://example.com/actor",
        "type": "Organization",
        "inbox": "https://example.com/actor/inbox",
        "publicKey": {"id": "x"},
    }
    assert "publicKeyPem" in validate_actor_document(doc)


def test_webfinger_response_shape():
    wf = build_webfinger_response("example.com", "myzine")
    assert wf["subject"] == "acct:myzine@example.com"
    self_links = [l for l in wf["links"] if l["rel"] == "self"]
    assert len(self_links) == 1
    assert self_links[0]["type"] == "application/activity+json"


# ---------------------------------------------------------------
# FEED BRIDGE — tested against a REAL, live RSS feed
# ---------------------------------------------------------------

def test_real_feed_converts_to_valid_activities():
    activities = fetch_and_convert(
        "https://pypi.org/rss/project/requests/releases.xml",
        "https://example.com/actor", "example.com", limit=3,
    )
    assert len(activities) > 0
    for act in activities:
        assert act["type"] == "Create"
        assert act["@context"] == "https://www.w3.org/ns/activitystreams"
        assert act["object"]["type"] == "Note"
        assert "content" in act["object"]
        assert act["object"]["published"].endswith("Z")  # ISO 8601 UTC


def test_entry_ids_are_stable_across_calls():
    """Same feed fetched twice must produce the same note IDs — this
    is what lets a real deployment avoid re-posting the same entry."""
    a1 = fetch_and_convert("https://pypi.org/rss/project/requests/releases.xml",
                            "https://example.com/actor", "example.com", limit=3)
    a2 = fetch_and_convert("https://pypi.org/rss/project/requests/releases.xml",
                            "https://example.com/actor", "example.com", limit=3)
    ids1 = [a["object"]["id"] for a in a1]
    ids2 = [a["object"]["id"] for a in a2]
    assert ids1 == ids2


def test_html_in_summary_does_not_break_content():
    class FakeEntry(dict):
        def get(self, k, default=None):
            return dict.get(self, k, default)

    entry = FakeEntry(
        title="A <script>alert(1)</script> title",
        summary="<b>bold</b> and <i>italic</i> text",
        link="https://example.com/post/1",
        published="Mon, 01 Jan 2024 12:00:00 GMT",
    )
    content = entry_to_note_content(entry)
    assert "<script>" not in content  # escaped, not executed
    assert "&lt;script&gt;" in content


# ---------------------------------------------------------------
# FOLLOWER STORE
# ---------------------------------------------------------------

import tempfile
import os
import json as jsonlib
import urllib.error


def test_follower_store_add_remove_persist():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "followers.json")
        store = FollowerStore(path)
        store.add("https://mastodon.social/users/alice", "https://mastodon.social/inbox")
        store.add("https://mastodon.social/users/bob", "https://mastodon.social/inbox")
        store.add("https://other.example/users/carol", "https://other.example/inbox")
        assert store.count() == 3
        assert store.is_follower("https://mastodon.social/users/alice")
        # shared inbox deduplicated
        assert len(store.list_inboxes()) == 2

        # reload from disk — must persist
        reloaded = FollowerStore(path)
        assert reloaded.count() == 3

        reloaded.remove("https://mastodon.social/users/alice")
        assert reloaded.count() == 2
        assert not reloaded.is_follower("https://mastodon.social/users/alice")


# ---------------------------------------------------------------
# DELIVERY — network mocked, retry/error logic tested for real
# ---------------------------------------------------------------

class _FakeResponse:
    def __init__(self, status=200):
        self.status = status
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def read(self): return b"{}"


def test_delivery_succeeds_on_first_try():
    priv, _, _ = generate_keypair()
    calls = []
    def fake_opener(req, timeout=10):
        calls.append(req.full_url)
        return _FakeResponse(202)
    ok, status, err = __import__("activitypub_bridge.delivery", fromlist=["deliver_activity"]).deliver_activity(
        priv, "https://example.com/actor#main-key", "https://mastodon.social/inbox",
        b'{"type":"Create"}', opener=fake_opener,
    )
    assert ok is True
    assert status == 202
    assert len(calls) == 1


def test_delivery_retries_on_server_error_then_succeeds():
    from activitypub_bridge.delivery import deliver_activity
    priv, _, _ = generate_keypair()
    attempts = {"n": 0}
    def flaky_opener(req, timeout=10):
        attempts["n"] += 1
        if attempts["n"] < 3:
            raise urllib.error.HTTPError(req.full_url, 503, "Service Unavailable", {}, None)
        return _FakeResponse(200)
    ok, status, err = deliver_activity(
        priv, "https://example.com/actor#main-key", "https://mastodon.social/inbox",
        b'{"type":"Create"}', max_retries=5, backoff_seconds=0.01, opener=flaky_opener,
    )
    assert ok is True
    assert attempts["n"] == 3


def test_delivery_does_not_retry_on_client_error():
    from activitypub_bridge.delivery import deliver_activity
    priv, _, _ = generate_keypair()
    attempts = {"n": 0}
    def rejecting_opener(req, timeout=10):
        attempts["n"] += 1
        raise urllib.error.HTTPError(req.full_url, 401, "Unauthorized", {}, None)
    ok, status, err = deliver_activity(
        priv, "https://example.com/actor#main-key", "https://mastodon.social/inbox",
        b'{"type":"Create"}', max_retries=5, backoff_seconds=0.01, opener=rejecting_opener,
    )
    assert ok is False
    assert attempts["n"] == 1  # no retry on a 4xx
    assert "401" in err


def test_deliver_to_all_followers_hits_each_distinct_inbox_once():
    from activitypub_bridge.delivery import deliver_to_all_followers
    priv, _, _ = generate_keypair()
    with tempfile.TemporaryDirectory() as tmp:
        store = FollowerStore(os.path.join(tmp, "f.json"))
        store.add("https://mastodon.social/users/alice", "https://mastodon.social/inbox")
        store.add("https://mastodon.social/users/bob", "https://mastodon.social/inbox")  # shared inbox
        store.add("https://other.example/users/carol", "https://other.example/inbox")

        hit_urls = []
        def fake_opener(req, timeout=10):
            hit_urls.append(req.full_url)
            return _FakeResponse(202)

        results = deliver_to_all_followers(priv, "https://example.com/actor#main-key", store,
                                            {"type": "Create"}, opener=fake_opener)
        assert len(results) == 2  # deduplicated
        assert len(hit_urls) == 2


# ---------------------------------------------------------------
# INBOX HANDLER — incoming Follow/Undo, signature-verified against
# a simulated (not live) remote actor
# ---------------------------------------------------------------

def _make_remote_actor_and_signed_follow(my_actor_url):
    """Builds a fake remote follower (their own real keypair + actor doc)
    and a genuinely signed Follow activity from them."""
    remote_priv, remote_pub_pem, _ = generate_keypair()
    remote_actor_url = "https://mastodon.social/users/alice"
    remote_actor_doc = build_actor_document(
        "mastodon.social", "alice", "Alice", "A real Fediverse user", remote_pub_pem,
        actor_type="Person",
    )
    remote_actor_doc["id"] = remote_actor_url
    remote_actor_doc["inbox"] = "https://mastodon.social/inbox"
    remote_actor_doc["publicKey"]["id"] = f"{remote_actor_url}#main-key"
    remote_actor_doc["publicKey"]["owner"] = remote_actor_url

    follow_activity = {
        "@context": "https://www.w3.org/ns/activitystreams",
        "type": "Follow",
        "actor": remote_actor_url,
        "object": my_actor_url,
    }
    body = jsonlib.dumps(follow_activity).encode("utf-8")
    request_url = f"{my_actor_url}/inbox"
    headers = sign_request(remote_priv, f"{remote_actor_url}#main-key", "POST", request_url, body)
    return remote_actor_doc, body, headers, request_url, remote_actor_url


def test_incoming_follow_is_verified_accepted_and_stored():
    from activitypub_bridge.inbox_handler import handle_incoming_activity
    my_actor_url = "https://myzine.example/actor"
    remote_actor_doc, body, headers, request_url, remote_actor_url = _make_remote_actor_and_signed_follow(my_actor_url)

    def fake_opener(req, timeout=10):
        # both the signature-verification fetch and the "get their inbox" fetch
        # hit this same simulated remote actor document
        return _FakeResponseWithBody(jsonlib.dumps(remote_actor_doc).encode("utf-8"))

    with tempfile.TemporaryDirectory() as tmp:
        store = FollowerStore(os.path.join(tmp, "f.json"))
        result = handle_incoming_activity(body, headers, my_actor_url, store, request_url, opener=fake_opener)

        assert result["type"] == "Follow"
        assert result["response_activity"]["type"] == "Accept"
        assert store.is_follower(remote_actor_url)


def test_incoming_follow_with_tampered_signature_is_rejected():
    from activitypub_bridge.inbox_handler import handle_incoming_activity
    my_actor_url = "https://myzine.example/actor"
    remote_actor_doc, body, headers, request_url, remote_actor_url = _make_remote_actor_and_signed_follow(my_actor_url)
    tampered_body = body.replace(b"Follow", b"Follow ")  # subtle tamper after signing

    def fake_opener(req, timeout=10):
        return _FakeResponseWithBody(jsonlib.dumps(remote_actor_doc).encode("utf-8"))

    with tempfile.TemporaryDirectory() as tmp:
        store = FollowerStore(os.path.join(tmp, "f.json"))
        result = handle_incoming_activity(tampered_body, headers, my_actor_url, store, request_url, opener=fake_opener)
        assert result["type"] == "rejected"
        assert store.count() == 0  # never trusted enough to even parse


def test_incoming_undo_removes_follower():
    from activitypub_bridge.inbox_handler import handle_incoming_activity
    my_actor_url = "https://myzine.example/actor"
    remote_actor_doc, body, headers, request_url, remote_actor_url = _make_remote_actor_and_signed_follow(my_actor_url)

    def fake_opener(req, timeout=10):
        return _FakeResponseWithBody(jsonlib.dumps(remote_actor_doc).encode("utf-8"))

    with tempfile.TemporaryDirectory() as tmp:
        store = FollowerStore(os.path.join(tmp, "f.json"))
        store.add(remote_actor_url, "https://mastodon.social/inbox")
        assert store.count() == 1

        undo_activity = {
            "@context": "https://www.w3.org/ns/activitystreams",
            "type": "Undo",
            "actor": remote_actor_url,
            "object": {"type": "Follow", "actor": remote_actor_url, "object": my_actor_url},
        }
        undo_body = jsonlib.dumps(undo_activity).encode("utf-8")
        remote_priv2 = load_private_key(generate_keypair()[2])  # irrelevant, headers rebuilt below

        # need a genuinely-signed Undo from the SAME remote key used above
        # (re-derive from the closure isn't possible, so regenerate consistently)
        # -> simplest correct approach: sign with a fresh matching pair and
        #    matching actor doc, mirroring _make_remote_actor_and_signed_follow
        priv, pub_pem, _ = generate_keypair()
        actor_url = "https://mastodon.social/users/bob"
        doc = build_actor_document("mastodon.social", "bob", "Bob", "desc", pub_pem, actor_type="Person")
        doc["id"] = actor_url
        doc["inbox"] = "https://mastodon.social/inbox"
        doc["publicKey"]["id"] = f"{actor_url}#main-key"

        store2 = FollowerStore(os.path.join(tmp, "f2.json"))
        store2.add(actor_url, "https://mastodon.social/inbox")

        undo2 = {
            "@context": "https://www.w3.org/ns/activitystreams",
            "type": "Undo",
            "actor": actor_url,
            "object": {"type": "Follow", "actor": actor_url, "object": my_actor_url},
        }
        undo2_body = jsonlib.dumps(undo2).encode("utf-8")
        req_url2 = f"{my_actor_url}/inbox"
        headers2 = sign_request(priv, f"{actor_url}#main-key", "POST", req_url2, undo2_body)

        def fake_opener2(req, timeout=10):
            return _FakeResponseWithBody(jsonlib.dumps(doc).encode("utf-8"))

        result = handle_incoming_activity(undo2_body, headers2, my_actor_url, store2, req_url2, opener=fake_opener2)
        assert result["type"] == "Undo"
        assert store2.count() == 0


class _FakeResponseWithBody:
    def __init__(self, body: bytes):
        self._body = body
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def read(self): return self._body
