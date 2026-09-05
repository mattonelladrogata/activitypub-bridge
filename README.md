# activitypub-bridge

Gives any magazine that already publishes an RSS or Atom feed — which
is nearly all of them, for free, via WordPress, Substack, Jekyll, Hugo
— a real, followable presence on Mastodon and the wider Fediverse.
No Mastodon instance to run, no ActivityPub expertise required.

## The problem this solves

Small independent magazines depend on centralized platforms
(Instagram, Substack's own network) for reach. If the algorithm
changes, they lose their audience overnight, with zero portability of
followers. The Fediverse (Mastodon, and anything speaking
ActivityPub) is the alternative — but running your own instance, or
hand-implementing the protocol, is real, unforgiving work: get the
cryptographic signing wrong and Mastodon just silently drops your
posts, no error message telling you why.

## What's implemented and verified

- **RSA keypair generation** for actor identity (`keys.py`).
- **HTTP Signatures** — signing AND independent verification, with
  tests that deliberately tamper with the body and swap in a wrong
  key to confirm both are correctly rejected (`signatures.py`).
- **ActivityPub Actor document + WebFinger response**, with
  validation that catches a broken document before deployment
  (`actor.py`).
- **RSS/Atom → ActivityPub Note conversion**, tested against a real,
  live feed (PyPI's own release RSS feed) — not a fixture pretending
  to be one (`feed_bridge.py`).
- **Real outbound delivery** to follower inboxes, with retry-on-5xx /
  no-retry-on-4xx logic, tested against a controlled fake HTTP layer
  since this sandbox has no path to a live Mastodon inbox — and
  shouldn't spam a real one just to prove a point (`delivery.py`).
- **Persistent follower store** (JSON-backed; swappable for a real
  database in production), tested for add/remove/reload (`followers.py`).
- **Incoming Follow/Undo handling** that verifies the sender's HTTP
  signature against their OWN published public key before trusting
  anything they claim — tested with a simulated but genuinely
  cryptographically signed remote follower, including a rejection
  test where a tampered request is correctly refused before it's even
  parsed (`inbox_handler.py`).

21 tests, all passing — one against a live external feed, the rest
against realistic, honestly-labeled simulations of what a real
Mastodon exchange looks like.

## Install

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

## Use

```python
from activitypub_bridge.keys import generate_keypair
from activitypub_bridge.actor import build_actor_document, build_webfinger_response
from activitypub_bridge.feed_bridge import fetch_and_convert
from activitypub_bridge.followers import FollowerStore
from activitypub_bridge.delivery import deliver_to_all_followers
from activitypub_bridge.inbox_handler import handle_incoming_activity

priv, pub_pem, priv_pem = generate_keypair()
actor = build_actor_document("myzine.example", "poetry", "My Zine",
                              "An independent literary magazine", pub_pem)
store = FollowerStore("followers.json")

# publishing a new issue:
activities = fetch_and_convert("https://myzine.example/feed.xml", actor["id"], "myzine.example")
for activity in activities:
    deliver_to_all_followers(priv, f"{actor['id']}#main-key", store, activity)

# wired into your web framework's POST /inbox route:
# result = handle_incoming_activity(request.body, request.headers, actor["id"], store, request.url)
# if result["response_activity"]: deliver_activity(..., result["response_activity"] ...)
```

## What's not built (honest scope)

- No bundled web server — this is deliberate: the protocol logic is
  meant to be wired into whatever framework a magazine's site already
  runs (Flask, Django, a static-site host with a small serverless
  function), not to impose a new one.
- Delivery and incoming-verification logic is tested against a
  controlled fake HTTP layer, not a live Mastodon instance — this
  sandbox has no network path to one, and deliberately testing against
  a real third-party service without cause isn't something this
  project does even where technically possible.

## License

MIT — see `LICENSE`.
