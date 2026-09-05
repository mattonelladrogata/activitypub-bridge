"""
Delivery — actually POSTing signed activities to real inboxes.

The `opener` parameter throughout is dependency injection for testing:
in production it defaults to `urllib.request.urlopen`; tests pass a
fake one that returns controlled responses without touching the
network. This sandbox has no path to a live Mastodon inbox (and
shouldn't spam a real one just to test), so this is the honest way to
verify the delivery LOGIC — retry behavior, error handling, request
construction — without pretending an end-to-end live test happened
when it didn't.
"""

import json
import time
import urllib.error
import urllib.request
from typing import Optional, Callable, Dict, Tuple

from .signatures import sign_request


def deliver_activity(
    private_key,
    key_id: str,
    inbox_url: str,
    activity_body: bytes,
    max_retries: int = 3,
    backoff_seconds: float = 2.0,
    opener: Optional[Callable] = None,
) -> Tuple[bool, Optional[int], Optional[str]]:
    """
    Delivers one signed activity to one inbox.
    Returns (success, http_status_or_None, error_message_or_None).

    Retries on 5xx (server-side, transient) and network errors; does
    NOT retry on 4xx (client error — our request was rejected for a
    reason retrying won't fix, e.g. bad signature or unknown actor).
    """
    headers = sign_request(private_key, key_id, "POST", inbox_url, activity_body)
    opener_fn = opener or urllib.request.urlopen
    last_error = None

    for attempt in range(max_retries):
        try:
            req = urllib.request.Request(inbox_url, data=activity_body, headers=headers, method="POST")
            with opener_fn(req, timeout=10) as resp:
                status = getattr(resp, "status", 200)
                return True, status, None
        except urllib.error.HTTPError as e:
            last_error = f"HTTP {e.code}"
            if e.code < 500:
                break  # client error: retrying identically won't help
        except Exception as e:
            last_error = str(e)
        if attempt < max_retries - 1:
            time.sleep(backoff_seconds * (attempt + 1))

    return False, None, last_error


def deliver_to_all_followers(
    private_key,
    key_id: str,
    follower_store,
    activity: dict,
    opener: Optional[Callable] = None,
) -> Dict[str, Tuple[bool, Optional[int], Optional[str]]]:
    """Delivers one activity to every distinct inbox URL currently on record."""
    body = json.dumps(activity).encode("utf-8")
    results = {}
    for inbox_url in follower_store.list_inboxes():
        results[inbox_url] = deliver_activity(private_key, key_id, inbox_url, body, opener=opener)
    return results
