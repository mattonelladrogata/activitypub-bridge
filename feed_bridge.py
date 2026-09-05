"""
Feed bridge — converts real RSS/Atom entries (from feedparser, a
mature, widely-used library) into valid ActivityPub Create/Note
activities.

This is the actual bridge: a literary magazine that already publishes
an RSS feed (WordPress, Substack, Jekyll/Hugo, and virtually every
publishing platform already does this for free) gets a Fediverse
presence without hosting a full Mastodon instance or hand-writing any
ActivityPub JSON.
"""

import hashlib
import html
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Optional

import feedparser


def _entry_id(entry) -> str:
    """A stable identifier for deduplication, independent of feed order."""
    base = entry.get("id") or entry.get("link") or entry.get("title", "")
    return hashlib.sha256(base.encode("utf-8")).hexdigest()[:16]


def _parse_published(entry) -> str:
    for field in ["published", "updated"]:
        raw = entry.get(field)
        if raw:
            try:
                dt = parsedate_to_datetime(raw)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            except (TypeError, ValueError):
                continue
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def entry_to_note_content(entry, max_summary_len: int = 400) -> str:
    title = html.escape(entry.get("title", "").strip())
    summary = entry.get("summary", "") or entry.get("description", "")
    # feedparser leaves summaries as raw (possibly HTML) text; strip
    # tags crudely for a plain preview — good enough for a toot body,
    # real HTML rendering happens link-side when the reader clicks through
    import re
    plain_summary = re.sub("<[^<]+?>", "", summary).strip()
    if len(plain_summary) > max_summary_len:
        plain_summary = plain_summary[:max_summary_len].rsplit(" ", 1)[0] + "…"
    link = entry.get("link", "")

    parts = [f"<p><strong>{title}</strong></p>"]
    if plain_summary:
        parts.append(f"<p>{html.escape(plain_summary)}</p>")
    if link:
        parts.append(f'<p><a href="{html.escape(link)}">{html.escape(link)}</a></p>')
    return "".join(parts)


def entry_to_activity(entry, actor_url: str, domain: str) -> dict:
    entry_id = _entry_id(entry)
    note_url = f"https://{domain}/notes/{entry_id}"
    published = _parse_published(entry)
    content = entry_to_note_content(entry)

    note = {
        "id": note_url,
        "type": "Note",
        "attributedTo": actor_url,
        "content": content,
        "published": published,
        "url": entry.get("link", note_url),
        "to": ["https://www.w3.org/ns/activitystreams#Public"],
        "cc": [f"{actor_url}/followers"],
    }
    return {
        "@context": "https://www.w3.org/ns/activitystreams",
        "id": f"{note_url}/activity",
        "type": "Create",
        "actor": actor_url,
        "published": published,
        "to": note["to"],
        "cc": note["cc"],
        "object": note,
    }


def fetch_and_convert(feed_url: str, actor_url: str, domain: str, limit: Optional[int] = 10) -> list:
    """
    Fetches a REAL feed (any RSS or Atom URL) and returns a list of
    ActivityPub Create activities, newest first, capped at `limit`.
    """
    parsed = feedparser.parse(feed_url)
    entries = parsed.entries[:limit] if limit else parsed.entries
    return [entry_to_activity(e, actor_url, domain) for e in entries]
