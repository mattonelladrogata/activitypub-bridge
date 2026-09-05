"""
Follower store — a plain JSON file. Deliberately not a database: this
tool is a library meant to be wired into whatever a magazine's site
already runs, not a bundled service with its own infra opinions. A
real deployment can swap this for SQLite/Postgres by implementing the
same four methods.
"""

import json
from pathlib import Path
from typing import Dict


class FollowerStore:
    def __init__(self, path: str):
        self.path = Path(path)
        self._data: Dict[str, str] = self._load()

    def _load(self) -> Dict[str, str]:
        if self.path.exists():
            return json.loads(self.path.read_text())
        return {}

    def _save(self) -> None:
        self.path.write_text(json.dumps(self._data, indent=2))

    def add(self, actor_url: str, inbox_url: str) -> None:
        self._data[actor_url] = inbox_url
        self._save()

    def remove(self, actor_url: str) -> None:
        self._data.pop(actor_url, None)
        self._save()

    def is_follower(self, actor_url: str) -> bool:
        return actor_url in self._data

    def list_inboxes(self) -> list:
        """Deduplicated: several followers on the same server often
        share one shared inbox, and each activity should go there once."""
        return sorted(set(self._data.values()))

    def count(self) -> int:
        return len(self._data)
