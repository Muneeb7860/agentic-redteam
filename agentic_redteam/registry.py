"""Multi-App Target Registry — named endpoints for governance auditing.

Stores app targets in a JSON config file so users can name their endpoints
and run audits by app name rather than pasting URLs every time.

Usage:
    from agentic_redteam.registry import Registry

    reg = Registry()
    reg.add("payment-agent", "https://pay.company.com/api/agent", tags=["production"])
    reg.add("support-bot", "http://localhost:8000/api/v1/govern", tags=["staging"])

    apps = reg.list()
    url = reg.get_url("payment-agent")
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DEFAULT_REGISTRY_PATH = Path.home() / ".swishos" / "app_registry.json"


class Registry:
    """Manages named application targets for red-team auditing."""

    def __init__(self, path: Path | None = None):
        self.path = path or DEFAULT_REGISTRY_PATH
        self._data = self._load()

    def _load(self) -> dict[str, Any]:
        if self.path.exists():
            return json.loads(self.path.read_text())
        return {"version": "1.0", "apps": {}}

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self._data, indent=2) + "\n")

    def add(self, name: str, url: str, tags: list[str] | None = None, description: str = "") -> None:
        """Register a new app target."""
        self._data["apps"][name] = {
            "url": url,
            "tags": tags or [],
            "description": description,
            "added_at": datetime.now(timezone.utc).isoformat(),
        }
        self._save()

    def remove(self, name: str) -> bool:
        """Remove an app by name. Returns True if found and removed."""
        if name in self._data["apps"]:
            del self._data["apps"][name]
            self._save()
            return True
        return False

    def get_url(self, name: str) -> str | None:
        """Get the URL for a named app."""
        app = self._data["apps"].get(name)
        return app["url"] if app else None

    def get(self, name: str) -> dict[str, Any] | None:
        """Get full app config by name."""
        return self._data["apps"].get(name)

    def list(self) -> dict[str, Any]:
        """List all registered apps."""
        return self._data["apps"]

    def list_names(self) -> list[str]:
        """List registered app names."""
        return list(self._data["apps"].keys())
