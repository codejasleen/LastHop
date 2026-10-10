"""Authenticated GitHub push events refresh previously connected public repos."""

from __future__ import annotations

import hashlib
import hmac
import json
import os


def verify_push(body: bytes, signature: str | None, event: str | None) -> str | None:
    secret = os.getenv("GITHUB_WEBHOOK_SECRET")
    if not secret:
        raise ValueError("GITHUB_WEBHOOK_SECRET is not configured")
    expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    if not signature or not hmac.compare_digest(signature, expected):
        raise PermissionError("Invalid GitHub webhook signature")
    if event != "push":
        return None
    payload = json.loads(body)
    repo = payload.get("repository", {})
    if repo.get("private"):
        return None
    if payload.get("ref") != f"refs/heads/{repo.get('default_branch')}":
        return None
    return repo.get("full_name")
