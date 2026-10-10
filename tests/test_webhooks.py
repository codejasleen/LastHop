import hashlib
import hmac
import json

import pytest

from app.webhooks import verify_push


def test_webhook_requires_signature_and_default_branch(monkeypatch):
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", "test-secret")
    body = json.dumps({"repository": {"full_name": "owner/repo", "private": False, "default_branch": "main"}, "ref": "refs/heads/main"}).encode()
    signature = "sha256=" + hmac.new(b"test-secret", body, hashlib.sha256).hexdigest()
    assert verify_push(body, signature, "push") == "owner/repo"
    assert verify_push(body, signature, "issues") is None
    with pytest.raises(PermissionError):
        verify_push(body, "sha256=wrong", "push")
