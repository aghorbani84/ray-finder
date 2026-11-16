"""Security regression tests for untrusted subscription sources and node targets."""

import json
import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fetch import fetch_url, load_sources
from test_nodes import _resolve_public_targets


class _FakeResponse:
    def __init__(self, status_code=200, chunks=()):
        self.status_code = status_code
        self._chunks = chunks

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError("HTTP error")

    def iter_content(self, chunk_size):
        return iter(self._chunks)


class SourceSecurityTests(unittest.TestCase):
    def test_source_allowlist_rejects_http_and_untrusted_hosts(self):
        data = {
            "sources": [{
                "name": "test",
                "urls": [
                    "https://raw.githubusercontent.com/org/repo/main/sub.txt",
                    "http://raw.githubusercontent.com/org/repo/main/sub.txt",
                    "https://example.com/sub.txt",
                    "https://user:pass@raw.githubusercontent.com/org/repo/main/sub.txt",
                ],
            }]
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sources.json"
            path.write_text(json.dumps(data), encoding="utf-8")
            sources = load_sources(path)
        self.assertEqual(
            sources,
            [{
                "name": "test",
                "urls": ["https://raw.githubusercontent.com/org/repo/main/sub.txt"],
            }],
        )

    def test_redirects_are_rejected(self):
        class FakeSession:
            def get(self, *_args, **_kwargs):
                return _FakeResponse(status_code=302)

        with self.assertRaisesRegex(ValueError, "redirects are not allowed"):
            fetch_url(FakeSession(), "https://raw.githubusercontent.com/org/repo/main/sub.txt")

    @patch("fetch.MAX_RESPONSE_BYTES", 4)
    def test_oversized_responses_are_rejected(self):
        class FakeSession:
            def get(self, *_args, **_kwargs):
                return _FakeResponse(chunks=[b"12345"])

        with self.assertRaisesRegex(ValueError, "exceeds"):
            fetch_url(FakeSession(), "https://raw.githubusercontent.com/org/repo/main/sub.txt")


class NodeTargetSecurityTests(unittest.TestCase):
    @patch("test_nodes.socket.getaddrinfo")
    def test_private_dns_targets_are_never_returned(self, getaddrinfo):
        getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.8", 443)),
        ]
        self.assertEqual(_resolve_public_targets("attacker.example", 443), [])

    @patch("test_nodes.socket.getaddrinfo")
    def test_only_global_dns_targets_are_returned(self, getaddrinfo):
        getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443)),
        ]
        targets = _resolve_public_targets("mixed.example", 443)
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0][3], ("8.8.8.8", 443))


if __name__ == "__main__":
    unittest.main()
