from __future__ import annotations

import http.client
import json
import os
import socket
import tempfile
import threading
import unittest
from pathlib import Path

from shipcheck.api import create_server
from shipcheck.ledger import DecisionLedger


def _available_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


class LoopbackInterfaceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        if os.name == "posix":
            os.chmod(self.root, 0o700)
        self.ledger = DecisionLedger(self.root / "ledger.sqlite")
        self.ledger.append("NOTE", {"purpose": "interface-fixture"}, idempotency_key="interface-note")
        self.token = "shipcheck-loopback-test-token-000000000000000000"
        self.server, _ = create_server(
            ledger=self.ledger,
            token=self.token,
            host="127.0.0.1",
            port=_available_port(),
        )
        self.port = int(self.server.server_address[1])
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temporary.cleanup()

    def request(self, method: str, path: str, *, authorized: bool = False, host: str | None = None) -> tuple[int, dict[str, str], bytes]:
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        headers = {}
        if authorized:
            headers["Authorization"] = f"Bearer {self.token}"
        if host is not None:
            headers["Host"] = host
        connection.request(method, path, headers=headers)
        response = connection.getresponse()
        body = response.read()
        response_headers = {name.casefold(): value for name, value in response.getheaders()}
        connection.close()
        return response.status, response_headers, body

    def test_health_and_dashboard_assets_are_loopback_read_only(self):
        status, headers, body = self.request("GET", "/health")
        self.assertEqual(200, status)
        self.assertEqual("read-only-loopback", json.loads(body)["mode"])
        self.assertIn("default-src 'none'", headers["content-security-policy"])
        for path, content_type in (("/", "text/html"), ("/app.js", "text/javascript"), ("/app.css", "text/css")):
            with self.subTest(path=path):
                asset_status, asset_headers, asset_body = self.request("GET", path)
                self.assertEqual(200, asset_status)
                self.assertTrue(asset_headers["content-type"].startswith(content_type))
                self.assertGreater(len(asset_body), 100)

    def test_api_requires_bearer_and_exposes_versioned_capabilities(self):
        status, _, body = self.request("GET", "/api/capabilities")
        self.assertEqual((401, "AUTH_REQUIRED"), (status, json.loads(body)["error"]))
        status, _, body = self.request("GET", "/api/capabilities", authorized=True)
        self.assertEqual(200, status)
        self.assertEqual("shipcheck/api-v1", json.loads(body)["schema_version"])

    def test_api_lists_ledger_summaries_without_mutation(self):
        status, _, body = self.request("GET", "/api/entries?after=0&limit=10", authorized=True)
        value = json.loads(body)
        self.assertEqual((200, "ascending-after", 1), (status, value["order"], len(value["entries"])))
        before = self.ledger.verify()["entries"]
        status, _, body = self.request("POST", "/api/entries", authorized=True)
        self.assertEqual((405, "READ_ONLY"), (status, json.loads(body)["error"]))
        self.assertEqual(before, self.ledger.verify()["entries"])

    def test_api_rejects_non_loopback_host_and_unknown_operation(self):
        status, _, body = self.request("GET", "/api/capabilities", authorized=True, host="example.invalid")
        self.assertEqual((400, "INVALID_HOST"), (status, json.loads(body)["error"]))
        status, _, body = self.request("GET", "/api/execute", authorized=True)
        self.assertEqual((404, "NOT_FOUND"), (status, json.loads(body)["error"]))


if __name__ == "__main__":
    unittest.main()
