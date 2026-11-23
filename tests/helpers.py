"""Shared test fixtures: throwaway DB + live server on a random port.

PENENV_DB is set *before* tracker modules are imported, so the real
tracker/penenv.db is never opened by the test suite.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TMP = Path(tempfile.mkdtemp(prefix="penenv-test-"))
os.environ["PENENV_DB"] = str(TMP / "test.db")
# Agent config: never read or write the real ~/.config/penenv/agent.json or ~/.strix config.
os.environ["PENENV_AGENT_CONFIG"] = str(TMP / "agent.json")
os.environ["PENENV_STRIX_CONFIG"] = str(TMP / "strix-cli-config.json")
sys.path.insert(0, str(ROOT / "tracker"))

import ingest  # noqa: E402
import server  # noqa: E402

FAKE_DNS = {
    "app.example-public.com": ["93.184.216.34"],
    "shop.acme-corp.co.uk": ["93.184.216.35"],
    "intranet.acme-corp.co.uk": ["10.1.2.3"],
    "split.acme-corp.co.uk": ["93.184.216.36", "192.168.0.9"],
}


def fake_resolver(host: str) -> list[str]:
    return FAKE_DNS.get(host, [])


class LiveServer:
    def __init__(self):
        ingest.connect().close() if hasattr(ingest, "connect") else None
        server.ensure_projects_table()
        server.RESOLVER = fake_resolver
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def call(self, method: str, path: str, body=None):
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(self.base + path, data=data, method=method,
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req) as r:
                return r.status, json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()
