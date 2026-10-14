#!/usr/bin/env python3
"""A fake Keyless server for testing the Android app on an emulator (CI):
just the Supabase Auth and Data API routes the app uses, over the made-up
account of `cargo run -p keyless-client --example fixture`. It keeps what
the app uploads and writes each write as a JSON line to `writes.jsonl`.

Usage: mock_server.py <fixture.json> [port]
"""

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

fixture = json.load(open(sys.argv[1]))
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8787
items = {row["id"]: dict(row) for row in fixture["items"]}
seq = [max(row["seq"] for row in items.values())]
lock = threading.Lock()
TOKEN = "mock-access-token"


def session():
    return {"access_token": TOKEN, "refresh_token": "mock-refresh-token", "expires_in": 3600, "token_type": "bearer", "user": {"id": fixture["userId"], "email": fixture["email"]}}


def record(kind, row):
    with open("writes.jsonl", "a") as out:
        out.write(json.dumps({"kind": kind, "id": row["id"], "vault_id": row["vault_id"], "revision": row["revision"]}) + "\n")


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        sys.stderr.write("mock: " + (fmt % args) + "\n")

    def answer(self, status, body=None):
        data = b"" if body is None else json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def body(self):
        length = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(length) or b"{}") if length else {}

    def authorized(self):
        return self.headers.get("Authorization") == f"Bearer {TOKEN}"

    def do_GET(self):
        url = urlparse(self.path)
        query = parse_qs(url.query)
        # Test builds read sites' Digital Asset Links here.
        if url.path.startswith("/assetlinks/"):
            site = url.path[len("/assetlinks/"):].removesuffix(".json")
            return self.answer(200, fixture.get("assetLinks", {}).get(site, []))
        if not url.path.startswith("/rest/v1/"):
            return self.answer(404, {"message": "not found"})
        if not self.authorized():
            return self.answer(401, {"message": "JWT expired", "code": "PGRST301"})
        if url.path == "/rest/v1/profiles":
            return self.answer(200, [fixture["profile"]])
        if url.path == "/rest/v1/vault_members":
            return self.answer(200, fixture["memberships"])
        if url.path == "/rest/v1/items" and "id" in query:
            item_id = query["id"][0][3:]
            with lock:
                row = items.get(item_id)
            return self.answer(200, [row] if row else [])
        if url.path == "/rest/v1/items":
            vault = query.get("vault_id", ["eq."])[0][3:]
            cursor = int(query.get("seq", ["gt.0"])[0][3:])
            limit = int(query.get("limit", ["500"])[0])
            with lock:
                rows = sorted((r for r in items.values() if r["vault_id"] == vault and r["seq"] > cursor), key=lambda r: r["seq"])
            return self.answer(200, rows[:limit])
        return self.answer(404, {"message": "not found", "code": "PGRST205"})

    def do_POST(self):
        url = urlparse(self.path)
        query = parse_qs(url.query)
        body = self.body()
        if url.path == "/auth/v1/token":
            grant = query.get("grant_type", [""])[0]
            if grant == "password":
                if body.get("email") == fixture["email"] and body.get("password") == fixture["authSecret"]:
                    return self.answer(200, session())
                return self.answer(400, {"error_code": "invalid_credentials", "msg": "Invalid login credentials"})
            if grant == "refresh_token":
                return self.answer(200, session())
            return self.answer(400, {"error_code": "validation_failed"})
        if url.path == "/auth/v1/logout":
            return self.answer(204)
        if url.path.startswith("/rest/v1/rpc/"):
            return self.answer(404, {"code": "PGRST202", "message": "Could not find the function"})
        if url.path == "/rest/v1/items":
            if not self.authorized():
                return self.answer(401, {"message": "JWT expired"})
            with lock:
                if body["id"] in items:
                    return self.answer(409, {"code": "23505", "message": "duplicate key"})
                seq[0] += 1
                row = {"id": body["id"], "vault_id": body["vault_id"], "enc_overview": body["enc_overview"], "enc_details": body["enc_details"], "revision": 1, "seq": seq[0], "deleted_at": None, "enc_tombstone": None}
                items[row["id"]] = row
            record("insert", row)
            return self.answer(201, [row])
        return self.answer(404, {"message": "not found"})

    def do_PATCH(self):
        url = urlparse(self.path)
        query = parse_qs(url.query)
        body = self.body()
        if url.path != "/rest/v1/items" or not self.authorized():
            return self.answer(404, {"message": "not found"})
        item_id = query.get("id", ["eq."])[0][3:]
        revision = int(query.get("revision", ["eq.-1"])[0][3:])
        with lock:
            row = items.get(item_id)
            if row is None or row["revision"] != revision:
                return self.answer(200, [])
            seq[0] += 1
            for key in ("enc_overview", "enc_details", "enc_tombstone"):
                if key in body:
                    row[key] = body[key]
            # The server decides when an item was deleted, as the real one.
            row["deleted_at"] = None if row.get("enc_tombstone") is None else (row.get("deleted_at") or "2026-01-01T00:00:00Z")
            row.update(revision=revision + 1, seq=seq[0])
        record("delete" if row["deleted_at"] else "update", row)
        return self.answer(200, [row])


if __name__ == "__main__":
    print(f"mock server on port {PORT}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
