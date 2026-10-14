#!/usr/bin/env python3
"""A fake Keyless server for testing the Android app on an emulator (CI):
just the Supabase Auth and Data API routes the app uses, over the made-up
account of `cargo run -p keyless-client --example fixture`. It keeps what
the app uploads and writes each write as a JSON line to `writes.jsonl`.

Usage: mock_server.py <fixture.json> [port]
"""

import hashlib
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

fixture = json.load(open(sys.argv[1]))
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8787
items = {row["id"]: dict(row) for row in fixture["items"]}
# The account's devices, and new devices asking to sign in (the device_setup
# functions), as the real server keeps them.
devices = {}
requests = {}
seq = [max(row["seq"] for row in items.values())]
lock = threading.Lock()
TOKEN = "mock-access-token"


def session():
    return {"access_token": TOKEN, "refresh_token": "mock-refresh-token", "expires_in": 3600, "token_type": "bearer", "user": {"id": fixture["userId"], "email": fixture["email"]}}


def record(kind, row):
    with open("writes.jsonl", "a") as out:
        out.write(json.dumps({"kind": kind, "id": row["id"], "vault_id": row["vault_id"], "revision": row["revision"]}) + "\n")


# Sentinel's public lists, shaped like the real ones: bank.example was
# breached after the fixture's items were saved.
def sentinel_list(kind):
    domains = ["bank.example"] + [f"site{i}.example" for i in range(300)]
    if kind == "breaches":
        return [{"Title": d, "Name": d, "Domain": d, "BreachDate": "2026-10-01", "PwnCount": 7,
                 "DataClasses": ["Email addresses", "Passwords"], "IsVerified": True} for d in domains]
    if kind == "twoFactor":
        return [[d, {"domain": d}] for d in domains]
    return {d: {"passwordless": "allowed"} for d in domains}


# Have I Been Pwned's range API: GitHub's password from the fixture was in
# breaches; other lines are padding.
BREACHED = {hashlib.sha1(b"github-pass-123").hexdigest().upper(): 42}


def range_answer(prefix):
    lines = [f"{h[5:]}:{count}" for h, count in BREACHED.items() if h.startswith(prefix)]
    lines += [f"{i:035X}:0" for i in range(20)]
    return "\r\n".join(lines)


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

    def send_text(self, text):
        data = text.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def body(self):
        length = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(length) or b"{}") if length else {}

    def authorized(self):
        return self.headers.get("Authorization") == f"Bearer {TOKEN}"

    def device_rpc(self, name, body):
        """The devices and device_setup functions (under the lock); None when unknown."""
        if name == "register_device":
            devices[body["p_id"]] = {"id": body["p_id"], "secret": body["p_secret"], "enc_info": body["p_enc_info"], "ip": "10.0.2.16", "country": "BR",
                                     "created_at": "2026-10-14T10:00:00Z", "last_seen_at": "2026-10-14T10:00:00Z", "revoked_at": None}
            return 204, None
        if name == "device_seen":
            device = devices.get(body["p_id"])
            return 200, "active" if device and not device["revoked_at"] else "unknown"
        if name == "remove_device":
            devices.pop(body["p_id"], None)
            return 204, None
        if name == "revoke_device":
            if body["p_id"] in devices:
                devices[body["p_id"]]["revoked_at"] = "2026-10-14T11:00:00Z"
            return 204, None
        if name == "pending_device_setups":
            return 200, [{k: r[k] for k in ("id", "public_key", "commitment", "platform", "ip", "country", "created_at", "expires_at", "status", "nonce", "mine")}
                         for r in requests.values() if r["status"] in ("pending", "answered", "revealed")]
        if name == "answer_device_setup":
            request = requests.get(body["p_id"])
            if not request or request["status"] != "pending":
                return 200, False
            request.update(status="answered", approver_key=body["p_public_key"], approver_nonce=body["p_nonce"], mine=True)
            return 200, True
        if name == "approve_device_setup":
            request = requests.get(body["p_id"])
            if not request or request["status"] != "revealed":
                return 200, False
            request.update(status="approved", enc_payload=body["p_enc_payload"])
            return 200, True
        if name == "deny_device_setup":
            if body["p_id"] in requests:
                requests[body["p_id"]]["status"] = "denied"
            return 204, None
        return None

    def do_GET(self):
        url = urlparse(self.path)
        query = parse_qs(url.query)
        # The test's view of a sign-in request (what the new device would poll).
        if url.path.startswith("/test/device/"):
            with lock:
                return self.answer(200, devices.get(url.path.rsplit("/", 1)[1]))
        if url.path.startswith("/test/device_request/"):
            with lock:
                return self.answer(200, requests.get(url.path.rsplit("/", 1)[1]))
        if url.path == "/rest/v1/devices" and self.authorized():
            with lock:
                rows = [{k: d[k] for k in ("id", "enc_info", "ip", "country", "created_at", "last_seen_at")} for d in devices.values() if not d["revoked_at"]]
            return self.answer(200, rows)
        # Test builds read Sentinel's lists and password checks here.
        if url.path.startswith("/sentinel/lists/"):
            return self.answer(200, sentinel_list(url.path.rsplit("/", 1)[1]))
        if url.path.startswith("/sentinel/range/"):
            return self.send_text(range_answer(url.path.rsplit("/", 1)[1].upper()))
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
        if url.path == "/test/device":
            with lock:
                devices[body["id"]] = {"id": body["id"], "secret": "x", "enc_info": body.get("enc_info", "not-for-this-account"), "ip": "203.0.113.9", "country": "PT",
                                       "created_at": "2026-10-01T10:00:00Z", "last_seen_at": "2026-10-13T10:00:00Z", "revoked_at": None}
            return self.answer(201, {})
        if url.path == "/test/device_request":
            with lock:
                requests[body["id"]] = dict(body, status="pending", approver_key=None, approver_nonce=None, nonce=None, enc_payload=None, created_at="2026-10-14T10:00:00Z", expires_at="2026-10-14T10:10:00Z", mine=False)
            return self.answer(201, {})
        if url.path.startswith("/test/device_request/") and url.path.endswith("/reveal"):
            with lock:
                request = requests[url.path.split("/")[3]]
                request.update(nonce=body["nonce"], status="revealed")
            return self.answer(200, {})
        if url.path.startswith("/rest/v1/rpc/"):
            name = url.path[len("/rest/v1/rpc/"):]
            # Open to anyone, as on the real server.
            if name == "device_status":
                with lock:
                    device = devices.get(body.get("p_id"))
                status = "unknown" if not device or device["secret"] != body.get("p_secret") else ("revoked" if device["revoked_at"] else "active")
                return self.answer(200, status)
            if not self.authorized():
                return self.answer(401, {"message": "JWT expired"})
            with lock:
                answer = self.device_rpc(name, body)
            if answer is None:
                return self.answer(404, {"code": "PGRST202", "message": "Could not find the function"})
            status, value = answer
            return self.answer(status, value)
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
