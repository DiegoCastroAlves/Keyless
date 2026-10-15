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
# New devices showing a QR code to sign in (the qr_sign_in functions).
qr_sign_ins = {}
# What each write replaced (item_versions), share links, attachment chunks
# (Storage) and the account's recovery key, as the real server keeps them.
versions = {}
shares = {}
objects = {}
recovery = {}
QUOTA = 1024 * 1024 * 1024
seq = [max(row["seq"] for row in items.values())]
lock = threading.Lock()
TOKEN = "mock-access-token"


def session():
    return {"access_token": TOKEN, "refresh_token": "mock-refresh-token", "expires_in": 3600, "token_type": "bearer", "user": {"id": fixture["userId"], "email": fixture["email"]}}


def record(kind, row):
    with open("writes.jsonl", "a") as out:
        out.write(json.dumps({"kind": kind, "id": row["id"], "vault_id": row["vault_id"], "revision": row["revision"]}) + "\n")


def record_other(kind, what):
    with open("writes.jsonl", "a") as out:
        out.write(json.dumps({"kind": kind, "id": what}) + "\n")


def insert(body):
    """Adds an item (under the lock); None when the id is taken."""
    if body["id"] in items:
        return None
    seq[0] += 1
    row = {"id": body["id"], "vault_id": body["vault_id"], "enc_overview": body["enc_overview"], "enc_details": body["enc_details"], "revision": 1, "seq": seq[0], "deleted_at": None, "enc_tombstone": None}
    items[row["id"]] = row
    return row


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

    def raw(self):
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(length) if length else b""

    def send_bytes(self, data):
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def storage_error(self, status, message):
        # Storage answers its errors as HTTP 400 with the real status inside.
        return self.answer(400, {"statusCode": str(status), "error": message, "message": message})

    def account_rpc(self, name, body):
        """Attachment space, vaults and the recovery key (under the lock); None when unknown."""
        if name == "attachment_space":
            return 200, {"used": sum(len(b) for b in objects.values()), "quota": QUOTA}
        if name == "create_vault":
            fixture["memberships"].append({"vault_id": body["p_id"], "role": "owner", "enc_vault_key": body["p_enc_vault_key"],
                                          "vaults": {"owner_id": fixture["userId"], "enc_meta": body["p_enc_meta"], "seq": 0, "deleted_at": None, "enc_tombstone": None}})
            record_other("vault", body["p_id"])
            return 200, {"owner_id": fixture["userId"], "seq": 0}
        if name == "recovery_key_created":
            return 200, recovery.get("created_at")
        if name == "set_recovery_key":
            recovery.update(proof=body["p_proof"], enc=body["p_enc_user_key"], created_at="2026-10-14T12:00:00Z")
            record_other("recovery_key", "set")
            return 204, None
        if name == "remove_recovery_key":
            recovery.clear()
            record_other("recovery_key", "removed")
            return 204, None
        return None

    def recovery_rpc(self, name, body):
        """Recovering an account (open to anyone); None when unknown."""
        if name not in ("begin_recovery", "complete_recovery"):
            return None
        if body.get("p_email") != fixture["email"] or not recovery or body.get("p_proof") != recovery["proof"]:
            return 200, {"error": "recovery_failed"}
        profile = fixture["profile"]
        if name == "begin_recovery":
            return 200, {"user_id": fixture["userId"], "enc_recovery_user_key": recovery["enc"], "format": profile["format"],
                         "public_key": profile["public_key"], "enc_private_key": profile["enc_private_key"]}
        profile.update(kdf=body["p_kdf"], enc_user_key=body["p_enc_user_key"])
        fixture["authSecret"] = body["p_auth_secret"]
        recovery.update(proof=body["p_new_proof"], enc=body["p_new_enc_recovery_user_key"])
        record_other("recovery", "completed")
        return 200, {}

    def authorized(self):
        return self.headers.get("Authorization") == f"Bearer {TOKEN}"

    def qr_rpc(self, name, body):
        """The qr_sign_in functions open to anyone (under the lock); None when unknown."""
        if name == "start_qr_sign_in":
            if len(body.get("p_secret") or "") != 43 or body.get("p_platform") not in ("linux", "windows", "macos", "android", "ios", "web") or body["p_id"] in qr_sign_ins:
                return 200, {"error": "invalid_request"}
            qr_sign_ins[body["p_id"]] = {"id": body["p_id"], "secret": body["p_secret"], "platform": body["p_platform"], "ip": "10.0.2.16", "country": "BR",
                                         "created_at": "2026-10-15T10:00:00Z", "expires_at": "2026-10-15T10:10:00Z", "status": "waiting",
                                         "approver_key": None, "enc_payload": None, "expired": False}
            return 200, {"ok": True}
        if name in ("qr_sign_in_status", "cancel_qr_sign_in"):
            request = qr_sign_ins.get(body.get("p_id"))
            if not request or request["secret"] != body.get("p_secret"):
                return (200, {"status": "unknown"}) if name == "qr_sign_in_status" else (204, None)
            if name == "cancel_qr_sign_in":
                del qr_sign_ins[request["id"]]
                return 204, None
            if request["status"] == "approved":
                del qr_sign_ins[request["id"]]
                return 200, {"status": "approved", "approver_key": request["approver_key"], "payload": request["enc_payload"]}
            if request["status"] == "denied":
                return 200, {"status": "denied"}
            return 200, {"status": "expired" if request["expired"] else "waiting"}
        return None

    def qr_signed_in_rpc(self, name, body):
        """The qr_sign_in functions of a signed-in device (under the lock); None when unknown."""
        request = qr_sign_ins.get(body.get("p_id"))
        live = request is not None and request["status"] == "waiting" and not request["expired"]
        if name == "qr_sign_in_request":
            return 200, ({k: request[k] for k in ("id", "platform", "ip", "country", "created_at", "expires_at")} if live else None)
        if name == "approve_qr_sign_in":
            if not live or len(body.get("p_approver_key") or "") != 43:
                return 200, False
            request.update(status="approved", approver_key=body["p_approver_key"], enc_payload=body["p_enc_payload"])
            return 200, True
        if name == "deny_qr_sign_in":
            if live:
                request["status"] = "denied"
            return 204, None
        return None

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
        # The test's view of QR code sign-ins: all of them, or one.
        if url.path == "/test/qr_sign_in":
            with lock:
                return self.answer(200, list(qr_sign_ins.values()))
        if url.path.startswith("/test/qr_sign_in/"):
            with lock:
                return self.answer(200, qr_sign_ins.get(url.path.rsplit("/", 1)[1]))
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
        if url.path.startswith("/storage/v1/object/authenticated/attachments/"):
            if not self.authorized():
                return self.storage_error(403, "Unauthorized")
            with lock:
                data = objects.get(url.path[len("/storage/v1/object/authenticated/attachments/"):])
            return self.send_bytes(data) if data is not None else self.storage_error(404, "not_found")
        if url.path.startswith("/test/shares"):
            with lock:
                return self.answer(200, list(shares.values()))
        if not url.path.startswith("/rest/v1/"):
            return self.answer(404, {"message": "not found"})
        if not self.authorized():
            return self.answer(401, {"message": "JWT expired", "code": "PGRST301"})
        if url.path == "/rest/v1/profiles":
            return self.answer(200, [fixture["profile"]])
        if url.path == "/rest/v1/vault_members":
            return self.answer(200, fixture["memberships"])
        if url.path == "/rest/v1/item_versions":
            item_id = query.get("item_id", ["eq."])[0][3:]
            with lock:
                rows = sorted(versions.get(item_id, []), key=lambda r: -r["revision"])
            return self.answer(200, rows)
        if url.path == "/rest/v1/passkeys":
            return self.answer(200, [])
        if url.path == "/rest/v1/shares":
            with lock:
                rows = [{k: s[k] for k in ("id", "enc_label", "expires_at", "max_views", "views", "created_at", "revoked_at")} for s in shares.values()]
            return self.answer(200, sorted(rows, key=lambda s: s["created_at"], reverse=True))
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
        if url.path.startswith("/storage/v1/object/attachments/"):
            data = self.raw()
            if not self.authorized():
                return self.storage_error(403, "Unauthorized")
            name = url.path[len("/storage/v1/object/attachments/"):]
            with lock:
                if name in objects:
                    return self.storage_error(409, "Duplicate")
                objects[name] = data
            record_other("object", name)
            return self.answer(200, {"Key": "attachments/" + name})
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
        if url.path == "/test/items":
            # More of the fixture's items, by key ("autofillItems": a card and an identity).
            with lock:
                for row in fixture.get(body.get("key", ""), []):
                    if row["id"] not in items:
                        seq[0] += 1
                        items[row["id"]] = dict(row, seq=seq[0])
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
        # A new device showing a QR code (for the phone to read), and a phone
        # answering the app's own QR code.
        if url.path == "/test/qr_sign_in":
            with lock:
                qr_sign_ins[body["id"]] = {"id": body["id"], "secret": "x" * 43, "platform": body.get("platform", "windows"), "ip": body.get("ip"), "country": body.get("country"),
                                           "created_at": "2026-10-15T10:00:00Z", "expires_at": "2026-10-15T10:10:00Z", "status": "waiting",
                                           "approver_key": None, "enc_payload": None, "expired": False}
            return self.answer(201, {})
        if url.path.startswith("/test/qr_sign_in/"):
            _, _, _, qr_id, action = url.path.split("/")
            with lock:
                request = qr_sign_ins[qr_id]
                if action == "approve":
                    request.update(status="approved", approver_key=body["approver_key"], enc_payload=body["enc_payload"])
                elif action == "deny":
                    request["status"] = "denied"
                elif action == "expire":
                    request["expired"] = True
            return self.answer(200, {})
        if url.path.startswith("/rest/v1/rpc/"):
            name = url.path[len("/rest/v1/rpc/"):]
            with lock:
                answer = self.qr_rpc(name, body)
            if answer is not None:
                return self.answer(*answer)
            # Open to anyone, as on the real server.
            if name == "device_status":
                with lock:
                    device = devices.get(body.get("p_id"))
                status = "unknown" if not device or device["secret"] != body.get("p_secret") else ("revoked" if device["revoked_at"] else "active")
                return self.answer(200, status)
            with lock:
                answer = self.recovery_rpc(name, body)
            if answer is not None:
                return self.answer(*answer)
            if not self.authorized():
                return self.answer(401, {"message": "JWT expired"})
            with lock:
                answer = self.device_rpc(name, body)
                if answer is None:
                    answer = self.qr_signed_in_rpc(name, body)
                if answer is None:
                    answer = self.account_rpc(name, body)
            if answer is None:
                return self.answer(404, {"code": "PGRST202", "message": "Could not find the function"})
            status, value = answer
            return self.answer(status, value)
        if url.path == "/rest/v1/items":
            if not self.authorized():
                return self.answer(401, {"message": "JWT expired"})
            # One item, or several at once (an import).
            with lock:
                rows = [insert(b) for b in (body if isinstance(body, list) else [body])]
                if any(row is None for row in rows):
                    return self.answer(409, {"code": "23505", "message": "duplicate key"})
            for row in rows:
                record("insert", row)
            return self.answer(201, rows)
        if url.path == "/rest/v1/shares":
            if not self.authorized():
                return self.answer(401, {"message": "JWT expired"})
            with lock:
                shares[body["id"]] = dict(body, views=0, created_at="2026-10-14T12:00:00Z", revoked_at=None, max_views=body.get("max_views"))
            record_other("share", body["id"])
            return self.answer(201)
        return self.answer(404, {"message": "not found"})

    def do_PATCH(self):
        url = urlparse(self.path)
        query = parse_qs(url.query)
        body = self.body()
        if url.path == "/rest/v1/shares" and self.authorized():
            with lock:
                share = shares.get(query.get("id", ["eq."])[0][3:])
                if share:
                    share["revoked_at"] = body.get("revoked_at")
            record_other("share_revoked", share["id"] if share else "")
            return self.answer(204)
        if url.path != "/rest/v1/items" or not self.authorized():
            return self.answer(404, {"message": "not found"})
        item_id = query.get("id", ["eq."])[0][3:]
        revision = int(query.get("revision", ["eq.-1"])[0][3:])
        with lock:
            row = items.get(item_id)
            if row is None or row["revision"] != revision:
                return self.answer(200, [])
            if row.get("enc_overview") and row.get("enc_details"):
                versions.setdefault(item_id, []).append({"revision": row["revision"], "enc_overview": row["enc_overview"], "enc_details": row["enc_details"]})
            seq[0] += 1
            for key in ("enc_overview", "enc_details", "enc_tombstone"):
                if key in body:
                    row[key] = body[key]
            # The server decides when an item was deleted, as the real one.
            row["deleted_at"] = None if row.get("enc_tombstone") is None else (row.get("deleted_at") or "2026-01-01T00:00:00Z")
            row.update(revision=revision + 1, seq=seq[0])
        record("delete" if row["deleted_at"] else "update", row)
        return self.answer(200, [row])

    def do_DELETE(self):
        url = urlparse(self.path)
        body = self.body()
        if url.path != "/storage/v1/object/attachments" or not self.authorized():
            return self.answer(404, {"message": "not found"})
        with lock:
            gone = [objects.pop(name) for name in body.get("prefixes", []) if name in objects]
        record_other("objects_deleted", str(len(gone)))
        return self.answer(200, [])


if __name__ == "__main__":
    print(f"mock server on port {PORT}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
