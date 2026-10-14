#!/usr/bin/env python3
"""The Android app end to end on an emulator (CI), against the fake server
(mock_server.py, reached at 10.0.2.2) and its made-up account: sign in, the
items synced, an item with its hidden password, lock and unlock, and
autofill in another app (formtest): filling a login and saving a new one.
Results are printed as GitHub annotations.

Usage: full_run.py <keyless-mock.apk> <formtest.apk> <fixture.json> <writes.jsonl> [requester]

`requester` is crates/keyless-client's example of a new device asking to
sign in; with it, approving a new device from the phone is tested too.
"""

import base64
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.request
import xml.etree.ElementTree as ET

PACKAGE = "io.github.diegocastroalves.keyless"
FORM = "io.github.diegocastroalves.keyless.formtest"
results = []


def adb(*args, check=True):
    return subprocess.run(["adb", *args], check=check, capture_output=True, text=True).stdout


def screen():
    """Every visible node, of every window: (text, class, center)."""
    dumped = adb("shell", "uiautomator", "dump", "--windows", "/sdcard/ui.xml", check=False)
    if "ERROR" in dumped or "dumped" not in dumped.lower():
        adb("shell", "uiautomator", "dump", "/sdcard/ui.xml", check=False)
    xml = adb("shell", "cat", "/sdcard/ui.xml", check=False)
    nodes = []
    for chunk in re.findall(r"<\?xml.*?(?=<\?xml|\Z)", xml, re.S) or [xml]:
        try:
            root = ET.fromstring(chunk.strip())
        except ET.ParseError:
            continue
        for node in root.iter("node"):
            bounds = re.findall(r"\d+", node.get("bounds", ""))
            if len(bounds) == 4:
                x1, y1, x2, y2 = map(int, bounds)
                nodes.append((node.get("text", ""), node.get("class", ""), ((x1 + x2) // 2, (y1 + y2) // 2), node.get("package", "")))
    return nodes


def texts():
    return " | ".join(n[0] for n in screen() if n[0])


def check(name, fragment, seconds=30):
    end = time.time() + seconds
    shown = ""
    while time.time() < end:
        shown = texts()
        if fragment in shown:
            results.append((name, True, ""))
            print(f"PASS {name}", flush=True)
            return True
        time.sleep(2)
    results.append((name, False, shown[:400]))
    print(f"FAIL {name}: {shown[:400]}", flush=True)
    return False


def tap_text(text, package=None):
    for t, _, (x, y), pkg in screen():
        if t == text and (package is None or pkg == package):
            adb("shell", "input", "tap", str(x), str(y))
            return True
    return False


def outcome(name, ok, detail=""):
    results.append((name, ok, detail))
    print(f"{'PASS' if ok else 'FAIL'} {name}", flush=True)


def tap_last(text):
    """Taps the last node with this text (a dialog's button over a screen's), ignoring case."""
    hits = [(x, y) for t, _, (x, y), _ in screen() if t.lower() == text.lower()]
    if hits:
        adb("shell", "input", "tap", str(hits[-1][0]), str(hits[-1][1]))
    return bool(hits)


def writes(path, kind):
    return open(path).read().count(f'"{kind}"') if os.path.exists(path) else 0


def wait_write(path, kind, before, seconds=30):
    end = time.time() + seconds
    while time.time() < end:
        if writes(path, kind) > before:
            return True
        time.sleep(1)
    return False


def replace_text(package, index, value):
    x, y = fields(package)[index]
    adb("shell", "input", "tap", str(x), str(y))
    time.sleep(0.4)
    adb("shell", "input", "keyevent", "KEYCODE_MOVE_END")
    for _ in range(30):
        adb("shell", "input", "keyevent", "KEYCODE_DEL")
    adb("shell", "input", "text", value)
    time.sleep(0.4)


def tap_described(description):
    """Taps the node whose content description is `description`."""
    adb("shell", "uiautomator", "dump", "/sdcard/ui.xml", check=False)
    xml = adb("shell", "cat", "/sdcard/ui.xml", check=False)
    for match in re.finditer(r'content-desc="([^"]*)"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', xml):
        if match.group(1) == description:
            x1, y1, x2, y2 = map(int, match.groups()[1:])
            adb("shell", "input", "tap", str((x1 + x2) // 2), str((y1 + y2) // 2))
            return True
    return False


def push_pictures(fixture):
    """The fixture's QR code pictures, in the phone's Downloads."""
    for key, name in (("qrTotp", "qr-totp.bmp"), ("qrSetup", "qr-setup.bmp")):
        local = os.path.join(tempfile.mkdtemp(), name)
        with open(local, "wb") as out:
            out.write(base64.b64decode(fixture[key]))
        adb("push", local, f"/sdcard/Download/{name}")


def scan_picture(name):
    """In the QR scanner: lets it use the camera once, then reads `name` from Downloads."""
    time.sleep(2)
    tap_last("Only this time")
    check(f"the QR scanner opens for {name}", "Choose an image or PDF", 20)
    tap_text("Choose an image or PDF")
    time.sleep(3)
    tap_described("Show roots")
    time.sleep(2)
    tap_last("Downloads")
    time.sleep(3)
    tap_text(name)


# The fake server as this computer reaches it (the emulator uses 10.0.2.2).
MOCK = os.environ.get("KEYLESS_MOCK", "http://127.0.0.1:8787")


def mock(path, body=None):
    """The fake server's test routes, from this computer."""
    data = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(MOCK + path, data=data, headers={"Content-Type": "application/json"}, method="POST" if data else "GET")
    with urllib.request.urlopen(request, timeout=10) as answer:
        text = answer.read().decode()
    return json.loads(text) if text else None


def wait_mock(path, test, seconds=60):
    end = time.time() + seconds
    while time.time() < end:
        state = mock(path)
        if state and test(state):
            return state
        time.sleep(1)
    return None


def reopen_list():
    """Goes to the settings and back: the list looks for new devices asking to sign in."""
    tap_text("⋮")
    tap_last("Settings")
    time.sleep(1)
    adb("shell", "input", "keyevent", "KEYCODE_BACK")


def approve_new_device(fixture, requester_path):
    asker = subprocess.Popen([requester_path], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)

    def ask(command):
        asker.stdin.write(json.dumps(command) + "\n")
        asker.stdin.flush()
        return json.loads(asker.stdout.readline())["ok"]

    started = ask({"op": "start"})
    mock("/test/device_request", {"id": "r1", "public_key": started["publicKey"], "commitment": started["commitment"], "platform": "linux", "ip": "198.51.100.7", "country": "BR"})
    reopen_list()
    check("shows that a new device asks to sign in", "A new device is asking to sign in", 30)
    tap_text("Review")
    check("asks whether it is me", "A new device wants to sign in", 15)
    tap_last("It's me, continue")
    answered = wait_mock("/test/device_request/r1", lambda r: r["status"] == "answered")
    outcome("answers the request", answered is not None)
    if not answered:
        asker.kill()
        return
    shown = ask({"op": "code", "approverKey": answered["approver_key"], "approverNonce": answered["approver_nonce"]})
    mock("/test/device_request/r1/reveal", {"nonce": shown["nonce"]})
    check("asks for the new device's code", "Type the 6-digit code", 30)
    type_into(PACKAGE, 0, shown["code"])
    tap_last("Approve")
    approved = wait_mock("/test/device_request/r1", lambda r: r["status"] == "approved", 30)
    outcome("approves the request", approved is not None)
    if approved:
        opened = ask({"op": "open", "requestId": "r1", "approverKey": answered["approver_key"], "approverNonce": answered["approver_nonce"], "payload": approved["enc_payload"]})
        outcome("the new device gets the email and Secret Key", opened["email"] == fixture["email"] and opened["secretKey"] == fixture["secretKey"])
    asker.kill()


def fields(package):
    return [(x, y) for _, cls, (x, y), pkg in screen() if cls == "android.widget.EditText" and pkg == package]


def type_into(package, index, value):
    x, y = fields(package)[index]
    adb("shell", "input", "tap", str(x), str(y))
    time.sleep(0.6)
    adb("shell", "input", "text", value)
    time.sleep(0.4)


def hide_keyboard():
    if "mInputShown=true" in adb("shell", "dumpsys", "input_method", check=False):
        adb("shell", "input", "keyevent", "KEYCODE_BACK")
        time.sleep(1)


def drive_sheet(done, buttons, seconds=90):
    """Goes through Credential Manager's sheets (tapping the first of `buttons`
    shown outside the form app) until the form app shows one of `done`."""
    end = time.time() + seconds
    while time.time() < end:
        nodes = screen()
        for text, _, _, pkg in nodes:
            if pkg == FORM and any(d in text for d in done):
                return text
        for wanted in buttons:
            hit = next(((x, y) for t, _, (x, y), pkg in nodes if pkg != FORM and t == wanted), None)
            if hit:
                adb("shell", "input", "tap", str(hit[0]), str(hit[1]))
                break
        time.sleep(2)
    return "timed out on: " + texts()[:300]


def main():
    keyless_apk, form_apk, fixture_path, writes_path = sys.argv[1:5]
    requester = sys.argv[5] if len(sys.argv) > 5 else None
    fixture = json.load(open(fixture_path))
    adb("install", "-r", keyless_apk)
    adb("install", "-r", form_apk)
    push_pictures(fixture)

    # Sign in.
    adb("shell", "am", "start", "-W", "-n", f"{PACKAGE}/.MainActivity")
    check("starts on the sign-in screen", "Sign in to Keyless", 60)
    # The Emergency Kit's QR code gives the email and Secret Key.
    tap_text("Scan your Emergency Kit")
    scan_picture("qr-setup.bmp")
    check("the Emergency Kit's QR code fills the Secret Key", "Secret Key received", 30)
    check("and the email", fixture["email"], 5)
    type_into(PACKAGE, 1, fixture["masterPassword"].replace(" ", "%s"))
    hide_keyboard()
    tap_text("Sign in")
    check("signs in and syncs the items", "GitHub", 120)
    check("lists every item", "Bank", 10)

    # An item.
    tap_text("GitHub")
    check("opens an item", "octo", 20)
    check("hides the password", "••••••••••••", 5)
    tap_text("Show")
    check("shows the password", "github-pass-123", 10)
    hide_keyboard()
    adb("shell", "input", "keyevent", "KEYCODE_BACK")
    check("back to the list", "GitHub", 10)

    # Lock and unlock.
    tap_text("Lock")
    check("locks", "Keyless is locked", 20)
    type_into(PACKAGE, 0, fixture["masterPassword"].replace(" ", "%s"))
    hide_keyboard()
    tap_text("Unlock")
    check("unlocks with the master password", "GitHub", 60)

    # Adding and changing items.
    tap_text("+")
    check("offers the categories for a new item", "What do you want to save?", 15)
    tap_text("Login")
    check("opens the editor with the login's fields", "Add field", 15)
    type_into(PACKAGE, 0, "Editor%stest")
    check("starts with the username used most", "client", 5)
    hide_keyboard()
    # A one-time password, from its QR code.
    tap_text("+ Add field")
    tap_last("One-Time Password")
    time.sleep(1)
    tap_text("Scan QR code")
    scan_picture("qr-totp.bmp")
    check("the QR code fills the one-time password", "otpauth://totp/Scanned", 30)
    tap_text("Generate")
    check("the generator makes a password", "Password generator", 15)
    tap_last("Use this password")
    time.sleep(1)
    inserts = writes(writes_path, "insert")
    tap_text("Save")
    check("saves the new item", "Editor test", 30)
    outcome("uploads the new item", wait_write(writes_path, "insert", inserts))
    check("the item has the generated password hidden", "••••••••••••", 5)
    check("and its one-time password", "One-Time Password", 5)

    updates = writes(writes_path, "update")
    tap_text("Edit")
    check("opens the item to edit", "Add field", 15)
    replace_text(PACKAGE, 0, "Edited%sitem")
    hide_keyboard()
    tap_text("Save")
    check("saves the change", "Edited item", 30)
    outcome("uploads the change", wait_write(writes_path, "update", updates))
    updates = writes(writes_path, "update")
    tap_text("☆")
    check("marks it a favorite", "★", 20)
    outcome("uploads the favorite", wait_write(writes_path, "update", updates))

    tap_text("⋮")
    tap_last("Move to Recently Deleted")
    check("moves it to Recently Deleted", "Recently Deleted", 20)
    tap_text("Recently Deleted")
    check("lists it in Recently Deleted", "Edited item", 15)
    tap_text("Edited item")
    check("offers to restore it", "Restore", 15)
    deletes = writes(writes_path, "delete")
    tap_text("Delete permanently")
    time.sleep(1)
    tap_last("Delete permanently")
    outcome("deletes it for good", wait_write(writes_path, "delete", deletes))
    check("back to the list", "All items", 20)
    tap_text("All items")

    # This phone in the account's devices, and signing another one out.
    mock("/test/device", {"id": "d2"})
    tap_text("⋮")
    tap_last("Settings")
    check("the settings open", "Lock when the screen turns off", 15)
    tap_text("Signed-in devices")
    check("lists this phone among the devices", "This device", 30)
    check("and the other device", "203.0.113.9", 10)
    tap_text("Sign out")
    tap_last("Sign out")
    signed_out = wait_mock("/test/device/d2", lambda d: d["revoked_at"] is not None, 20)
    outcome("signs the other device out", signed_out is not None)
    adb("shell", "input", "keyevent", "KEYCODE_BACK")
    adb("shell", "input", "keyevent", "KEYCODE_BACK")
    check("back to the list again", "All items", 15)

    if requester:
        approve_new_device(fixture, requester)

    # Sentinel: the lists and the password check come from the fake server.
    tap_text("⋮")
    tap_last("Sentinel")
    check("opens Sentinel", "Password health", 30)
    tap_text("Check online")
    check("finds the breached password", "Breached passwords", 60)
    check("and the breached website", "Breached websites", 10)
    tap_text("Breached passwords")
    check("names the item with the breached password", "GitHub", 15)
    adb("shell", "input", "keyevent", "KEYCODE_BACK")
    adb("shell", "input", "keyevent", "KEYCODE_BACK")
    check("the list shows Sentinel's summary", "serious alert", 30)

    # Autofill in another app.
    adb("shell", "settings", "put", "secure", "autofill_service", f"{PACKAGE}/.KeylessAutofillService")
    adb("shell", "am", "start", "-W", "-n", f"{FORM}/.LoginActivity")
    check("the other app's form opens", "Log in", 30)
    x, y = fields(FORM)[0]
    adb("shell", "input", "tap", str(x), str(y))
    if check("Keyless offers the app's login", "Form test", 30):
        # The suggestion: the title Keyless shows, in its own window.
        for t, _, (sx, sy), pkg in screen():
            if t == "Form test" and pkg != FORM:
                adb("shell", "input", "tap", str(sx), str(sy))
                break
        else:
            adb("shell", "input", "tap", str(x), str(y + 160))
        check("fills the username", "tester", 15)

    # Saving a new login.
    hide_keyboard()
    for index, value in ((0, "new-user"), (1, "new-pass-789")):
        fx, fy = fields(FORM)[index]
        adb("shell", "input", "tap", str(fx), str(fy))
        time.sleep(0.4)
        adb("shell", "input", "keyevent", "KEYCODE_MOVE_END")
        for _ in range(30):
            adb("shell", "input", "keyevent", "KEYCODE_DEL")
        adb("shell", "input", "text", value)
    hide_keyboard()
    tap_text("Log in", FORM)
    # "Save" for a new form, "Update" when it had been filled.
    if check("Android offers to save in Keyless", "in Keyless?", 30):
        tap_text("Save") or tap_text("Update")
        end = time.time() + 40
        saved = False
        while time.time() < end and not saved:
            saved = os.path.exists(writes_path) and '"insert"' in open(writes_path).read()
            time.sleep(2)
        results.append(("saves the new login on the server", saved, open(writes_path).read() if os.path.exists(writes_path) else "nothing written"))
        print(f"{'PASS' if saved else 'FAIL'} saves the new login on the server", flush=True)

    # Passkeys: Keyless as the provider for the form app's site (its Digital
    # Asset Links come from the fake server in this test build).
    component = f"{PACKAGE}/{PACKAGE}.KeylessCredentialService"
    adb("shell", "settings", "put", "secure", "credential_service", component)
    adb("shell", "settings", "put", "secure", "credential_service_primary", component)
    adb("shell", "am", "start", "-W", "-n", f"{FORM}/.LoginActivity")
    check("the form app is back", "Create passkey", 30)
    inserts_before = open(writes_path).read().count('"insert"') if os.path.exists(writes_path) else 0
    tap_text("Create passkey", FORM)
    created = drive_sheet(["Passkey created", "Create failed"], ["Create", "Continue", "Save", "Keyless", fixture["email"], "Create passkey"])
    results.append(("creates a passkey in Keyless", "Passkey created" in created, created))
    print(f"{'PASS' if 'Passkey created' in created else 'FAIL'} creates a passkey: {created}", flush=True)
    if "Passkey created" in created:
        stored = os.path.exists(writes_path) and open(writes_path).read().count('"insert"') > inserts_before
        results.append(("keeps the passkey on the server", stored, ""))
        tap_text("Sign in with passkey", FORM)
        used = drive_sheet(["Signed in with passkey", "Sign-in failed", "No signature"], ["Continue", "tester", "Sign in", "Use passkey", "Keyless"])
        results.append(("signs in with the passkey", "Signed in with passkey" in used, used))
        print(f"{'PASS' if 'Signed in with passkey' in used else 'FAIL'} signs in with the passkey: {used}", flush=True)

    failed = [r for r in results if not r[1]]
    summary = "%0A".join(f"{'✓' if ok else '✗'} {name}" for name, ok, _ in results)
    if failed:
        details = "%0A".join(f"{name}: {shown}" for name, _, shown in failed).replace("\n", " ")
        print(f"::error title=Android app end to end::{summary}%0A%0A{details}")
        print("::error title=Test site links::" + json.dumps(fixture.get("assetLinks", "none"))[:1500])
        if os.path.exists("mock.log"):
            asked = [line.strip() for line in open("mock.log") if "assetlinks" in line or "rpc/" in line][-10:]
            print("::error title=Fake server requests::" + "%0A".join(asked or ["no asset links asked"]))
        log = adb("logcat", "-d", "-s", "AndroidRuntime:E", check=False)[-3000:].replace("\n", "%0A")
        if log.strip():
            print(f"::error title=Android crash log::{log}")
        sys.exit(1)
    print(f"::notice title=Android app end to end::{summary}")


if __name__ == "__main__":
    main()
