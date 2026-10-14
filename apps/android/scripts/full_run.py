#!/usr/bin/env python3
"""The Android app end to end on an emulator (CI), against the fake server
(mock_server.py, reached at 10.0.2.2) and its made-up account: sign in, the
items synced, an item with its hidden password, lock and unlock, and
autofill in another app (formtest): filling a login and saving a new one.
Results are printed as GitHub annotations.

Usage: full_run.py <keyless-mock.apk> <formtest.apk> <fixture.json> <writes.jsonl>
"""

import json
import os
import re
import subprocess
import sys
import time
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


def main():
    keyless_apk, form_apk, fixture_path, writes_path = sys.argv[1:5]
    fixture = json.load(open(fixture_path))
    adb("install", "-r", keyless_apk)
    adb("install", "-r", form_apk)

    # Sign in.
    adb("shell", "am", "start", "-W", "-n", f"{PACKAGE}/.MainActivity")
    check("starts on the sign-in screen", "Sign in to Keyless", 60)
    type_into(PACKAGE, 0, fixture["email"])
    type_into(PACKAGE, 1, fixture["secretKey"])
    type_into(PACKAGE, 2, fixture["masterPassword"].replace(" ", "%s"))
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
    if check("Android offers to save in Keyless", "Save", 30):
        tap_text("Save")
        end = time.time() + 40
        saved = False
        while time.time() < end and not saved:
            saved = os.path.exists(writes_path) and '"insert"' in open(writes_path).read()
            time.sleep(2)
        results.append(("saves the new login on the server", saved, open(writes_path).read() if os.path.exists(writes_path) else "nothing written"))
        print(f"{'PASS' if saved else 'FAIL'} saves the new login on the server", flush=True)

    failed = [r for r in results if not r[1]]
    summary = "%0A".join(f"{'✓' if ok else '✗'} {name}" for name, ok, _ in results)
    if failed:
        details = "%0A".join(f"{name}: {shown}" for name, _, shown in failed).replace("\n", " ")
        print(f"::error title=Android app end to end::{summary}%0A%0A{details}")
        log = adb("logcat", "-d", "-s", "AndroidRuntime:E", check=False)[-3000:].replace("\n", "%0A")
        if log.strip():
            print(f"::error title=Android crash log::{log}")
        sys.exit(1)
    print(f"::notice title=Android app end to end::{summary}")


if __name__ == "__main__":
    main()
