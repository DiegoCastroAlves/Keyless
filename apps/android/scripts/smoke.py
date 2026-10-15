#!/usr/bin/env python3
"""Runs the APK on an emulator (CI) and walks through what works without an
account: the app starts and loads its Rust library, a keyless://setup link
fills the sign-in form, a bad Secret Key is refused by the client, and a
well-formed one goes through key derivation to the server, which refuses the
made-up account. Results are printed as GitHub annotations.

Usage: smoke.py <app.apk>
"""

import re
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

PACKAGE = "io.github.diegocastroalves.keyless"
# A well-formed Secret Key of no account (made for this test only).
KEY = "K1-D0NPNM-CYKQXE-NYFN0-HMDYM-7S6MG"
EMAIL = "smoke@example.invalid"
results = []


def adb(*args, check=True):
    return subprocess.run(["adb", *args], check=check, capture_output=True, text=True).stdout


def screen():
    """The visible nodes: (text, class, center)."""
    adb("shell", "uiautomator", "dump", "/sdcard/ui.xml", check=False)
    xml = adb("shell", "cat", "/sdcard/ui.xml", check=False)
    start = xml.find("<?xml")
    if start < 0:
        return []
    nodes = []
    for node in ET.fromstring(xml[start:].strip()).iter("node"):
        bounds = re.findall(r"\d+", node.get("bounds", ""))
        if len(bounds) == 4:
            x1, y1, x2, y2 = map(int, bounds)
            nodes.append((node.get("text", ""), node.get("class", ""), ((x1 + x2) // 2, (y1 + y2) // 2)))
    return nodes


def texts():
    return " | ".join(t for t, _, _ in screen() if t)


def wait_for(fragment, seconds=30):
    end = time.time() + seconds
    while time.time() < end:
        shown = texts()
        if fragment in shown:
            return shown
        time.sleep(2)
    return None


def check(name, fragment, seconds=30):
    shown = wait_for(fragment, seconds)
    ok = shown is not None
    results.append((name, ok, shown if ok else texts()))
    print(f"{'PASS' if ok else 'FAIL'} {name}", flush=True)
    return ok


def tap_text(text, tries=5):
    """Taps the node with this text, scrolling down to it (the CI's screen is small)."""
    for _ in range(tries):
        for t, _, (x, y) in screen():
            if t == text:
                adb("shell", "input", "tap", str(x), str(y))
                return True
        found = re.findall(r"(\d+)x(\d+)", adb("shell", "wm", "size", check=False))
        w, h = map(int, found[-1]) if found else (1080, 1920)
        adb("shell", "input", "swipe", str(w // 2), str(h * 3 // 4), str(w // 2), str(h * 2 // 5), "400")
        time.sleep(1)
    return False


def type_into(index, value):
    fields = [(x, y) for _, cls, (x, y) in screen() if cls == "android.widget.EditText"]
    x, y = fields[index]
    adb("shell", "input", "tap", str(x), str(y))
    time.sleep(0.5)
    adb("shell", "input", "text", value)
    time.sleep(0.5)
    # On a small screen the keyboard covers the next fields.
    hide_keyboard()


def hide_keyboard():
    """Back closes the soft keyboard; with none on screen it would leave the app."""
    if "mInputShown=true" in adb("shell", "dumpsys", "input_method", check=False):
        adb("shell", "input", "keyevent", "KEYCODE_BACK")
        time.sleep(1)


def main():
    apk = sys.argv[1]
    adb("install", "-r", apk)
    adb("shell", "am", "start", "-W", "-n", f"{PACKAGE}/.MainActivity")
    check("starts on the sign-in screen", "Sign in to Keyless", 60)

    # A setup link fills the form.
    adb("shell", f"am start -W -a android.intent.action.VIEW -d 'keyless://setup#email={EMAIL}&key={KEY}' {PACKAGE}")
    check("a setup link fills the email and Secret Key", "Secret Key received")
    check("with the link's email", EMAIL)

    # The made-up account: derivation runs, the server says no.
    type_into(1, "not-the-right-password-1")
    hide_keyboard()
    tap_text("Sign in")
    check("signing in reaches the server, which refuses the account", "Wrong email, Secret Key or master password.", 120)

    # A Secret Key with a typo is refused before anything is sent.
    tap_text("Type it instead")
    time.sleep(1)
    type_into(0, EMAIL)
    type_into(1, "K1-AAAAAA-BBBBBB-CCCCC-DDDDD-EEEEE")
    type_into(2, "whatever-password-2")
    hide_keyboard()
    tap_text("Sign in")
    check("a mistyped Secret Key is refused", "That Secret Key is not valid.", 60)

    # Another device: the request reaches the server and waits for approval.
    tap_text("Sign in with another device")
    check("signing in with another device waits for an approval", "Waiting for your other device", 40)

    failed = [r for r in results if not r[1]]
    summary = "%0A".join(f"{'✓' if ok else '✗'} {name}" for name, ok, _ in results)
    if failed:
        details = "%0A".join(f"{name}: screen was: {shown[:300]}" for name, _, shown in failed)
        print(f"::error title=Android on an emulator::{summary}%0A%0A{details}")
        log = adb("logcat", "-d", "-s", "AndroidRuntime:E", "keyless:*", check=False)[-3000:].replace("\n", "%0A")
        if log:
            print(f"::error title=Android crash log::{log}")
        sys.exit(1)
    print(f"::notice title=Android on an emulator::{summary}")


if __name__ == "__main__":
    main()
