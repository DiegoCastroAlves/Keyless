#!/usr/bin/env python3
"""Autofill end to end on an emulator (CI), against the fake server
(mock_server.py) and its made-up account, in another app (formtest):

- the autofill check screen: the autofill service, Credential Manager,
  notifications (asked for there), suggestions in the keyboard (turned on
  there; test builds start with them off);
- a credit card and an identity filled from the keyboard's chips (Gboard),
  in payment and address forms;
- a login filled from the list under the field, its one-time code copied
  (with a "Code copied" notification), then cleared after 90 seconds;
- the login of a site that names the app as its own (Digital Asset Links,
  by the app's certificate) suggested with no link, and not that of a
  site naming it with another certificate;
- "Search Keyless" in the list: another login chosen for the app, filled
  and linked to it (written to the server), then suggested by itself;
- passwords through Credential Manager: one that needs unlocking first,
  another chosen with "Search Keyless" (and linked to the app), and a new
  one saved in Keyless.

UIAutomator cannot read the keyboard's chips (its dump of every window
fails while they show), so a chip is found from Android's log (the
suggestions sent to the keyboard) and the keyboard's place on the screen,
and checked by what it fills.

Results are printed as GitHub annotations.

The fake server adds the fixture's logins of sites, card and identity
first (POST /test/items), at KEYLESS_MOCK (default http://127.0.0.1:8787),
and serves the sites' Digital Asset Links (the fixture's "assetLinks").

Usage: autofill_run.py <keyless-mock.apk> <formtest.apk> <fixture.json> <writes.jsonl>
"""

import base64
import hashlib
import hmac
import json
import os
import re
import struct
import subprocess
import sys
import time
import urllib.request
import xml.etree.ElementTree as ET

PACKAGE = "io.github.diegocastroalves.keyless"
FORM = "io.github.diegocastroalves.keyless.formtest"
TOTP_SECRET = "JBSWY3DPEHPK3PXP"
MOCK = os.environ.get("KEYLESS_MOCK", "http://127.0.0.1:8787")
results = []


def mock(path, body):
    """One of the fake server's test routes."""
    request = urllib.request.Request(MOCK + path, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(request, timeout=10) as answer:
        answer.read()


def adb(*args, check=True):
    # Bounded: when the emulator dies, adb waits for it for ever.
    return subprocess.run(["adb", *args], check=check, capture_output=True, text=True, timeout=300).stdout


def screen():
    """Every visible node, of every window: (text, class, center, package)."""
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
                # An icon button goes by its description (as a screen reader says it).
                nodes.append((node.get("text", "") or node.get("content-desc", ""), node.get("class", ""), ((x1 + x2) // 2, (y1 + y2) // 2), node.get("package", "")))
    return nodes


def texts():
    return " | ".join(n[0] for n in screen() if n[0])


def record(name, ok, details=""):
    results.append((name, ok, details))
    print(f"{'PASS' if ok else 'FAIL'} {name}" + ("" if ok or not details else f": {details[:400]}"), flush=True)
    return ok


def check(name, fragments, seconds=30):
    """Waits until the screen shows every fragment."""
    if isinstance(fragments, str):
        fragments = [fragments]
    end = time.time() + seconds
    shown = ""
    while time.time() < end:
        shown = texts()
        if all(f in shown for f in fragments):
            return record(name, True)
        time.sleep(2)
    missing = [f for f in fragments if f not in shown]
    return record(name, False, f"missing {missing} in: {shown}")


def tap(x, y):
    adb("shell", "input", "tap", str(x), str(y))


def tap_text(text, package=None, other_than=None):
    for t, _, (x, y), pkg in screen():
        if t == text and (package is None or pkg == package) and (other_than is None or pkg != other_than):
            tap(x, y)
            return True
    return False


def wait_tap(text, package=None, other_than=None, seconds=30):
    end = time.time() + seconds
    while time.time() < end:
        if tap_text(text, package, other_than):
            return True
        time.sleep(2)
    return False


_size = []


def screen_size():
    if not _size:
        found = re.findall(r"(\d+)x(\d+)", adb("shell", "wm", "size", check=False))
        _size.extend(map(int, found[-1]) if found else (1080, 1920))
    return _size


_density = []


def density():
    """Pixels per inch, as Android counts them (160: one pixel per dp)."""
    if not _density:
        found = re.findall(r"density: (\d+)", adb("shell", "wm", "density", check=False))
        _density.append(int(found[-1]) if found else 420)
    return _density[0]


def scroll_to(text, tries=8):
    """Scrolls down until `text` shows above the screen's lower fifth (the
    CI's emulator has a small screen; a node at its very edge may not take a tap)."""
    w, h = screen_size()
    for _ in range(tries):
        ys = [y for t, _, (_, y), _ in screen() if text in t]
        if ys and min(ys) < h * 4 // 5:
            return True
        adb("shell", "input", "swipe", str(w // 2), str(h * 3 // 4), str(w // 2), str(h * 2 // 5), "400")
        time.sleep(1)
    return text in texts()


def check_form(name, fragments, seconds=20):
    """As check, for a form taller than the screen (the CI's is small): the
    keyboard hidden, what the form shows read while scrolling down."""
    w, h = screen_size()
    end = time.time() + seconds
    seen = ""
    while time.time() < end:
        hide_keyboard()
        for _ in range(4):
            seen += " | " + texts()
            if all(f in seen for f in fragments):
                return record(name, True)
            adb("shell", "input", "swipe", str(w // 2), str(h * 3 // 4), str(w // 2), str(h * 2 // 5), "400")
            time.sleep(1)
        # Back to the top, for the next look.
        adb("shell", "input", "swipe", str(w // 2), str(h * 2 // 7), str(w // 2), str(h * 3 // 4), "100")
        time.sleep(2)
    missing = [f for f in fragments if f not in seen]
    return record(name, False, f"missing {missing} in: {seen}")


def fields(package):
    return [(x, y) for _, cls, (x, y), pkg in screen() if cls == "android.widget.EditText" and pkg == package]


def type_into(package, index, value):
    x, y = fields(package)[index]
    tap(x, y)
    time.sleep(0.6)
    adb("shell", "input", "text", value)
    time.sleep(0.4)
    # On a small screen the keyboard covers the next fields.
    hide_keyboard()


def hide_keyboard():
    # Back may close autofill's list under the field first.
    for _ in range(3):
        if "mInputShown=true" not in adb("shell", "dumpsys", "input_method", check=False):
            return
        adb("shell", "input", "keyevent", "KEYCODE_BACK")
        time.sleep(1)


def start(activity, *extras):
    """Starts one of formtest's forms afresh."""
    adb("shell", "am", "start", "-S", "-W", "-n", f"{FORM}/.{activity}", *extras)
    time.sleep(1)


def open_check_screen():
    # Not stopped first: Keyless would lock.
    adb("shell", "am", "start", "-W", "-n", f"{PACKAGE}/.AutofillCheckActivity")
    time.sleep(1)
    w, h = screen_size()
    adb("shell", "input", "swipe", str(w // 2), str(h * 2 // 7), str(w // 2), str(h * 3 // 4), "200")


def pick_from_list(name, text, field_index=0, seconds=30):
    """Taps a field of the form, then Keyless's suggestion showing `text`
    in the list under the field (Android's window, not the form's)."""
    x, y = fields(FORM)[field_index]
    tap(x, y)
    if wait_tap(text, other_than=FORM, seconds=seconds):
        return record(name, True)
    return record(name, False, texts())


def keyboard_top():
    """Where the keyboard starts on the screen: its touchable part from
    edge to edge. Gboard's first inline suggestions bring a tip above it,
    a little narrower ("Autofill suggestions are now above your keyboard")."""
    out = adb("shell", "dumpsys", "window", "InputMethod", check=False)
    found = re.search(r"touchable region=SkRegion\(((?:\(\d+,\d+,\d+,\d+\))+)\)", out)
    if not found:
        return None
    rects = [tuple(map(int, r)) for r in re.findall(r"\((\d+),(\d+),(\d+),(\d+)\)", found.group(1))]
    wide = [y1 for x1, y1, x2, _ in rects if x1 <= 0 and x2 >= screen_size()[0]]
    return min(wide) if wide else rects[0][1]


def pick_chip(name, filled, field_index=0, seconds=30):
    """Taps a field of the form, waits until Android sends Keyless's
    suggestions to the keyboard as chips, and taps the first chip (at the
    start of the keyboard's suggestion strip) until the field shows `filled`."""
    adb("logcat", "-c", check=False)
    x, y = fields(FORM)[field_index]
    tap(x, y)
    end = time.time() + seconds
    sent = None
    while time.time() < end and not sent:
        log = adb("logcat", "-d", check=False)
        sent = re.search(r"Send inline response: ([1-9]\d*)", log)
        time.sleep(1)
    if not record(f"{name}: chips sent to the keyboard", sent is not None, "no inline response in the log"):
        return False
    width = screen_size()[0]
    # The keyboard opened for the first time may still be settling (as on
    # the CI's emulator): tapped again while the field is empty.
    for _ in range(3):
        time.sleep(2)
        top = keyboard_top()
        if top is None:
            continue
        # Gboard: a button at the left, then the chips, about 22 dp below its top.
        tap(int(width * 0.31), top + 22 * density() // 160)
        time.sleep(2)
        if filled in texts():
            break
        print(f"  {name}: the chip at {top} filled nothing, again", flush=True)
    if top is None:
        return record(f"{name}: keyboard found", False, "no keyboard window")
    return True


def totp_codes(seconds):
    """The codes around `seconds` for the fixture's one-time password."""
    key = base64.b32decode(TOTP_SECRET)
    codes = []
    for step in range(-2, 2):
        counter = int(seconds // 30) + step
        digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
        offset = digest[-1] & 0x0F
        codes.append("%06d" % ((struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 1_000_000))
    return codes


def clipboard():
    """What formtest reads from the clipboard (it must be in front)."""
    hide_keyboard()
    tap_text("Paste", FORM)
    time.sleep(1.5)
    for t, *_ in screen():
        if t.startswith("Clipboard: ["):
            return t[len("Clipboard: ["):-1]
    return None


def inserts(path):
    return open(path).read().count('"insert"') if os.path.exists(path) else 0


def updates(path, item):
    """How many times the app uploaded a change of `item`."""
    if not os.path.exists(path):
        return 0
    return sum(1 for line in open(path) if json.loads(line).get("kind") == "update" and json.loads(line).get("id") == item)


def form_shows(name, text, seconds=20):
    """Whether the form app itself shows `text` (not Keyless's list over it)."""
    end = time.time() + seconds
    while time.time() < end:
        if any(t == text and pkg == FORM for t, _, _, pkg in screen()):
            return record(name, True)
        time.sleep(1)
    return record(name, False, texts())


def search_in_sheet(title, username, seconds=90):
    """Credential Manager's sheet: its sign-in options, "Search Keyless"
    there (scrolled to), then the login `title` in Keyless's list, searched
    for by `username`; returns what the form app says."""
    width, height = screen_size()
    end = time.time() + seconds
    while time.time() < end:
        nodes = screen()
        shown = [t for t, *_ in nodes]
        said = next((t for t, _, _, pkg in nodes if pkg == FORM and ("Got password for" in t or "Get failed" in t)), None)
        if said:
            return said
        if "Choose a login" in shown:
            # Searched for (the list may not fit a small screen), by another
            # text than the one tapped: the search box shows it too.
            type_into(PACKAGE, 0, username)
            wait_tap(title, PACKAGE, seconds=10)
        elif tap_text("Search Keyless", other_than=FORM):
            pass
        elif "Go back to the previous page" not in shown and tap_text("Sign-in options", other_than=FORM):
            pass
        else:
            # Further down the sheet: Keyless's action is under the logins.
            adb("shell", "input", "swipe", str(width // 2), str(int(height * 0.8)), str(width // 2), str(int(height * 0.4)), "300")
        time.sleep(2)
    return "timed out on: " + texts()[:300]


def drive_sheet(done, buttons, seconds=90, typing=None):
    """Goes through Credential Manager's sheets (tapping the first of
    `buttons` shown outside the form app) until the form app shows one of
    `done`. `typing` = (text on the screen, value): typed into Keyless's
    field once that text shows (its unlock screen)."""
    end = time.time() + seconds
    typed = False
    while time.time() < end:
        nodes = screen()
        for text, _, _, pkg in nodes:
            if pkg == FORM and any(d in text for d in done):
                return text
        if typing and not typed and any(t == typing[0] for t, *_ in nodes):
            type_into(PACKAGE, 0, typing[1])
            hide_keyboard()
            tap_text("Unlock", PACKAGE)
            typed = True
            time.sleep(3)
            continue
        for wanted in buttons:
            hit = next(((x, y) for t, _, (x, y), pkg in nodes if pkg != FORM and t == wanted), None)
            if hit:
                tap(*hit)
                break
        time.sleep(2)
    return "timed out on: " + texts()[:300]


def main():
    keyless_apk, form_apk, fixture_path, writes_path = sys.argv[1:5]
    fixture = json.load(open(fixture_path))
    password = fixture["masterPassword"].replace(" ", "%s")
    mock("/test/items", {"key": "autofillItems"})
    # Gboard as on a new phone, as the CI's emulator (with its first-run tips).
    adb("shell", "pm", "clear", "com.google.android.inputmethod.latin", check=False)
    adb("uninstall", PACKAGE, check=False)
    adb("install", "-r", keyless_apk)
    adb("install", "-r", form_apk)
    adb("shell", "settings", "put", "secure", "autofill_service", f"{PACKAGE}/.KeylessAutofillService")
    # Set anew, so Credential Manager sees the new install.
    component = f"{PACKAGE}/{PACKAGE}.KeylessCredentialService"
    for key in ("credential_service", "credential_service_primary"):
        adb("shell", "settings", "delete", "secure", key, check=False)
        adb("shell", "settings", "put", "secure", key, component)

    # Sign in.
    adb("shell", "am", "start", "-W", "-n", f"{PACKAGE}/.MainActivity")
    check("starts on the sign-in screen", "Sign in to Keyless", 60)
    type_into(PACKAGE, 0, fixture["email"])
    type_into(PACKAGE, 1, fixture["secretKey"])
    type_into(PACKAGE, 2, password)
    hide_keyboard()
    tap_text("Sign in")
    # Their rows in the list of every item (Items > All items).
    wait_tap("Items", PACKAGE, seconds=120)
    wait_tap("All items", PACKAGE, seconds=20)
    end = time.time() + 120
    synced = False
    while time.time() < end and not synced:
        synced = scroll_to("Test Visa", tries=3) and scroll_to("Tess Tester", tries=3)
        if not synced:
            time.sleep(2)
    record("signs in and syncs the card and the identity", synced, texts())

    # The autofill check screen (also the gear in Android's autofill settings).
    open_check_screen()
    check("the check screen sees the autofill service", ["Autofill check", "Keyless is the autofill service."], 30)
    # Android 14's first release answers "off" for a provider turned on with
    # `settings put` (fixed later): only the section is checked.
    check("the check screen tells about Credential Manager", ["Passwords and passkeys", "in Credential Manager.", "Open Credential Manager settings"], 10)
    scroll_to("Show suggestions in the keyboard")
    check("keyboard chips start off in a test build", "Off: suggestions show in a list under the field.", 10)
    tap_text("Show suggestions in the keyboard", PACKAGE)
    check("turns keyboard chips on", "Tap a field in another app", 10)
    scroll_to("Allow notifications")
    if check("notifications are not allowed yet", "Keyless may not notify you.", 10):
        tap_text("Allow notifications", PACKAGE)
        # Android's permission dialog.
        wait_tap("Allow", other_than=PACKAGE, seconds=20)
        check("notifications allowed from the check screen", "Keyless may notify you.", 20)
    scroll_to("chrome://settings/autofill")
    check("the check screen explains Chrome's setting", ["Open Chrome's autofill settings", "chrome://settings/autofill"], 10)

    # Nothing on the clipboard: the keyboard would show it in the first chip.
    start("LoginActivity")
    if wait_tap("Clear clipboard", FORM, seconds=20):
        check("the clipboard is empty", "Clipboard cleared", 10)

    # A credit card in a payment form, from a chip in the keyboard.
    start("CardActivity")
    check("the payment form opens", "Payment", 30)
    if pick_chip("Keyless suggests the card", "4111111111111111"):
        check_form("fills the card from the chip", ["4111111111111111", "07/31", "TESS TESTER", "•••"], 20)
    hide_keyboard()

    # An identity in an address form, from a chip.
    start("AddressActivity")
    check("the address form opens", "Shipping address", 30)
    if pick_chip("Keyless suggests the identity", "Tess"):
        check_form("fills the identity from the chip", ["Tess", "Tester", "tess@example.test", "+5511987654321", "Rua das Flores 123", "Springfield", "SP", "01234-567", "Brasil"], 20)
    hide_keyboard()

    open_check_screen()
    scroll_to("Show suggestions in the keyboard")
    check("the check screen sees the keyboard's chips", "showed Keyless's suggestions in the keyboard the last time", 20)
    # Back to the list: it tells logins apart by their username.
    tap_text("Show suggestions in the keyboard", PACKAGE)
    check("turns keyboard chips off", "Off: suggestions show in a list under the field.", 10)

    # A login with a one-time password: filled, and its code copied.
    start("LoginActivity")
    check("the form app opens", "Log in", 30)
    copied_at = None
    if pick_from_list("Keyless suggests the app's login in the list", "tester"):
        copied_at = time.time()
        check("fills the login", "tester", 20)
        dump = adb("shell", "dumpsys", "notification", "--noredact", check=False)
        record("says the code was copied", "Code copied" in dump and PACKAGE in dump, "no notification")
        pasted = clipboard()
        record("copies the one-time code", pasted in totp_codes(time.time()), f"clipboard: {pasted}")

    # The code leaves the clipboard after 90 seconds.
    if copied_at is not None:
        start("LoginActivity")
        time.sleep(max(0, copied_at + 100 - time.time()))
        pasted = clipboard()
        record("clears the code from the clipboard", pasted == "", f"clipboard: {pasted}")

    # The login of a site that names the app as its own (formtest.example),
    # with no link to the app; not that of a site naming it with another
    # certificate (formtest.test).
    start("LoginActivity")
    check("the form app opens for a site's login", "Log in", 30)
    if pick_from_list("suggests the login of a site that names the app", "shopper"):
        form_shows("fills the login of the site that names the app", "shopper")
    start("LoginActivity")
    check("the form app opens once more", "Log in", 30)
    x, y = fields(FORM)[0]
    tap(x, y)
    end = time.time() + 30
    shown = ""
    while time.time() < end and "shopper" not in shown:
        time.sleep(2)
        shown = texts()
    record("does not suggest the login of a site naming another certificate", "shopper" in shown and "impostor" not in shown, shown)
    hide_keyboard()

    # Another login, chosen with "Search Keyless" and linked to the app: then
    # it shows by itself. (GitHub's login has a website only, no app.)
    github = "cccccccc-0000-4000-8000-000000000002"
    before = updates(writes_path, github)
    start("LoginActivity")
    check("the form app opens for Search Keyless", "Log in", 30)
    if pick_from_list("offers Search Keyless in the list", "Search Keyless"):
        if check("lists the logins to choose from", ["Choose a login", "Link Form test to this login", "Suggested", "All logins"], 30):
            # Searched for (the list may not fit a small screen), by another
            # text than the one tapped: the search box shows it too.
            type_into(PACKAGE, 0, "octo")
            wait_tap("GitHub", PACKAGE, seconds=10)
            form_shows("fills the login chosen", "octo")
            end = time.time() + 30
            while time.time() < end and updates(writes_path, github) <= before:
                time.sleep(2)
            record("links the app to the login on the server", updates(writes_path, github) > before, "nothing written")
            start("LoginActivity")
            check("the form app opens again", "Log in", 30)
            if pick_from_list("suggests the linked login by itself", "octo"):
                form_shows("fills the linked login", "octo")

    # Passwords through Credential Manager, Keyless locked first.
    adb("shell", "am", "start", "-W", "-n", f"{PACKAGE}/.MainActivity")
    if wait_tap("Account", PACKAGE, seconds=20):
        time.sleep(1)
        wait_tap("Lock", PACKAGE, seconds=10)
        check("locks", "Keyless is locked", 20)
    start("LoginActivity")
    check("the form app is back", "Get password", 30)
    tap_text("Get password", FORM)
    got = drive_sheet(["Got password for", "Get failed"], ["Unlock Keyless to fill", "tester", "Continue", "Sign in"], typing=("Keyless is locked", password))
    record("gives a password through Credential Manager after unlocking", "Got password for tester" in got, got)

    # Another login through Credential Manager: "Search Keyless", then the
    # bank's login, linked to the app.
    bank = "cccccccc-0000-4000-8000-000000000003"
    before = updates(writes_path, bank)
    start("LoginActivity")
    hide_keyboard()
    tap_text("Get password", FORM)
    got = search_in_sheet("Bank", "client")
    record("gives a password chosen with Search Keyless in Credential Manager", "Got password for client" in got, got)
    end = time.time() + 30
    while time.time() < end and updates(writes_path, bank) <= before:
        time.sleep(2)
    record("links the app to the login chosen in Credential Manager", updates(writes_path, bank) > before, "nothing written")

    before = inserts(writes_path)
    start("LoginActivity", "--es", "username", "cm-user", "--es", "password", "cm-pass-789")
    hide_keyboard()
    scroll_to("Save password")
    tap_text("Save password", FORM)
    saved = drive_sheet(["Password saved", "Save failed"], ["Save", "Create", "Continue", "Keyless", fixture["email"]])
    record("saves a password through Credential Manager", "Password saved" in saved, saved)
    end = time.time() + 30
    while time.time() < end and inserts(writes_path) <= before:
        time.sleep(2)
    record("keeps the new password on the server", inserts(writes_path) > before, "nothing written")

    failed = [r for r in results if not r[1]]
    summary = "%0A".join(f"{'✓' if ok else '✗'} {name}" for name, ok, _ in results)
    if failed:
        details = "%0A".join(f"{name}: {shown}" for name, _, shown in failed).replace("\n", " ")
        print(f"::error title=Android autofill::{summary}%0A%0A{details}")
        log = adb("logcat", "-d", "-s", "AndroidRuntime:E", check=False)
        crashes = [block for block in log.split("FATAL EXCEPTION") if PACKAGE in block]
        if crashes:
            print("::error title=Android crash log::" + crashes[-1][-3000:].replace("\n", "%0A"))
        sys.exit(1)
    print(f"::notice title=Android autofill::{summary}")


if __name__ == "__main__":
    main()
