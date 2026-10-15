#!/usr/bin/env python3
"""The app's icons from the desktop's Lucide set (ISC License): each one in
res/drawable as a vector drawable, so both apps draw the same icons.

    python3 apps/android/scripts/lucide_icons.py

reads apps/desktop/node_modules/lucide-react (run pnpm install there first)
and writes every icon in ICONS; "name=lucide-name:filled" fills the shape
too (a favorite's star). The icon files are read as text: no code runs.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
LUCIDE = ROOT / "apps/desktop/node_modules/lucide-react/dist/esm/icons"
DRAWABLE = ROOT / "apps/android/app/src/main/res/drawable"

ICONS = """
ic_back=arrow-left ic_chevron_right=chevron-right ic_close=x ic_copy=copy ic_download=download ic_edit=pencil
ic_external=external-link ic_eye=eye ic_eye_off=eye-off ic_file_down=file-down ic_file_up=file-up ic_filter=filter
ic_fingerprint=fingerprint-pattern ic_lock=lock ic_log_out=log-out ic_more=ellipsis-vertical ic_paperclip=paperclip
ic_plus=plus ic_search=search ic_shield=shield-check ic_smartphone=smartphone ic_sort=arrow-down-wide-narrow
ic_star=star ic_star_filled=star:filled ic_trash=trash ic_user=user ic_scan=scan-qr-code
ic_home=house ic_items=layout-grid ic_settings=settings ic_info=info ic_history=history ic_sparkles=sparkles
ic_tag=tag ic_archive=archive ic_setup=list-checks ic_customize=sliders-horizontal ic_autofill=text-cursor-input
ic_check=check ic_chevron_down=chevron-down ic_chevron_up=chevron-up ic_alert=shield-alert ic_monitor=monitor ic_globe=globe
ic_cat_login=key-round ic_cat_password=asterisk ic_cat_secure_note=sticky-note ic_cat_credit_card=credit-card
ic_cat_identity=id-card ic_cat_bank_account=landmark ic_cat_api_credential=braces ic_cat_database=database
ic_cat_server=server ic_cat_ssh_key=terminal ic_cat_software_license=award ic_cat_wireless_router=wifi
ic_cat_email_account=mail ic_cat_passport=book-user ic_cat_driver_license=car ic_cat_membership=badge-check
ic_cat_crypto_wallet=wallet ic_cat_medical_record=heart-pulse ic_cat_document=file-text ic_cat_other=box
""".split()


def num(v):
    return float(v)


def fmt(x):
    s = ("%.3f" % x).rstrip("0").rstrip(".")
    return s if s not in ("-0", "") else "0"


NUMBER = re.compile(r"-?(?:\d+\.?\d*|\.\d+)(?:[eE][-+]?\d+)?")

def normalized(d):
    """Path data with every value spelled apart: Android misreads an arc's
    flags written together ("a4 4 0 00-8 0")."""
    out, pos, cmd, arg = [], 0, "", 0
    while pos < len(d):
        c = d[pos]
        if c in " ,\t\n":
            pos += 1
        elif c.isalpha():
            cmd, arg = c, 0
            out.append(c)
            pos += 1
        elif cmd in "Aa" and arg % 7 in (3, 4):
            out.append(c)
            arg += 1
            pos += 1
        else:
            m = NUMBER.match(d, pos)
            if not m:
                raise SystemExit("bad path data at %d: %s" % (pos, d))
            out.append(m.group(0))
            arg += 1
            pos = m.end()
    text = ""
    for token in out:
        text += token if (token.isalpha() or not text or text[-1].isalpha()) else " " + token
    return text


def shape(tag, a):
    return normalized(raw_shape(tag, a))


def raw_shape(tag, a):
    if tag == "path": return a["d"]
    if tag == "circle":
        cx, cy, r = num(a["cx"]), num(a["cy"]), num(a["r"])
        return f"M{fmt(cx - r)},{fmt(cy)}a{fmt(r)},{fmt(r)} 0 1,0 {fmt(2 * r)},0a{fmt(r)},{fmt(r)} 0 1,0 {fmt(-2 * r)},0"
    if tag == "ellipse":
        cx, cy, rx, ry = num(a["cx"]), num(a["cy"]), num(a["rx"]), num(a["ry"])
        return f"M{fmt(cx - rx)},{fmt(cy)}a{fmt(rx)},{fmt(ry)} 0 1,0 {fmt(2 * rx)},0a{fmt(rx)},{fmt(ry)} 0 1,0 {fmt(-2 * rx)},0"
    if tag == "rect":
        x, y, w, h = num(a.get("x", "0")), num(a.get("y", "0")), num(a["width"]), num(a["height"])
        rx = num(a.get("rx", a.get("ry", "0"))); ry = num(a.get("ry", a.get("rx", "0")))
        rx, ry = min(rx, w / 2), min(ry, h / 2)
        if rx == 0:
            return f"M{fmt(x)},{fmt(y)}h{fmt(w)}v{fmt(h)}h{fmt(-w)}z"
        return (f"M{fmt(x + rx)},{fmt(y)}h{fmt(w - 2 * rx)}a{fmt(rx)},{fmt(ry)} 0 0,1 {fmt(rx)},{fmt(ry)}"
                f"v{fmt(h - 2 * ry)}a{fmt(rx)},{fmt(ry)} 0 0,1 {fmt(-rx)},{fmt(ry)}h{fmt(-(w - 2 * rx))}"
                f"a{fmt(rx)},{fmt(ry)} 0 0,1 {fmt(-rx)},{fmt(-ry)}v{fmt(-(h - 2 * ry))}a{fmt(rx)},{fmt(ry)} 0 0,1 {fmt(rx)},{fmt(-ry)}z")
    if tag == "line":
        return f"M{a['x1']},{a['y1']}L{a['x2']},{a['y2']}"
    if tag in ("polyline", "polygon"):
        pts = re.findall(r"-?[\d.]+", a["points"])
        pairs = [f"{pts[i]},{pts[i + 1]}" for i in range(0, len(pts), 2)]
        return "M" + "L".join(pairs) + ("z" if tag == "polygon" else "")
    raise SystemExit("unknown shape " + tag)


def main():
    src, out = LUCIDE, DRAWABLE
    for spec in sys.argv[1:] or ICONS:
        name, lucide = spec.split("=")
        lucide, _, style = lucide.partition(":")
        text = (src / f"{lucide}.mjs").read_text()
        # Aliases re-export another icon.
        while (alias := re.search(r"export \{ default \} from '\./([\w-]+)\.mjs'", text)):
            text = (src / f"{alias.group(1)}.mjs").read_text()
        node = text.split("node:", 1)[1].split("\n};", 1)[0]
        paths = []
        for tag, attrs in re.findall(r'\[\s*"(\w+)",\s*\{([^}]*)\}\s*\]', node):
            a = dict(re.findall(r'(\w+):\s*"([^"]*)"', attrs))
            filled = a.get("fill") == "currentColor" or style == "filled"
            fill = '\n        android:fillColor="#FF000000"' if filled else ""
            paths.append(f'''    <path
        android:pathData="{shape(tag, a)}"{fill}
        android:strokeColor="#FF000000"
        android:strokeWidth="2"
        android:strokeLineCap="round"
        android:strokeLineJoin="round" />''')
        if not paths:
            raise SystemExit("no shapes in " + lucide)
        what = f'Lucide "{lucide}"' + (", filled" if style == "filled" else "")
        (out / f"{name}.xml").write_text(f'''<?xml version="1.0" encoding="utf-8"?>
<!-- {what} (ISC License, lucide.dev), as on the desktop app; made by scripts/lucide_icons.py. -->
<vector xmlns:android="http://schemas.android.com/apk/res/android"
    android:width="24dp"
    android:height="24dp"
    android:viewportWidth="24"
    android:viewportHeight="24">
{chr(10).join(paths)}
</vector>
''')
        print(name, lucide)


if __name__ == "__main__":
    main()
