"""Renders the email templates for a preview, with the subset of Go's
text/template they use ({{ $lang := printf "%v" .Data.lang }}, if / else if /
else / end on `eq $lang "x"` or a .Data field, and plain fields). Raises on
anything else or on unbalanced blocks.

Usage: python3 preview.py <out dir>  (open the HTML files it writes there)"""

import re
import sys
from pathlib import Path

TOKEN = re.compile(r"\{\{(-?)\s*(.*?)\s*(-?)\}\}", re.S)


def tokenize(src):
    out, pos = [], 0
    for m in TOKEN.finditer(src):
        text = src[pos:m.start()]
        if m.group(1):
            text = text.rstrip()
        if out and out[-1][0] == "trim-next":
            out.pop()
            text = text.lstrip()
        out.append(("text", text))
        out.append(("action", m.group(2)))
        if m.group(3):
            out.append(("trim-next", None))
        pos = m.end()
    text = src[pos:]
    if out and out[-1][0] == "trim-next":
        out.pop()
        text = text.lstrip()
    out.append(("text", text))
    return out


def parse(tokens, i=0, stop=("end", "else")):
    """Returns (nodes, index, the action that stopped it)."""
    nodes = []
    while i < len(tokens):
        kind, value = tokens[i]
        i += 1
        if kind == "text":
            nodes.append(("text", value))
            continue
        word = value.split()[0]
        if word in stop or value.startswith("else"):
            return nodes, i, value
        if word == "if":
            branches = []
            cond = value[3:].strip()
            while True:
                body, i, ended = parse(tokens, i)
                branches.append((cond, body))
                if ended == "end":
                    break
                if ended == "else":
                    cond = None
                elif ended.startswith("else if "):
                    cond = ended[len("else if "):].strip()
                else:
                    raise ValueError(f"unexpected {ended!r}")
            nodes.append(("if", branches))
        elif value.startswith("$lang :="):
            nodes.append(("setlang", None))
        elif value.startswith("."):
            nodes.append(("field", value))
        else:
            raise ValueError(f"unsupported action {value!r}")
    return nodes, i, None


def truth(cond, data, env):
    m = re.fullmatch(r'eq \$lang "([^"]*)"', cond)
    if m:
        return env["lang"] == m.group(1)
    m = re.fullmatch(r"\.Data\.(\w+)", cond)
    if m:
        return bool(data["Data"].get(m.group(1)))
    raise ValueError(f"unsupported condition {cond!r}")


def render(nodes, data, env):
    out = []
    for kind, value in nodes:
        if kind == "text":
            out.append(value)
        elif kind == "setlang":
            lang = data["Data"].get("lang")
            env["lang"] = "<nil>" if lang is None else str(lang)
        elif kind == "field":
            out.append(str(data[value[1:]]))
        elif kind == "if":
            for cond, body in value:
                if cond is None or truth(cond, data, env):
                    out.append(render(body, data, env))
                    break
    return "".join(out)


def run(path, data):
    nodes, i, ended = parse(tokenize(Path(path).read_text()))
    if ended is not None:
        raise ValueError(f"{path}: stray {ended!r}")
    return render(nodes, data, {})


if __name__ == "__main__":
    src, out = Path(__file__).parent, Path(sys.argv[1])
    fonts = (src.parent.parent / "apps/site/dist/fonts").resolve()
    out.mkdir(parents=True, exist_ok=True)
    base = {
        "Token": "482913",
        "ConfirmationURL": "https://ednfhgbjtgkrmtnudcjr.supabase.co/auth/v1/verify?token=pkce_3f9a1c&type=signup&redirect_to=https://keyless.diegoalves.dev/",
        "Email": "diego@exemplo.com",
        "NewEmail": "diego.novo@exemplo.com",
    }
    cases = {
        "confirmation-share": ("confirmation", {"keyless_share_recipient": True}),
        "confirmation-signup": ("confirmation", {}),
        "magic_link": ("magic_link", {"keyless_share_recipient": True}),
        "email_change": ("email_change", {}),
    }
    for name, (template, meta) in cases.items():
        for lang in ("pt-BR", "en", "es", None):
            data = dict(base, Data=dict(meta, **({"lang": lang} if lang else {})))
            html = run(src / f"{template}.html", data).replace("https://keyless.diegoalves.dev/fonts/", f"file://{fonts}/")
            subject = run(src / f"{template}.subject.txt", data).strip()
            (out / f"{name}.{lang or 'nolang'}.html").write_text(html)
            print(f"{name}.{lang or 'nolang'}: {subject}")
