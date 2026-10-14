"""Builds the Supabase Auth email templates (supabase/templates/*.html) in
the site's look: paper and ink, Instrument Serif titles, IBM Plex text, the
teal accent and the redaction bars. Texts in pt-BR (default), en and es,
picked by the user's metadata (`lang`).

Usage: python3 build.py (writes next to this file; see README.md)"""

import sys
from pathlib import Path

OUT = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).parent
SITE = "https://keyless.diegoalves.dev"

PAPER, PAPER2, INK, INK2, RULE, ACCENT = "#f3f0e8", "#e8e3d6", "#15171a", "#555a61", "#cdc5b4", "#0b7366"
SERIF = "'Instrument Serif', 'Iowan Old Style', 'Palatino Linotype', Georgia, serif"
SANS = "'IBM Plex Sans', -apple-system, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif"
MONO = "'IBM Plex Mono', ui-monospace, Menlo, Consolas, 'Courier New', monospace"

LANG = '{{- $lang := printf "%v" .Data.lang -}}'


def L(pt, en, es):
    """The text in the email's language."""
    return f'{{{{ if eq $lang "en" }}}}{en}{{{{ else if eq $lang "es" }}}}{es}{{{{ else }}}}{pt}{{{{ end }}}}'


def redact(text):
    return f'<span class="k-redact" style="background:{INK};color:{PAPER};padding:1px 6px;white-space:nowrap;">{text}</span>'


def head():
    fonts = [
        ("Instrument Serif", "instrument-serif-400", 400, "normal"),
        ("Instrument Serif", "instrument-serif-400-italic", 400, "italic"),
        ("IBM Plex Sans", "ibm-plex-sans-400", 400, "normal"),
        ("IBM Plex Sans", "ibm-plex-sans-600", 600, "normal"),
        ("IBM Plex Mono", "ibm-plex-mono-500", 500, "normal"),
    ]
    faces = "\n".join(
        f'@font-face {{ font-family: "{family}"; src: url("{SITE}/fonts/{file}.woff2") format("woff2"); font-weight: {weight}; font-style: {style}; }}'
        for family, file, weight, style in fonts
    )
    return f"""<!doctype html>
<html lang="{L("pt-BR", "en", "es")}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<meta name="supported-color-schemes" content="light dark">
<title>Keyless</title>
<style>
{faces}
@media (prefers-color-scheme: dark) {{
  .k-bg {{ background: #0f1113 !important; }}
  .k-ink {{ color: #ebe6da !important; }}
  .k-ink2 {{ color: #a19f97 !important; }}
  .k-accent {{ color: #3fd6c2 !important; }}
  .k-box {{ background: #171a1d !important; border-color: #ebe6da !important; }}
  .k-line {{ border-color: #ebe6da !important; }}
  .k-rule {{ border-color: #2b2f34 !important; }}
  .k-redact {{ background: #000000 !important; color: #ebe6da !important; }}
  .k-bar {{ color: #000000 !important; }}
  .k-btn {{ background: #ebe6da !important; border-color: #ebe6da !important; box-shadow: 4px 4px 0 #3fd6c2 !important; }}
  .k-btn a {{ color: #0f1113 !important; }}
}}
@media (max-width: 480px) {{
  .k-title {{ font-size: 36px !important; }}
  .k-code {{ font-size: 30px !important; letter-spacing: 0.22em !important; }}
}}
</style>
</head>"""


def page(preheader, eyebrow, title, blocks):
    """The shared frame: logo, eyebrow, title, the email's blocks, footer."""
    return f"""{LANG}
{head()}
<body class="k-bg" style="margin:0;padding:0;background:{PAPER};">
<div style="display:none;max-height:0;overflow:hidden;mso-hide:all;">{preheader}</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" class="k-bg" style="background:{PAPER};">
<tr><td align="center" style="padding:32px 16px 40px;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="max-width:560px;">
<tr><td class="k-line" style="padding:0 0 18px;border-bottom:1px solid {INK};">
  <table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr>
    <td style="padding:0 10px 0 0;vertical-align:middle;"><img src="{SITE}/icon-128.png" width="28" height="28" alt="" style="display:block;border:0;"></td>
    <td class="k-ink" style="vertical-align:middle;font-family:{SERIF};font-size:26px;line-height:1;color:{INK};letter-spacing:-0.01em;">keyless</td>
  </tr></table>
</td></tr>
<tr><td class="k-ink2" style="padding:32px 0 0;font-family:{MONO};font-size:11px;line-height:1.5;font-weight:500;letter-spacing:0.14em;text-transform:uppercase;color:{INK2};">{eyebrow}</td></tr>
<tr><td class="k-ink k-title" style="padding:12px 0 0;font-family:{SERIF};font-size:44px;line-height:1.02;letter-spacing:-0.02em;color:{INK};">{title}</td></tr>
{blocks}
<tr><td class="k-rule k-ink2" style="padding:20px 0 0;border-top:1px solid {RULE};font-family:{MONO};font-size:11px;line-height:1.7;letter-spacing:0.06em;color:{INK2};">
  <a href="{SITE}/" class="k-ink2" style="color:{INK2};text-decoration:underline;">keyless.diegoalves.dev</a>
</td></tr>
</table>
</td></tr>
</table>
</body>
</html>
"""


def text(body, top=18, size=16):
    return f'<tr><td class="k-ink2" style="padding:{top}px 0 0;font-family:{SANS};font-size:{size}px;line-height:1.6;color:{INK2};">{body}</td></tr>'


def note(body):
    """The last words before the footer, after a light rule."""
    return f'<tr><td style="padding:32px 0 28px;"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr><td class="k-rule k-ink2" style="padding:18px 0 0;border-top:1px solid {RULE};font-family:{SANS};font-size:13px;line-height:1.7;color:{INK2};">{body}</td></tr></table></td></tr>'


def specimen(rows):
    """Labelled rows in a bordered box, like the site's specimen."""
    cells = []
    for i, (tag, value, value_style) in enumerate(rows):
        border = "" if i == 0 else f"border-top:1px solid {RULE};"
        cells.append(
            f'<tr><td class="k-rule" style="padding:14px 18px 16px;{border}">'
            f'<div class="k-ink2" style="font-family:{MONO};font-size:10px;line-height:1.4;font-weight:500;letter-spacing:0.14em;text-transform:uppercase;color:{INK2};padding:0 0 8px;">{tag}</div>'
            f'<div style="{value_style}">{value}</div></td></tr>'
        )
    return f'<tr><td style="padding:26px 0 0;"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" class="k-box" style="border:1px solid {INK};background:{PAPER2};">{"".join(cells)}</table></td></tr>'


def button(label):
    return (
        f'<tr><td style="padding:28px 0 0;"><table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr>'
        f'<td class="k-btn" style="background:{INK};border:2px solid {INK};box-shadow:4px 4px 0 {ACCENT};">'
        f'<a href="{{{{ .ConfirmationURL }}}}" style="display:inline-block;padding:14px 22px;font-family:{SANS};font-size:16px;line-height:1;font-weight:600;color:{PAPER};text-decoration:none;">{label} &rarr;</a>'
        f"</td></tr></table></td></tr>"
    )


def fallback_link():
    return text(
        L("Se o botão não funcionar, abra este endereço:", "If the button does not work, open this address:", "Si el botón no funciona, abre esta dirección:")
        + f'<br><a href="{{{{ .ConfirmationURL }}}}" class="k-ink2" style="font-family:{MONO};font-size:12px;line-height:1.5;color:{INK2};word-break:break-all;">{{{{ .ConfirmationURL }}}}</a>',
        top=22,
        size=13,
    )


# ---------------------------------------------------------------------------
# The emails
# ---------------------------------------------------------------------------

def code_email():
    """A code to open a link restricted to emails."""
    bar = f'<span class="k-bar" aria-hidden="true" style="font-family:{MONO};font-size:15px;letter-spacing:-1px;color:{INK};">&#9608;&#9608;&#9608;&#9608;&#9608;&#9608;&#9608;&#9608;&#9608;&#9608;&#9608;&#9608;&#9608;&#9608;&#9608;&#9608;</span>'
    caption = f'<span class="k-ink2" style="font-family:{MONO};font-size:12px;color:{INK2};">&nbsp;&nbsp;{L("criptografado até você abrir", "encrypted until you open it", "cifrado hasta que lo abras")}</span>'
    code_style = f"font-family:{MONO};font-size:36px;line-height:1.1;font-weight:500;letter-spacing:0.3em;color:{INK};"
    return page(
        L("Seu código para abrir o item compartilhado com você.", "Your code to open the item shared with you.", "Tu código para abrir el elemento compartido contigo."),
        L("Item compartilhado · código de acesso", "Shared item · access code", "Elemento compartido · código de acceso"),
        L("Alguém compartilhou um item", "Someone shared an item", "Alguien compartió un elemento")
        + f' <em class="k-accent" style="font-style:italic;color:{ACCENT};">{L("com você.", "with you.", "contigo.")}</em>',
        "\n".join([
            text(L(
                "Para abrir, digite este código na página do Keyless em que você o pediu.",
                "To open it, enter this code on the Keyless page where you asked for it.",
                "Para abrirlo, escribe este código en la página de Keyless donde lo pediste.",
            )),
            specimen([
                (L("O item", "The item", "El elemento"), bar + caption, "line-height:1;"),
                (L("Seu código", "Your code", "Tu código"), f'<span class="k-ink k-code" style="{code_style}">{{{{ .Token }}}}</span>', ""),
            ]),
            text(L("Ele expira em pouco tempo e só funciona uma vez.", "It expires soon and works only once.", "Caduca pronto y solo funciona una vez."), top=14, size=13),
            note(L(
                "Ninguém do Keyless vai pedir este código a você. Digite-o só na página em que o pediu. Se não foi você, ignore este e-mail.",
                "No one from Keyless will ask you for this code. Enter it only on the page where you asked for it. If this was not you, ignore this email.",
                "Nadie de Keyless te pedirá este código. Escríbelo solo en la página donde lo pediste. Si no fuiste tú, ignora este correo.",
            )),
        ]),
    )


def signup_email():
    return page(
        L("Confirme seu e-mail para começar a usar o Keyless.", "Confirm your email to start using Keyless.", "Confirma tu correo para empezar a usar Keyless."),
        L("Conta nova · confirmação", "New account · confirmation", "Cuenta nueva · confirmación"),
        L("Falta só", "Just", "Solo falta")
        + f' <em class="k-accent" style="font-style:italic;color:{ACCENT};">{L("um passo.", "one more step.", "un paso.")}</em>',
        "\n".join([
            text(L(
                "Confirme este e-mail para ativar sua conta. Depois, volte ao Keyless e entre com sua senha mestra.",
                "Confirm this email to activate your account. Then go back to Keyless and sign in with your master password.",
                "Confirma este correo para activar tu cuenta. Después, vuelve a Keyless e inicia sesión con tu contraseña maestra.",
            )),
            button(L("Confirmar meu e-mail", "Confirm my email", "Confirmar mi correo")),
            fallback_link(),
            note(
                L("O Keyless nunca pede por e-mail sua ", "Keyless never asks for your ", "Keyless nunca te pide por correo tu ")
                + redact(L("senha mestra", "master password", "contraseña maestra"))
                + L(" nem sua ", " or your ", " ni tu ")
                + redact(L("Chave Secreta", "Secret Key", "Clave Secreta"))
                + L(
                    ". Se você não criou uma conta, ignore este e-mail.",
                    " by email. If you did not create an account, ignore this email.",
                    ". Si no creaste una cuenta, ignora este correo.",
                )
            ),
        ]),
    )


def email_change_email():
    mono = f"font-family:{MONO};font-size:15px;line-height:1.4;color:{INK};word-break:break-all;"
    return page(
        L("Confirme a troca do e-mail da sua conta Keyless.", "Confirm the email change on your Keyless account.", "Confirma el cambio de correo de tu cuenta de Keyless."),
        L("Conta · troca de e-mail", "Account · email change", "Cuenta · cambio de correo"),
        L("Confirme o", "Confirm the", "Confirma el")
        + f' <em class="k-accent" style="font-style:italic;color:{ACCENT};">{L("novo e-mail.", "new email.", "nuevo correo.")}</em>',
        "\n".join([
            text(L(
                "Pediram para trocar o e-mail da sua conta Keyless. A troca só acontece depois da confirmação nos dois endereços.",
                "Someone asked to change the email of your Keyless account. It changes only after both addresses confirm it.",
                "Se pidió cambiar el correo de tu cuenta de Keyless. El cambio solo ocurre cuando ambas direcciones lo confirman.",
            )),
            specimen([
                (L("De", "From", "De"), f'<span class="k-ink" style="{mono}">{{{{ .Email }}}}</span>', ""),
                (L("Para", "To", "A"), f'<span class="k-ink" style="{mono}">{{{{ .NewEmail }}}}</span>', ""),
            ]),
            button(L("Confirmar a troca", "Confirm the change", "Confirmar el cambio")),
            fallback_link(),
            note(L(
                "Se não foi você, não confirme. Abra o Keyless e veja em Configurações → Dispositivos onde sua conta está conectada.",
                "If this was not you, do not confirm. Open Keyless and check Settings → Devices to see where your account is signed in.",
                "Si no fuiste tú, no lo confirmes. Abre Keyless y revisa en Ajustes → Dispositivos dónde está conectada tu cuenta.",
            )),
        ]),
    )


def strip_lang(html):
    """The emails' bodies without their own $lang line, to nest them."""
    return html.split("\n", 1)[1]


OUT.mkdir(parents=True, exist_ok=True)
# "Confirm signup" serves both new accounts and people opening a restricted
# link for the first time (their metadata marks them).
(OUT / "confirmation.html").write_text(
    LANG + "\n{{ if .Data.keyless_share_recipient }}\n" + strip_lang(code_email()) + "{{ else }}\n" + strip_lang(signup_email()) + "{{ end }}\n"
)
(OUT / "magic_link.html").write_text(code_email())
(OUT / "email_change.html").write_text(email_change_email())

# Subjects may have at most 255 characters, template included: the compact
# form, and one subject for both kinds of "Confirm signup" (the code also
# confirms the email).
def subject(pt, en, es):
    return f'{{{{$l := printf "%v" .Data.lang}}}}{{{{if eq $l "en"}}}}{en}{{{{else if eq $l "es"}}}}{es}{{{{else}}}}{pt}{{{{end}}}}'


SUBJECTS = {
    "confirmation": subject("Confirme seu e-mail no Keyless", "Confirm your email on Keyless", "Confirma tu correo en Keyless"),
    "magic_link": subject("Seu código de acesso do Keyless", "Your Keyless access code", "Tu código de acceso de Keyless"),
    "email_change": subject("Confirme a troca de e-mail no Keyless", "Confirm the email change on Keyless", "Confirma el cambio de correo en Keyless"),
}
for name, text in SUBJECTS.items():
    assert len(text) <= 255, (name, len(text))
    (OUT / f"{name}.subject.txt").write_text(text + "\n")
print("written", ", ".join(sorted(p.name for p in OUT.glob("*.html")) + sorted(p.name for p in OUT.glob("*.subject.txt"))))
