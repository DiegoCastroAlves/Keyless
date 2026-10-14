# Account emails

The emails Supabase Auth sends, in the site's look (paper and ink, Instrument
Serif, IBM Plex, the teal accent) and in the reader's language: pt-BR, en or
es, from the `lang` the app and the share page put in the user's metadata.
Users without it (accounts made before) get pt-BR.

They go in the dashboard: **Authentication → Emails → Templates**. For each
one, the subject is in `<name>.subject.txt` and the body in `<name>.html`.

| Dashboard template   | Files            | Who gets it |
| -------------------- | ---------------- | ----------- |
| Confirm signup       | `confirmation.*` | A new Keyless account (a link), or someone opening a link restricted to emails for the first time (a code; `keyless_share_recipient` in their metadata) |
| Magic Link           | `magic_link.*`   | Someone asking a restricted link for a code again |
| Change Email Address | `email_change.*` | Both addresses, when an account changes its email |

The templates are Go `text/template`. Keep comparisons to `$lang`, which is
always a string: `eq` on a metadata field that is missing fails, and Supabase
then sends nothing.

## Changing them

Edit `build.py` (the texts and the layout), then:

```sh
python3 build.py            # writes the .html and .subject.txt files here
python3 preview.py /tmp/x   # renders every email and language to open in a browser
```

Paste the new files in the dashboard again. The fonts load from the site
(`/fonts/*` allows other origins); clients that block them fall back to
Georgia and the system's sans-serif.
