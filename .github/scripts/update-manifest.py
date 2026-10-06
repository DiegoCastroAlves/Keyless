#!/usr/bin/env python3
"""Writes latest.json, the update manifest the Keyless app reads.

Usage: update-manifest.py <version> <owner/repo> <directory>

<directory> holds the release installers and, next to each one, the .sig file
written by `tauri signer sign --app-version <version>`. Every installer type
must be present exactly once, so a release can never ship a partial manifest.
"""

import datetime
import json
import pathlib
import sys
import urllib.parse

# Keys follow tauri-plugin-updater ("{os}-{arch}-{installer}"); the pacman
# entry is read by Keyless itself (see updates.rs).
TARGETS = [
    ("windows-x86_64-nsis", lambda name: name.endswith("_x64-setup.exe")),
    ("linux-x86_64-appimage", lambda name: name.endswith(".AppImage")),
    ("linux-x86_64-deb", lambda name: name.endswith(".deb")),
    ("linux-x86_64-rpm", lambda name: name.endswith(".rpm")),
    ("linux-x86_64-pacman", lambda name: name.endswith(".pkg.tar.zst")),
]


def main() -> None:
    version, repo, directory = sys.argv[1:4]
    root = pathlib.Path(directory)
    files = [p for p in root.iterdir() if p.is_file() and not p.name.endswith(".sig") and p.name != "latest.json"]

    platforms = {}
    for target, matches in TARGETS:
        found = [p for p in files if matches(p.name)]
        if len(found) != 1:
            sys.exit(f"expected exactly one file for {target}, found {[p.name for p in found]}")
        installer = found[0]
        signature = installer.with_name(installer.name + ".sig").read_text().strip()
        if not signature:
            sys.exit(f"empty signature for {installer.name}")
        url = f"https://github.com/{repo}/releases/download/v{version}/{urllib.parse.quote(installer.name)}"
        platforms[target] = {"signature": signature, "url": url}

    manifest = {
        "version": version,
        "notes": f"Keyless {version}",
        "pub_date": datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "platforms": platforms,
    }
    (root / "latest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"latest.json: {', '.join(platforms)}")


if __name__ == "__main__":
    main()
