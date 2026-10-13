// Packages the extension for the stores (after `pnpm build`), into dist/:
// - keyless-chrome-<version>.zip: the Chrome Web Store and Edge Add-ons;
// - keyless-firefox-<version>.zip: addons.mozilla.org (it signs it);
// - keyless-source-<version>.zip: the source Mozilla asks for, since the
//   published code is built from TypeScript (see store/README.md).
// Plain zip files, written here so nothing outside Node is needed.
import { execFileSync } from "node:child_process";
import { readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { crc32, deflateRawSync } from "node:zlib";

const pkg = JSON.parse(readFileSync("package.json", "utf8"));

/** Every file under `dir`, as paths relative to it (with "/"). */
function files(dir) {
  const out = [];
  const walk = (at) => {
    for (const name of readdirSync(at).sort()) {
      const path = join(at, name);
      if (statSync(path).isDirectory()) walk(path);
      else out.push(relative(dir, path).split(sep).join("/"));
    }
  };
  walk(dir);
  return out;
}

/** A zip archive of `entries` ([name in the archive, bytes]). Dates are fixed,
 * so the same files give the same archive. */
function zip(entries) {
  const local = [];
  const central = [];
  let offset = 0;
  // 1 January 2020, in MS-DOS format.
  const time = 0;
  const date = ((2020 - 1980) << 9) | (1 << 5) | 1;
  for (const [name, data] of entries) {
    const nameBytes = Buffer.from(name, "utf8");
    const packed = deflateRawSync(data, { level: 9 });
    const crc = crc32(data);
    const header = Buffer.alloc(30);
    header.writeUInt32LE(0x04034b50, 0);
    header.writeUInt16LE(20, 4);
    header.writeUInt16LE(0x0800, 6); // UTF-8 names
    header.writeUInt16LE(8, 8); // deflate
    header.writeUInt16LE(time, 10);
    header.writeUInt16LE(date, 12);
    header.writeUInt32LE(crc, 14);
    header.writeUInt32LE(packed.length, 18);
    header.writeUInt32LE(data.length, 22);
    header.writeUInt16LE(nameBytes.length, 26);
    local.push(header, nameBytes, packed);
    const entry = Buffer.alloc(46);
    entry.writeUInt32LE(0x02014b50, 0);
    entry.writeUInt16LE(20, 4);
    entry.writeUInt16LE(20, 6);
    entry.writeUInt16LE(0x0800, 8);
    entry.writeUInt16LE(8, 10);
    entry.writeUInt16LE(time, 12);
    entry.writeUInt16LE(date, 14);
    entry.writeUInt32LE(crc, 16);
    entry.writeUInt32LE(packed.length, 20);
    entry.writeUInt32LE(data.length, 24);
    entry.writeUInt16LE(nameBytes.length, 28);
    entry.writeUInt32LE(offset, 42);
    central.push(entry, nameBytes);
    offset += header.length + nameBytes.length + packed.length;
  }
  const centralSize = central.reduce((n, b) => n + b.length, 0);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(centralSize, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...local, ...central, end]);
}

function pack(name, dir, list, change = (_file, data) => data) {
  const path = `dist/${name}-${pkg.version}.zip`;
  writeFileSync(path, zip(list.map((file) => [file, change(file, readFileSync(join(dir, file)))])));
  console.log(`${path} (${list.length} files)`);
}

// The stores give the extension an id of their own and refuse a "key" (it
// fixes the id of the builds loaded by hand); the app is told the stores'
// ids instead (CHROME_EXTENSION_IDS, see store/README.md).
pack("keyless-chrome", "dist/chrome", files("dist/chrome"), (file, data) => {
  if (file !== "manifest.json") return data;
  const { key: _key, ...manifest } = JSON.parse(data.toString("utf8"));
  return Buffer.from(JSON.stringify(manifest, null, 2));
});
pack("keyless-firefox", "dist/firefox", files("dist/firefox"));

// The source: this folder as git has it (no dependencies, no builds), with
// how to build it (store/README.md, "Source for Mozilla").
const tracked = execFileSync("git", ["ls-files", "-z", "."], { encoding: "utf8" })
  .split("\0")
  .filter((file) => file && !file.startsWith("store/images/"));
pack("keyless-source", ".", tracked);
