// Field-detection tests: builds the harness, generates the test pages, and
// checks each one in a headless Chromium (its own, throwaway profile).
//
//   node test/run.mjs              all generated pages
//   node test/run.mjs 012 145      only these
//   node test/run.mjs --survey urls.txt   what Keyless finds on real pages
//                                          (read only: nothing is typed)
//
// EXPLAIN=1 prints why failing fields read as they did; NOGEN=1 keeps the
// pages already generated (one added by hand, say); with --survey, SHOTS=dir
// saves screenshots and EVAL="expression" prints more about each page.

import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { extname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";

const HERE = fileURLToPath(new URL(".", import.meta.url));
const args = process.argv.slice(2);
const surveyFile = args[0] === "--survey" ? args[1] : null;

await build({ entryPoints: [join(HERE, "harness.ts")], bundle: true, format: "iife", target: "chrome120", outfile: join(HERE, "dist/harness.js"), logLevel: "warning" });

// ----- Chromium over CDP --------------------------------------------------------------

const profile = mkdtempSync(join(tmpdir(), "keyless-fields-"));
const port = 9500 + Math.floor(Math.random() * 400);
const browser = spawn(
  process.env.CHROMIUM ?? "chromium",
  [
    `--remote-debugging-port=${port}`,
    "--headless=new",
    "--disable-gpu",
    "--no-first-run",
    "--no-default-browser-check",
    `--user-data-dir=${profile}`,
    "--window-size=1280,1000",
    // CI runners refuse the user namespaces Chromium's sandbox needs; the
    // pages there are only the generated ones.
    ...(process.env.CI ? ["--no-sandbox"] : []),
    "about:blank",
  ],
  { stdio: ["ignore", "ignore", "pipe"] },
);
/** The end of what Chromium wrote, to tell why it did not start. */
let chromiumErrors = "";
browser.stderr.on("data", (chunk) => (chromiumErrors = (chromiumErrors + chunk).slice(-4000)));

/** On GitHub Actions, failures also become annotations (readable without
 * the full log). */
function annotate(message) {
  if (process.env.GITHUB_ACTIONS) console.log(`::error::${String(message).replace(/%/g, "%25").replace(/\r?\n/g, "%0A")}`);
}
/** Closes Chromium and deletes its profile (it grows with every site). */
async function finish(code) {
  if (browser.exitCode === null) {
    const exited = new Promise((r) => browser.once("exit", r));
    browser.kill();
    await Promise.race([exited, new Promise((r) => setTimeout(r, 3000))]);
  }
  rmSync(profile, { recursive: true, force: true });
  process.exit(code);
}
process.on("SIGINT", () => void finish(130));
process.on("SIGTERM", () => void finish(143));
for (const event of ["uncaughtException", "unhandledRejection"]) {
  process.on(event, (err) => {
    console.error(err);
    annotate(`${err?.stack ?? err}\n${chromiumErrors}`);
    void finish(1);
  });
}

async function target() {
  // A first start on a fresh machine can take a while.
  for (let i = 0; i < 300; i++) {
    try {
      const list = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
      const page = list.find((t) => t.type === "page");
      if (page) return page.webSocketDebuggerUrl;
    } catch {
      // Not up yet.
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error("chromium did not start");
}

const ws = new WebSocket(await target());
await new Promise((r) => (ws.onopen = r));
let id = 0;
const waiters = new Map();
const events = new Map();
ws.onmessage = (event) => {
  const msg = JSON.parse(event.data);
  if (msg.id && waiters.has(msg.id)) {
    waiters.get(msg.id)(msg);
    waiters.delete(msg.id);
  } else if (msg.method && events.has(msg.method)) {
    events.get(msg.method)(msg.params);
  }
};
const send = (method, params = {}) =>
  new Promise((resolve) => {
    const i = ++id;
    waiters.set(i, resolve);
    ws.send(JSON.stringify({ id: i, method, params }));
  });
const once = (method, ms) =>
  new Promise((resolve) => {
    const timer = setTimeout(() => (events.delete(method), resolve(null)), ms);
    events.set(method, (params) => {
      clearTimeout(timer);
      events.delete(method);
      resolve(params);
    });
  });
await send("Page.enable");
await send("Runtime.enable");

async function visit(url, waitMs) {
  const loaded = once("Page.loadEventFired", 20_000);
  await send("Page.navigate", { url });
  await loaded;
  await new Promise((r) => setTimeout(r, waitMs));
}

async function evaluate(expression) {
  const r = await send("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true });
  if (r.result?.exceptionDetails) throw new Error(r.result.exceptionDetails.exception?.description ?? r.result.exceptionDetails.text);
  return r.result?.result?.value;
}

// ----- Real pages ---------------------------------------------------------------------

if (surveyFile) {
  // As a regular Chrome: many sites turn "HeadlessChrome" away.
  const version = await (await fetch(`http://127.0.0.1:${port}/json/version`)).json();
  await send("Network.setUserAgentOverride", { userAgent: version["User-Agent"].replace("HeadlessChrome", "Chrome"), acceptLanguage: "pt-BR,pt;q=0.9,en;q=0.8" });
  const harness = readFileSync(join(HERE, "dist/harness.js"), "utf8");
  await send("Page.addScriptToEvaluateOnNewDocument", { source: harness });
  const urls = readFileSync(surveyFile, "utf8").split("\n").map((l) => l.trim()).filter((l) => l && !l.startsWith("#"));
  const results = [];
  for (const url of urls) {
    try {
      await visit(url, 3500);
      // Headless Chromium draws (and runs animations) when asked for a frame.
      await send("Page.captureScreenshot", { format: "jpeg", quality: 10 });
      await new Promise((r) => setTimeout(r, 300));
      await send("Page.captureScreenshot", { format: "jpeg", quality: 10 });
      const value = await evaluate("__keyless.survey()");
      results.push({ url, ...value });
      if (process.env.SHOTS) {
        const shot = await send("Page.captureScreenshot", { format: "jpeg", quality: 50 });
        writeFileSync(join(process.env.SHOTS, `${new URL(url).hostname}.jpg`), Buffer.from(shot.result.data, "base64"));
      }
      // EVAL="js expression": something more to look at on each page.
      if (process.env.EVAL) console.log(JSON.stringify(await evaluate(process.env.EVAL), null, 1));
      console.log(`${url}\n  login: user=${value.login.username} pass=${value.login.password}${value.login.otp ? ` otp=${value.login.otp}` : ""}  loginForm=${value.loginForm} shadowInputs=${value.shadowInputs}\n  fields: ${value.inputs.join(", ")}`);
    } catch (err) {
      results.push({ url, error: String(err) });
      console.log(`${url}\n  ERROR ${err}`);
    }
  }
  writeFileSync(join(HERE, "survey.json"), JSON.stringify(results, null, 1));
  ws.close();
  await finish(0);
}

// ----- Generated pages ----------------------------------------------------------------

if (!process.env.NOGEN) await import("./gen.mjs");
const TYPES = { ".html": "text/html", ".js": "text/javascript", ".json": "application/json" };
const server = createServer((req, res) => {
  try {
    const path = join(HERE, decodeURIComponent(new URL(req.url, "http://x").pathname));
    if (!path.startsWith(HERE)) throw new Error("outside");
    const body = readFileSync(path);
    res.writeHead(200, { "content-type": TYPES[extname(path)] ?? "application/octet-stream" });
    res.end(body);
  } catch {
    res.writeHead(404);
    res.end();
  }
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const base = `http://127.0.0.1:${server.address().port}`;

const index = JSON.parse(readFileSync(join(HERE, "pages/index.json"), "utf8"));
const only = new Set(args);
const failures = [];
const byKind = {};
for (const page of index) {
  if (only.size && !only.has(page.name)) continue;
  await visit(`${base}/pages/${page.name}.html`, 60);
  const result = await evaluate("__keyless.check()");
  if (process.env.EXPLAIN && !result.ok) {
    for (const key of Object.keys(JSON.parse(await evaluate('document.getElementById("expect").textContent')).fields ?? {})) {
      console.log(page.name, key, JSON.stringify(await evaluate(`__keyless.explain(${JSON.stringify(key)})`)));
    }
  }
  const stats = (byKind[page.kind] ??= { pass: 0, fail: 0 });
  if (result.ok) stats.pass++;
  else {
    stats.fail++;
    failures.push({ ...page, problems: result.problems, seen: result.seen });
  }
}
server.close();
ws.close();

for (const f of failures) console.log(`FAIL ${f.name} ${f.kind} [${f.lang} ${f.labeling} ${f.container}]: ${f.problems.join("; ")}`);
for (const f of failures.slice(0, 10)) annotate(`FAIL ${f.name} ${f.kind} [${f.lang} ${f.labeling} ${f.container}]: ${f.problems.join("; ")}`);
console.log("\nby kind:", Object.entries(byKind).map(([k, s]) => `${k} ${s.pass}/${s.pass + s.fail}`).join(", "));
const total = Object.values(byKind).reduce((a, s) => a + s.pass + s.fail, 0);
console.log(`${total - failures.length}/${total} pages pass`);
await finish(failures.length ? 1 : 0);
