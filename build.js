// SolarSync — precompile the single-page app.
//
// public/index.html stays the source: its <script type="text/babel"> blocks are
// written in JSX and, unbuilt, are compiled in the visitor's browser by the Babel
// library in public/vendor/babel-standalone.min.js (~3 MB, plus the CPU time on
// every load).
//
// This script does that compile once, at build time, and writes dist/index.html:
//   - every text/babel block becomes a plain <script> with the compiled code,
//     in the same place and order;
//   - the Babel library's <script> tag is left out.
// It uses that same Babel copy with the same options the browser used
// (presets react + env, the same three plugins), so the app behaves identically.
// No packages to install. server.js serves dist/index.html when it exists and
// falls back to public/index.html otherwise.
//
//   node build.js
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const SRC = path.join(__dirname, "public", "index.html");
const OUT_DIR = path.join(__dirname, "dist");
const OUT = path.join(OUT_DIR, "index.html");

const html = fs.readFileSync(SRC, "utf8");

// 1. Load the same Babel library the unbuilt page uses, in a sandbox.
const BABEL_TAG = '<script src="/vendor/babel-standalone.min.js"></script>';
const babelStart = html.indexOf(BABEL_TAG);
if (babelStart < 0) throw new Error("Babel <script> tag not found in public/index.html");
const babelEnd = babelStart + BABEL_TAG.length;
const babelSrc = fs.readFileSync(path.join(__dirname, "public", "vendor", "babel-standalone.min.js"), "utf8");
const sandbox = { exports: {}, console };
sandbox.module = { exports: sandbox.exports };
vm.createContext(sandbox);
vm.runInContext(babelSrc, sandbox, { filename: "babel-standalone.js" });
const Babel = sandbox.exports;
if (!Babel || typeof Babel.transform !== "function") throw new Error("Couldn't load the Babel library");

// Same options @babel/standalone applies to <script type="text/babel"> tags.
let n = 0;
const compile = (code) => Babel.transform(code, {
  filename: "Inline Babel script" + (++n > 1 ? " (" + n + ")" : ""),
  presets: ["react", "env"],
  plugins: ["transform-class-properties", "transform-object-rest-spread", "transform-flow-strip-types"],
  targets: { browsers: undefined },
  browserslistConfigFile: false,
  sourceMaps: false,
  compact: false,
  comments: false,
}).code;

// 2. Rebuild the page: drop the Babel library, compile each text/babel block in place.
const OPEN = '<script type="text/babel">';
let out = "";
let pos = 0;
let blocks = 0;
while (true) {
  const at = html.indexOf(OPEN, pos);
  // Keep everything up to the next block, minus the Babel library itself.
  const chunkEnd = at < 0 ? html.length : at;
  let chunk = html.slice(pos, chunkEnd);
  if (babelStart >= pos && babelStart < chunkEnd) {
    chunk = html.slice(pos, babelStart) + "<!-- Babel library removed by build.js (app is precompiled) -->" + html.slice(babelEnd, chunkEnd);
  }
  out += chunk;
  if (at < 0) break;
  const close = html.indexOf("</script>", at + OPEN.length);
  if (close < 0) throw new Error("Unclosed text/babel script at offset " + at);
  const js = compile(html.slice(at + OPEN.length, close));
  if (/<\/script/i.test(js)) throw new Error("Compiled block " + (blocks + 1) + " contains </script>");
  out += "<script>\n" + js + "\n</script>";
  pos = close + "</script>".length;
  blocks++;
}

// 3. Sanity checks before writing.
if (out.includes(OPEN)) throw new Error("A text/babel block was left uncompiled");
if (out.includes("babel-standalone")) throw new Error("The Babel library is still referenced in the output");
if (/\bregeneratorRuntime\b/.test(out)) throw new Error("Output needs the global regeneratorRuntime that the Babel library provided");

fs.mkdirSync(OUT_DIR, { recursive: true });
fs.writeFileSync(OUT, out);
const kb = (b) => Math.round(b / 1024).toLocaleString() + " KB";
console.log(`build.js: compiled ${blocks} blocks → ${path.relative(__dirname, OUT)} (${kb(Buffer.byteLength(out))}; the ${kb(Buffer.byteLength(babelSrc))} Babel library is no longer sent to browsers)`);
