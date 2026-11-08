// Fails `npm run check` if the frontend gains a raw-HTML sink (issue #20).
// Titles, usernames, URLs and notes come from untrusted sources (CSV, backups,
// browser auto-save, sync): an XSS in this WebView can call every Tauri
// command its window is granted. Render text with Svelte's escaping only.
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";

const ROOT = new URL("../src/", import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1");
const BANNED = [
  [/\{@html\b/, "{@html}"],
  [/\.(inner|outer)HTML\s*=/, "innerHTML/outerHTML assignment"],
  [/\.insertAdjacentHTML\s*\(/, "insertAdjacentHTML"],
  [/document\.write(ln)?\s*\(/, "document.write"],
  [/\beval\s*\(|new\s+Function\s*\(/, "eval / new Function"],
  [/\bwindow\.open\s*\(/, "window.open"],
];

function* files(dir) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) yield* files(p);
    else if (/\.(svelte|ts|js|mjs)$/.test(name)) yield p;
  }
}

let failures = 0;
for (const file of files(ROOT)) {
  readFileSync(file, "utf8")
    .split(/\r?\n/)
    .forEach((line, i) => {
      for (const [re, what] of BANNED) {
        if (re.test(line)) {
          console.error(`${relative(ROOT, file)}:${i + 1}: banned ${what} (issue #20)`);
          failures++;
        }
      }
    });
}
if (failures) process.exit(1);
console.log("no-raw-html: ok");
