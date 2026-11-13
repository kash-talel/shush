// shush popup (issue #53): pairing, status, and filling the current tab.
// Clicking a login here is the user gesture for a fill.

import { formatCode } from "./pairing.js";

const $ = (id) => document.getElementById(id);

const MESSAGES = {
  NOT_CONNECTED: "shush is not running, or browser support is off. Start shush and turn it on in Settings.",
  NO_PAIRING_CODE: "No pairing code is showing in shush. Show a new one and try again.",
  WRONG_PAIRING_CODE: "That code is wrong. Check it and try again.",
  NOT_PAIRED: "This browser is not paired any more. Pair it again.",
  LOCKED: "shush is locked. Unlock it first.",
  TIMEOUT: "shush did not answer in time.",
  BAD_ORIGIN: "This page cannot be filled.",
  BAD_ANSWER_MAC: "The answer from shush could not be verified. Pair again.",
  CORRUPT_MESSAGE: "The pairing message was invalid. Show a new code and try again.",
  BAD_SIDE: "The pairing message was invalid. Show a new code and try again.",
};

const ask = (msg) =>
  new Promise((resolve) =>
    chrome.runtime.sendMessage(msg, (r) => {
      void chrome.runtime.lastError;
      resolve(r ?? { ok: false, error: "NOT_CONNECTED" });
    }),
  );

function showError(code) {
  const el = $("error");
  el.hidden = code == null;
  el.textContent = code == null ? "" : (MESSAGES[code] ?? `Something went wrong (${code}).`);
}

async function renderLogins() {
  const box = $("login-list");
  box.replaceChildren();
  const r = await ask({ cmd: "matches" });
  if (!r.ok) {
    $("logins-title").textContent = "Logins for this site";
    return showError(r.error);
  }
  $("logins-title").textContent = r.result.length ? "Logins for this site" : "No saved login for this site.";
  for (const m of r.result) {
    const b = document.createElement("button");
    b.type = "button";
    b.className = "plain";
    b.textContent = m.username ? `${m.title} (${m.username})` : m.title;
    b.addEventListener("click", async () => {
      b.disabled = true;
      const f = await ask({ cmd: "fill", id: m.id });
      if (f.ok) window.close();
      else {
        b.disabled = false;
        showError(f.error);
      }
    });
    box.append(b);
  }
}

async function render() {
  showError(null);
  const r = await ask({ cmd: "status" });
  const s = r.ok ? r.result : { connected: false, error: r.error, paired: false };
  $("pair").hidden = true;
  $("logins").hidden = true;
  if (!s.connected) {
    $("state").textContent = "Not connected to shush.";
    return showError(s.error ?? "NOT_CONNECTED");
  }
  if (s.error) {
    $("state").textContent = "Not connected to shush.";
    return showError(s.error);
  }
  if (!s.paired) {
    $("state").textContent = "Connected. This browser is not paired yet.";
    $("pair").hidden = false;
    return;
  }
  $("state").textContent = s.locked ? "Paired. shush is locked." : "Paired and ready.";
  $("logins").hidden = false;
  if (s.locked) {
    $("login-list").replaceChildren();
    $("logins-title").textContent = "Unlock shush to see logins.";
  } else {
    await renderLogins();
  }
}

$("code").addEventListener("input", (e) => {
  e.target.value = formatCode(e.target.value);
});

$("pair-go").addEventListener("click", async () => {
  $("pair-go").disabled = true;
  const r = await ask({ cmd: "pair", code: $("code").value });
  $("pair-go").disabled = false;
  $("code").value = "";
  if (r.ok) await render();
  else showError(r.error);
});

$("unpair").addEventListener("click", async () => {
  await ask({ cmd: "unpair" });
  await render();
});

render();
