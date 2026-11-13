// shush content script (issue #53): detects login forms in the top frame,
// shows a small shush button next to the password field, and fills only after
// a trusted click on that button or on a login in its list. It holds no key and
// never decides which login fits a site: it asks the service worker, which asks
// shush. The origin always comes from the browser's tab URL, not from here.

(() => {
  "use strict";
  if (window.top !== window) return;

  const send = (msg) =>
    new Promise((resolve) => {
      try {
        chrome.runtime.sendMessage(msg, (r) => {
          void chrome.runtime.lastError;
          resolve(r ?? { ok: false, error: "NOT_CONNECTED" });
        });
      } catch {
        resolve({ ok: false, error: "NOT_CONNECTED" });
      }
    });

  const HINTS = {
    LOCKED: "shush is locked. Unlock it, then try again.",
    NOT_PAIRED: "Pair this browser from the shush toolbar button.",
    NOT_CONNECTED: "Start shush and enable browser support in its settings.",
  };

  const visible = (el) => {
    const r = el.getBoundingClientRect();
    const s = getComputedStyle(el);
    return r.width > 0 && r.height > 0 && s.visibility !== "hidden" && s.display !== "none";
  };

  function passwordField() {
    return [...document.querySelectorAll('input[type="password"]')].find(visible) ?? null;
  }

  function usernameFor(pw) {
    const scope = pw.form ?? document;
    const fields = [
      ...scope.querySelectorAll('input[type="text"], input[type="email"], input:not([type])'),
    ].filter((el) => visible(el) && !el.disabled);
    const before = fields.filter(
      (el) => el.compareDocumentPosition(pw) & Node.DOCUMENT_POSITION_FOLLOWING,
    );
    return before.at(-1) ?? null;
  }

  function setValue(el, value) {
    const proto = Object.getPrototypeOf(el);
    Object.getOwnPropertyDescriptor(proto, "value").set.call(el, value);
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  }

  function apply(secrets) {
    const pw = passwordField();
    if (!pw) return;
    const user = usernameFor(pw);
    if (user && secrets.username) setValue(user, secrets.username);
    setValue(pw, secrets.password);
    if (secrets.totp) {
      const otp = document.querySelector('input[autocomplete="one-time-code"]');
      if (otp && visible(otp)) setValue(otp, secrets.totp);
    }
  }

  // ---- UI: closed shadow root so the page cannot read or click it ------------------

  let host = null;
  let root = null;
  let button = null;
  let list = null;
  let anchor = null;

  function build() {
    host = document.createElement("div");
    host.style.cssText = "all:initial;position:fixed;z-index:2147483647;top:0;left:0;";
    root = host.attachShadow({ mode: "closed" });
    const style = document.createElement("style");
    style.textContent = `
      button { all: initial; font: 12px system-ui, sans-serif; cursor: pointer; }
      .btn { position: fixed; width: 22px; height: 22px; border-radius: 5px; background: #0b0b10;
        border: 1px solid #34d399; color: #34d399; display: flex; align-items: center;
        justify-content: center; font-weight: 700; }
      .list { position: fixed; min-width: 220px; max-width: 320px; background: #0b0b10; color: #e4e4e7;
        border: 1px solid #3f3f46; border-radius: 6px; padding: 4px; font: 13px system-ui, sans-serif;
        box-shadow: 0 6px 24px rgb(0 0 0 / .5); }
      .list button { display: block; width: 100%; box-sizing: border-box; padding: 6px 8px; border-radius: 4px; color: #e4e4e7; }
      .list button:hover, .list button:focus-visible { background: #27272a; }
      .list p { margin: 0; padding: 6px 8px; color: #a1a1aa; }
      .u { color: #a1a1aa; }
    `;
    button = document.createElement("button");
    button.className = "btn";
    button.type = "button";
    button.title = "Fill with shush";
    button.setAttribute("aria-label", "Fill with shush");
    button.textContent = "s";
    button.addEventListener("click", onButton);
    root.append(style, button);
    document.documentElement.append(host);
  }

  function place() {
    if (!anchor || !button) return;
    const r = anchor.getBoundingClientRect();
    button.style.top = `${Math.max(0, r.top + (r.height - 22) / 2)}px`;
    button.style.left = `${Math.max(0, r.right - 28)}px`;
    if (list) {
      list.style.top = `${r.bottom + 4}px`;
      list.style.left = `${Math.max(0, r.right - 240)}px`;
    }
  }

  function closeList() {
    list?.remove();
    list = null;
  }

  function showList(children) {
    closeList();
    list = document.createElement("div");
    list.className = "list";
    list.append(...children);
    root.append(list);
    place();
  }

  const note = (text) => {
    const p = document.createElement("p");
    p.textContent = text;
    return p;
  };

  async function onButton(ev) {
    if (!ev.isTrusted) return; // fill only from a real user gesture
    if (list) return closeList();
    const r = await send({ cmd: "matches" });
    if (!r.ok) return showList([note(HINTS[r.error] ?? "shush could not be reached.")]);
    if (r.result.length === 0) return showList([note("No saved login for this site.")]);
    showList(
      r.result.map((m) => {
        const b = document.createElement("button");
        b.type = "button";
        b.textContent = m.title;
        if (m.username) {
          const u = document.createElement("span");
          u.className = "u";
          u.textContent = `  ${m.username}`;
          b.append(u);
        }
        b.addEventListener("click", (e) => onPick(e, m.id));
        return b;
      }),
    );
  }

  async function onPick(ev, id) {
    if (!ev.isTrusted) return;
    closeList();
    const r = await send({ cmd: "fill", id });
    if (!r.ok) return showList([note(HINTS[r.error] ?? "shush refused to fill this page.")]);
    apply(r.result);
    r.result.password = r.result.username = r.result.totp = "";
  }

  function refresh() {
    const pw = passwordField();
    if (!pw) {
      host?.remove();
      host = root = button = list = anchor = null;
      return;
    }
    anchor = pw;
    if (!host) build();
    else if (!host.isConnected) document.documentElement.append(host);
    place();
  }

  // ---- offer to save: a trusted submit with a typed password -----------------------

  document.addEventListener(
    "submit",
    (ev) => {
      if (!ev.isTrusted) return;
      const form = ev.target;
      if (!(form instanceof HTMLFormElement)) return;
      const pw = [...form.querySelectorAll('input[type="password"]')].find((el) => el.value);
      if (!pw) return;
      const user = usernameFor(pw);
      void send({ cmd: "save", username: user?.value ?? "", password: pw.value });
    },
    true,
  );

  // The popup's fill is delivered here after the user clicked it.
  chrome.runtime.onMessage.addListener((msg, sender) => {
    if (sender.id !== chrome.runtime.id || msg?.cmd !== "shush-fill") return;
    apply(msg.secrets);
  });

  let timer = 0;
  const schedule = () => {
    clearTimeout(timer);
    timer = setTimeout(refresh, 150);
  };
  new MutationObserver(schedule).observe(document.documentElement, {
    childList: true,
    subtree: true,
  });
  addEventListener("resize", place);
  addEventListener("scroll", place, true);
  refresh();
})();
