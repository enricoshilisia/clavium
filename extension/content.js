// Fills a username/password into whatever login form is on the page, on
// request from the popup. Never initiates anything itself — this script
// is passive until a `clavium-fill` message arrives, and that message
// only ever follows a person clicking "Fill" on a record they picked
// themselves in the extension popup.

function setReactCompatibleValue(input, value) {
  // A plain `input.value = x` does not notify a framework-controlled
  // input (React, in particular) that anything changed, because it
  // bypasses the setter the framework itself installed. Going through
  // the native prototype's setter first, then dispatching a real `input`
  // event, is the standard way around that.
  const prototype = input.tagName === "TEXTAREA" ? window.HTMLTextAreaElement.prototype : window.HTMLInputElement.prototype;
  const nativeSetter = Object.getOwnPropertyDescriptor(prototype, "value")?.set;
  if (nativeSetter) {
    nativeSetter.call(input, value);
  } else {
    input.value = value;
  }
  input.dispatchEvent(new Event("input", { bubbles: true }));
  input.dispatchEvent(new Event("change", { bubbles: true }));
}

function findPasswordField() {
  return Array.from(document.querySelectorAll('input[type="password"]')).find(
    (el) => el.offsetParent !== null, // visible
  );
}

function findUsernameField(passwordField) {
  const form = passwordField.closest("form") || document;
  const candidates = Array.from(
    form.querySelectorAll('input[type="text"], input[type="email"], input:not([type])'),
  ).filter((el) => el.offsetParent !== null);

  if (candidates.length === 0) return null;

  // Prefer the field that sits just before the password field in the
  // document, which is how almost every login form is laid out —
  // falling back to the first visible candidate otherwise.
  const passwordIndex = candidates.findIndex(
    (el) => el.compareDocumentPosition(passwordField) & Node.DOCUMENT_POSITION_FOLLOWING,
  );
  return candidates[passwordIndex] ?? candidates[0];
}

chrome.runtime.onMessage.addListener((message) => {
  if (message?.type !== "clavium-fill") return;

  const passwordField = findPasswordField();
  if (!passwordField) return;

  const usernameField = findUsernameField(passwordField);
  if (usernameField && message.username) {
    setReactCompatibleValue(usernameField, message.username);
  }
  setReactCompatibleValue(passwordField, message.password);
});


// ---- Phishing guard ----
// When a page asks for a password, ask the desktop app (on this computer
// only) whether the page imitates a known site, and warn before anything
// is typed. Nothing is filled or blocked here; the popup refuses to fill.
(() => {
  if (window.top !== window || !/^https?:$/.test(location.protocol)) return;
  let asked = false;
  function ask() {
    if (asked || !findPasswordField()) return;
    asked = true;
    chrome.runtime.sendMessage({ type: "clavium-check" }, (check) => {
      if (chrome.runtime.lastError || !check || check.verdict !== "dangerous") return;
      showWarning(check);
    });
  }
  function showWarning(check) {
    const host = document.createElement("div");
    host.style.cssText = "position:fixed;top:0;left:0;right:0;z-index:2147483647;";
    const root = host.attachShadow({ mode: "closed" });
    const bar = document.createElement("div");
    bar.style.cssText =
      "font:14px/1.4 system-ui,-apple-system,'Segoe UI',sans-serif;background:#7f1d1d;color:#fff;padding:12px 16px;" +
      "display:flex;gap:12px;align-items:flex-start;box-shadow:0 2px 12px rgba(0,0,0,.4);";
    const text = document.createElement("div");
    text.style.flex = "1";
    const title = document.createElement("strong");
    title.textContent = check.imitates ? `Clavium: this is not ${check.imitates}. ` : "Clavium: this looks like a fake site. ";
    text.appendChild(title);
    text.appendChild(document.createTextNode((check.reasons[0] || "") + " Do not type your password here."));
    const close = document.createElement("button");
    close.textContent = "Dismiss";
    close.style.cssText = "background:#fff;color:#7f1d1d;border:0;border-radius:6px;padding:6px 10px;font:inherit;cursor:pointer;";
    close.onclick = () => host.remove();
    bar.append(text, close);
    root.appendChild(bar);
    document.documentElement.appendChild(host);
  }
  ask();
  if (!asked) {
    const obs = new MutationObserver(() => {
      ask();
      if (asked) obs.disconnect();
    });
    obs.observe(document.documentElement, { childList: true, subtree: true });
    setTimeout(() => obs.disconnect(), 30000);
  }
})();
