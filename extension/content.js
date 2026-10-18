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
