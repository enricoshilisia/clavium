const app = document.getElementById("app");

function el(tag, props = {}, children = []) {
  const node = document.createElement(tag);
  Object.entries(props).forEach(([key, value]) => {
    if (key === "text") node.textContent = value;
    else if (key === "onClick") node.addEventListener("click", value);
    else node.setAttribute(key, value);
  });
  children.forEach((c) => node.appendChild(c));
  return node;
}

async function currentTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.url) return null;
  try {
    const u = new URL(tab.url);
    if (u.protocol !== "https:" && u.protocol !== "http:") return null;
    return { url: tab.url, host: u.hostname };
  } catch {
    return null;
  }
}

function verdictBox(check) {
  if (!check || check.verdict === "unknown") return null;
  if (check.verdict === "trusted") return el("div", { class: "verdict verdict-ok", text: check.reasons[0] });
  const box = el("div", { class: `verdict ${check.verdict === "dangerous" ? "verdict-danger" : "verdict-warn"}` }, [
    el("strong", { text: check.verdict === "dangerous" ? "Stop: this looks like a fake site" : "Be careful on this page" }),
  ]);
  check.reasons.forEach((r) => box.appendChild(el("div", { text: r })));
  return box;
}

function renderPairingForm(message) {
  app.replaceChildren();
  if (message) {
    app.appendChild(el("div", { class: "notice notice-danger", text: message }));
  }
  app.appendChild(
    el("p", {
      class: "faint",
      text: "Open Clavium on this computer, generate a pairing code from the Account panel, and enter it here.",
    }),
  );

  const codeField = el("div", { class: "field" }, [
    el("label", { class: "label", text: "Pairing code" }),
    el("input", { id: "code-input", maxlength: "6", autocapitalize: "characters", autocomplete: "off" }),
  ]);
  const button = el("button", { class: "btn-primary", text: "Connect" });

  button.addEventListener("click", async () => {
    const code = document.getElementById("code-input").value.trim();
    if (!code) return;
    button.disabled = true;
    button.textContent = "Connecting…";
    try {
      await pair(code, await browserLabel());
      await renderMain();
    } catch (err) {
      renderPairingForm(pairingErrorMessage(err));
    }
  });

  app.appendChild(codeField);
  app.appendChild(button);
}

function pairingErrorMessage(err) {
  if (err.message === "not-running") {
    return "Can't reach Clavium — make sure the desktop app is open.";
  }
  return err.message || "Pairing failed.";
}

async function browserLabel() {
  // Best-effort — this is only ever shown to the person themselves, in
  // their own desktop app's "connected extensions" list.
  const ua = navigator.userAgent;
  if (ua.includes("Edg/")) return "Edge";
  if (ua.includes("Firefox/")) return "Firefox";
  if (ua.includes("Chrome/")) return "Chrome";
  return "Browser extension";
}

async function renderMain() {
  app.replaceChildren(el("p", { class: "muted", text: "Checking…" }));

  const token = await getToken();
  if (!token) return renderPairingForm();

  let unlocked;
  try {
    ({ unlocked } = await status());
  } catch (err) {
    if (err.message === "not-paired") return renderPairingForm("This connection was revoked — pair again.");
    return renderDisconnected(err);
  }

  if (!unlocked) {
    app.replaceChildren(
      el("div", { class: "notice notice-warn", text: "Clavium is locked. Unlock it on your computer, then reopen this." }),
    );
    return;
  }

  const tab = await currentTab();
  const host = tab?.host;
  if (!host) {
    app.replaceChildren(el("p", { class: "muted", text: "No page open here." }));
    return;
  }

  let hits;
  let check = null;
  try {
    check = await checkPage(tab.url).catch(() => null);
    hits = await search(host);
  } catch (err) {
    return renderDisconnected(err);
  }

  app.replaceChildren();
  const box = verdictBox(check);
  if (box) app.appendChild(box);
  if (check?.verdict === "dangerous") {
    app.appendChild(el("p", { class: "muted", text: "Clavium will not fill passwords on this page. Close it and go to the real site yourself." }));
    return;
  }
  if (hits.length === 0) {
    app.appendChild(el("p", { class: "muted", text: `No saved logins for ${host}.` }));
  } else {
    const list = el("div", { class: "hit-list" });
    hits.forEach((hit) => {
      const fillBtn = el("button", { text: "Fill" });
      fillBtn.addEventListener("click", () => fillInto(hit.id, tab.url, fillBtn));
      list.appendChild(
        el("div", { class: "hit" }, [
          el("div", { class: "hit-text" }, [
            el("div", { class: "hit-title", text: hit.title || "(untitled)" }),
            el("div", { class: "hit-username", text: hit.username || "—" }),
          ]),
          fillBtn,
        ]),
      );
    });
    app.appendChild(list);
  }

  app.appendChild(
    el("button", {
      class: "footer-link",
      text: "Disconnect this browser",
      onClick: async () => {
        await clearToken();
        await renderMain();
      },
    }),
  );
}

function renderDisconnected(err) {
  app.replaceChildren(
    el("div", {
      class: "notice notice-danger",
      text: err.message === "not-running" ? "Can't reach Clavium — make sure the desktop app is open." : err.message,
    }),
  );
}

async function fillInto(recordId, pageUrl, button) {
  button.disabled = true;
  button.textContent = "…";
  try {
    const { username, password } = await reveal(recordId, pageUrl);
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    await chrome.tabs.sendMessage(tab.id, { type: "clavium-fill", username, password });
    window.close();
  } catch (err) {
    button.disabled = false;
    button.textContent = "Fill";
    renderDisconnected(err);
  }
}

renderMain();
