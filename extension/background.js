// Background worker: the only part that can reach the desktop app for a
// page (content scripts are bound by the page's own network rules). It
// answers one question for the content script: is this page a fake?
importScripts("bridge.js");

chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  if (msg?.type !== "clavium-check" || !sender.tab?.url) return false;
  (async () => {
    if (!(await getToken())) return reply(null);
    try {
      reply(await checkPage(sender.tab.url));
    } catch {
      reply(null); // app closed or locked: say nothing rather than guess
    }
  })();
  return true; // reply asynchronously
});
