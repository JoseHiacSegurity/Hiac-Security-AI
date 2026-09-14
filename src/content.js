/* global PhishGuardRules */
(function scan() {
  const forms = Array.from(document.forms).map((form) => ({
    hasPassword: Boolean(form.querySelector('input[type="password"]')),
    action: form.getAttribute("action") || ""
  }));
  const hiddenIframes = Array.from(document.querySelectorAll("iframe")).filter((frame) => {
    const style = getComputedStyle(frame);
    return style.display === "none" || style.visibility === "hidden" || frame.width === "0" || frame.height === "0";
  }).length;
  const loginLanguage = /\b(sign in|log in|iniciar sesi[oó]n|contrase[nñ]a|password)\b/i.test(document.body?.innerText || "");
  const result = PhishGuardRules.inspectPage({ url: location.href, forms, hiddenIframes, loginLanguage });
  chrome.runtime.sendMessage({ type: "PHISHGUARD_RESULT", url: location.href, ...result });
}());