/* global PhishGuardRules */
(function startPhishGuard() {
  const HIGH_RISK = 60;
  const BANNER_ID = "__phishguard_warning";
  const allowedForms = new WeakSet();
  let lastFingerprint = "";
  let lastResult = { score: 0, findings: [] };
  let queued = false;

  function hasPasswordField(form) {
    return Boolean(Element.prototype.querySelector.call(form, 'input[type="password"]'));
  }
  function formAction(form) {
    return Element.prototype.getAttribute.call(form, "action") || "";
  }
  function pageFacts() {
    const forms = Array.from(document.forms).slice(0, 30).map((form) => ({
      hasPassword: hasPasswordField(form),
      action: formAction(form)
    }));
    const hiddenIframes = Array.from(document.querySelectorAll("iframe")).slice(0, 50).filter((frame) => {
      const style = getComputedStyle(frame);
      return style.display === "none" || style.visibility === "hidden" || frame.width === "0" || frame.height === "0";
    }).length;
    const text = (document.body?.innerText || "").slice(0, 50000);
    return {
      url: location.href,
      forms,
      hiddenIframes,
      loginLanguage: /\b(sign in|log in|iniciar sesi[oó]n|contrase[nñ]a|password)\b/i.test(text),
      redirectCount: Math.min(5, performance.getEntriesByType("navigation")[0]?.redirectCount || 0)
    };
  }

  function showWarning(result) {
    if (result.score < HIGH_RISK || document.getElementById(BANNER_ID)) return;
    const host = document.createElement("div");
    host.id = BANNER_ID;
    host.setAttribute("role", "alert");
    const shadow = host.attachShadow({ mode: "closed" });
    const box = document.createElement("section");
    const title = document.createElement("strong");
    const message = document.createElement("span");
    title.textContent = "PhishGuard: posible phishing";
    message.textContent = " Se detectaron señales de alto riesgo. No introduzcas contraseñas ni datos bancarios hasta verificar el dominio.";
    box.append(title, message);
    const style = document.createElement("style");
    style.textContent = ":host{all:initial}section{position:fixed;z-index:2147483647;top:16px;left:16px;right:16px;padding:14px 18px;border:2px solid #fecaca;border-radius:10px;background:#7f1d1d;color:#fff;font:600 15px/1.4 system-ui,sans-serif;box-shadow:0 8px 24px #0008;}";
    shadow.append(style, box);
    document.documentElement.append(host);
  }

  function scan() {
    queued = false;
    if (!document.documentElement) return;
    const result = PhishGuardRules.inspectPage(pageFacts());
    lastResult = result;
    const fingerprint = `${location.href}:${result.score}:${result.findings.map((item) => item.code).join(",")}`;
    if (fingerprint === lastFingerprint) return;
    lastFingerprint = fingerprint;
    showWarning(result);
    chrome.runtime.sendMessage({ type: "PHISHGUARD_RESULT", score: result.score, findings: result.findings });
  }
  function scheduleScan() {
    if (!queued) { queued = true; setTimeout(scan, 500); }
  }

  document.addEventListener("submit", (event) => {
    const form = event.target;
    if (!(form instanceof HTMLFormElement) || !hasPasswordField(form) || allowedForms.has(form)) return;
    lastResult = PhishGuardRules.inspectPage(pageFacts());
    if (lastResult.score < HIGH_RISK) return;
    event.preventDefault();
    event.stopImmediatePropagation();
    const proceed = globalThis.confirm("PhishGuard detectó señales de phishing de alto riesgo. Verifica el dominio. ¿Deseas enviar este formulario de todos modos?");
    if (!proceed) return;
    allowedForms.add(form);
    queueMicrotask(() => {
      try { form.requestSubmit(event.submitter || undefined); }
      finally { setTimeout(() => allowedForms.delete(form), 0); }
    });
  }, true);

  scan();
  new MutationObserver(scheduleScan).observe(document.documentElement, { childList: true, subtree: true });
  addEventListener("popstate", scheduleScan, { passive: true });
  addEventListener("hashchange", scheduleScan, { passive: true });
}());