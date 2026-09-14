/* Motor local y explicable. No lee valores de campos ni transmite datos. */
(function exposeRules() {
  const BRANDS = ["google", "microsoft", "apple", "amazon", "paypal", "facebook", "instagram", "linkedin", "netflix", "dropbox", "github", "banco"];

  function distance(a, b) {
    const rows = Array.from({ length: a.length + 1 }, (_, i) => [i]);
    for (let j = 1; j <= b.length; j += 1) rows[0][j] = j;
    for (let i = 1; i <= a.length; i += 1) {
      for (let j = 1; j <= b.length; j += 1) {
        rows[i][j] = a[i - 1] === b[j - 1] ? rows[i - 1][j - 1] : Math.min(rows[i - 1][j] + 1, rows[i][j - 1] + 1, rows[i - 1][j] + 1);
      }
    }
    return rows[a.length][b.length];
  }

  function isBrandLookalike(hostname) {
    const labels = hostname.toLowerCase().split(".");
    return BRANDS.find((brand) => labels.some((label) => label !== brand && label.length > 3 && distance(label, brand) <= 1));
  }

  function add(findings, points, code, message) { findings.push({ points, code, message }); }

  function inspectPage({ url, forms, hiddenIframes, loginLanguage }) {
    const findings = [];
    let parsed;
    try { parsed = new URL(url); } catch { return { score: 0, findings }; }
    const host = parsed.hostname.toLowerCase();
    const hasPasswordForm = forms.some((form) => form.hasPassword);

    if (parsed.protocol === "http:" && hasPasswordForm) add(findings, 45, "INSECURE_PASSWORD_FORM", "Formulario de contraseña en una página sin HTTPS.");
    if (host.startsWith("xn--")) add(findings, 30, "PUNYCODE", "El dominio usa punycode y puede imitar caracteres.");
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) add(findings, 25, "IP_HOST", "La URL usa una dirección IP en vez de un dominio.");
    if (parsed.username || url.includes("@")) add(findings, 20, "URL_AT", "La URL contiene una arroba, una técnica para ocultar el destino.");
    const brand = isBrandLookalike(host);
    if (brand) add(findings, 40, "LOOKALIKE_DOMAIN", `El dominio se parece a la marca “${brand}”.`);
    if (hiddenIframes > 0) add(findings, 15, "HIDDEN_IFRAME", "La página contiene iframe(s) oculto(s).");

    forms.forEach((form) => {
      if (!form.hasPassword || !form.action) return;
      try {
        const actionHost = new URL(form.action, url).hostname.toLowerCase();
        if (actionHost && actionHost !== host) add(findings, 40, "CROSS_DOMAIN_LOGIN", "El formulario de contraseña envía datos a otro dominio.");
      } catch { add(findings, 15, "MALFORMED_ACTION", "El formulario tiene un destino no válido."); }
    });
    if (hasPasswordForm && loginLanguage && host.split(".").length > 3) add(findings, 10, "LOGIN_ON_DEEP_SUBDOMAIN", "Inicio de sesión en un subdominio inusual.");

    return { score: Math.min(100, findings.reduce((sum, item) => sum + item.points, 0)), findings };
  }

  window.PhishGuardRules = { inspectPage };
}());