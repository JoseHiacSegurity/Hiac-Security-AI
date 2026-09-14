/* Motor local, explicable y sin acceso a valores de formularios. */
(function exposeRules() {
  const BRAND_DOMAINS = {
    google: ["google.com", "google.es"],
    microsoft: ["microsoft.com", "live.com", "office.com"],
    apple: ["apple.com"],
    amazon: ["amazon.com", "amazon.es"],
    paypal: ["paypal.com"],
    facebook: ["facebook.com", "fb.com"],
    instagram: ["instagram.com"],
    linkedin: ["linkedin.com"],
    netflix: ["netflix.com"],
    dropbox: ["dropbox.com"],
    github: ["github.com"]
  };
  const SUSPICIOUS_TLDS = new Set(["zip", "mov", "top", "xyz", "click", "gq", "tk", "work", "support", "rest", "country"]);
  const MAX_FINDINGS = 12;

  function isSubdomainOf(host, domain) { return host === domain || host.endsWith(`.${domain}`); }
  function trustedBrand(host) {
    return Object.entries(BRAND_DOMAINS).find(([, domains]) => domains.some((domain) => isSubdomainOf(host, domain)))?.[0] || null;
  }
  function distance(a, b) {
    if (Math.abs(a.length - b.length) > 1) return 2;
    const rows = Array.from({ length: a.length + 1 }, (_, i) => [i]);
    for (let j = 1; j <= b.length; j += 1) rows[0][j] = j;
    for (let i = 1; i <= a.length; i += 1) {
      for (let j = 1; j <= b.length; j += 1) {
        rows[i][j] = a[i - 1] === b[j - 1] ? rows[i - 1][j - 1] : Math.min(rows[i - 1][j] + 1, rows[i][j - 1] + 1, rows[i - 1][j] + 1);
      }
    }
    return rows[a.length][b.length];
  }
  function lookalikeBrand(host) {
    if (trustedBrand(host)) return null;
    const labels = host.split(".");
    return Object.keys(BRAND_DOMAINS).find((brand) => labels.some((label) => {
      const normalized = label.replace(/[0o]/g, "o").replace(/[1il]/g, "i");
      return (label.length >= 4 && distance(label, brand) <= 1) || (normalized !== label && distance(normalized, brand) <= 1);
    })) || null;
  }
  function add(findings, points, code, message) {
    if (findings.length < MAX_FINDINGS && !findings.some((item) => item.code === code)) findings.push({ points, code, message });
  }
  function safeUrl(value, base) {
    try {
      const url = new URL(value, base);
      return (url.protocol === "http:" || url.protocol === "https:") ? url : null;
    } catch { return null; }
  }

  function inspectPage({ url, forms, hiddenIframes, loginLanguage, redirectCount }) {
    const findings = [];
    const parsed = safeUrl(url);
    if (!parsed) return { score: 0, findings };
    const host = parsed.hostname.toLowerCase().replace(/\.$/, "");
    const hasPasswordForm = forms.some((form) => form.hasPassword);
    const suspiciousTld = host.split(".").at(-1);
    const officialBrand = trustedBrand(host);

    if (parsed.protocol === "http:" && hasPasswordForm) add(findings, 45, "INSECURE_PASSWORD_FORM", "Formulario de contraseña en una página sin HTTPS.");
    if (host.includes("xn--")) add(findings, 30, "PUNYCODE", "El dominio usa punycode; puede imitar visualmente caracteres.");
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(":")) add(findings, 25, "IP_HOST", "La URL usa una dirección IP en lugar de un dominio.");
    if (parsed.username || /%40|@/i.test(url)) add(findings, 20, "URL_AT", "La URL contiene una arroba, una técnica para ocultar el destino.");
    if (/%[0-9a-f]{2}/i.test(parsed.pathname) && hasPasswordForm) add(findings, 10, "ENCODED_URL", "La URL codifica caracteres junto a un formulario de acceso.");
    if (SUSPICIOUS_TLDS.has(suspiciousTld) && hasPasswordForm) add(findings, 15, "SUSPICIOUS_TLD", "El sitio de acceso usa un dominio de alto riesgo histórico.");
    const brand = lookalikeBrand(host);
    if (brand) add(findings, 45, "LOOKALIKE_DOMAIN", `El dominio se parece a la marca “${brand}”, pero no es un dominio oficial conocido.`);
    if (hiddenIframes > 0) add(findings, 15, "HIDDEN_IFRAME", "La página contiene iframe(s) oculto(s).");
    if (redirectCount >= 2) add(findings, 15, "MULTIPLE_REDIRECTS", "La página realizó varias redirecciones antes de cargar.");

    forms.forEach((form) => {
      if (!form.hasPassword) return;
      if (!form.action) { add(findings, 10, "EMPTY_ACTION", "El formulario de contraseña no declara un destino."); return; }
      const action = safeUrl(form.action, url);
      if (!action) { add(findings, 20, "MALFORMED_ACTION", "El formulario tiene un destino no HTTP válido."); return; }
      if (action.hostname.toLowerCase() !== host) add(findings, 40, "CROSS_DOMAIN_LOGIN", "El formulario de contraseña envía datos a otro dominio.");
      if (action.protocol !== "https:") add(findings, 30, "INSECURE_FORM_ACTION", "El formulario envía datos a un destino sin HTTPS.");
    });
    if (hasPasswordForm && loginLanguage && host.split(".").length > 3 && !officialBrand) add(findings, 10, "LOGIN_ON_DEEP_SUBDOMAIN", "Inicio de sesión en un subdominio inusual.");
    return { score: Math.min(100, findings.reduce((sum, item) => sum + item.points, 0)), findings };
  }
  window.PhishGuardRules = { inspectPage };
}());