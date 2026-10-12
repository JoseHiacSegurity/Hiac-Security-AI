import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";

const source = readFileSync(new URL("../src/rules.js", import.meta.url), "utf8");
const context = { window: {}, URL, Set, Object, Array, Math };
vm.runInNewContext(source, context, { filename: "src/rules.js" });
const { inspectPage } = context.window.PhishGuardRules;

function inspect(overrides = {}) {
  return inspectPage({
    url: "https://accounts.example.test/login",
    forms: [{ hasPassword: true, action: "/session" }],
    hiddenIframes: 0,
    loginLanguage: true,
    redirectCount: 0,
    ...overrides
  });
}
function has(result, code) { return result.findings.some((finding) => finding.code === code); }

{
  const result = inspect({ url: "https://accounts.google.com/signin" });
  assert.equal(result.score, 0, "un dominio oficial no debe marcarse por parecerse a sí mismo");
}
{
  const result = inspect({ url: "http://portal.example.test/login" });
  assert.ok(result.score >= 60);
  assert.ok(has(result, "INSECURE_PASSWORD_FORM"));
}
{
  const result = inspect({ url: "https://micros0ft-seguro.zip/login" });
  assert.ok(result.score >= 60);
  assert.ok(has(result, "LOOKALIKE_DOMAIN"));
  assert.ok(has(result, "SUSPICIOUS_TLD"));
}
{
  const result = inspect({ forms: [{ hasPassword: true, action: "https://receiver.evil.test/collect" }] });
  assert.ok(has(result, "CROSS_DOMAIN_LOGIN"));
  assert.ok(result.score >= 55);
}
{
  const result = inspect({ forms: [{ hasPassword: true, action: "http://accounts.example.test/session" }] });
  assert.ok(result.score >= 60);
  assert.ok(has(result, "INSECURE_FORM_ACTION"));
}
{
  const result = inspect({ url: "https://xn--paypa1-example.test/login", hiddenIframes: 1, redirectCount: 2 });
  assert.ok(has(result, "PUNYCODE"));
  assert.ok(has(result, "HIDDEN_IFRAME"));
  assert.ok(has(result, "MULTIPLE_REDIRECTS"));
}

console.log("Reglas PhishGuard: todas las pruebas superadas.");
