const HIGH_RISK = 60;
const MAX_FINDINGS = 12;

function level(score) {
  if (score >= HIGH_RISK) return "danger";
  if (score >= 30) return "warning";
  return "safe";
}
function sanitize(message) {
  if (!message || typeof message.score !== "number" || !Number.isFinite(message.score) || !Array.isArray(message.findings)) return null;
  const findings = message.findings.slice(0, MAX_FINDINGS)
    .filter((item) => item && typeof item.code === "string" && typeof item.message === "string" && Number.isFinite(item.points))
    .map((item) => ({ code: item.code.slice(0, 64), message: item.message.slice(0, 240), points: Math.max(0, Math.min(100, item.points)) }));
  return { score: Math.max(0, Math.min(100, Math.round(message.score))), findings };
}

chrome.runtime.onMessage.addListener((message, sender) => {
  if (message?.type !== "PHISHGUARD_RESULT" || !sender.tab?.id || !sender.url?.startsWith("http")) return;
  const data = sanitize(message);
  if (!data) return;
  const result = { ...data, level: level(data.score) };
  chrome.storage.session.set({ [`tab:${sender.tab.id}`]: result });
  chrome.action.setBadgeText({ tabId: sender.tab.id, text: result.score ? String(result.score) : "" });
  chrome.action.setBadgeBackgroundColor({ tabId: sender.tab.id, color: result.level === "danger" ? "#b91c1c" : result.level === "warning" ? "#b45309" : "#15803d" });
  chrome.action.setTitle({ tabId: sender.tab.id, title: result.level === "danger" ? "PhishGuard: riesgo alto" : result.level === "warning" ? "PhishGuard: procede con cautela" : "PhishGuard: sin señales importantes" });
});

chrome.tabs?.onRemoved?.addListener((tabId) => chrome.storage.session.remove(`tab:${tabId}`));