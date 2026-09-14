const THRESHOLD = 60;

function level(score) {
  if (score >= THRESHOLD) return "danger";
  if (score >= 30) return "warning";
  return "safe";
}

chrome.runtime.onMessage.addListener((message, sender) => {
  if (message.type !== "PHISHGUARD_RESULT" || !sender.tab?.id) return;
  const result = { score: message.score, findings: message.findings, url: message.url, level: level(message.score) };
  chrome.storage.session.set({ [`tab:${sender.tab.id}`]: result });
  chrome.action.setBadgeText({ tabId: sender.tab.id, text: result.score ? String(result.score) : "" });
  chrome.action.setBadgeBackgroundColor({
    tabId: sender.tab.id,
    color: result.level === "danger" ? "#b91c1c" : result.level === "warning" ? "#b45309" : "#15803d"
  });
});