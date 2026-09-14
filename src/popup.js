const status = document.querySelector("#status");
const score = document.querySelector("#score");
const findings = document.querySelector("#findings");

chrome.tabs.query({ active: true, currentWindow: true }, ([tab]) => {
  chrome.storage.session.get(`tab:${tab.id}`, (data) => {
    const result = data[`tab:${tab.id}`];
    if (!result) { status.textContent = "Sin resultado para esta página."; return; }
    status.textContent = result.level === "danger" ? "Riesgo alto: verifica el sitio." : result.level === "warning" ? "Riesgo moderado: procede con cautela." : "No se detectaron señales importantes.";
    status.className = result.level;
    score.textContent = `Puntuación: ${result.score}/100`;
    result.findings.forEach((finding) => {
      const item = document.createElement("li");
      item.textContent = finding.message;
      findings.append(item);
    });
  });
});