// PhishGuard Frontend Interactions
document.addEventListener("DOMContentLoaded", function () {
  // Initialize URL analysis form if present
  const urlForm = document.getElementById("urlAnalysisForm");
  if (urlForm) {
    urlForm.addEventListener("submit", async function (e) {
      e.preventDefault();
      const urlInput = document.getElementById("targetUrl").value;
      const resultsDiv = document.getElementById("urlResults");
      const submitBtn = urlForm.querySelector("button[type='submit']");

      submitBtn.disabled = true;
      submitBtn.innerHTML = "Analyzing Indicators...";
      resultsDiv.classList.remove("d-none");
      resultsDiv.innerHTML = `<div class="text-center py-4 text-muted"><div class="spinner-border text-info mb-2" role="status"></div><p>Evaluating heuristic features and entropy...</p></div>`;

      try {
        const response = await fetch("/analyze/url", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url: urlInput })
        });
        const data = await response.json();
        renderURLResults(data, resultsDiv);
      } catch (err) {
        resultsDiv.innerHTML = `<div class="alert alert-danger">Analysis error: ${err.message}</div>`;
      } finally {
        submitBtn.disabled = false;
        submitBtn.innerHTML = "Analyze URL";
      }
    });
  }

  // Initialize Email analysis form if present
  const emailForm = document.getElementById("emailAnalysisForm");
  if (emailForm) {
    emailForm.addEventListener("submit", async function (e) {
      e.preventDefault();
      const subject = document.getElementById("emailSubject").value;
      const sender = document.getElementById("emailSender").value;
      const body = document.getElementById("emailBody").value;
      const resultsDiv = document.getElementById("emailResults");
      const submitBtn = emailForm.querySelector("button[type='submit']");

      submitBtn.disabled = true;
      submitBtn.innerHTML = "Inspecting Email...";
      resultsDiv.classList.remove("d-none");
      resultsDiv.innerHTML = `<div class="text-center py-4 text-muted"><div class="spinner-border text-primary mb-2" role="status"></div><p>Extracting social engineering patterns & ML vectors...</p></div>`;

      try {
        const response = await fetch("/analyze/email", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ subject, sender, body })
        });
        const data = await response.json();
        renderEmailResults(data, resultsDiv);
      } catch (err) {
        resultsDiv.innerHTML = `<div class="alert alert-danger">Analysis error: ${err.message}</div>`;
      } finally {
        submitBtn.disabled = false;
        submitBtn.innerHTML = "Analyze Email Content";
      }
    });
  }
});

function getBadgeClass(level) {
  switch (level) {
    case "SAFE": return "badge-safe";
    case "LOW": return "badge-low";
    case "MEDIUM": return "badge-medium";
    case "HIGH": return "badge-high";
    case "CRITICAL": return "badge-critical";
    default: return "bg-secondary";
  }
}

function getMeterColor(score) {
  if (score <= 15) return "#10b981";
  if (score <= 40) return "#3b82f6";
  if (score <= 65) return "#f59e0b";
  return "#ef4444";
}

function renderURLResults(data, container) {
  let findingsHtml = "";
  if (data.findings && data.findings.length > 0) {
    findingsHtml = data.findings.map(f => `
      <div class="p-2 mb-2 rounded border border-secondary border-opacity-25 bg-dark">
        <div class="d-flex justify-content-between align-items-center">
          <strong class="text-light">${f.description}</strong>
          <span class="badge ${getBadgeClass(f.severity)}">${f.severity}</span>
        </div>
        ${f.details ? `<div class="small text-muted mt-1">${f.details}</div>` : ""}
      </div>
    `).join("");
  } else {
    findingsHtml = `<div class="text-success small">No high-risk URL indicators detected.</div>`;
  }

  container.innerHTML = `
    <div class="cyber-card p-4 mt-3">
      <div class="d-flex justify-content-between align-items-center mb-3">
        <h5 class="m-0 text-light">URL Risk Assessment</h5>
        <span class="badge ${getBadgeClass(data.risk_level)} px-3 py-2 fs-6">${data.risk_level}</span>
      </div>
      <div class="mb-3">
        <div class="d-flex justify-content-between small text-muted mb-1">
          <span>Threat Score</span>
          <span class="fw-bold text-light">${data.risk_score} / 100</span>
        </div>
        <div class="risk-meter">
          <div class="risk-meter-fill" style="width: ${data.risk_score}%; background-color: ${getMeterColor(data.risk_score)};"></div>
        </div>
      </div>
      <div class="row g-2 mb-3 small">
        <div class="col-6"><span class="text-muted">SSL Encrypted:</span> <strong class="text-light">${data.has_ssl ? "Yes (HTTPS)" : "No (HTTP)"}</strong></div>
        <div class="col-6"><span class="text-muted">Shortened:</span> <strong class="text-light">${data.is_shortened ? "Yes" : "No"}</strong></div>
      </div>
      <h6 class="text-muted text-uppercase small mb-2">Findings (${data.findings ? data.findings.length : 0})</h6>
      ${findingsHtml}
    </div>
  `;
}

function renderEmailResults(data, container) {
  let tacticsHtml = "";
  if (data.social_engineering_tactics && data.social_engineering_tactics.length > 0) {
    tacticsHtml = data.social_engineering_tactics.map(t => `
      <div class="p-2 mb-2 rounded bg-dark border border-secondary border-opacity-25">
        <span class="badge bg-warning text-dark me-2">${t.tactic.toUpperCase()}</span>
        <span class="small text-light">${t.description}</span>
      </div>
    `).join("");
  } else {
    tacticsHtml = `<div class="text-muted small">No prominent social engineering manipulation flags.</div>`;
  }

  let findingsHtml = "";
  if (data.findings && data.findings.length > 0) {
    findingsHtml = data.findings.map(f => `
      <li class="mb-1 text-light small">
        <span class="badge ${getBadgeClass(f.severity)} me-1">${f.severity}</span>
        ${f.description}
      </li>
    `).join("");
  } else {
    findingsHtml = `<li class="text-success small">No security anomalies flagged.</li>`;
  }

  container.innerHTML = `
    <div class="cyber-card p-4 mt-3">
      <div class="d-flex justify-content-between align-items-center mb-3">
        <h5 class="m-0 text-light">Email Phishing Inspection</h5>
        <span class="badge ${getBadgeClass(data.risk_level)} px-3 py-2 fs-6">${data.risk_level}</span>
      </div>
      <div class="mb-3">
        <div class="d-flex justify-content-between small text-muted mb-1">
          <span>Overall Phishing Score</span>
          <span class="fw-bold text-light">${data.risk_score} / 100</span>
        </div>
        <div class="risk-meter">
          <div class="risk-meter-fill" style="width: ${data.risk_score}%; background-color: ${getMeterColor(data.risk_score)};"></div>
        </div>
      </div>
      <div class="alert alert-dark border-secondary small mb-3">
        <strong>Recommended Action:</strong> ${data.recommended_action || "Report or inspect carefully."}
      </div>
      <h6 class="text-muted text-uppercase small mb-2">Social Engineering Flags</h6>
      <div class="mb-3">${tacticsHtml}</div>
      <h6 class="text-muted text-uppercase small mb-2">Analysis Findings</h6>
      <ul class="ps-3 mb-0">${findingsHtml}</ul>
    </div>
  `;
}
