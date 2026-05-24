document.addEventListener("DOMContentLoaded", function () {
  const resultDiv = document.getElementById("result");
  const loadingDiv = document.getElementById("loading");
  const historyDiv = document.getElementById("history");

  loadingDiv.style.display = "block";
  resultDiv.textContent = "Checking current tab...";

  // Force a fresh scan
  chrome.runtime.sendMessage({ action: "scanCurrentTab" }, (response) => {
    loadingDiv.style.display = "none";

    if (chrome.runtime.lastError) {
      resultDiv.innerHTML = `
        <div class="error">❌ Popup → background error<br>
        <small>${chrome.runtime.lastError.message}</small></div>`;
      return;
    }

    if (!response) {
      resultDiv.innerHTML = `<div class="error">❌ No response from background</div>`;
      return;
    }

    if (response.error) {
      resultDiv.innerHTML = `
        <div class="error">
          ❌ Error checking URL<br>
          <small>${response.error}</small>
        </div>`;
      return;
    }

    const verdict = response.isPhishing ? "❌ Phishing" : "✅ Safe";
    const verdictClass = response.isPhishing ? "phishing" : "safe";

    resultDiv.innerHTML = `
      <div class="${verdictClass}">
        <strong>${verdict}</strong><br>
        <small>${response.url}</small>
      </div>
    `;

    // Explainable AI
    const xaiBox = document.getElementById("xai-box");
    const reasonsUl = document.getElementById("xai-reasons");
    if (xaiBox && reasonsUl) {
      reasonsUl.innerHTML = "";
      if (response.reasons && response.reasons.length) {
        xaiBox.style.display = "block";
        response.reasons.forEach((r) => {
          const li = document.createElement("li");
          li.textContent = r;
          reasonsUl.appendChild(li);
        });
      } else {
        xaiBox.style.display = "none";
      }
    }
  });

  // History (unchanged)
  function loadHistory() {
    chrome.runtime.sendMessage({ action: "getHistory" }, (history) => {
      if (!historyDiv || !Array.isArray(history)) return;
      historyDiv.innerHTML = "";
      history.forEach((entry) => {
        const el = document.createElement("div");
        el.className = `history-entry ${entry.isPhishing ? 'phishing' : 'safe'}`;
        el.innerHTML = `
          <div>
            <strong>${entry.isPhishing ? '❌ Phishing' : '✅ Safe'}</strong>
            <a href="https://safebrowsing.google.com/safebrowsing/report_phish/?url=${encodeURIComponent(entry.url)}"
               target="_blank" class="report-link">Report</a>
          </div>
          <div class="url">${entry.url}</div>
          <div class="time">Scanned at: ${entry.timestamp}</div>
        `;
        historyDiv.appendChild(el);
      });
    });
  }

  loadHistory();
  setInterval(loadHistory, 5000);
});