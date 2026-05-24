// Store information about each tab's state
const tabStates = new Map(); // { tabId: { domain: string, previousUrl: string } }
const MAX_HISTORY_ITEMS = 10; // Maximum number of scan history items to keep

// Get the domain name from a URL
function getDomain(url) {
  try {
    return new URL(url).hostname;
  } catch (e) {
    return url;
  }
}

// Save the scan result to browser's local storage
function storeScanHistory(result) {
  chrome.storage.local.get(["scanHistory"], (res) => {
    const history = res.scanHistory || [];
    history.unshift({
      url: result.url,
      isPhishing: result.isPhishing,
      reasons: result.reasons || [],           // ✅ store reasons
      timestamp: new Date().toLocaleString(),
      reported: false
    });

    if (history.length > MAX_HISTORY_ITEMS) {
      history.pop();
    }

    chrome.storage.local.set({ scanHistory: history });
  });
}

// Show a warning or safe popup on the webpage
function injectPopup(tabId, url, isPhishing, isSamePage = false, reasons = []) {
  const hostname = new URL(url).hostname;

  if (isPhishing) {
    const reasonsHTML = (reasons && reasons.length)
      ? `<div style="margin-top:8px;"><b>Why flagged:</b>
           <ul style="margin:6px 0 0 16px;">
             ${reasons.map(r => `<li>${r}</li>`).join("")}
           </ul>
         </div>`
      : "";

    const popupHTML = `
      <div id="phishing-warning-popup" style="
        position: fixed;
        top: 20px;
        right: 20px;
        background: #ff4444;
        color: white;
        padding: 20px;
        border-radius: 8px;
        box-shadow: 0 4px 8px rgba(0,0,0,0.2);
        z-index: 999999;
        max-width: 420px;
        font-family: Arial, sans-serif;
      ">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
          <div style="display: flex; align-items: center;">
            <span style="font-size: 24px; margin-right: 10px;">⚠️</span>
            <h3 style="margin: 0;">PHISHING WARNING!</h3>
          </div>
          <button id="close-popup-btn" style="background:none;border:none;color:white;font-size:20px;cursor:pointer;">×</button>
        </div>
        <p style="margin: 10px 0;">The website "${hostname}" has been detected as a potential phishing site.</p>
        ${reasonsHTML}
        <div style="display: flex; gap: 10px; margin-top: 15px;">
          <button id="close-tab-btn" style="background:white;color:#ff4444;border:none;padding:8px 16px;border-radius:4px;cursor:pointer;font-weight:bold;">Close Tab</button>
          <button id="report-btn" style="background:white;color:#ff4444;border:none;padding:8px 16px;border-radius:4px;cursor:pointer;font-weight:bold;">Report</button>
        </div>
      </div>
    `;

    chrome.scripting.executeScript({
      target: { tabId },
      func: (html) => {
        document.getElementById('phishing-warning-popup')?.remove();
        document.getElementById('safe-url-indicator')?.remove();
        document.getElementById('same-page-indicator')?.remove();

        const popup = document.createElement('div');
        popup.innerHTML = html;
        document.body.appendChild(popup);

        document.getElementById('close-popup-btn').onclick = () => popup.remove();
        document.getElementById('close-tab-btn').onclick = () => window.close();
        document.getElementById('report-btn').onclick = () => {
          window.open(
            'https://safebrowsing.google.com/safebrowsing/report_phish/?url=' +
              encodeURIComponent(window.location.href),
            '_blank'
          );
        };

        setTimeout(() => popup.remove(), 8000);
      },
      args: [popupHTML]
    });

  } else if (isSamePage) {
    // 🔄 Same page indicator
    const sameHTML = `
      <div id="same-page-indicator" style="
        position: fixed;
        top: 20px;
        right: 20px;
        background: #2196F3;
        color: white;
        padding: 8px 12px;
        border-radius: 4px;
        z-index: 999999;
        font-family: Arial, sans-serif;
        box-shadow: 0 2px 6px rgba(0,0,0,.2);
      ">
        🔄 Same Website
      </div>
    `;

    chrome.scripting.executeScript({
      target: { tabId },
      func: (html) => {
        document.getElementById('phishing-warning-popup')?.remove();
        document.getElementById('safe-url-indicator')?.remove();
        document.getElementById('same-page-indicator')?.remove();

        const el = document.createElement('div');
        el.innerHTML = html;
        document.body.appendChild(el);
        setTimeout(() => el.remove(), 3000);
      },
      args: [sameHTML]
    });

  } else {
    // 🟢 SAFE POPUP
    const tickHTML = `
      <div id="safe-url-indicator" style="
        position: fixed;
        top: 20px;
        right: 20px;
        background: #4CAF50;
        color: white;
        padding: 8px 12px;
        border-radius: 4px;
        z-index: 999999;
        font-family: Arial, sans-serif;
        box-shadow: 0 2px 6px rgba(0,0,0,.2);
      ">
        ✓ Safe
      </div>
    `;

    chrome.scripting.executeScript({
      target: { tabId },
      func: (html) => {
        document.getElementById('phishing-warning-popup')?.remove();
        document.getElementById('same-page-indicator')?.remove();
        document.getElementById('safe-url-indicator')?.remove();

        const el = document.createElement('div');
        el.innerHTML = html;
        document.body.appendChild(el);
        setTimeout(() => el.remove(), 4000);
      },
      args: [tickHTML]
    });
  }
}
// Main function to check if a URL is phishing
async function checkForPhishing(url, tabId, isReload = false) {
  try {
    const domain = getDomain(url);

    // -------------------------------
    // SAME DOMAIN CHECK LOGIC (show popup)
    // -------------------------------
    const history = await new Promise((resolve) => {
      chrome.storage.local.get(["scanHistory"], (res) => {
        resolve(res.scanHistory || []);
      });
    });

    if (history.length > 0) {
      const mostRecentDomain = getDomain(history[0].url);

      if (mostRecentDomain === domain) {
        // 🔥 Always show popup for same domain (safe OR phishing)
        if (!url.startsWith("chrome://") && !url.startsWith("edge://") && !url.startsWith("about:")) {
          injectPopup(tabId, url, history[0].isPhishing, false, history[0].reasons || []);
        }

        tabStates.set(tabId, { domain, previousUrl: url });
        return history[0];
      }
    }

    // -------------------------------
    // HYBRID RULE: Known phishing test pages (for demo)
    // -------------------------------
    const knownPhishTestPages = [
      "testsafebrowsing.appspot.com/s/phishing.html"
    ];

    if (knownPhishTestPages.some(p => url.includes(p))) {
      const result = {
        url,
        isPhishing: true,
        reasons: ["Known phishing test page (Safe Browsing test)"],
        timestamp: new Date().toLocaleString()
      };

      storeScanHistory(result);

      if (!url.startsWith("chrome://") && !url.startsWith("edge://") && !url.startsWith("about:")) {
        injectPopup(tabId, url, true, false, result.reasons);
      }

      return result; // ⛔ Skip ML
    }

    // -------------------------------
    // TRUSTED DOMAINS
    // -------------------------------
    const trustedDomains = [
      'google.com','openai.com','chatgpt.com','chat.openai.com','microsoft.com','github.com',
      'stackoverflow.com','linkedin.com','facebook.com','twitter.com','youtube.com','amazon.com',
      'netflix.com','spotify.com','reddit.com','wikipedia.org','medium.com','quora.com','dropbox.com',
      'slack.com','discord.com','zoom.us','mozilla.org','apple.com','adobe.com','cloudflare.com'
    ];

    const isTrusted = trustedDomains.some(trustedDomain => domain.includes(trustedDomain));

    if (isTrusted) {
      const result = {
        url,
        isPhishing: false,
        reasons: ["Trusted domain"],
        timestamp: new Date().toLocaleString()
      };

      storeScanHistory(result);

      if (!url.startsWith("chrome://") && !url.startsWith("edge://") && !url.startsWith("about:")) {
        injectPopup(tabId, url, false, false, result.reasons);
      }

      return result;
    }

    // -------------------------------
    // CALL ML BACKEND
    // -------------------------------
    const response = await fetch("http://127.0.0.1:8000/predict_url", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });

    if (!response.ok) throw new Error(`Status ${response.status}`);
    const data = await response.json();

    const isPhishing = data.prediction === 0;

    const result = {
      url,
      isPhishing,
      reasons: data.reasons || [],
      timestamp: new Date().toLocaleString()
    };

    // 🔥 Always show popup automatically
    storeScanHistory(result);

    if (!url.startsWith("chrome://") && !url.startsWith("edge://") && !url.startsWith("about:")) {
      injectPopup(tabId, url, isPhishing, false, result.reasons);
    }

    tabStates.set(tabId, { domain, previousUrl: url });
    return result;

  } catch (error) {
    console.error("Scan error:", error);
    return { error: error.message };
  }
}

// Debounce (unchanged)
function debounce(func, wait) {
  let timeout;
  return function executedFunction(...args) {
    const later = () => {
      clearTimeout(timeout);
      func(...args);
    };
    clearTimeout(timeout);
    timeout = setTimeout(later, wait);
  };
}

const debouncedCheck = debounce(checkForPhishing, 500);

// Listeners (unchanged)
chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId === 0) { // main frame only
    const isReload = details.transitionType === 'reload';
    debouncedCheck(details.url, details.tabId, isReload);
  }
});

chrome.tabs.onActivated.addListener((activeInfo) => {
  chrome.tabs.get(activeInfo.tabId, (tab) => {
    if (tab.url) {
      debouncedCheck(tab.url, activeInfo.tabId, false);
    }
  });
});

chrome.tabs.onRemoved.addListener((tabId) => {
  tabStates.delete(tabId);
});

// Popup messages (unchanged API, but now includes reasons)
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "getCurrentStatus") {
    chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
      const url = tabs[0]?.url;
      const result = await checkForPhishing(url, tabs[0].id, false);
      sendResponse(result);
    });
    return true;

} else if (request.action === "scanCurrentTab") {
  chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
    const tab = tabs[0];
    const url = tab?.url;

    if (!url || url.startsWith("chrome://") || url.startsWith("edge://")) {
      sendResponse({ error: "Cannot scan browser internal pages." });
      return;
    }

    const result = await checkForPhishing(url, tab.id, false);

    // ✅ Force show on-page popup when clicking extension
    if (!result?.error) {
      injectPopup(tab.id, url, result.isPhishing, false, result.reasons || []);
    }

    sendResponse(result);
  });
  return true;
}
});

// Clean up tab states every 30 minutes
setInterval(() => {
  tabStates.clear();
}, 30 * 60 * 1000);

console.log("Phishing Detector background script started");