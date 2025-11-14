// ================== TerraPhish Background Script (OPTIMIZED) ==================

// --- Cached blocked URLs ---
let blockedUrls = [];
let blockedSet = new Set();
let scanDebounce = new Map(); // Throttle per-tab

// --- Domains to ignore ---
const ignoredDomains = ["localhost", "127.0.0.1"];

// ================== Helpers ==================

// --- Normalize URL ---
function normalizeUrl(url) {
  try {
    const u = new URL(url);
    const host = u.hostname.toLowerCase();
    let path = (u.pathname || "").replace(/\/$/, "");
    if (!path || path === "/") path = "";
    return (host + path).toLowerCase();
  } catch {
    return url.toLowerCase().replace(/\/$/, "");
  }
}

// --- Add to cache ---
function addToBlockedCache(url) {
  const normUrl = normalizeUrl(url);
  if (!blockedSet.has(normUrl)) {
    blockedUrls.push(normUrl);
    blockedSet.add(normUrl);
    chrome.storage.local.set({ blockedUrls });
    console.log("✅ Cached:", normUrl);
  }
}

// --- FAST LOCAL CHECK (1st priority) ---
function isBlocked(url) {
  return blockedSet.has(normalizeUrl(url));
}

// --- INSTANT REDIRECT ---
function redirectIfBlocked(tabId, url) {
  if (url.startsWith(chrome.runtime.getURL("blocked.html"))) return false;
  if (isBlocked(url)) {
    const blockedPage = chrome.runtime.getURL(`blocked.html?url=${encodeURIComponent(url)}`);
    chrome.tabs.update(tabId, { url: blockedPage });
    console.log("🚨 INSTANT Redirect:", url);
    return true;
  }
  return false;
}

// ================== Backend Sync (Background Only) ==================
function updateBlockedUrls() {
  chrome.storage.local.get(["user_token"], ({ user_token }) => {
    if (!user_token) return;

    fetch("http://127.0.0.1:5000/api/blocked-urls", {
      method: "GET",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${user_token}` },
      credentials: "include",
    })
      .then(res => res.json())
      .then(data => {
        const newUrls = (data.blocked_urls || []).map(normalizeUrl);
        blockedUrls = newUrls;
        blockedSet = new Set(newUrls);
        chrome.storage.local.set({ blockedUrls });
        console.log("✅ Synced:", newUrls.length, "URLs");

        // Redirect OPEN tabs (non-blocking)
        chrome.tabs.query({}, tabs => {
          tabs.forEach(tab => {
            if (tab.url && isBlocked(tab.url)) {
              redirectIfBlocked(tab.id, tab.url);
            }
          });
        });
      })
      .catch(err => console.error("❌ Sync failed:", err));
  });
}

// ================== Core Scan (LOCAL FIRST + ASYNC FETCH) ==================
function checkUrl(tabId, url, manual = false) {
  if (!url || url.startsWith("chrome://") || url.startsWith("edge://") || url.startsWith("about:") || 
      url.startsWith(chrome.runtime.getURL("blocked.html")) || 
      ignoredDomains.some(d => url.includes(d))) {
    return;
  }

  // 🚀 INSTANT LOCAL CHECK (0ms)
  const startTime = performance.now();
  if (redirectIfBlocked(tabId, url)) {
    console.log(`⚡ Local block: ${performance.now() - startTime}ms`);
    return;
  }

  // ⏱️ DEBOUNCE (prevent spam)
  if (!manual && scanDebounce.has(tabId)) return;
  if (!manual) scanDebounce.set(tabId, true);

  // 🔥 ASYNC FETCH (non-blocking)
  chrome.storage.local.get(["user_token"], ({ user_token }) => {
    const payload = { url, manual };
    if (manual && user_token) payload.user_token = user_token;

    fetch("http://127.0.0.1:5000/predict", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify(payload),
    })
      .then(res => res.json())
      .then(data => {
        const { result, user_blocked } = data;
        if (user_blocked) {
          addToBlockedCache(url);
          redirectIfBlocked(tabId, url); // Re-check after cache
        }

        if (manual) {
          chrome.notifications.create({
            type: "basic",
            iconUrl: "icon.png",
            title: user_blocked ? "Manual Block" : "Scan Result",
            message: user_blocked ? `Blocked: ${url}` : 
                     result?.toLowerCase() === "phish" ? `Suspicious: ${url}` : `Safe: ${url}`,
          });
        } else {
          console.log(`✅ Auto-scan ${performance.now() - startTime}ms:`, url, result);
        }
      })
      .catch(err => console.error("❌ Scan failed:", err))
      .finally(() => { if (!manual) scanDebounce.delete(tabId); });
  });
}

// ================== Listeners ==================

// Manual scan
chrome.action.onClicked.addListener((tab) => tab?.url && checkUrl(tab.id, tab.url, true));

// Tab load COMPLETE → SCAN
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab?.url) {
    setTimeout(() => { // Micro-delay for stability
      checkUrl(tabId, tab.url, false);
    }, 100);
  }
});

// Tab activate → INSTANT CHECK
chrome.tabs.onActivated.addListener(({ tabId }) => {
  chrome.tabs.get(tabId, tab => tab?.url && redirectIfBlocked(tabId, tab.url));
});

// Navigation commit → INSTANT CHECK
chrome.webNavigation.onCommitted.addListener(details => {
  if (details.url) redirectIfBlocked(details.tabId, details.url);
});

// ================== 🚀 ULTRA-FAST BLOCKING (BEFORE LOAD) ==================
chrome.webRequest.onBeforeRequest.addListener(
  details => {
    if (details.type !== "main_frame") return;
    const start = performance.now();
    if (isBlocked(details.url)) {
      return {
        redirectUrl: chrome.runtime.getURL(`blocked.html?url=${encodeURIComponent(details.url)}`)
      };
    }
    console.log(`⚡ webRequest check: ${performance.now() - start}ms`);
  },
  { urls: ["<all_urls>"], types: ["main_frame"] },
  ["blocking"] // PRIORITY: Blocks before fetch!
);

// ================== INIT & SYNC ==================
function init() {
  chrome.storage.local.get(["blockedUrls"], ({ blockedUrls: stored }) => {
    blockedUrls = (stored || []).map(normalizeUrl);
    blockedSet = new Set(blockedUrls);
    console.log("🟢 Loaded:", blockedUrls.length);
    updateBlockedUrls();
  });
}

// Startup
chrome.runtime.onStartup.addListener(init);
chrome.runtime.onInstalled.addListener(init);
init();

// SYNC every 30s + on focus
setInterval(updateBlockedUrls, 30000);
chrome.windows.onFocusChanged.addListener(updateBlockedUrls);