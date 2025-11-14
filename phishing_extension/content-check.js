// content-check.js

const currentUrl = window.location.href;

fetch("http://127.0.0.1:5000/predict", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  credentials: "include",
  body: JSON.stringify({ url: currentUrl })
})
  .then(response => {
    if (!response.ok) throw new Error("Network error");
    return response.json();
  })
  .then(data => {
    if (data.status === "phish" || data.status === "already_blocked") {
      console.log("🚫 Phishing URL detected, redirecting to blocked.html");

      // Redirect to your blocked.html
      window.location.href =
        chrome.runtime.getURL("blocked.html") + "?url=" + encodeURIComponent(currentUrl);
    }
  })
  .catch(err => console.error("❌ Error checking URL:", err));
