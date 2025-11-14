document.addEventListener('DOMContentLoaded', () => {
  const currentUrlDiv = document.getElementById("current-url");
  const scanBtn = document.getElementById("scan-btn");
  const resultText = document.getElementById("result");
  const blockBtn = document.getElementById("block-btn");
  const loginReminder = document.getElementById("loginReminder");
  const historyLink = document.getElementById("historyLink");

  // Reset UI
  resultText.textContent = "";
  resultText.style.display = "none";
  blockBtn.style.display = "none";
  loginReminder.style.display = "none";
  historyLink.style.display = "none";

  // ✅ Check login
  fetch("http://127.0.0.1:5000/check_login", {
    method: "GET",
    credentials: "include"
  })
  .then(res => res.json())
  .then(data => {
    if (data.logged_in) {
      historyLink.style.display = "block";
      loginReminder.style.display = "none";
    } else {
      historyLink.style.display = "none";
      loginReminder.style.display = "block";
    }
  })
  .catch(err => {
    console.error("Login check failed:", err);
    loginReminder.style.display = "block";
    historyLink.style.display = "none";
  });

  // Show current tab URL
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs.length > 0 && tabs[0].url) {
      currentUrlDiv.textContent = `🔗 ${tabs[0].url}`;
    } else {
      currentUrlDiv.textContent = "❌ No active URL found.";
    }
  });

  // --- Manual scan function ---
  function performManualScan(url) {
    resultText.style.display = "flex";  // 👈 show it when scanning starts
    resultText.textContent = "Scanning...";
    blockBtn.style.display = "none";


    fetch("http://127.0.0.1:5000/predict", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify({ url, manual: true })
    })
    .then(async res => {
      const contentType = res.headers.get("content-type") || "";

      if (res.status === 401) {
        loginReminder.style.display = "block";
        resultText.textContent = "Please log in to scan.";
        throw new Error("User not logged in");
      }

      if (!contentType.includes("application/json")) {
        const text = await res.text();
        throw new Error("Invalid response: " + text.slice(0, 100));
      }

      return res.json();
    })
    .then(data => {
      console.log("Scan result:", data);

      // Reset previous styles first
      resultText.classList.remove("phish", "safe");

      if (data.result === "Phish") {
        resultText.textContent = "ALERT: This site is phishing!";
        resultText.classList.add("phish");
        blockBtn.style.display = "inline-block";
      } else if (data.result === "Safe") {
        resultText.textContent = "This site is safe.";
        resultText.classList.add("safe");
      } else {
        resultText.textContent = "Phishing site already blocked";
      }
    })

    .catch(err => {
      console.error("Scan error:", err);
      if (!resultText.textContent.includes("Please log in")) {
        resultText.textContent = "Scan failed. " + err.message;
      }
    });
  }

  // Scan button
  scanBtn.addEventListener("click", () => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (!tabs || tabs.length === 0) {
        resultText.textContent = "No active tab found.";
        return;
      }
      performManualScan(tabs[0].url);
    });
  });

  // Block button
  blockBtn.addEventListener("click", () => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (!tabs || tabs.length === 0) {
        resultText.textContent = "No active tab found.";
        return;
      }
      const url = tabs[0].url;

      fetch("http://127.0.0.1:5000/block_url", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ url })
      })
      .then(async response => {
        if (response.status === 401) {
          loginReminder.style.display = "block";
          resultText.textContent = "Please log in to block URLs.";
          return;
        }

        const contentType = response.headers.get("content-type") || "";
        let data = {};
        if (contentType.includes("application/json")) {
          data = await response.json();
        }

        if (response.ok) {
          resultText.textContent = data.message || "Site has been blocked!";
          blockBtn.style.display = "none";

          // Redirect tab to blocked.html
          chrome.tabs.update(tabs[0].id, { url: chrome.runtime.getURL("blocked.html") });
        } else {
          resultText.textContent = "Failed to block site. " + (data.error || "");
        }
      })
      .catch(error => {
        console.error("Block error:", error);
        resultText.textContent = "Error blocking site.";
      });
    });
  });
});
