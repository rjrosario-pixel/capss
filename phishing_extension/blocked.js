const params = new URLSearchParams(window.location.search);
const blockedUrl = params.get("url");
if (blockedUrl) {
  document.getElementById("phish-url").textContent = decodeURIComponent(blockedUrl);
}

document.getElementById("go-back").addEventListener("click", () => {
  if (document.referrer && document.referrer !== window.location.href) {
    window.location.href = document.referrer;
  } else {
    window.location.href = "https://www.google.com";
  }
});
