import pytest
from main import app

@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client

# 1. ✅ Safe URL (Google should return Safe or Unknown but never Phish)
def test_safe_url(client):
    response = client.post("/predict", json={"url": "https://google.com"})
    data = response.get_json()
    assert data["result"] in ["Safe", "Unknown"]

# 2. ⚠️ Blacklisted URL (phishingsite.com should be detected as Phish)
def test_blacklist_url(client):
    response = client.post("/predict", json={"url": "http://phishingsite.com"})
    data = response.get_json()
    assert data["result"] == "Phish"

# 3. ❌ Empty input
def test_empty_url(client):
    response = client.post("/predict", json={"url": ""})
    assert response.status_code == 400
    data = response.get_json()
    assert data["error"] == "No URL provided"

# 4. 🧪 Suspicious keyword in URL
def test_suspicious_keyword_url(client):
    response = client.post("/predict", json={"url": "http://login-bank.com"})
    data = response.get_json()
    assert data["result"] in ["Phish", "Unknown"]

# 5. 🔍 Long URL (2000+ chars)
def test_long_url(client):
    long_url = "http://example.com/" + "a" * 2100
    response = client.post("/predict", json={"url": long_url})
    data = response.get_json()
    assert "result" in data  # must not crash

# 6. 🌐 URL with IP address instead of domain
def test_ip_based_url(client):
    response = client.post("/predict", json={"url": "http://192.168.1.1"})
    data = response.get_json()
    assert data["result"] in ["Safe", "Unknown", "Phish"]

# 7. 🔁 Duplicate scan (same URL twice should not break)
def test_duplicate_scan(client):
    url = "https://duplicate.com"
    response1 = client.post("/predict", json={"url": url})
    response2 = client.post("/predict", json={"url": url})
    assert response1.status_code == 200
    assert response2.status_code == 200

# 8. ❓ Invalid URL format
def test_invalid_url_format(client):
    response = client.post("/predict", json={"url": "htp:/invalid"})
    data = response.get_json()
    assert data["result"] in ["Unknown", "Phish"]

# 9. 🚫 Blocked domain test (simulate if domain exists in blacklist_domains)
def test_blacklist_domain(client):
    response = client.post("/predict", json={"url": "http://blocked-domain.com"})
    data = response.get_json()
    assert data["result"] in ["Phish", "Unknown"]

# 10. 🔒 HTTPS safe site
def test_https_url(client):
    response = client.post("/predict", json={"url": "https://microsoft.com"})
    data = response.get_json()
    assert data["result"] in ["Safe", "Unknown"]
