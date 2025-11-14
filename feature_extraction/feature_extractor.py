# feature_extraction.py — optimized (no nested ThreadPoolExecutor)
import logging
import sys
import re
import socket
import ssl
import requests
import whois
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from datetime import datetime
from functools import lru_cache

# Silence noisy libs
logging.getLogger("whois").setLevel(logging.CRITICAL)
logging.getLogger("requests").setLevel(logging.CRITICAL)
logging.getLogger("urllib3").setLevel(logging.CRITICAL)
for name in ("whois", "requests", "urllib3"):
    logging.getLogger(name).propagate = False

class NullWriter:
    def write(self, *_): pass
    def flush(self): pass

sys.stderr = NullWriter()

# --- Cached Network Helpers ---
@lru_cache(maxsize=5000)
def cached_whois(domain):
    try:
        return whois.whois(domain)
    except Exception:
        return None

@lru_cache(maxsize=5000)
def cached_ssl(hostname):
    try:
        return ssl.get_server_certificate((hostname, 443))
    except Exception:
        return None

@lru_cache(maxsize=5000)
def cached_dns(hostname):
    try:
        socket.gethostbyname(hostname)
        return True
    except Exception:
        return False

def fetch_page(url, timeout=2):
    try:
        r = requests.get(url, timeout=timeout)
        return r.text or ""
    except Exception:
        return ""

# --- Feature helpers (same as yours, minor robustness fixes) ---
def url_having_ip(url):
    try:
        hostname = urlparse(url).hostname
        if not hostname:
            return 1
        # IPv4
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname):
            return 1
        # IPv6 (basic check)
        if re.match(r"^\[?([a-fA-F0-9:]+)\]?$", hostname):
            return 1
        return 0
    except Exception:
        return 1

def url_length(url):
    l = len(url)
    if l < 54:
        return 0
    elif 54 <= l <= 75:
        return 0.5
    else:
        return 1

def url_short(url):
    shortening_services = r"bit\.ly|goo\.gl|shorte\.st|x\.co|ow\.ly|t\.co|tinyurl|is\.gd|tr\.im|cli\.gs|migre\.me|ff\.im|tiny\.cc"
    return 1 if re.search(shortening_services, url) else 0

def having_at_symbol(url):
    return 1 if "@" in url else 0

def doubleSlash(url):
    last_slash = url.rfind('//')
    return 1 if last_slash > 6 else 0

def prefix_suffix(url):
    domain = urlparse(url).netloc or ""
    return 1 if '-' in domain else 0

def sub_domain(url):
    domain = urlparse(url).netloc or ""
    dots = domain.count('.')
    if dots <= 1:
        return 0
    elif dots == 2:
        return 0.5
    else:
        return 1

def favicon(url, html):
    try:
        if not html:
            return 0
        return 1 if f"{urlparse(url).netloc}/favicon.ico" not in html else 0
    except Exception:
        return 1

def port(url):
    try:
        p = urlparse(url).port
        return 1 if p not in [None, 80, 443] else 0
    except Exception:
        return 0

def https_token(url):
    domain = (urlparse(url).netloc or "").lower()
    return 1 if "https" in domain and not domain.startswith("https.") and not domain.startswith("www.https.") else 0

def request_url(url, html):
    try:
        external_links = re.findall(r'src=["\'](http[s]?://.*?)["\']', html or "")
        if not external_links:
            return 0
        outside = sum(1 for l in external_links if urlparse(l).netloc != urlparse(url).netloc)
        percent = outside / len(external_links) * 100
        if percent < 22:
            return 0
        elif 22 <= percent < 61:
            return 0.5
        else:
            return 1
    except Exception:
        return 1

def url_of_anchor(url, soup):
    try:
        anchors = [a.get('href') for a in (soup.find_all('a', href=True) if soup else [])]
        anchors = [a for a in anchors if a]
        if not anchors:
            return 0
        outside = sum(1 for a in anchors if urlparse(a).netloc != urlparse(url).netloc)
        percent = outside / len(anchors) * 100
        if percent < 31:
            return 0
        elif 31 <= percent < 67:
            return 0.5
        else:
            return 1
    except Exception:
        return 1

def Links_in_tags(url, soup):
    try:
        tags = soup.find_all(['script', 'link', 'meta']) if soup else []
        if not tags:
            return 0
        outside = 0
        for t in tags:
            src = t.get('src') or t.get('href')
            if src and urlparse(src).netloc != urlparse(url).netloc:
                outside += 1
        percent = outside / len(tags) * 100
        if percent < 17:
            return 0
        elif 17 <= percent < 81:
            return 0.5
        else:
            return 1
    except Exception:
        return 1

def sfh(url, html):
    try:
        forms = re.findall(r'<form[^>]+action=["\']([^"\']+)["\']', html or "")
        if not forms:
            return 0
        outside = sum(1 for f in forms if urlparse(f).netloc != urlparse(url).netloc)
        return 0.5 if outside > 0 else 0
    except Exception:
        return 1

def email_submit(html):
    try:
        return 1 if "mailto:" in (html or "") else 0
    except Exception:
        return 1

def abnormal_url(url):
    return 0 if urlparse(url).hostname else 1

def redirect(url):
    try:
        r = requests.get(url, timeout=2, allow_redirects=True)
        if len(r.history) == 0:
            return 0
        elif len(r.history) < 3:
            return 0.5
        else:
            return 1
    except Exception:
        return 0.5

def on_mouseover(html):
    try:
        return 1 if 'onmouseover' in (html or "") else 0
    except Exception:
        return 1

def rightClick(html):
    try:
        return 1 if 'contextmenu' in (html or "") else 0
    except Exception:
        return 1

def popup(html):
    try:
        return 1 if 'alert(' in (html or "") else 0
    except Exception:
        return 1

def iframe(html):
    try:
        return 1 if '<iframe' in (html or "") else 0
    except Exception:
        return 1

def web_traffic(url):
    """
    Checks if TLD is commonly used for phishing or legitimate websites.
    Returns:
        0  → Legitimate
        0.5 → Suspicious
        1  → Phishing
    """
    try:
        ext = tldextract.extract(url)
        tld = ext.suffix.lower()
        name = ext.domain.lower()

        # Very low reputation free TLDs → phishing
        if tld in ["tk", "ml", "ga", "cf", "gq"]:
            return 1
        # Government, education, or military → trusted
        if tld in ["gov", "edu", "mil"]:
            return 0
        # Short, generic names → somewhat suspicious
        if len(name) < 4:
            return 1
        # Normal domains
        return 0.5
    except Exception:
        return 0.5


def page_rank(url):
    """
    Simple heuristic for domain ranking / trust.
    Returns:
        0  → Legitimate
        0.5 → Suspicious
        1  → Phishing
    """
    try:
        ext = tldextract.extract(url)
        tld = ext.suffix.lower()
        name = ext.domain.lower()

        # Free or throwaway TLDs → phishing
        if tld in ["tk", "ml", "ga", "cf", "gq", "xyz", "top", "work"]:
            return 1
        # Trusted TLDs
        if tld in ["gov", "edu", "mil"]:
            return 0
        # Common TLDs with reasonable length
        if tld in ["com", "org", "net"] and 5 <= len(name) <= 20:
            return 0
        # Otherwise
        return 0.5
    except Exception:
        return 0.5


def google_index(url):
    """
    Detect if domain is likely not indexed or suspicious based on structure.
    Returns:
        0 → Legitimate
        1 → Phishing
    """
    try:
        domain = urlparse(url).netloc.lower()
        tld = tldextract.extract(url).suffix.lower()

        # IP-based or free TLDs → phishing
        if re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", domain):
            return 1
        if tld in ["tk", "ml", "ga", "cf", "gq"]:
            return 1
        return 0
    except Exception:
        return 0.5


def links_pointing(url):
    """
    Checks TLD reputation as proxy for backlinks.
    Returns:
        0 → Legitimate
        0.5 → Suspicious
        1 → Phishing
    """
    try:
        ext = tldextract.extract(url)
        tld = ext.suffix.lower()
        if tld in ["gov", "edu", "mil"]:
            return 0
        if tld in ["tk", "ml", "ga", "cf", "gq"]:
            return 1
        return 0.5
    except Exception:
        return 0.5


def statistical(url):
    """
    Detects domain/path irregularities using basic statistical cues.
    Returns:
        0 → Legitimate
        0.5 → Suspicious
        1 → Phishing
    """
    try:
        parsed = urlparse(url)
        domain = parsed.netloc
        path = parsed.path
        tld = tldextract.extract(url).suffix.lower()
        score = 0

        if domain.count("-") > 3:
            score += 1
        if domain.count(".") > 4:
            score += 1
        if re.search(r"[a-z0-9]{30,}", domain + path):
            score += 1
        if tld in ["tk", "ml", "ga", "cf", "gq", "xyz", "top", "work"]:
            score += 1

        if score >= 3:
            return 1
        elif score >= 2:
            return 0.5
        else:
            return 0
    except Exception:
        return 0.5

# --- Main Feature Extraction (optimized: sequential cached network calls) ---
def extract_url_features(url):
    html = fetch_page(url, timeout=2)
    soup = BeautifulSoup(html, 'html.parser') if html else None

    domain = urlparse(url).netloc or ""
    hostname = urlparse(url).hostname or ""

    # call cached helpers directly (no nested executors)
    whois_data = cached_whois(domain)
    ssl_data = cached_ssl(hostname)
    dns_ok = cached_dns(hostname)

    def SSLfinal_State_override():
        try:
            scheme = urlparse(url).scheme.lower()
            if scheme != 'https':
                return 1
            return 0 if ssl_data else 1
        except Exception:
            return 1

    def domain_registration_override():
        try:
            w = whois_data
            if not w:
                return 1
            exp_date = getattr(w, "expiration_date", None)
            if isinstance(exp_date, list):
                exp_date = exp_date[0]
            if isinstance(exp_date, str):
                try:
                    exp_date = datetime.strptime(exp_date, "%Y-%m-%d")
                except Exception:
                    exp_date = None
            if not exp_date or (exp_date - datetime.now()).days <= 365:
                return 1
            return 0
        except Exception:
            return 1

    def age_of_domain_override():
        try:
            w = whois_data
            if not w:
                return 1
            creation = getattr(w, "creation_date", None)
            if isinstance(creation, list):
                creation = creation[0]
            if isinstance(creation, str):
                try:
                    creation = datetime.strptime(creation, "%Y-%m-%d")
                except Exception:
                    creation = None
            if not creation:
                return 1
            age_months = (datetime.now() - creation).days / 30
            return 1 if age_months <= 6 else 0
        except Exception:
            return 1

    def check_dns_override():
        return 0 if dns_ok else 1

    return {
        'url_having_ip': url_having_ip(url),
        'url_length': url_length(url),
        'url_short': url_short(url),
        'having_at_symbol': having_at_symbol(url),
        'doubleSlash': doubleSlash(url),
        'prefix_suffix': prefix_suffix(url),
        'sub_domain': sub_domain(url),
        'SSLfinal_State': SSLfinal_State_override(),
        'domain_registration': domain_registration_override(),
        'favicon': favicon(url, html),
        'port': port(url),
        'https_token': https_token(url),
        'request_url': request_url(url, html),
        'url_of_anchor': url_of_anchor(url, soup),
        'Links_in_tags': Links_in_tags(url, soup),
        'sfh': sfh(url, html),
        'email_submit': email_submit(html),
        'abnormal_url': abnormal_url(url),
        'redirect': redirect(url),
        'on_mouseover': on_mouseover(html),
        'rightClick': rightClick(html),
        'popup': popup(html),
        'iframe': iframe(html),
        'age_of_domain': age_of_domain_override(),
        'check_dns': check_dns_override(),
        'web_traffic': web_traffic(url),
        'page_rank': page_rank(url),
        'google_index': google_index(url),
        'links_pointing': links_pointing(url),
        'statistical': statistical(url)
    }
