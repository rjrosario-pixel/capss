# ip_probe.py
import socket, ssl, requests, re
from dns import resolver, reversename

requests.packages.urllib3.disable_warnings()

def ptr_lookup(ip):
    try:
        return [socket.gethostbyaddr(ip)[0]]
    except Exception:
        return []

def dns_ptr(ip):
    try:
        rev = reversename.from_address(ip)
        ans = resolver.resolve(rev, "PTR")
        return [str(r).rstrip('.') for r in ans]
    except Exception:
        return []

def tls_names(ip):
    names = []
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((ip, 443), timeout=4) as s:
            with ctx.wrap_socket(s, server_hostname=ip) as ss:
                cert = ss.getpeercert()
        for t in cert.get('subject', ()):
            for k,v in t:
                if k == 'commonName':
                    names.append(v)
        for typ,val in cert.get('subjectAltName', ()):
            if typ.lower() == 'dns':
                names.append(val)
    except Exception:
        pass
    return list(set(names))

def http_probe(ip):
    found = set()
    for scheme in ("http", "https"):
        url = f"{scheme}://{ip}"
        try:
            r = requests.get(url, timeout=5, verify=False, allow_redirects=True)
            found.add(r.url)
            if r.headers.get('location'):
                found.add(r.headers['location'])
            m = re.search(r'<title>(.*?)</title>', r.text, re.I|re.S)
            if m:
                found.add(m.group(1).strip())
        except Exception:
            pass
    return list(found)

if __name__ == "__main__":
    ip = "103.255.237.203"
    print("PTR:", ptr_lookup(ip))
    print("dns_ptr:", dns_ptr(ip))
    print("TLS names:", tls_names(ip))
    print("HTTP probe:", http_probe(ip))
