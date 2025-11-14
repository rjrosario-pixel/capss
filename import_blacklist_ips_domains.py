from datetime import datetime, timezone
from main import app, db
from models.db_models import BlacklistIP, BlacklistDomain

def load_txt(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        return [line.strip() for line in f if line.strip()]

def import_ips():
    print("🔄 Importing IPs from phishing_ips.txt...")
    ips = load_txt('phishing_ips.txt')
    count = 0
    with app.app_context():
        for i, ip in enumerate(ips, start=1):
            if not BlacklistIP.query.filter_by(ip_address=ip).first():
                db.session.add(BlacklistIP(
                    ip_address=ip,
                    source='GitHub',
                    added_on=datetime.now(timezone.utc)
                ))
                count += 1
                print(f"[{i}] ✅ Inserted IP: {ip}")
            else:
                print(f"[{i}] ⚠️ Already exists: {ip}")
        db.session.commit()
    print(f"\n✅ Finished importing IPs. New entries: {count}")

def import_domains():
    print("🔄 Importing Domains from phishing_domains.txt...")
    domains = load_txt('phishing_domains.txt')
    count = 0
    with app.app_context():
        for i, domain in enumerate(domains, start=1):
            if not BlacklistDomain.query.filter_by(domain=domain).first():
                db.session.add(BlacklistDomain(
                    domain=domain,
                    source='GitHub',
                    added_on=datetime.now(timezone.utc)
                ))
                count += 1
                print(f"[{i}] ✅ Inserted Domain: {domain}")
            else:
                print(f"[{i}] ⚠️ Already exists: {domain}")
        db.session.commit()
    print(f"\n✅ Finished importing Domains. New entries: {count}")

if __name__ == '__main__':
    import_ips()
    import_domains()
