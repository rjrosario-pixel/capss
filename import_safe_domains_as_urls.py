import csv
from datetime import datetime, timezone
from main import app, db
from models.db_models import SafeURL

def load_domains_as_urls():
    print("Importing domains as safe URLs...")
    count = 0
    with app.app_context():
        with open('safe_domains.csv', 'r', encoding='utf-8', newline='') as file:
            reader = csv.DictReader(file)
            for row in reader:
                domain = row.get('domain') or row.get('Domain') or row.get('DOMAIN')
                if domain:
                    url = "https://" + domain.strip()
                    exists = SafeURL.query.filter_by(url=url).first()
                    if not exists:
                        safe_url = SafeURL(url=url, added_on=datetime.now(timezone.utc))
                        db.session.add(safe_url)
                        count += 1
                        if count % 100 == 0:
                            print(f"Inserted {count} safe URLs...")
            db.session.commit()
    print(f"✅ Done! Total safe URLs added: {count}")

if __name__ == '__main__':
    load_domains_as_urls()
