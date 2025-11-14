import csv
from datetime import datetime
from main import app
from models.db_models import db, BlacklistURL

MAX_URL_LENGTH = 2000  # safe cutoff for PostgreSQL indexing

def load_phishtank_csv():
    print("Loading PhishTank...")
    with open('phishtank.csv', newline='', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        count = 0
        for row in reader:
            url = row.get('url')
            if url and len(url) <= MAX_URL_LENGTH:
                exists = BlacklistURL.query.filter_by(url=url).first()
                if not exists:
                    domain = url.split('/')[2] if '://' in url else url
                    new_entry = BlacklistURL(
                        url=url,
                        domain=domain,
                        source='PhishTank',
                        added_on=datetime.utcnow()
                    )
                    db.session.add(new_entry)
                    count += 1
        db.session.commit()
        print(f"PhishTank import complete. {count} new entries added.")

def load_github_txt():
    print("Loading GitHub phishing URLs...")
    count = 0
    with open('github_phishing.txt', 'r', encoding='utf-8') as file:
        for line in file:
            url = line.strip()
            if url and len(url) <= MAX_URL_LENGTH:
                exists = BlacklistURL.query.filter_by(url=url).first()
                if not exists:
                    domain = url.split('/')[2] if '://' in url else url
                    new_entry = BlacklistURL(
                        url=url,
                        domain=domain,
                        source='GitHub',
                        added_on=datetime.utcnow()
                    )
                    db.session.add(new_entry)
                    count += 1
    db.session.commit()
    print(f"GitHub import complete. {count} new entries added.")

if __name__ == '__main__':
    with app.app_context():
        load_phishtank_csv()
        load_github_txt()
