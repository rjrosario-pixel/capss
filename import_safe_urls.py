import csv
from datetime import datetime, timezone
from main import app, db
from models.db_models import SafeURL

def load_safe_urls():
    print("Loading safe URLs from CSV...")
    count = 0

    with app.app_context():
        with open('safe_urls.csv', 'r', newline='', encoding='utf-8') as file:
            reader = csv.DictReader(file)

            for row in reader:
                url = row['Domain'].strip()
                if not url:
                    continue

                # Skip duplicates
                if SafeURL.query.filter_by(url=url).first():
                    continue

                # Insert into database
                safe_url = SafeURL(
                    url=url,
                    added_on=datetime.now(timezone.utc)
                )
                db.session.add(safe_url)
                count += 1
                print(f"[{count}] Inserted: {url}")

            db.session.commit()
    print(f"✅ Done! Total new safe URLs inserted: {count}")

if __name__ == '__main__':
    load_safe_urls()
