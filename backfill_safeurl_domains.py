from models.db_models import db, SafeURL
from urllib.parse import urlparse
from flask import Flask
import math
import time

# Set up Flask app context
app = Flask(__name__)
app.config.from_object('config.Config')  # make sure this points to your config
db.init_app(app)

def extract_domain(url):
    try:
        parsed_url = urlparse(url)
        return parsed_url.netloc.lower()
    except Exception:
        return None

def print_progress(current, total):
    percent = (current / total) * 100
    bar = "=" * int(percent // 2)  # 50 characters width
    print(f"\rProgress: [{bar:<50}] {percent:.2f}%", end="")

with app.app_context():
    urls = SafeURL.query.all()
    total = len(urls)
    updated = 0

    for index, url_record in enumerate(urls, start=1):
        if not url_record.domain:
            domain = extract_domain(url_record.url)
            if domain:
                url_record.domain = domain
                db.session.add(url_record)
                updated += 1

        print_progress(index, total)
        time.sleep(0.01)  # just to simulate a visible progress bar

    db.session.commit()
    print(f"\n✅ Updated {updated} record(s) with domain values.")
