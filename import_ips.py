from main import app, db
from models.db_models import BlacklistIP
from datetime import datetime
import sys

file_path = 'blacklist_ips.txt'  # your txt file with IPs

with app.app_context():
    print("📄 Reading file:", file_path)
    with open(file_path, 'r') as f:
        ips = [line.strip() for line in f if line.strip()]

    total = len(ips)
    print(f"✅ Loaded {total} IPs from file.")

    added = 0
    skipped = 0

    for i, ip in enumerate(ips, start=1):
        existing = BlacklistIP.query.filter_by(ip_address=ip).first()
        if not existing:
            db.session.add(
                BlacklistIP(
                    ip_address=ip,
                    source='GitHub',
                    added_on=datetime.utcnow()
                )
            )
            added += 1
        else:
            skipped += 1

        # Print progress clearly (one per line)
        print(f"Processing {i}/{total} ...", end='\r')

        if i % 500 == 0:
            db.session.commit()

    db.session.commit()
    print(f"\n✅ Done! Imported {added} new IPs, skipped {skipped} existing ones (Total: {total}).")
