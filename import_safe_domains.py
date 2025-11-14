from models.db_models import db, SafeURL, SafeDomain
from urllib.parse import urlparse
from sqlalchemy.exc import IntegrityError
from main import app
from tqdm import tqdm  # Make sure to install: pip install tqdm

def extract_domain(url):
    try:
        parsed = urlparse(url)
        return parsed.netloc.lower()
    except:
        return None

def import_domains(batch_size=1000):
    with app.app_context():
        safe_urls = SafeURL.query.all()
        total = len(safe_urls)
        if total == 0:
            print("No safe URLs to process.")
            return

        existing_domains = set([d.domain for d in SafeDomain.query.all()])
        new_domains = []
        inserted = 0
        skipped = 0

        print("[*] Importing safe domains...\n")

        for safe_url in tqdm(safe_urls, desc="Progress", unit="url"):
            domain = extract_domain(safe_url.url)
            if domain and domain not in existing_domains:
                new_domains.append(SafeDomain(domain=domain))
                existing_domains.add(domain)
                inserted += 1

                # Commit in batches
                if len(new_domains) >= batch_size:
                    try:
                        db.session.bulk_save_objects(new_domains)
                        db.session.commit()
                        new_domains.clear()
                    except IntegrityError:
                        db.session.rollback()
                        skipped += len(new_domains)
                        new_domains.clear()

            else:
                skipped += 1

        # Final commit for remaining
        if new_domains:
            try:
                db.session.bulk_save_objects(new_domains)
                db.session.commit()
            except IntegrityError:
                db.session.rollback()
                skipped += len(new_domains)

        print(f"\n[✓] Imported: {inserted}")
        print(f"[~] Skipped (already exists or error): {skipped}")

if __name__ == "__main__":
    import_domains()
