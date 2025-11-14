#!/usr/bin/env python3
"""
dev_test_rescan.py

Run this from your project root (same folder as main.py).
It will:
 - ensure beautifulsoup4 is installed
 - create a test PhishingURL row (Safe, last_checked > 1 hour ago)
 - monkeypatch predict_url_with_heuristic to return Phish for the test URL
 - run rescan_phishing_urls()
 - print updated PhishingURL and the latest Notification
 - optionally clean up test rows (set CLEANUP_AFTER = True)

Warning: Run in development only. Adjust TEST_USER_ID to match a valid user in your DB.
"""

import sys
import subprocess
import importlib
from datetime import datetime, timedelta, timezone

# --- Config ---
TEST_URL = "http://test-safe-now-phish.example"
TEST_USER_ID = 1
CLEANUP_AFTER = False
MAIN_MODULE = "main"

# --- Ensure bs4 is available ---
try:
    import bs4  # noqa: F401
except Exception:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "beautifulsoup4"])

# --- Import main module ---
main = importlib.import_module(MAIN_MODULE)

# --- Access required objects ---
db = getattr(main, "db")
PhishingURL = getattr(main, "PhishingURL")
Notification = getattr(main, "Notification")
rescan_phishing_urls = getattr(main, "rescan_phishing_urls")
predict_url_with_heuristic = getattr(main, "predict_url_with_heuristic")

print("Starting dev test rescan...")

with main.app.app_context():
    # Step 1 — create or update test PhishingURL entry
    entry = PhishingURL.query.filter_by(url=TEST_URL, user_id=TEST_USER_ID).first()
    if not entry:
        entry = PhishingURL(
            url=TEST_URL,
            user_id=TEST_USER_ID,
            result="Safe",
            last_checked=datetime.utcnow() - timedelta(hours=2)
        )
        db.session.add(entry)
        db.session.commit()
        print(f"Created test PhishingURL id={entry.id}")
    else:
        entry.result = "Safe"
        entry.last_checked = datetime.utcnow() - timedelta(hours=2)
        db.session.commit()
        print(f"Updated existing PhishingURL id={entry.id} to Safe")

    # Step 2 — monkeypatch predict_url_with_heuristic
    original_predict = predict_url_with_heuristic
    def test_predict(url_arg):
        if url_arg == TEST_URL:
            return {"result": "Phish", "score": 0.99}
        return original_predict(url_arg)
    main.predict_url_with_heuristic = test_predict

    # Step 3 — run the rescan
    rescan_phishing_urls()
    print("Rescan completed.")

    # Step 4 — fetch updated PhishingURL
    updated = PhishingURL.query.filter_by(url=TEST_URL, user_id=TEST_USER_ID).first()
    print(f"Updated PhishingURL: url={updated.url} result={updated.result} last_checked={updated.last_checked}")

    # Step 5 — fetch latest Notification for this URL
    note = Notification.query.filter_by(url=TEST_URL, user_id=TEST_USER_ID).order_by(Notification.created_at.desc()).first()
    if note:
        print(f"Latest Notification: id={note.id} user_id={note.user_id} created_at={note.created_at} message={note.message}")
    else:
        print("No notification created.")

    # Step 6 — revert monkeypatch
    main.predict_url_with_heuristic = original_predict

    # Step 7 — cleanup if requested
    if CLEANUP_AFTER:
        if note:
            db.session.delete(note)
        if updated:
            db.session.delete(updated)
        db.session.commit()
        print("Cleanup done.")

print("Done. Check your frontend notifications panel (reload or wait for polling).")
