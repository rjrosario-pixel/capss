import traceback
try:
    print("🔍 Importing main.py...")
except Exception as e:
    print("❌ Import error:", e)
    traceback.print_exc()

import os
print("🔹 ENV PORT:", os.environ.get("PORT"))
print("🔹 Starting app import...")

try:
    print("🔹 App imported successfully!")
except Exception as e:
    print("❌ ERROR WHILE IMPORTING APP:", e)
    raise

from flask import Flask, request, jsonify, render_template, redirect, flash, session, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from flask_socketio import SocketIO, emit, join_room
from urllib.parse import urlparse
from datetime import datetime, timedelta, timezone
from flask_mail import Mail, Message
from sqlalchemy import func
from functools import lru_cache
from feature_extraction.feature_extractor import extract_url_features
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
from tzlocal import get_localzone
from zoneinfo import ZoneInfo
from markupsafe import escape
import atexit
import joblib
import random
import socket
import time
import string
import concurrent.futures
import re
import pandas as pd
import os


from models.db_models import db, SafeURL, SafeDomain, PhishingURL, BlacklistURL, BlacklistDomain, BlacklistIP, Notification, BlockedURL, User
from predict_url import predict_url

rf_model = joblib.load("trained_models/randomForest_final.pkl")

import traceback
try:
    app = Flask(__name__)
except Exception as e:
    print("❌ Flask app creation failed:", e)
    traceback.print_exc()

CORS(app, supports_credentials=True)

scheduler = None

# Configuration
app.config['SECRET_KEY'] = 'rjphishingscanner123'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://rj:1234567890@localhost/backupdb'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Mail setup
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'terraphish00@gmail.com'         # 👈 Set your email
app.config['MAIL_PASSWORD'] = 'mzxj obpm etek itrw'            # 👈 Use an App Password (not your Gmail password)

mail = Mail(app)


# Initialize extensions
db.init_app(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"   # 👈 Redirect to login page instead of JSON
login_manager.login_message_category = "info"

try: 
    socketio = SocketIO(app, cors_allowed_origins="*")  # ✅ added
except Exception as e:
    print("❌ SocketIO creation failed:", e)
    traceback.print_exc()

print("🔹 App object ready:", app)   

@socketio.on("join")
def handle_join(data):
    try:
        # Expect frontend to send { user_id: "<id>" } (string or int)
        user_id = str(data.get("user_id", "guest"))
        join_room(user_id)
        print(f"[SocketIO] client joined room: {user_id}")
        # optional ack back to client
        emit("joined", {"room": user_id})
    except Exception as e:
        print("Join room error:", e)


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))
    
FEATURE_NAMES = [
    'url_having_ip', 'url_length', 'url_short', 'having_at_symbol', 'doubleSlash',
    'prefix_suffix', 'sub_domain', 'SSLfinal_State', 'domain_registration', 'favicon',
    'port', 'https_token', 'request_url', 'url_of_anchor', 'Links_in_tags', 'sfh',
    'email_submit', 'abnormal_url', 'redirect', 'on_mouseover', 'rightClick', 'popup',
    'iframe', 'age_of_domain', 'check_dns', 'web_traffic', 'page_rank', 'google_index',
    'links_pointing', 'statistical'
]


# ---------------- Helper Functions ----------------

def resolve_ip_timeout(url, timeout=5.0):
    """Resolve IP address with a timeout using ThreadPoolExecutor."""
    hostname = urlparse(url).hostname
    if not hostname:
        return None
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(socket.gethostbyname, hostname)
        try:
            return future.result(timeout=timeout)
        except Exception:
            return None

# ---------------- Routes ----------------

@app.route('/signup', methods=['GET'])
def signup_page():
    return render_template('signup.html')

@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    if not data:
        return jsonify({'message': 'Invalid or missing JSON'}), 400

    email = data.get('email')
    username = data.get('username')
    password = data.get('password')

    if not all([email, username, password]):
        return jsonify({'message': 'All fields are required'}), 400

    # Email validation
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.(com|org|net|edu|ph)$'
    if not re.match(email_pattern, email):
        return jsonify({'message': 'Invalid email format'}), 400

    # Check if email or username already exists
    if User.query.filter_by(email=email).first():
        return jsonify({'message': 'Email already registered'}), 409
    if User.query.filter_by(username=username).first():
        return jsonify({'message': 'Username already taken'}), 409

    try:
        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(email=email, username=username, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'message': 'Account created successfully'}), 201
    except Exception as e:
        print("Registration error:", e)
        return jsonify({'message': 'Internal server error'}), 500


@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if request.method == 'GET':
        return render_template('login.html')

    # Handle normal form logins
    if request.form:
        email = request.form.get("email")
        password = request.form.get("password")
        user = User.query.filter_by(email=email).first()
        if not user:
            flash("Invalid email or password", "danger")
            return redirect(url_for("login"))
        if not bcrypt.check_password_hash(user.password, password):
            flash("Incorrect password", "danger")
            return redirect(url_for("login"))

        login_user(user)
        next_page = request.args.get("next")
        return redirect(next_page or url_for("dash"))

    # Handle JSON logins (for JS or extensions)
    data = request.get_json()
    if data:
        email = data.get('email')
        password = data.get('password')
        if not all([email, password]):
            return jsonify({'message': 'Email and password are required'}), 400

        user = User.query.filter_by(email=email).first()
        if not user:
            return jsonify({'message': 'Invalid credentials'}), 401
        if not bcrypt.check_password_hash(user.password, password):
            return jsonify({'message': 'Incorrect password'}), 401

        login_user(user)
        return jsonify({'message': 'Login successful'}), 200

    return jsonify({'message': 'Invalid request'}), 400

@app.route("/check_login")
def check_login():
    return jsonify({"logged_in": current_user.is_authenticated})

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('scanner'))

# --- Helper function to normalize URLs consistently ---
def normalize_url_for_matching(u):
    if not u:
        return ""
    u = u.strip().lower()
    if u.endswith('/'):
        u = u.rstrip('/')
    return u

# --- Cache blacklists and safelists in memory ---
@lru_cache(maxsize=1)
def load_blacklist_cache():
    urls = {normalize_url_for_matching(b.url) for b in BlacklistURL.query.all()}
    domains = {d.domain.lower() for d in BlacklistDomain.query.all()}
    ips = {i.ip_address for i in BlacklistIP.query.all()}
    return urls, domains, ips

@lru_cache(maxsize=1)
def load_safelist_cache():
    urls = {normalize_url_for_matching(s.url) for s in SafeURL.query.all()}
    domains = {d.domain.lower() for d in SafeDomain.query.all()}
    return urls, domains

import concurrent.futures
import socket
from urllib.parse import urlparse

# --- Helper: Resolve IP with timeout ---
def resolve_ip_timeout(url, timeout=5.0):
    """Resolve IP address with a timeout using ThreadPoolExecutor."""
    hostname = urlparse(url).hostname
    if not hostname:
        return None
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(socket.gethostbyname, hostname)
        try:
            return future.result(timeout=timeout)
        except Exception:
            return None

def normalize_url(url: str) -> str:
    """Normalize URLs to ensure consistent matching."""
    if not url:
        return url
    
    url = url.strip().lower()

    # Ensure scheme
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)

    # Remove default ports
    netloc = parsed.hostname or ""
    if parsed.port:
        if (parsed.scheme == "http" and parsed.port == 80) or \
           (parsed.scheme == "https" and parsed.port == 443):
            # If default port, use hostname only. Otherwise, netloc already has the port.
            netloc = parsed.hostname 

    # Normalize path (remove trailing slash unless root)
    path = parsed.path
    if path.endswith('/') and len(path) > 1:
        path = path.rstrip('/')

    query = f"?{parsed.query}" if parsed.query else ""

    return f"{parsed.scheme}://{netloc}{path}{query}"

# --- Heuristic + RF combined prediction ---
def predict_url_with_heuristic(url, model=None):
    # Use preloaded RF model (loaded once at startup)
    rf = model if model is not None else rf_model

    # --- Domain-based caching for features ---
    if not hasattr(app, "_domain_feature_cache"):
        app._domain_feature_cache = {}

    parsed = urlparse(url)
    domain = parsed.hostname or parsed.netloc
    domain_lower = domain.lower() if domain else url

    if domain_lower in app._domain_feature_cache:
        features = app._domain_feature_cache[domain_lower]
    else:
        features = extract_url_features(url)  # still computes all features (WHOIS/DNS/etc.)
        app._domain_feature_cache[domain_lower] = features

    # --- JS-based heuristic ---
    suspicious_js_features = [
        'iframe', 'popup', 'rightClick', 'on_mouseover',
        'Links_in_tags', 'sfh', 'email_submit', 'abnormal_url'
    ]
    js_suspicious_count = sum(features.get(f, 0) for f in suspicious_js_features)

    # --- Prepare features for RF ---
    feature_df = pd.DataFrame(
        [[features.get(f, 0) for f in FEATURE_NAMES]],
        columns=FEATURE_NAMES
    )

    rf_pred = rf.predict(feature_df)[0]
    rf_result = "Phish" if rf_pred == 1 else "Safe"
    rf_proba = rf.predict_proba(feature_df)[0]

    # --- Final heuristic override ---
    final_result = "Phish" if js_suspicious_count >= 3 else rf_result

    return {
        "result": final_result,
        "rf_result": rf_result,
        "rf_proba": rf_proba,
        "suspicious_js_count": js_suspicious_count,
        "features": features
    }


@app.route('/predict', methods=['POST'])
def predict():
    import time
    from datetime import datetime, timezone
    start_time = time.time()
    data = request.get_json()
    raw_url = data.get('url')
    manual = bool(data.get('manual', False))
    user_token = data.get('user_token')

    # ✅ identify the logged-in user (if any)
    from flask_login import current_user
    user = current_user if current_user.is_authenticated else None

    # --- Progress emitter ---
    def emit_progress(progress, message, stage_index=None, stage_info=None, result=None, url=None):
        if not manual:
            return
        try:
            payload = {"progress": progress, "message": message}
            if stage_index is not None:
                payload["stage_index"] = stage_index
            if stage_info is not None:
                payload["stage_info"] = stage_info
            if result is not None:
                payload["result"] = result
            if url is not None:
                payload["url"] = url

            if user and hasattr(user, "id"):
                socketio.emit("scan_progress", payload, room=str(user.id))
            elif user_token:
                socketio.emit("scan_progress", payload, room=f"token_{user_token}")
            else:
                socketio.emit("scan_progress", payload)
        except Exception as e:
            print("Socket emit error:", e)

    # --- Progress helper: emit + flush ---
    def progress_step(progress, message, **kwargs):
        emit_progress(progress, message, **kwargs)
        try:
            socketio.sleep(0)  # forces SocketIO to send immediately
        except Exception:
            pass


    if not raw_url:
        progress_step(100, "No URL provided", stage_index=0, result="Unknown")
        return jsonify({'result': 'Unknown', 'error': 'No URL provided'}), 400

    try:
        progress_step(0, "Starting scan...", url=raw_url)
        # 🚫 Skip scanning internal/system URLs
        if "localhost:5000" in raw_url or "127.0.0.1:5000" in raw_url:
            progress_step(100, "Internal URL skipped", stage_index=0, result="Safe", url=raw_url)
            return jsonify({
                "result": "Safe",
                "status": "internal_skip",
                "user_blocked": False,
                "url": raw_url,
                "domain": "internal",
                "ip_address": "127.0.0.1",
                "user": "system",
                "guest": False,
                "time": 0
            }), 200

        # --- Ensure URL has scheme ---
        progress_step(5, "Checking URL scheme...", url=raw_url)
        full_normalized = normalize_url(raw_url)
        original_url = raw_url # Keep original for display
        progress_step(10, "Normalizing URL...", url=original_url)
        # Use the full normalized URL (with query params) for matching
        normalized_url_for_match = full_normalized.lower()
        print(f"Normalized URL for Matching: {normalized_url_for_match}")
        progress_step(15, "URL normalized", stage_index=1, stage_info=normalized_url_for_match, url=original_url)

                # INSTANT USER BLOCK CHECK — SUPPORTS PARENT PATH BLOCKING
        if user:
            blocked_urls = BlockedURL.query.filter_by(user_id=user.id).all()
            current_url = normalized_url_for_match

            for blocked in blocked_urls:
                blocked_norm = normalize_url(blocked.url).lower()
                # Match: exact OR current URL starts with blocked path + "/"
                if current_url == blocked_norm or current_url.startswith(blocked_norm + "/"):
                    print(f"URL blocked by parent path: {blocked_norm} → {original_url}")
                    progress_step(100, "Blocked by user (path match)", result="Blocked", url=original_url)

                    # Update or create scan record
                    scan = PhishingURL.query.filter(
                        PhishingURL.user_id == user.id,
                        db.func.lower(PhishingURL.url) == original_url.lower()
                    ).first()
                    if scan:
                        scan.result = "Blocked"
                        scan.last_checked = datetime.now(timezone.utc)
                    else:
                        scan = PhishingURL(
                            url=original_url,
                            domain=urlparse(full_normalized).hostname or "unknown",
                            ip_address=None,
                            result="Blocked",
                            user_id=user.id,
                            created_at=datetime.now(timezone.utc),
                            last_checked=datetime.now(timezone.utc)
                        )
                        db.session.add(scan)

                    db.session.add(Notification(
                        user_id=user.id,
                        message=f"This URL has been manually blocked and is inaccessible.",
                        url=original_url,
                        created_at=datetime.now(timezone.utc)
                    ))
                    db.session.commit()

                    return jsonify({
                        "result": "Blocked",
                        "status": "user_blocked",
                        "user_blocked": True,
                        "url": original_url,
                        "domain": urlparse(full_normalized).hostname or "unknown",
                        "ip_address": None,
                        "user": user.username if user else "Guest",
                        "guest": not bool(user),
                        "time": 0
                    })

        parsed = urlparse(full_normalized)
        domain = parsed.hostname or parsed.netloc
        if not domain:
            import tldextract
            ext = tldextract.extract(full_normalized)
            domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else full_normalized
        domain_lower = domain.lower()
        progress_step(20, f"Domain extracted: {domain}", url=original_url)

        # --- Determine user ---
        user = current_user if current_user.is_authenticated else None
        if user_token and not user:
            user = User.query.filter_by(api_token=user_token).first()
        progress_step(25, "User determined", url=original_url)

        # --- Resolve IP with caching ---
        ip_cache = getattr(app, "_ip_cache", {})
        if domain in ip_cache:
            ip_address = ip_cache[domain]
        else:
            ip_address = resolve_ip_timeout(raw_url, timeout=5.0)
            ip_cache[domain] = ip_address
            app._ip_cache = ip_cache

        print("\n====== URL Scan Request ======")
        print(f"Scanning URL: {original_url}")
        print(f"Domain: {domain}")
        print(f"IP Address: {ip_address}")
        progress_step(35, "IP resolved", stage_index=2, stage_info=ip_address, url=original_url)

        result = None
        status = "scanned"
        user_blocked = False

        # --- Find existing scan record FIRST ---
        existing_scan = None
        if user:
            existing_scan = PhishingURL.query.filter(
                PhishingURL.user_id == user.id,
                func.lower(PhishingURL.url) == func.lower(original_url)
            ).first()
            if existing_scan:
                print(f"→ Found existing scan record (ID: {existing_scan.id})")

        # --- Load caches ---
        bl_urls, bl_domains, bl_ips = load_blacklist_cache()
        bl_urls = {u.lower(): True for u in bl_urls}
        bl_domains = {d.lower(): True for d in bl_domains}
        bl_ips = {i for i in bl_ips}

        safe_urls, safe_domains = load_safelist_cache()
        safe_urls = {u.lower(): True for u in safe_urls}
        progress_step(39, "Caches loaded", url=original_url)

        # --- Step 2: Global blacklists ---
        if normalized_url_for_match in bl_urls:
            result = "Phish"
            status = "global_blocked_url"
            print(f"→ Matched GLOBAL BLACKLIST URL: {original_url}")
            progress_step(55, "Matched GLOBAL BLACKLIST URL", stage_index=4, stage_info=original_url, result=result, url=original_url)
        elif domain_lower in bl_domains:
            result = "Phish"
            status = "global_blocked_domain"
            print(f"→ Matched GLOBAL BLACKLIST DOMAIN: {domain}")
            progress_step(55, "Matched GLOBAL BLACKLIST DOMAIN", stage_index=4, stage_info=domain, result=result, url=original_url)
        elif ip_address in bl_ips:
            result = "Phish"
            status = "global_blocked_ip"
            print(f"→ Matched GLOBAL BLACKLIST IP: {ip_address}")
            progress_step(55, "Matched GLOBAL BLACKLIST IP", stage_index=4, stage_info=ip_address, result=result, url=original_url)

        # --- Step 3: Safe URLs ---
        if result is None and normalized_url_for_match in safe_urls:
            result = "Safe"
            status = "safe_url"
            print(f"→ Matched SAFE URL: {original_url}")
            progress_step(65, "Matched SAFE URL", stage_index=5, stage_info=original_url, result=result, url=original_url)

        # --- Step 5: ML prediction ---
        if result is None:
            heuristic_result = predict_url_with_heuristic(raw_url)
            result = heuristic_result["result"]
            rf_result = heuristic_result["rf_result"]
            proba = heuristic_result["rf_proba"]
            features = heuristic_result["features"]

            print("\n====== Random Forest Debug ======")
            print(f"Scanned URL: {original_url}")
            for k, v in features.items():
                print(f"{k}: {v}")
            print(f"Prediction: {result}")
            print(f"Confidence: {proba}")
            print("================================\n")
            progress_step(90, "ML Prediction complete", stage_index=7, stage_info=f"Result: {result}", result=result, url=original_url)

        # --- Save scan & notification (old behavior) ---
        if user and manual:
            if not existing_scan:
                new_scan = PhishingURL(
                    url=original_url,
                    domain=domain,
                    ip_address=ip_address,
                    result=result,
                    user_id=user.id,
                    created_at=datetime.now(timezone.utc),
                    last_checked=datetime.now(timezone.utc)
                )
                db.session.add(new_scan)
                db.session.flush()
                scan_entry = new_scan
            else:
                existing_scan.result = result
                existing_scan.last_checked = datetime.now(timezone.utc)
                scan_entry = existing_scan

            if status == "user_blocked":
                notif_msg = f"The URL '{original_url}' is already blocked."
            elif status.startswith("global_blocked"): # Blacklist match
                notif_msg = "ALERT: This site has been flagged as a phishing threat. (Blacklist)"
            elif status == "safe_url": # Whitelist match
                notif_msg = "SAFE: The URL was classified as Safe. (Whitelist)"
            else:
                # This is for Random Forest results
                if result == "Phish":
                    notif_msg = "ALERT: This site has been flagged as a phishing threat. (Random Forest Classification)"
                else: # Safe
                    notif_msg = "SAFE: The URL was classified as Safe. (Random Forest Classification)"

            db.session.add(Notification(
                user_id=user.id,
                message=notif_msg,
                url=original_url,
                created_at=datetime.now(timezone.utc)
            ))
            db.session.commit()
            print("→ Notification sent for user:", user.username)
            progress_step(95, "Notification saved", stage_index=8, result=result, url=original_url)

            # Schedule re-scan for Safe URLs
            if result == "Safe" and scheduler:
                schedule_url_rescan(scan_entry)
                logger.info(f"Scheduled re-scan for Safe URL: {scan_entry.url}")

        # --- Done ---
        elapsed_time = round(time.time() - start_time, 2)
        print(f"✓ Scan completed in {elapsed_time} seconds")
        progress_step(100, "Scan complete", stage_index=9, stage_info=f"Time: {elapsed_time}s", result=result, url=original_url)
        return jsonify({
            "result": result,
            "status": status,
            "user_blocked": user_blocked,
            "url": original_url,
            "domain": domain,
            "ip_address": ip_address,
            "user": user.username if user else "Guest",
            "guest": not bool(user),
            "time": elapsed_time
        })

    except Exception as e:
        print("Prediction error:", e)
        progress_step(100, "Error during scan", stage_index=-1, stage_info=str(e), result="Unknown", url=raw_url)
        return jsonify({
            "result": "Unknown",
            "error": str(e),
            "message": "Internal server error occurred during URL prediction."
        }), 500

@app.route('/api/blocklist', methods=['GET'])
@login_required
def get_blocklist():
    from flask import jsonify
    # Fetch blocked URLs/domains/IPs for the logged-in user
    urls = [b.url for b in BlacklistURL.query.all()]
    domains = [d.domain for d in BlacklistDomain.query.all()]
    ips = [i.ip for i in BlacklistIP.query.all()]
    
    return jsonify({
        "urls": urls,
        "domains": domains,
        "ips": ips
    })


@app.route('/dashboard')
@login_required
def dashboard():
    user = current_user
    scan_count = PhishingURL.query.filter_by(user_id=user.id).count()
    blocked_count = BlockedURL.query.filter_by(user_id=current_user.id).count()

    # --- Fetch history for table ---
    scans = (
        PhishingURL.query
        .filter_by(user_id=user.id)
        .order_by(PhishingURL.created_at.desc())
        .all()
    )
    history = [{
        'url': s.url,
        'domain': s.domain,
        'ip_address': s.ip_address,
        'result': s.result,
        'created_at': s.created_at.strftime('%Y-%m-%d')
    } for s in scans]

    # --- Aggregate scans by day (last 30 days) ---
    scan_stats = (
        db.session.query(
            func.date(PhishingURL.created_at).label('date'),
            func.count().label('count')
        )
        .filter(PhishingURL.user_id == user.id)
        .group_by(func.date(PhishingURL.created_at))
        .order_by(func.date(PhishingURL.created_at))
        .all()
    )

    # Convert to dict list for chart
    chart_data = [{'date': str(r.date), 'count': r.count} for r in scan_stats]

    return render_template(
        'dash.html',
        user=user,
        scan_count=scan_count,
        block_count=blocked_count,
        history=history,
        chart_data=chart_data
    )
@app.route('/')
def home():
    # Landing page is scanner
    return render_template('Scanner.html', user=current_user if current_user.is_authenticated else None)

@app.route('/scanner')
def scanner():
    # Public scanner page (no login required)
    return render_template('scanner.html', user=current_user if current_user.is_authenticated else None)


@app.route('/blockpage', methods=['GET'])
@login_required
def block_page():
    user = current_user
    blocked_urls = BlockedURL.query.filter_by(user_id=user.id).all()
    return render_template('blockpage.html', user=user, blocked_urls=blocked_urls)

@app.route('/get_notifications')
@login_required
def get_notifications():
    notifs = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.created_at.desc()).all()
    return jsonify([
        {
            'message': n.message,
            'url': n.url,  # ✅ Include the URL so frontend can make it clickable
            'is_read': n.is_read,
            'timestamp': n.created_at.isoformat()
        }
        for n in notifs
    ])

@app.route('/clear_notifications', methods=['POST'])
@login_required
def clear_notifications():
    Notification.query.filter_by(user_id=current_user.id).delete()
    db.session.commit()
    return '', 204

@app.route('/block_url', methods=['POST'])
def block_url():
    if not current_user.is_authenticated:
        return jsonify({'status': 'error', 'message': 'Login required'}), 401

    data = request.get_json()
    url = normalize_url(data.get('url'))

    # Safely parse domain
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower() if parsed.netloc else None
    except Exception:
        domain = None

    if not url or not domain:
        return jsonify({'status': 'error', 'message': 'Invalid URL'}), 400

    # Prevent duplicates
    existing = BlockedURL.query.filter_by(user_id=current_user.id, url=url).first()
    if existing:
        return jsonify({'status': 'already_blocked', 'message': 'URL already blocked'}), 200

    # Save blocked entry
    blocked = BlockedURL(
        user_id=current_user.id,
        url=url,
        domain=domain,
        ip_address=resolve_ip_timeout(url)
    )
    db.session.add(blocked)
    db.session.commit()

    return '', 204

@app.route('/unblock', methods=['POST'])
@login_required
def unblock_url():
    url_id = request.form.get('url_id')
    blocked = BlockedURL.query.filter_by(id=url_id, user_id=current_user.id).first()

    if blocked:
        db.session.delete(blocked)
        db.session.commit()
        flash("URL has been unblocked.", "success")
    else:
        flash("URL not found or unauthorized.", "danger")

    return redirect(url_for('block_page'))

@app.route('/remove_blacklist/<int:id>', methods=['POST'])
@login_required
def remove_blacklist(id):
    item = BlockedURL.query.filter_by(id=id, user_id=current_user.id).first()
    if item:
        db.session.delete(item)
        db.session.commit()
    return redirect(url_for('block_page'))


@app.route('/api/blocked-urls', methods=['GET'])
@login_required
def get_blocked_urls():
    blocked = BlockedURL.query.filter_by(user_id=current_user.id).all()
    urls = [entry.url for entry in blocked]
    return jsonify({'blocked_urls': urls})

@app.route('/check_url', methods=['POST'])
def check_url():
    import time
    import pandas as pd
    from urllib.parse import urlparse
    import sys
    import os

    # Ensure feature_extractor can be imported
    sys.path.append(os.path.join(os.path.dirname(__file__), "feature_extraction"))
    from feature_extractor import extract_url_features as extract_features

    data = request.get_json()
    raw_url = data.get('url')

    if not raw_url:
        return jsonify({'result': 'Unknown', 'domain': None, 'elapsed_time': 0}), 400

    start_time = time.time()
    try:
        # Normalize and parse URL
        url = normalize_url(raw_url.strip().lower())
        parsed = urlparse(url)
        domain = parsed.netloc
        result = None

        print(f"\n🔍 Testing URL (ML only): {url}")

        # --- ML model prediction only ---
        try:
            features = extract_features(url)
            df = pd.DataFrame([features])
            prediction = rf_model.predict(df)[0]  # Use preloaded model
            result = 'phish' if prediction == 1 else 'safe'
            print(f"🤖 ML predicted: {result}")
        except Exception as ml_err:
            print(f"⚠️ ML prediction failed: {ml_err}")
            result = 'Unknown'

        # Compute elapsed time
        elapsed = round(time.time() - start_time, 2)
        print(f"✅ Finished ML-only check in {elapsed}s")

        # Return JSON
        return jsonify({
            'result': result,
            'domain': domain,
            'elapsed_time': elapsed
        })

    except Exception as e:
        elapsed = round(time.time() - start_time, 2)
        print("❌ Error in /check_url:", e)
        return jsonify({
            'result': 'error',
            'domain': None,
            'elapsed_time': elapsed,
            'error': str(e)
        }), 500


@login_manager.unauthorized_handler
def unauthorized_callback():
    # If the request prefers JSON (API/extension requests)
    if request.accept_mimetypes['application/json'] >= request.accept_mimetypes['text/html']:
        return jsonify({'error': 'Unauthorized'}), 401
    # Otherwise, redirect normal browser users to the login page
    return redirect(url_for('login_page'))

@app.route("/send-reset-code", methods=["POST"])
def send_reset_code():
    email = request.form.get("email")
    user = User.query.filter_by(email=email).first()

    # 🟡 If email not found → return message (no redirect)
    if not user:
        return jsonify({"message": "No account found with that email."}), 404

    # Generate a 6-digit reset code
    reset_code = ''.join(random.choices(string.digits, k=6))
    user.reset_code = reset_code
    user.reset_expiration = datetime.utcnow() + timedelta(minutes=2)
    db.session.commit()

    # Save email to session for later verification
    session['reset_email'] = email

    # Compose email
    msg = Message("Your Reset Code", sender="your@email.com", recipients=[email])

    # Plain-text fallback
    msg.body = (
        "⚠️ DO NOT share this code with anyone.\n\n"
        "This reset code is valid for only 2 minutes.\n\n"
        f"Your reset code: {reset_code}"
    )

    # HTML-styled message
    msg.html = f"""
    <!DOCTYPE html>
    <html>
      <body style="font-family: Arial, sans-serif; background-color: #f9f9f9; padding: 20px;">
        <div style="max-width: 500px; margin: auto; background-color: #ffffff; border-radius: 10px; padding: 30px; box-shadow: 0 0 10px rgba(0,0,0,0.1);">
          <h2 style="color: #d9534f;">Do Not Share This Code</h2>
          <p style="font-size: 16px;">This reset code is private. <strong>Do not share it</strong> with anyone.</p>
          <p><strong>Code expires in <span style="color:#d9534f;">2 minutes</span>.</strong></p>
          <p style="margin-top: 20px; font-size: 20px;"> <strong>Your Reset Code:</strong></p>
          <div style="font-size: 32px; font-weight: bold; color: #003082; margin: 10px 0;">{reset_code}</div>
          <p style="font-size: 14px; color: #999;">If you didn't request this, please ignore this email.</p>
        </div>
      </body>
    </html>
    """

    mail.send(msg)

    # 🟢 Return success JSON (to be handled below the form)
    return jsonify({"message": "A reset code has been sent to your email."}), 200


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            reset_code = ''.join(random.choices(string.digits, k=6))
            user.reset_code = reset_code
            user.reset_expiration = datetime.utcnow() + timedelta(minutes=10)
            db.session.commit()
            send_reset_email(user.email, reset_code)
            session['reset_user_id'] = user.id
            flash('Reset code sent to your email.', 'success')
            return redirect(url_for('verify_code'))
        else:
            flash('Email not found.', 'danger')
    return render_template('forgot_password.html')

@app.route("/verify_code", methods=["GET", "POST"])
def verify_code():
    if request.method == "POST":
        code = request.form.get("code")
        email = session.get("reset_email")

        user = User.query.filter_by(email=email).first()

        if not user or not user.reset_code or user.reset_code != code:
            flash("Invalid or expired reset code.", "error")
            return redirect(url_for("verify_code"))

        if datetime.utcnow() > user.reset_expiration:
            flash("Reset code has expired.", "error")
            return redirect(url_for("forgot_password"))

        # ✅ Valid code — proceed to set password, but DO NOT flash success yet
        return redirect(url_for("set_new_password"))

    return render_template("verify_code.html")

@app.route("/set-new-password", methods=["GET", "POST"])
def set_new_password():
    email = session.get("reset_email")
    user = User.query.filter_by(email=email).first()

    if not user:
        flash("Session expired. Please try again.", "error")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        new_password = request.form.get("new_password")
        confirm = request.form.get("confirm")

        if new_password != confirm:
            flash("Passwords do not match.", "error")
            return redirect(url_for("set_new_password"))

        hashed_pw = bcrypt.generate_password_hash(new_password).decode("utf-8")
        user.password = hashed_pw
        user.reset_code = None
        user.reset_expiration = None
        db.session.commit()

        flash("Password reset successfully!", "success")
        return redirect(url_for("login_page"))

    return render_template("set_new_password.html")

@app.route('/is_blocked', methods=['POST'])
def is_blocked():
    data = request.get_json()
    url = data.get("url", "")
    normalized = normalize_url(url)
    domain = urlparse(normalized).netloc
    ip = socket.gethostbyname(domain)

    if (
        db.session.query(BlacklistURL).filter_by(url=normalized).first() or
        db.session.query(BlacklistDomain).filter_by(domain=domain).first() or
        db.session.query(BlacklistIP).filter_by(ip_address=ip).first()
    ):
        return jsonify({'blocked': True})
    
    return jsonify({'blocked': False})

@app.route('/get_recent_scan')
@login_required
def get_recent_scan():
    recent_scan = PhishingURL.query.filter_by(user_id=current_user.id)\
                                   .order_by(PhishingURL.timestamp.desc()).first()
    if recent_scan:
        return jsonify({
            "url": recent_scan.url,
            "result": recent_scan.result,
            "timestamp": recent_scan.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        })
    return jsonify({"result": "Unknown"})

@app.route('/clear_scan_history', methods=['POST'])
@login_required
def clear_scan_history():
    try:
        PhishingURL.query.filter_by(user_id=current_user.id).delete()
        db.session.commit()
        return jsonify({'status': 'success'})
    except Exception as e:
        print("Error clearing scan history:", e)
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route("/api/scan-history", methods=["GET"])
@login_required
def api_scan_history():
    filter_type = request.args.get("filter", "7days")
    now = datetime.utcnow()
    if filter_type == "7days":
        start_date = now - timedelta(days=7)
    elif filter_type == "1m":
        start_date = now - timedelta(days=30)
    elif filter_type == "1y":
        start_date = now - timedelta(days=365)
    else:
        start_date = now - timedelta(days=7)

    scans = (
    PhishingURL.query.filter(
        PhishingURL.user_id == current_user.id,
        PhishingURL.created_at >= start_date
    )
    .order_by(PhishingURL.created_at.desc())
    .all()
)


    history = []
    for scan in scans:
        history.append({
            "url": scan.url,
            "domain": scan.domain or "-",
            "ip_address": scan.ip_address or "-",
            "result": scan.result
        })

    return jsonify({"history": history})

    # --- Prepare data for frontend ---
    history = []
    safe_count = 0
    phishing_count = 0
    blocked_count = 0

    for scan in scans:
        history.append({
            "url": scan.url,
            "domain": scan.domain or "-",
            "ip_address": scan.ip_address or "-",
            "result": scan.result or "Unknown",
            "timestamp": scan.timestamp.strftime("%Y-%m-%d %H:%M"),
            "blocked": scan.blocked if hasattr(scan, "blocked") else False
        })

        if scan.result == "Safe":
            safe_count += 1
        elif scan.result == "Phish":
            phishing_count += 1

        if hasattr(scan, "blocked") and scan.blocked:
            blocked_count += 1

    return jsonify({
        "history": history,
        "stats": {
            "safe": safe_count,
            "phish": phishing_count,
            "blocked": blocked_count
        }
    })

@app.route('/api/chart-data/<period>')
@login_required
def chart_data(period):
    from datetime import datetime, timedelta
    from sqlalchemy import extract, func
    from calendar import month_name

    now = datetime.utcnow()
    user_id = current_user.id

    labels = []
    data = []

    # --- 7-day chart ---
    if period == "7d":
        start_date = now - timedelta(days=6)  # last 7 days including today
        rows = (
            db.session.query(
                func.date(BlockedURL.added_on).label("day"),
                func.count().label("count")
            )
            .filter(BlockedURL.user_id == user_id, BlockedURL.added_on >= start_date)
            .group_by(func.date(BlockedURL.added_on))
            .order_by(func.date(BlockedURL.added_on))
            .all()
        )
        counts = {row.day: row.count for row in rows}

        for i in range(7):
            day = (start_date + timedelta(days=i)).date()
            labels.append(day.strftime("%b %d"))  # e.g., "Aug 26"
            data.append(counts.get(day, 0))

    # --- 1-month chart (weekly) ---
    elif period == "1m":
        start_date = now - timedelta(days=30)
        rows = (
            db.session.query(
                extract("year", BlockedURL.added_on).label("year"),
                extract("month", BlockedURL.added_on).label("month"),
                func.floor((extract("day", BlockedURL.added_on)-1)/7 + 1).label("week_of_month"),
                func.count().label("count")
            )
            .filter(BlockedURL.user_id == user_id, BlockedURL.added_on >= start_date)
            .group_by(
                extract("year", BlockedURL.added_on),
                extract("month", BlockedURL.added_on),
                func.floor((extract("day", BlockedURL.added_on)-1)/7 + 1)
            )
            .order_by(
                extract("year", BlockedURL.added_on),
                extract("month", BlockedURL.added_on),
                func.floor((extract("day", BlockedURL.added_on)-1)/7 + 1)
            )
            .all()
        )

        counts = {(int(r.year), int(r.month), int(r.week_of_month)): r.count for r in rows}

        # Generate labels week by week from start_date to now
        current = start_date
        while current <= now:
            y, m, d = current.year, current.month, current.day
            week_of_month = (d - 1) // 7 + 1
            # Determine suffix
            suffix = "th"
            if week_of_month == 1: suffix = "st"
            elif week_of_month == 2: suffix = "nd"
            elif week_of_month == 3: suffix = "rd"
            label = f"{month_name[m]} {week_of_month}{suffix} Week"
            labels.append(label)
            data.append(counts.get((y, m, week_of_month), 0))
            current += timedelta(days=7)

    # --- 1-year chart (monthly) ---
    elif period == "1y":
        start_date = now - timedelta(days=365)
        rows = (
            db.session.query(
                extract("month", BlockedURL.added_on).label("month"),
                func.count().label("count")
            )
            .filter(BlockedURL.user_id == user_id, BlockedURL.added_on >= start_date)
            .group_by(extract("month", BlockedURL.added_on))
            .order_by(extract("month", BlockedURL.added_on))
            .all()
        )

        counts = {int(r.month): r.count for r in rows}
        for i in range(1, 13):
            labels.append(month_name[i])
            data.append(counts.get(i, 0))

    else:
        return jsonify({"labels": [], "data": []})

    return jsonify({"labels": labels, "data": data})

@app.route('/check_urls_batch', methods=['POST'])
def check_urls_batch():
    import logging
    import pandas as pd
    from joblib import Parallel, delayed
    import multiprocessing
    from flask import request, jsonify

    data = request.get_json()
    urls = data.get('urls', [])
    if not urls:
        return jsonify({"results": [], "error": "No URLs provided"}), 400

    def predict_single(u):
        try:
            # Extract features (skip WHOIS if not needed)
            features = extract_url_features(u)
            df = pd.DataFrame([[features[f] for f in FEATURE_NAMES]], columns=FEATURE_NAMES)
            pred = rf_model.predict(df)[0]
            return {"url": u, "result": "phish" if pred == 1 else "safe"}
        except Exception as e:
            logging.error(f"Error scanning {u}: {e}")
            return {"url": u, "result": "Unknown"}

    # Run in parallel for speed
    n_jobs = min(len(urls), multiprocessing.cpu_count())
    results = Parallel(n_jobs=n_jobs)(delayed(predict_single)(u) for u in urls)

    # Ensure all URLs are returned, even if errors occurred
    return jsonify({"results": results})

@app.route('/get_dashboard_stats')
def get_dashboard_stats():
    total_users = User.query.count()
    total_scans = PhishingURL.query.count()
    total_blocks = BlockedURL.query.count()
    return jsonify({
        "users": total_users,
        "scans": total_scans,
        "blocks": total_blocks
    })


# ---------------- APScheduler: Per-URL Re-scan ----------------
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
import atexit
import logging
import traceback

# ---------------- Logging Setup ----------------
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
)
logger = logging.getLogger(__name__)

scheduler = None

# ⚙️ CONFIGURATION: Change this for testing vs production
RESCAN_INTERVAL_MINUTES = 60  # 🔴 2 minutes for TESTING, change to 60 for production

# ---------------- Helper: Make datetime timezone-aware ----------------
from zoneinfo import ZoneInfo

def make_aware(dt):
    if dt is None:
        return None
    local_tz = ZoneInfo("Asia/Manila")
    if dt.tzinfo is None:
        return dt.replace(tzinfo=local_tz)
    return dt


# ---------------- APScheduler Startup ----------------
def start_scheduler():
    global scheduler
    
    print("=" * 70)
    print("DEBUG: Inside start_scheduler() function")
    print(f"DEBUG: scheduler variable = {scheduler}")
    print("=" * 70)
    
    if scheduler:
        logger.warning("Scheduler already running")
        return
    
    print("DEBUG: Passed the scheduler check, continuing...")
    
    try:
        logger.info("=" * 70)
        print("=" * 70)  # ADD
        logger.info("INITIALIZING SCHEDULER")
        print("INITIALIZING SCHEDULER")  # ADD
        logger.info(f"Re-scan interval: {RESCAN_INTERVAL_MINUTES} minute(s)")
        print(f"Re-scan interval: {RESCAN_INTERVAL_MINUTES} minute(s)")  # ADD
        logger.info("=" * 70)
        print("=" * 70)  # ADD
        
        with app.app_context():
            db.create_all()
            logger.info("Database tables verified")
            print("Database tables verified")  # ADD
            
            load_blacklist_cache.cache_clear()
            load_safelist_cache.cache_clear()
            load_blacklist_cache()
            load_safelist_cache()
            logger.info("Blacklist and Safelist caches preloaded")
            print("Blacklist and Safelist caches preloaded")  # ADD

        jobstores = {
            'default': SQLAlchemyJobStore(url=app.config['SQLALCHEMY_DATABASE_URI'])
        }
        
        SCHED_TZ = ZoneInfo("Asia/Manila")

        scheduler = BackgroundScheduler(
            jobstores=jobstores,
            timezone=SCHED_TZ,
            job_defaults={
                'coalesce': True,
                'max_instances': 1,
                'misfire_grace_time': 300
            }
        )
        logger.info("Scheduler object created")
        print("Scheduler object created")  # ADD
        print(f"Scheduler timezone: {scheduler.timezone}")

        # === RESTORE JOBS ===
        with app.app_context():
            safe_urls = PhishingURL.query.filter_by(result="Safe").all()
            logger.info(f"Found {len(safe_urls)} Safe URLs in database")
            print(f"Found {len(safe_urls)} Safe URLs in database")  # ADD
            
            scheduled_count = 0
            for entry in safe_urls:
                job_id = f"rescan_{entry.id}"
                if scheduler.get_job(job_id):
                    continue
                
                # Compute based purely on LOCAL time (no UTC conversion)
                if entry.last_checked:
                    # Treat stored time as local, not UTC
                    last_checked_local = entry.last_checked
                    if last_checked_local.tzinfo is None:
                        last_checked_local = last_checked_local.replace(tzinfo=SCHED_TZ)
                else:
                    last_checked_local = datetime.now(SCHED_TZ)

                next_run = last_checked_local + timedelta(minutes=RESCAN_INTERVAL_MINUTES)

                # If the time already passed, run it soon
                now = datetime.now(SCHED_TZ)
                if next_run < now:
                    next_run = now + timedelta(seconds=10)

                scheduler.add_job(
                    func=rescan_single_url,
                    trigger="interval",
                    minutes=RESCAN_INTERVAL_MINUTES,
                    args=[entry.id],
                    id=job_id,
                    replace_existing=True,
                    next_run_time=next_run
                )
                scheduled_count += 1
                
                user = User.query.get(entry.user_id)
                username = user.username if user else "Unknown"
                logger.info(f"[{scheduled_count}] Scheduled: {entry.url} to {next_run.strftime('%Y-%m-%d %H:%M:%S %Z')} (User: {username})")
                print(f"[{scheduled_count}] Scheduled: {entry.url} to {next_run.strftime('%H:%M:%S %Z')} (User: {username})")


        print("🔍 DEBUG: Active job list after start:")
        for job in scheduler.get_jobs():
            print(f"  → {job.id}: next run at {job.next_run_time}")



        # === START SCHEDULER ===
        if not scheduler.running:
            scheduler.start()
            print(f"Scheduler timezone actual: {scheduler.timezone}")
            for job in scheduler.get_jobs():
                print(f"{job.id} → {job.next_run_time.astimezone(ZoneInfo('Asia/Manila'))} (Asia/Manila)")
            logger.info("=" * 70)
            print("=" * 70)  # ADD
            logger.info("SCHEDULER STARTED SUCCESSFULLY")
            print("SCHEDULER STARTED SUCCESSFULLY")  # ADD
            logger.info(f"Active jobs: {scheduled_count}")
            print(f"Active jobs: {scheduled_count}")  # ADD
            logger.info(f"Re-scan interval: {RESCAN_INTERVAL_MINUTES} minute(s)")
            print(f"Re-scan interval: {RESCAN_INTERVAL_MINUTES} minute(s)")  # ADD
            logger.info("=" * 70)
            print("=" * 70)  # ADD
        else:
            logger.warning("Scheduler already running")
            print("Scheduler already running")  # ADD

        atexit.register(lambda: scheduler and scheduler.shutdown(wait=False))
        
    except Exception as e:
        logger.error("=" * 70)
        print("=" * 70)  # ADD
        logger.error("SCHEDULER STARTUP FAILED")
        print("SCHEDULER STARTUP FAILED")  # ADD
        logger.error(f"Error: {e}")
        print(f"EXCEPTION IN start_scheduler(): {e}")  # ADD
        logger.error(traceback.format_exc())
        import traceback
        traceback.print_exc()

# ---------------- Schedule Re-scan for Individual URL ----------------
def schedule_url_rescan(entry):
    """Schedule periodic re-scan for a Safe URL"""
    if not scheduler:
        logger.error("❌ Scheduler not initialized, cannot schedule rescan")
        return
    
    if entry.result != "Safe":
        logger.info(f"⏭️ Skipping rescan schedule for {entry.url} (result: {entry.result})")
        return
    
    job_id = f"rescan_{entry.id}"
    
    try:
        # Remove existing job if present
        try:
            scheduler.remove_job(job_id)
            logger.info(f"🗑️ Removed existing job {job_id}")
        except:
            pass
        
        # Calculate next run time
        SCHED_TZ = ZoneInfo("Asia/Manila")
        last_checked = make_aware(entry.last_checked)
        now = datetime.now(SCHED_TZ)

        if last_checked:
            next_run = last_checked + timedelta(minutes=RESCAN_INTERVAL_MINUTES)
            if next_run < now:
                next_run = now + timedelta(seconds=10)
        else:
            next_run = now + timedelta(seconds=10)
        
        # Add new job
        scheduler.add_job(
            func=rescan_single_url,
            trigger="interval",
            minutes=RESCAN_INTERVAL_MINUTES,
            args=[entry.id],
            id=job_id,
            replace_existing=True,
            next_run_time=next_run
        )
        
        user = User.query.get(entry.user_id)
        username = user.username if user else "Unknown"
        
        logger.info(f"⏰ Scheduled {RESCAN_INTERVAL_MINUTES}-min rescan:")
        logger.info(f"    User: {username}")
        logger.info(f"    URL: {entry.url}")
        logger.info(f"    Next scan: {next_run.strftime('%Y-%m-%d %H:%M:%S %Z')}")
        
    except Exception as e:
        logger.error(f"❌ Failed to schedule job {job_id}: {e}")
        logger.error(traceback.format_exc())

        logger.info(f"SUCCESS: Re-scan scheduled for {entry.url} at {next_run}")
        print(f"SUCCESS: Re-scan scheduled for {entry.url} at {next_run.strftime('%H:%M:%S')}")


# ---------------- Re-scan Function ----------------
def rescan_single_url(url_id):
    current_time = datetime.now(ZoneInfo("Asia/Manila"))
    print(f"🔁 DEBUG: Executing rescan_single_url() for job: rescan_{url_id}, at {current_time}")
    """Re-scan a single URL and update database"""
    logger.info("")
    logger.info("=" * 70)
    logger.info(f"🔄 STARTING AUTOMATIC RE-SCAN")
    logger.info("=" * 70)
    
    try:
        with app.app_context():
            # Fetch the URL entry
            entry = db.session.get(PhishingURL, url_id)
            if not entry:
                logger.warning(f"⚠️ URL id={url_id} not found in database")
                return
            
            # Get user info
            user = User.query.get(entry.user_id)
            username = user.username if user else "Unknown"

            # Print clean summary
            print(f"\n🔁 Re-scan started at: {current_time.strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"🔗 URL: {entry.url}")
            print(f"👤 User: {username}")
            logger.info(f"🔁 Re-scan started at {current_time} for {entry.url} (User: {username})")

            # Perform scan
            heuristic_result = predict_url_with_heuristic(entry.url)
            new_result = heuristic_result.get("result", "Unknown")

            print(f"🎯 Result: {new_result}")
            logger.info(f"🎯 Result: {new_result}")
            
            # Check if status changed from Safe to Phish
            if entry.result == "Safe" and new_result == "Phish":
                logger.warning("")

                escaped_url = escape(entry.url)

                logger.warning("🚨" * 35)
                logger.warning("🚨 PHISHING DETECTED - STATUS CHANGED!")
                logger.warning("🚨" * 35)
                logger.warning(f"URL: {entry.url}")
                logger.warning(f"User: {username}")
                logger.warning(f"Status: Safe → Phish")
                logger.warning("🚨" * 35)
                
                # Create notification in database
                notif_msg = (
                    f"The URL '{escaped_url}' was Safe before but is now flagged as Phish."
                )
                notif_html_msg = (
                    f"Phishing Alert: The URL <strong>{escaped_url}</strong> was previously marked as "
                    f"<strong>Safe</strong>, but is now detected as <strong>Phishing</strong>!"
                )
                notification = Notification(
                    user_id=entry.user_id,
                    # Use the HTML version for storage, assuming it might be rendered in a context that supports it (like email).
                    # The frontend JS will handle creating a safe display message.
                    message=notif_html_msg,
                    url=entry.url,
                    created_at=current_time
                )
                db.session.add(notification)
                db.session.flush()
                
                logger.info(f"✅ Notification saved to database (ID: {notification.id})")
                
                # Emit real-time notification via SocketIO
                try:
                    socketio.emit(
                        'new_notification',
                        {
                            'message': notif_msg,
                            'url': entry.url,
                            'is_read': False,
                            'created_at': datetime.now(timezone.utc).isoformat()
                        },
                        room=str(entry.user_id)
                    )
                    logger.info(f"📨 Real-time notification sent to user {username} (room: {entry.user_id})")
                except Exception as sock_err:
                    logger.error(f"❌ SocketIO notification failed: {sock_err}")
            
            elif entry.result == "Safe" and new_result == "Safe":
                logger.info("✅ URL is still Safe - no notification needed")
            
            elif entry.result == "Phish" and new_result == "Safe":
                logger.info("✅ URL improved: Phish → Safe")
            
            # Update entry in database
            old_result = entry.result
            entry.result = new_result
            entry.last_checked = current_time
            db.session.commit()
            
            logger.info(f"💾 Database updated: {old_result} → {new_result}")
            
            # If no longer Safe, stop re-scanning
            if new_result != "Safe":
                job_id = f"rescan_{entry.id}"
                try:
                    if scheduler and scheduler.get_job(job_id):
                        scheduler.remove_job(job_id)
                        logger.info(f"🛑 Stopped automatic re-scans (URL is now {new_result})")
                except Exception as job_err:
                    logger.error(f"❌ Failed to remove job {job_id}: {job_err}")
            else:
                next_run = current_time + timedelta(minutes=RESCAN_INTERVAL_MINUTES)
                print(f"⏰ Next automatic re-scan scheduled at: {next_run.strftime('%Y-%m-%d %H:%M:%S')}")
                logger.info(f"⏰ Next automatic re-scan scheduled at: {next_run}")
            
            logger.info("=" * 70)
            logger.info("✅ RE-SCAN COMPLETE")
            logger.info("=" * 70)
            logger.info("")
                
    except Exception as e:
        logger.error("=" * 70)
        logger.error(f"❌ FATAL ERROR IN RE-SCAN")
        logger.error("=" * 70)
        logger.error(f"URL ID: {url_id}")
        logger.error(f"Error: {e}")
        logger.error(traceback.format_exc())
        logger.error("=" * 70)

# ---------------- Diagnostic Routes ----------------
@app.route('/scheduler_status')
def scheduler_status():
    """Debug endpoint to check scheduler state"""
    local_tz = ZoneInfo("Asia/Manila")  # 👈 Add this line
    if not scheduler:
        return jsonify({
            "status": "not initialized", 
            "error": "Scheduler is None"
        }), 500
    
    try:
        jobs = scheduler.get_jobs()
        job_details = []
        
        with app.app_context():
            for j in jobs:
                # Extract URL ID from job ID
                url_id = int(j.id.replace("rescan_", ""))
                entry = db.session.get(PhishingURL, url_id)
                
                if entry:
                    user = User.query.get(entry.user_id)
                    job_details.append({
                        "job_id": j.id,
                        "url": entry.url,
                        "user": user.username if user else "Unknown",
                        "result": entry.result,
                        "last_checked_local": entry.last_checked.astimezone(local_tz).strftime('%Y-%m-%d %H:%M:%S %Z') if entry.last_checked else None,
                        "next_run_local": j.next_run_time.astimezone(local_tz).strftime('%Y-%m-%d %H:%M:%S %Z') if j.next_run_time else None
                    })
        
        return jsonify({
            "status": "running" if scheduler.running else "stopped",
            "interval_minutes": RESCAN_INTERVAL_MINUTES,
            "job_count": len(jobs),
            "jobs": job_details
        })
    except Exception as e:
        return jsonify({
            "error": str(e), 
            "traceback": traceback.format_exc()
        }), 500


@app.route('/trigger_rescan/<int:url_id>')
@login_required
def trigger_manual_rescan(url_id):
    """Manually trigger a rescan for testing"""
    try:
        with app.app_context():
            entry = db.session.get(PhishingURL, url_id)
            if not entry:
                return jsonify({"error": "URL not found"}), 404
            
            if entry.user_id != current_user.id:
                return jsonify({"error": "Unauthorized"}), 403
            
            # Trigger rescan in background
            import threading
            thread = threading.Thread(target=rescan_single_url, args=[url_id])
            thread.start()
            
            return jsonify({
                "message": f"Manual rescan triggered for {entry.url}",
                "check_console": "Check server console for logs"
            })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------- Preload Caches on Startup ----------------
def preload_caches():
    print("=" * 70)
    print("📦 PRELOADING CACHES")
    print("=" * 70)
    try:
        with app.app_context():
            load_blacklist_cache.cache_clear()
            load_safelist_cache.cache_clear()
            load_blacklist_cache()
            load_safelist_cache()
        print("✅ Caches preloaded successfully")
        print("=" * 70)
    except Exception as e:
        print(f"⚠️ Cache preload failed: {e}")
        print("=" * 70)

@app.route('/recent_urls', methods=['GET'])
def recent_urls():
    # Fetch the 10 most recent scanned URLs
    recent = (
        PhishingURL.query
        .order_by(PhishingURL.created_at.desc())
        .limit(10)
        .all()
    )

    return jsonify([
        {
            "url": r.url,
            "domain": r.domain,
            "result": r.result or "Unknown",
            "timestamp": r.created_at.isoformat(),
            "user_id": r.user_id
        } for r in recent
    ])


# ---------------- Main Entrypoint ---------------- 
if __name__ == "__main__":
    import os
    import traceback

    print("\n" + "=" * 70)
    print("🔍 DEBUG: Starting application (local dev mode)")
    print("=" * 70)

    # Preload caches
    try:
        preload_caches()
    except Exception as e:
        print(f"❌ Cache preload failed: {e}")
        traceback.print_exc()

    # Start scheduler in background
    def run_scheduler():
        with app.app_context():
            try:
                start_scheduler()
            except Exception as e:
                print(f"❌ Scheduler failed: {e}")
                traceback.print_exc()

    socketio.start_background_task(run_scheduler)

    # Local testing only — remove this for Render
    if os.environ.get("RENDER") != "true":
        port = int(os.environ.get("PORT", 5000))
        socketio.run(app, host="0.0.0.0", port=port, debug=True)










