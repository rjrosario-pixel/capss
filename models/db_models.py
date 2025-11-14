from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime, timedelta

db = SQLAlchemy()

# User accounts
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    phishing_urls = db.relationship('PhishingURL', backref='user', lazy=True)
    safe_urls = db.relationship('SafeURL', backref='safe_user', lazy=True)

    reset_code = db.Column(db.String(6), nullable=True)
    reset_expiration = db.Column(db.DateTime, nullable=True)
    
# URLs submitted by users for scanning
from sqlalchemy import UniqueConstraint

class PhishingURL(db.Model):
    __tablename__ = 'phishing_urls'
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String, nullable=False)
    domain = db.Column(db.String)
    ip_address = db.Column(db.String(45))
    result = db.Column(db.String)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_checked = db.Column(db.DateTime, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))

    # ✅ Enforce uniqueness for each user-url pair
    __table_args__ = (
        UniqueConstraint('user_id', 'url', name='unique_user_url'),
    )


# Blacklisted URLs from PhishTank or GitHub
class BlacklistURL(db.Model):
    __tablename__ = 'blacklist_urls'
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String, nullable=False, unique=True)
    domain = db.Column(db.String)
    source = db.Column(db.String)  # e.g., 'PhishTank', 'GitHub', or 'User'
    added_on = db.Column(db.DateTime, default=datetime.utcnow)

    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))  # ✅ Add this line

# Safe URLs submitted or imported
class SafeURL(db.Model):
    __tablename__ = 'safe_urls'
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String, nullable=False, unique=True)
    added_on = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))

class BlacklistIP(db.Model):
    __tablename__ = 'blacklist_ips'
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String, unique=True, nullable=False)
    source = db.Column(db.String, default='GitHub')
    added_on = db.Column(db.DateTime, default=datetime.utcnow)

class BlacklistDomain(db.Model):
    __tablename__ = 'blacklist_domains'
    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String, unique=True, nullable=False)
    source = db.Column(db.String, default='GitHub')
    added_on = db.Column(db.DateTime, default=datetime.utcnow)

class SafeDomain(db.Model):
    __tablename__ = 'safe_domains'
    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(255), unique=True, nullable=False)
    added_on = db.Column(db.DateTime, default=datetime.utcnow)

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    message = db.Column(db.String(255))
    url = db.Column(db.String(255), nullable=True)  # Add URL field
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref='notifications')
    
class BlockedURL(db.Model):
    __tablename__ = 'blocked_urls'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    url = db.Column(db.String, nullable=False)
    domain = db.Column(db.String, nullable=False)
    ip_address = db.Column(db.String, nullable=True)
    added_on = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref='blocked_urls')

