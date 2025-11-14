import os

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "your-secret-key")
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL", "postgresql://postgres:06032004@localhost/phishing_db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
