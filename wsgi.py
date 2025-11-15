#!/usr/bin/env python3
"""
WSGI entry point for Gunicorn
"""
import os
import sys
import traceback

print("\n" + "=" * 70)
print("🚀 Starting WSGI Application")
print("=" * 70)

try:
    print("📦 Importing Flask and SocketIO...")
    from flask import Flask
    from flask_socketio import SocketIO
    
    print("📦 Importing app from main.py...")
    from main import app, socketio
    print("✅ App imported successfully")
    
    print("🔧 Creating WSGI application wrapper...")
    # Correct way to wrap Flask app with SocketIO for WSGI/Gunicorn
    app.wsgi_app = socketio.WSGIApp(socketio, app.wsgi_app)
    application = app
    print("✅ WSGI application created successfully")
    print("=" * 70 + "\n")
    
except Exception as e:
    print(f"\n❌ FATAL ERROR DURING WSGI SETUP: {e}")
    traceback.print_exc()
    sys.exit(1)
