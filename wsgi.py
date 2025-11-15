#!/usr/bin/env python3
"""
WSGI entry point for Gunicorn
This bypasses main.py complexity and creates app directly
"""
import os
import sys

print("\n" + "=" * 70)
print("🚀 Starting WSGI Application")
print("=" * 70)

try:
    # Import Flask and create app
    from flask import Flask
    from flask_socketio import SocketIO
    
    print("✅ Flask and SocketIO imported")
    
    # Import your app from main
    from main import app, socketio
    print("✅ App imported from main.py")
    
    # Create WSGI application for Gunicorn
    application = socketio.WSGIApp(socketio, app)
    print("✅ WSGI application created")
    print("=" * 70 + "\n")
    
except Exception as e:
    print(f"\n❌ ERROR DURING WSGI SETUP: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
