#!/usr/bin/env python3
"""
WSGI entry point for Gunicorn - Simple approach
"""
import os
import sys
import traceback

print("\n" + "=" * 70)
print("🚀 Starting WSGI Application")
print("=" * 70)

try:
    print("📦 Importing main module...")
    from main import app, socketio
    print("✅ Main module imported")
    
    print("✅ Creating application wrapper for Gunicorn...")
    # Simple approach: just use app directly with eventlet worker
    # Eventlet will handle SocketIO compatibility
    application = app
    print("✅ Application ready")
    print("=" * 70 + "\n")
    
except Exception as e:
    print(f"\n❌ FATAL ERROR: {e}")
    traceback.print_exc()
    sys.exit(1)
