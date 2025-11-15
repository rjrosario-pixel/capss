import os
import multiprocessing

bind = f"0.0.0.0:{os.environ.get('PORT', 10000)}"
workers = 1
worker_class = "eventlet"
worker_connections = 1000
timeout = 120
keepalive = 2
max_requests = 0
preload_app = True
