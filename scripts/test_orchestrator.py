#!/usr/bin/env python3
import sys
import time
import json
import threading
sys.path.insert(0, '.')

try:
    from core.orchestrator import Orchestrator
except ImportError:
    from core.orchestrator import orchestrator as Orchestrator

from shared.logger import get_logger
import redis

logger = get_logger("test")

# Global flag to stop orchestrator
stop_flag = False

def run_orchestrator():
    config_file = "config/core.yaml"
    print("[*] Starting orchestrator...")
    orch = Orchestrator(config_file)
    
    # Run orchestrator (this blocks)
    try:
        orch.run()
    except Exception as e:
        print(f"[!] Orchestrator error: {e}")
    finally:
        print("[*] Orchestrator stopped.")

# Start orchestrator in a thread
orch_thread = threading.Thread(target=run_orchestrator, daemon=True)
orch_thread.start()

# Wait for orchestrator to init
time.sleep(2)

# Push a test task
r = redis.Redis(host='localhost', port=6379, decode_responses=True)
task = {
    "task_id": "test-001",
    "type": "generic",          # ✅ Lowercase (matches TaskType enum)
    "target": "http://example.com",
    "params": {"test": True},
    "max_retries": 1
}
r.lpush("tasks:incoming", json.dumps(task))
print("[+] Test task pushed. Check logs...")

# Let it run for a while (e.g., 10 seconds)
time.sleep(10)

# Now we need to stop orchestrator gracefully.
# Since we can't send signal to thread, we can implement a shutdown method.
# But orchestrator currently doesn't have a public shutdown method.
# For now, we'll just let the thread die (daemon=True ensures it exits when main exits).
print("[*] Test completed. Exiting.")