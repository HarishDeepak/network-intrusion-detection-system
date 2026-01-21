#!/usr/bin/env python
"""
Backend startup script for frontend integration.
Run this to start the API server and fusion pipeline in background.
"""

import subprocess
import time
import sys
import os
from pathlib import Path

def main():
    print("="*70)
    print("NETWORK ANOMALY DETECTION - BACKEND STARTUP")
    print("="*70)
    
    # Get workspace root
    workspace_root = Path(__file__).parent
    backend_dir = workspace_root / "backend"
    
    print(f"\nWorkspace: {workspace_root}")
    print(f"Backend: {backend_dir}")
    
    # Start API server
    print("\n[1/2] Starting API Server...")
    api_process = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "main:app", 
         "--host", "0.0.0.0", "--port", "8000"],
        cwd=backend_dir,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    time.sleep(3)  # Wait for startup
    
    if api_process.poll() is not None:
        _, stderr = api_process.communicate()
        print(f"  ERROR: API server failed to start")
        print(f"  {stderr}")
        return 1
    
    print("  ✓ API Server running on http://0.0.0.0:8000")
    
    # Start fusion pipeline (optional, in background)
    print("\n[2/2] Starting Fusion Pipeline (background)...")
    try:
        fusion_process = subprocess.Popen(
            [sys.executable, "run_fusion.py"],
            cwd=backend_dir,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        print("  ✓ Fusion pipeline started in background")
    except Exception as e:
        print(f"  ⚠ Warning: Could not start fusion pipeline: {e}")
    
    print("\n" + "="*70)
    print("BACKEND READY FOR FRONTEND INTEGRATION")
    print("="*70)
    print("\nAccess Points:")
    print("  API Base URL:        http://localhost:8000/api")
    print("  Swagger UI:          http://localhost:8000/docs")
    print("  ReDoc:               http://localhost:8000/redoc")
    
    print("\nKey Endpoints:")
    print("  - GET  /api/stats                          (Dashboard stats)")
    print("  - GET  /api/alerts/stats                   (Alert statistics)")
    print("  - GET  /api/alerts/attack_logs             (Recent attacks)")
    print("  - GET  /api/alerts/alert_logs              (Alert delivery status)")
    print("  - GET  /api/analytics/attack_distribution  (Attack types chart)")
    print("  - GET  /api/analytics/time_trends          (Time series)")
    print("  - GET  /api/packets                        (Recent packets)")
    
    print("\n" + "="*70)
    print("Press CTRL+C to stop the server")
    print("="*70 + "\n")
    
    # Keep process running
    try:
        api_process.wait()
    except KeyboardInterrupt:
        print("\n\nShutting down...")
        api_process.terminate()
        try:
            api_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            api_process.kill()
        print("Backend stopped.")
        return 0

if __name__ == "__main__":
    sys.exit(main())
