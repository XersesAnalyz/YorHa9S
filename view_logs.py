#!/usr/bin/env python3
"""
9S Log Viewer - Simple tool untuk view scan results
"""

import glob
import os
from datetime import datetime

def view_recent_logs():
    """Show recent scan logs"""
    log_files = glob.glob("9s_scan_*.log")
    
    if not log_files:
        print("❌ No log files found! Run scanner first.")
        return
    
    # Sort by modification time (newest first)
    log_files.sort(key=os.path.getmtime, reverse=True)
    
    print("📊 9S SCAN LOG VIEWER")
    print("=" * 60)
    
    for log_file in log_files[:3]:  # Show 3 most recent
        file_time = datetime.fromtimestamp(os.path.getmtime(log_file))
        print(f"\n📁 {log_file}")
        print(f"⏰ Created: {file_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print("-" * 50)
        
        with open(log_file, 'r') as f:
            for line in f:
                if "VULNERABILITY" in line or "SECURITY_ISSUE" in line:
                    # Color code based on type
                    if "VULNERABILITY" in line:
                        print(f"🔴 {line.strip()}")
                    else:
                        print(f"🟡 {line.strip()}")
        
        print(f"\n📄 Full log: {os.path.abspath(log_file)}")

def main():
    view_recent_logs()

if __name__ == "__main__":
    main()
