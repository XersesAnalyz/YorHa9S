#!/usr/bin/env python3
"""
9S Pro Log Viewer - TABLE EDITION 🎨
Professional log viewer dengan target website display
"""

import glob
import os
import re
from datetime import datetime

class Color:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

def print_table(headers, rows, column_widths):
    """Print beautiful table dengan borders dan warna"""
    if not rows:
        print(f"{Color.YELLOW}📭 No data to display{Color.END}")
        return
    
    header_line = "┌" + "┬".join("─" * (w + 2) for w in column_widths) + "┐"
    print(f"{Color.CYAN}{header_line}{Color.END}")
    
    header_str = "│"
    for i, header in enumerate(headers):
        header_str += f" {Color.BOLD}{header:<{column_widths[i]}}{Color.END} │"
    print(f"{Color.CYAN}{header_str}{Color.END}")
    
    separator_line = "├" + "┼".join("─" * (w + 2) for w in column_widths) + "┤"
    print(f"{Color.CYAN}{separator_line}{Color.END}")
    
    for row in rows:
        row_str = "│"
        for i, cell in enumerate(row):
            color = Color.WHITE
            cell_str = str(cell)
            
            if "CRITICAL" in cell_str:
                color = Color.RED + Color.BOLD
            elif "HIGH" in cell_str:
                color = Color.RED
            elif "MEDIUM" in cell_str:
                color = Color.YELLOW
            elif "LOW" in cell_str:
                color = Color.BLUE
            elif "INFO" in cell_str:
                color = Color.GREEN
            elif "8" in cell_str or "9" in cell_str:
                color = Color.GREEN
            elif "5" in cell_str or "6" in cell_str or "7" in cell_str:
                color = Color.YELLOW
            elif "0" in cell_str or "1" in cell_str or "2" in cell_str or "3" in cell_str or "4" in cell_str:
                color = Color.RED
                
            row_str += f" {color}{cell_str:<{column_widths[i]}}{Color.END} │"
        print(row_str)
    
    footer_line = "└" + "┴".join("─" * (w + 2) for w in column_widths) + "┘"
    print(f"{Color.CYAN}{footer_line}{Color.END}")

def extract_scan_target(log_file):
    """Extract target website dari log file"""
    try:
        with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                if "Target:" in line:
                    match = re.search(r'Target:\s*(.+)', line)
                    if match:
                        return match.group(1).strip()
                elif "SYSTEM" in line and "initialized for target:" in line:
                    match = re.search(r'initialized for target:\s*(.+)', line)
                    if match:
                        return match.group(1).strip()
                elif "Starting AI-powered security scan" in line:
                    # Cari line setelahnya yang ada target
                    continue
    except:
        pass
    return "Unknown Target"

def parse_log_file(log_file):
    """Parse log file dan extract vulnerabilities & issues"""
    vulnerabilities = []
    security_issues = []
    
    try:
        with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                
                if "[VULNERABILITY]" in line:
                    match = re.search(r'\[(\d+:\d+:\d+)\] \[VULNERABILITY\] (\w+) \| (\d+%) \| (.+?) \| (.+)', line)
                    if match:
                        time, severity, confidence, category, description = match.groups()
                        vulnerabilities.append([time, severity, confidence, category, description])
                
                elif "[SECURITY_ISSUE]" in line:
                    match = re.search(r'\[(\d+:\d+:\d+)\] \[SECURITY_ISSUE\] (\w+) \| (.+)', line)
                    if match:
                        time, severity, description = match.groups()
                        security_issues.append([time, severity, description])
    
    except Exception as e:
        print(f"{Color.RED}❌ Error reading log file: {e}{Color.END}")
    
    return vulnerabilities, security_issues

def show_log_statistics(log_files):
    """Show statistics dari semua log files"""
    total_scans = len(log_files)
    total_vulns = 0
    total_issues = 0
    high_critical = 0
    
    for log_file in log_files:
        vulns, issues = parse_log_file(log_file)
        total_vulns += len(vulns)
        total_issues += len(issues)
        high_critical += sum(1 for v in vulns if "HIGH" in v[1] or "CRITICAL" in v[1])
    
    print(f"{Color.MAGENTA}{Color.BOLD}")
    print("╔═══════════════════════════════════════════╗")
    print("║             9S SCAN STATISTICS            ║")
    print("╚═══════════════════════════════════════════╝")
    print(f"{Color.END}")
    
    stats_headers = ["Metric", "Count"]
    stats_rows = [
        ["Total Scan Files", f"{total_scans}"],
        ["Vulnerabilities Found", f"{total_vulns}"],
        ["Security Issues", f"{total_issues}"],
        ["High/Critical Findings", f"{high_critical}"]
    ]
    
    print_table(stats_headers, stats_rows, [25, 10])
    print()

def view_recent_logs():
    """Show recent scan logs dengan target website"""
    log_files = glob.glob("9s_scan_*.log")
    
    if not log_files:
        print(f"{Color.RED}❌ No log files found!{Color.END}")
        print(f"{Color.YELLOW}💡 Run YorHa9S.py first to generate logs{Color.END}")
        return
    
    log_files.sort(key=os.path.getmtime, reverse=True)
    show_log_statistics(log_files)
    
    print(f"{Color.CYAN}{Color.BOLD}")
    print("╔═══════════════════════════════════════════╗")
    print("║           9S SCAN LOG VIEWER              ║")
    print("║             TABLE EDITION                 ║")
    print("╚═══════════════════════════════════════════╝")
    print(f"{Color.END}")
    
    for log_file in log_files[:2]:
        file_time = datetime.fromtimestamp(os.path.getmtime(log_file))
        target_website = extract_scan_target(log_file)
        
        print(f"{Color.MAGENTA}📁 Log File: {Color.WHITE}{log_file}{Color.END}")
        print(f"{Color.YELLOW}⏰ Scan Time: {Color.WHITE}{file_time.strftime('%Y-%m-%d %H:%M:%S')}{Color.END}")
        print(f"{Color.GREEN}🎯 Target: {Color.WHITE}{target_website}{Color.END}")
        print()
        
        vulnerabilities, security_issues = parse_log_file(log_file)
        
        if vulnerabilities:
            print(f"{Color.RED}{Color.BOLD}🔴 VULNERABILITIES FOUND:{Color.END}")
            vuln_headers = ["Time", "Severity", "Confidence", "Category", "Description"]
            vuln_widths = [8, 10, 12, 20, 40]
            
            formatted_vulns = []
            for vuln in vulnerabilities:
                desc = vuln[4]
                if len(desc) > 37:
                    desc = desc[:37] + "..."
                formatted_vulns.append([vuln[0], vuln[1], vuln[2], vuln[3], desc])
            
            print_table(vuln_headers, formatted_vulns, vuln_widths)
            print()
        else:
            print(f"{Color.GREEN}✅ No vulnerabilities found{Color.END}")
            print()
        
        if security_issues:
            print(f"{Color.YELLOW}{Color.BOLD}🟡 SECURITY ISSUES:{Color.END}")
            issue_headers = ["Time", "Severity", "Description"]
            issue_widths = [8, 10, 60]
            
            formatted_issues = []
            for issue in security_issues:
                desc = issue[2]
                if len(desc) > 57:
                    desc = desc[:57] + "..."
                formatted_issues.append([issue[0], issue[1], desc])
            
            print_table(issue_headers, formatted_issues, issue_widths)
            print()
        else:
            print(f"{Color.GREEN}✅ No security issues found{Color.END}")
            print()
        
        print(f"{Color.CYAN}{Color.BOLD}📊 SCAN SUMMARY:{Color.END}")
        summary_headers = ["Metric", "Count"]
        summary_rows = [
            ["Vulnerabilities", f"{len(vulnerabilities)}"],
            ["Security Issues", f"{len(security_issues)}"],
            ["High/Critical", f"{sum(1 for v in vulnerabilities if 'HIGH' in v[1] or 'CRITICAL' in v[1])}"]
        ]
        print_table(summary_headers, summary_rows, [20, 8])
        print()

def main():
    """Main function"""
    view_recent_logs()
    
    log_files = glob.glob("9s_scan_*.log")
    if log_files:
        print(f"{Color.BLUE}📂 Available Log Files:{Color.END}")
        for log_file in sorted(log_files, key=os.path.getmtime, reverse=True)[:3]:
            file_time = datetime.fromtimestamp(os.path.getmtime(log_file))
            target = extract_scan_target(log_file)
            print(f"   📄 {log_file}")
            print(f"      🎯 {target}")
            print(f"      ⏰ {file_time.strftime('%Y-%m-%d %H:%M')}")
            print()

if __name__ == "__main__":
    main()
