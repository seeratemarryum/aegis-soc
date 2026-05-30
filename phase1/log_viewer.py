"""
=============================================================================
SOC ANALYST TRAINING — PHASE 1: LOG VIEWER (SOC CONSOLE)
=============================================================================

WHAT THIS FILE DOES:
    Ties together the generator and parser into a simple interactive console.
    This is your FIRST SOC tool — run it and watch the pipeline work.

SOC CONCEPT:
    Even before dashboards (Phase 7), SOC analysts use command-line tools.
    Commands like: grep, awk, sort, uniq — are used daily in real SOCs.
    We're building a Python version of those workflow patterns.

RUN THIS FILE TO:
    1. Generate sample logs
    2. Parse them into structured data
    3. View a SOC-style summary report
    4. Identify suspicious IPs

USAGE:
    python log_viewer.py
=============================================================================
"""

import json
import os
import sys
from collections import defaultdict

# Import our modules — Phase 1 components working together
# In a real SOC system, these would be microservices or Splunk apps
sys.path.insert(0, os.path.dirname(__file__))

from log_generator import generate_log_file
from log_parser import parse_log_file, save_parsed_events


# =============================================================================
# SOC REPORT GENERATION
# This is what a TIER 1 analyst reads at the start of their shift
# =============================================================================

def print_soc_report(events):
    """
    Generate a SOC-style shift report from parsed events.
    
    SOC CONTEXT:
    At the start of every 8-hour shift, Tier 1 analysts review:
    - How many events occurred
    - Any high-severity incidents
    - Top attacking IPs
    - Most targeted usernames
    
    This is called the "Morning Brief" or "Shift Handoff Report" in real SOCs.
    Enterprise tools like Splunk generate this automatically. We build it manually
    so you understand what the tool is actually computing.
    """
    
    print("\n")
    print("╔══════════════════════════════════════════════════════════╗")
    print("║          SOC ANALYST — SHIFT REPORT                    ║")
    print("║          PHASE 1 TRAINING SYSTEM                       ║")
    print("╚══════════════════════════════════════════════════════════╝")
    
    if not events:
        print("\n  [!] No events to report.")
        return
    
    # ─── Section 1: Volume Summary ─────────────────────────────────────────
    # SOC Metric: "Events Per Second" (EPS) is how SIEM capacity is measured
    # Enterprise SIEMs handle millions of EPS. We're working with hundreds.
    
    total_events = len(events)
    event_types = defaultdict(int)
    severity_counts = defaultdict(int)
    ip_activity = defaultdict(lambda: {"FAILED_LOGIN": 0, "SUCCESSFUL_LOGIN": 0,
                                        "INVALID_USER": 0, "CONNECTION_CLOSED": 0})
    username_targets = defaultdict(int)
    
    for event in events:
        event_types[event["event_type"]] += 1
        severity_counts[event.get("severity", "UNKNOWN")] += 1
        
        if "source_ip" in event:
            ip = event["source_ip"]
            ip_activity[ip][event["event_type"]] += 1
        
        if "username" in event and event["event_type"] in ("FAILED_LOGIN", "INVALID_USER"):
            username_targets[event["username"]] += 1
    
    print(f"\n  📊 TOTAL EVENTS ANALYZED: {total_events}")
    print(f"\n  EVENT BREAKDOWN:")
    for etype, count in sorted(event_types.items(), key=lambda x: -x[1]):
        bar = "▓" * min(count // 2, 30)
        print(f"    {etype:<22} {count:>5}  {bar}")
    
    # ─── Section 2: Severity Alert Summary ─────────────────────────────────
    print(f"\n  🚨 SEVERITY SUMMARY:")
    severity_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "INFO": "⚪"}
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = severity_counts.get(sev, 0)
        emoji = severity_emoji.get(sev, "  ")
        print(f"    {emoji} {sev:<10} {count:>5} events")
    
    # ─── Section 3: Top Attacking IPs ──────────────────────────────────────
    # SOC ACTION: IPs with high failure counts get investigated first
    # Then cross-referenced with threat intel (AbuseIPDB, VirusTotal)
    
    print(f"\n  🌐 TOP SOURCE IPs (by failed login attempts):")
    print(f"  {'IP ADDRESS':<20} {'FAILURES':>8} {'SUCCESSES':>10} {'INVALID_USERS':>14} {'RISK':>6}")
    print(f"  {'-'*65}")
    
    sorted_ips = sorted(ip_activity.items(), 
                       key=lambda x: x[1]["FAILED_LOGIN"] + x[1]["INVALID_USER"], 
                       reverse=True)
    
    for ip, counts in sorted_ips[:10]:  # Top 10 IPs
        failures = counts["FAILED_LOGIN"]
        successes = counts["SUCCESSFUL_LOGIN"]
        invalid = counts["INVALID_USER"]
        
        # Simple risk scoring: failures + invalid users = suspicion score
        # Phase 4 will do this properly with ML
        risk_score = failures + (invalid * 2)  # Invalid user = double weight
        
        if risk_score >= 30:
            risk_label = "🔴 HIGH"
        elif risk_score >= 10:
            risk_label = "🟠 MED"
        elif risk_score >= 3:
            risk_label = "🟡 LOW"
        else:
            risk_label = "⚪ OK"
        
        # Mark internal IPs differently
        ip_display = f"{ip} (internal)" if ip.startswith(("10.", "192.168.")) else ip
        print(f"  {ip_display:<28} {failures:>8} {successes:>10} {invalid:>14} {risk_label}")
    
    # ─── Section 4: Most Targeted Usernames ────────────────────────────────
    # SOC INSIGHT: Attackers use wordlists. "root" appearing 100x = wordlist attack.
    # This view shows you WHAT accounts are being targeted — critical for defense.
    
    print(f"\n  👤 MOST TARGETED USERNAMES (failed + invalid):")
    sorted_users = sorted(username_targets.items(), key=lambda x: -x[1])
    for username, count in sorted_users[:8]:
        bar = "▓" * min(count // 2, 25)
        flag = " ⚠ HIGH-RISK ACCOUNT" if username in {"root", "admin", "administrator"} else ""
        print(f"    {username:<15} {count:>5} attempts  {bar}{flag}")
    
    # ─── Section 5: SOC Analyst Recommendations ────────────────────────────
    # In a real SOC, this section would be written by Tier 2 analysts
    # and emailed to the security team. We auto-generate basic ones here.
    
    print(f"\n  📋 AUTO-GENERATED RECOMMENDATIONS:")
    
    # Find IPs with high failure rates (brute force indicators)
    high_fail_ips = [(ip, d["FAILED_LOGIN"]) for ip, d in ip_activity.items() 
                     if d["FAILED_LOGIN"] > 20]
    
    if high_fail_ips:
        print(f"\n  [ACTION REQUIRED] Possible SSH Brute Force Detected:")
        for ip, count in sorted(high_fail_ips, key=lambda x: -x[1]):
            print(f"    → IP {ip} — {count} failed attempts")
            print(f"      Recommended: Block at firewall, investigate source")
            print(f"      Command: ufw deny from {ip} to any port 22")
    
    if username_targets.get("root", 0) > 5:
        print(f"\n  [BEST PRACTICE] Root login targeting detected.")
        print(f"    → Add to sshd_config: PermitRootLogin no")
        print(f"    → This single config change eliminates all root-based attacks")
    
    print("\n" + "═"*62)
    print("  End of Report — Phase 2 will AUTOMATE these detections")
    print("═"*62 + "\n")


# =============================================================================
# MAIN EXECUTION PIPELINE
# This is the "pipeline" concept — data flows through stages
#
# PIPELINE DIAGRAM:
#
#  [Log Generator] → [sample_auth.log] → [Log Parser] → [JSON Events]
#       ↓                                                      ↓
#  Simulates attack/                                    [SOC Report]
#  normal traffic                                    Human readable
#                                                     analysis
# =============================================================================

def run_pipeline():
    """
    Execute the complete Phase 1 pipeline.
    
    PIPELINE STAGES:
    Stage 1: Generate → Creates raw log file (simulates real log source)
    Stage 2: Parse    → Converts raw text to structured JSON (normalization)
    Stage 3: Report   → Generates SOC analyst report (analysis)
    
    In production SOC:
    Stage 1 = Log collection agent (Beats, NXLog, rsyslog)
    Stage 2 = SIEM parsing engine (Logstash, Splunk Heavy Forwarder)
    Stage 3 = SIEM dashboard or automated report
    """
    
    base_dir = os.path.dirname(__file__)
    log_file = os.path.join(base_dir, "sample_auth.log")
    json_file = os.path.join(base_dir, "parsed_events.json")
    
    print("\n🔐 SOC ANALYST TRAINING SYSTEM — PHASE 1")
    print("   Building: Log Pipeline & Analysis")
    print("─" * 50)
    
    # STAGE 1: Generate logs (or use existing)
    print("\n[STAGE 1] Log Generation")
    if os.path.exists(log_file):
        overwrite = input("   Log file exists. Regenerate? (y/n): ").strip().lower()
        if overwrite == 'y':
            generate_log_file(output_file="sample_auth.log")
        else:
            print("   Using existing log file.")
    else:
        generate_log_file(output_file="sample_auth.log")
    
    # STAGE 2: Parse logs
    print("\n[STAGE 2] Log Parsing & Normalization")
    events, stats = parse_log_file(log_file)
    save_parsed_events(events, output_file="parsed_events.json")
    
    # STAGE 3: Generate SOC report
    print("\n[STAGE 3] SOC Report Generation")
    print_soc_report(events)
    
    # STAGE 4: Interactive investigation mode
    print("\n[STAGE 4] Interactive Investigation")
    print("  You can now query the parsed data.")
    print("  Enter an IP address to see all its activity (or 'q' to quit):\n")
    
    while True:
        query_ip = input("  Enter IP to investigate (or 'q' to quit): ").strip()
        
        if query_ip.lower() == 'q':
            break
        
        # Filter events for this IP
        ip_events = [e for e in events if e.get("source_ip") == query_ip]
        
        if not ip_events:
            print(f"  No events found for IP: {query_ip}\n")
            continue
        
        print(f"\n  ┌─ Investigation: {query_ip} ─────────────────────────")
        print(f"  │  Total events: {len(ip_events)}")
        
        # Group by event type
        by_type = defaultdict(list)
        for e in ip_events:
            by_type[e["event_type"]].append(e)
        
        for etype, type_events in by_type.items():
            print(f"  │  {etype}: {len(type_events)}")
            if etype == "FAILED_LOGIN":
                usernames_tried = set(e.get("username", "?") for e in type_events)
                print(f"  │    Usernames tried: {', '.join(usernames_tried)}")
        
        # SOC VERDICT
        failure_count = len(by_type.get("FAILED_LOGIN", []))
        if failure_count > 20:
            print(f"  │")
            print(f"  │  🔴 SOC VERDICT: HIGH CONFIDENCE BRUTE FORCE")
            print(f"  │     {failure_count} failures detected from this IP")
            print(f"  │     Recommended action: BLOCK & INVESTIGATE")
        elif failure_count > 5:
            print(f"  │  🟠 SOC VERDICT: SUSPICIOUS — investigate further")
        else:
            print(f"  │  🟢 SOC VERDICT: LOW risk, monitor for patterns")
        
        print(f"  └{'─'*45}\n")
    
    print("\n✅ Phase 1 Complete!")
    print("   Files created:")
    print(f"   → {log_file}")
    print(f"   → {json_file}")
    print("\n   NEXT: Phase 2 — Automated Rule-Based Detection")
    print("   We'll write Python rules that automatically flag these IPs\n")


if __name__ == "__main__":
    run_pipeline()
