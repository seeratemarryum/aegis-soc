"""
=============================================================================
SOC ANALYST TRAINING -- PHASE 6: SOAR RESPONSE CONSOLE
=============================================================================

This is the main entry point for the Phase 6 SOAR system.
It loads alerts from Phase 2, the incident report from Phase 5,
and runs them through the playbook engine.

RUN: python phase6/response_console.py
=============================================================================
"""

import sys
import os
import json
import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PHASE2_DIR = os.path.join(BASE_DIR, "phase2")
PHASE5_DIR = os.path.join(BASE_DIR, "phase5")
PHASE6_DIR = os.path.join(BASE_DIR, "phase6")

sys.path.insert(0, BASE_DIR)
sys.path.insert(0, PHASE6_DIR)

from playbook_engine import PlaybookEngine
from soar_actions import AUDIT_LOG_PATH, BLOCKED_IPS_PATH, INCIDENTS_PATH, _load_json


def load_alerts():
    path = os.path.join(PHASE2_DIR, "alerts.json")
    if not os.path.exists(path):
        print("[!] No Phase 2 alerts found. Run: python phase2/detection_engine.py")
        return []
    with open(path) as f:
        return json.load(f)


def load_report():
    path = os.path.join(PHASE5_DIR, "incident_report.json")
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return json.load(f)


def print_soar_summary(results):
    """Print a summary of all SOAR actions taken."""
    print(f"\n{'='*62}")
    print(f"  SOAR EXECUTION SUMMARY")
    print(f"{'='*62}")

    total_actions = sum(len(r.get("actions_taken", [])) for r in results)
    total_blocked = sum(len(r.get("actions_blocked", [])) for r in results)

    print(f"\n  Playbooks executed: {len(results)}")
    print(f"  Actions taken:      {total_actions}")
    print(f"  Actions blocked:    {total_blocked} (human denied or safeguard)")

    print(f"\n  Blocked IPs:")
    blocked_ips = _load_json(BLOCKED_IPS_PATH, {})
    if blocked_ips:
        for ip, rec in blocked_ips.items():
            print(f"    {ip:<20} | reason: {rec['reason'][:40]}")
            print(f"    {'':20}   auto-unblock: {rec['auto_unblock_at']}")
    else:
        print(f"    (none -- all block actions were denied or simulated)")

    print(f"\n  Incidents created:")
    incidents = _load_json(INCIDENTS_PATH, [])
    for inc in incidents:
        print(f"    {inc['incident_id']} | {inc['severity']} | {inc['rule_triggered']}")

    print(f"\n  Audit log: {AUDIT_LOG_PATH}")
    print(f"  (Every action is permanently recorded)")

    print(f"\n  {'='*58}")
    print(f"  WHAT SOAR DID IN SECONDS vs WHAT A HUMAN WOULD TAKE:")
    print(f"  {'='*58}")
    print(f"  SOAR: Enrich IP + Create ticket + Alert team = ~3 seconds")
    print(f"  Human: Read alert + Google IP + Fill ticket form = ~15 minutes")
    print(f"\n  Those 15 minutes are exactly what attackers exploit.")
    print(f"  Average attacker dwell time after initial access: 24 days.")
    print(f"  SOAR compresses containment from hours to seconds.")


def main():
    print("\n")
    print("  ##########################################################")
    print("  ##  PHASE 6: SOAR RESPONSE CONSOLE                      ##")
    print("  ##  Automated Security Orchestration & Response          ##")
    print("  ##########################################################")

    print("\n  CONFIGURATION OPTIONS:")
    print("  1. Interactive mode (you approve each high-risk action)")
    print("  2. Dry-run auto mode (all actions simulated, no approvals)")
    print("  3. Read audit log from previous run")

    choice = input("\n  Enter 1, 2, or 3: ").strip()

    if choice == "3":
        # Just show the audit log
        if os.path.exists(AUDIT_LOG_PATH):
            print(f"\n  SOAR AUDIT LOG ({AUDIT_LOG_PATH}):")
            print(f"  {'-'*58}")
            with open(AUDIT_LOG_PATH, encoding="utf-8") as f:
                for line in f:
                    print(f"  {line.rstrip()}")
        else:
            print("  No audit log found. Run option 1 or 2 first.")
        return

    dry_run = True
    require_approval = (choice == "1")

    if choice == "2":
        print("\n  [MODE] Dry-run auto mode: all actions simulated, no human prompts.")
        print("         In production, this would be a cron-triggered automated response.")
    else:
        print("\n  [MODE] Interactive mode: you will be prompted before high-risk actions.")
        print("         This simulates an analyst approving SOAR actions in real time.")

    # Load data
    print("\n[+] Loading Phase 2 alerts...")
    alerts = load_alerts()
    print(f"[OK] {len(alerts)} alerts loaded")

    print("[+] Loading Phase 5 incident report...")
    report = load_report()
    print(f"[OK] Report {'loaded' if report else 'not found (continuing without it)'}")

    if not alerts:
        return

    # Initialize and run the SOAR engine
    engine = PlaybookEngine(
        dry_run=dry_run,
        require_approval=require_approval,
        analyst="Student-Analyst-01",
    )

    print(f"\n[+] Starting SOAR playbook execution...")
    print(f"    Alerts to process: {len(alerts)}")
    print(f"    Playbooks registered: {list(engine.playbook_registry.keys())}")
    print(f"    Dry run: {dry_run}")
    print(f"    Human approval gates: {require_approval}")

    results = engine.run_all_alerts(alerts, report)

    # Final summary
    print_soar_summary(results)

    # Save SOAR execution results
    out_path = os.path.join(PHASE6_DIR, "soar_results.json")
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\n[OK] SOAR results saved: {out_path}")

    print(f"\n{'='*62}")
    print(f"  EXPERIMENTS FOR PHASE 6")
    print(f"{'='*62}")
    print("""
  1. RUN IN AUTO MODE (choice 2):
     Watch all playbooks execute WITHOUT approval prompts.
     This is "lights-out SOC automation" -- the ideal for 3am alerts.
     Notice: dry_run=True still prevents real firewall changes.

  2. UNDERSTAND THE SAFEGUARDS:
     In soar_actions.py, find block_ip().
     Try passing an internal IP like "10.0.0.5" to block_ip().
     Watch the SAFEGUARD fire: "Cannot auto-block internal IP."
     This prevents blocking your own users.

  3. READ THE AUDIT LOG (choice 3):
     Every single action is timestamped and logged.
     This is what forensics teams read during post-incident review.

  4. ADD A NEW PLAYBOOK:
     In playbook_engine.py, add a new method: playbook_data_exfil()
     Register it: self.playbook_registry["DATA_EXFIL"] = self.playbook_data_exfil
     Think about: what actions would a data exfiltration response need?
     (Block outbound IP, capture network traffic, notify legal team)
    """)


if __name__ == "__main__":
    main()
