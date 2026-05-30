"""
=============================================================================
SOC ANALYST TRAINING — PHASE 3: RED vs BLUE (Full Pipeline)
=============================================================================

THIS IS THE MOST IMPORTANT FILE IN PHASE 3.

It runs the complete pipeline in one command:

  [RED TEAM]  Attack simulation  →  Generates raw logs
  [PIPELINE]  Parse logs         →  Structured events
  [BLUE TEAM] Detection engine   →  Alerts fire in real time

You will SEE the attack happen AND be detected, event by event.

RUN THIS: python phase3/red_vs_blue.py

WHAT YOU'LL OBSERVE:
  1. Red Team starts attack (port scan at 02:14)
  2. First "Connection closed" entries appear in logs
  3. Port Scan alert fires (SOC-00001)
  4. Brute force begins
  5. Failure count climbs: 1, 2, 3, 4...
  6. At attempt 5 → BRUTE FORCE alert fires (SOC-00002)
  7. If lucky → SUCCESS alert fires (SOC-00003 CRITICAL)

This is EXACTLY how a real SOC SIEM would process these events.
=============================================================================
"""

import json
import os
import sys
import time
import datetime
import random

# Path setup
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PHASE1_DIR = os.path.join(BASE_DIR, "phase1")
PHASE2_DIR = os.path.join(BASE_DIR, "phase2")
PHASE3_DIR = os.path.join(BASE_DIR, "phase3")

sys.path.insert(0, BASE_DIR)
sys.path.insert(0, PHASE1_DIR)
sys.path.insert(0, PHASE2_DIR)
sys.path.insert(0, PHASE3_DIR)

# Import our modules
from log_parser import parse_log_line
from rules.brute_force import BruteForceDetector
from rules.port_scan import PortScanDetector
from alert_manager import AlertManager
from port_scanner_sim import simulate_port_scan, ATTACKER_PROFILES
from brute_force_sim import BruteForceSimulator, run_full_attack_chain
from log_generator import simulate_normal_traffic, generate_log_file


# =============================================================================
# DISPLAY HELPERS
# =============================================================================

def print_banner():
    print("\n")
    print("  ##########################################################")
    print("  ##                                                      ##")
    print("  ##      RED TEAM vs BLUE TEAM — LIVE SIMULATION         ##")
    print("  ##      SOC Analyst Training — Phase 3                  ##")
    print("  ##                                                      ##")
    print("  ##########################################################")
    print()


def print_red(text):
    """Print text prefixed with RED TEAM tag."""
    print(f"  [RED  TEAM] {text}")


def print_blue(text):
    """Print text prefixed with BLUE TEAM tag."""
    print(f"  [BLUE TEAM] {text}")


def print_event(event, show_detail=False):
    """Print a single parsed event in SOC monitoring style."""
    etype = event.get("event_type", "?")
    ip = event.get("source_ip", "?")
    user = event.get("username", "")
    ts = event.get("timestamp", "?")
    sev = event.get("severity", "INFO")

    severity_tag = {
        "CRITICAL": "[!!!]",
        "HIGH":     "[HI ]",
        "MEDIUM":   "[MED]",
        "LOW":      "[LOW]",
        "INFO":     "[   ]",
    }.get(sev, "[?]")

    user_str = f" | user={user}" if user else ""
    print(f"    {severity_tag} {ts} | {etype:<20} | {ip}{user_str}")


def print_alert_live(alert):
    """Print an alert as it fires — this is the SOC live feed."""
    severity = alert.get("severity", "INFO")
    alert_id = alert.get("alert_id", "?")
    rule = alert.get("rule_name", "?")
    ip = alert.get("source_ip", "?")

    banner = {
        "CRITICAL": ">>> CRITICAL ALERT FIRED <<<",
        "HIGH":     ">> HIGH ALERT FIRED <<",
        "MEDIUM":   "> MEDIUM ALERT FIRED <",
    }.get(severity, "ALERT FIRED")

    print(f"\n  {'*'*58}")
    print(f"  *** {banner}")
    print(f"  {'*'*58}")
    print(f"  Alert ID:  {alert_id}")
    print(f"  Rule:      {rule}")
    print(f"  Severity:  {severity}")
    print(f"  Source IP: {ip}")

    if rule == "SSH_BRUTE_FORCE":
        print(f"  Failures:  {alert.get('failure_count')} in {alert.get('window_seconds')}s")
        print(f"  Usernames: {alert.get('unique_usernames')}")
        if alert.get("is_wordlist_attack"):
            print(f"  Type:      WORDLIST ATTACK")

    elif rule == "PORT_SCAN_DETECTED":
        print(f"  Probes:    {alert.get('rapid_connection_count')} rapid connections")

    elif rule == "BRUTE_FORCE_SUCCESS":
        print(f"  !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        print(f"  !!! ACCOUNT COMPROMISED: {alert.get('successful_username')}")
        print(f"  !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        print(f"  Prior failures: {alert.get('prior_failures')}")

    if alert.get("escalation_reason"):
        print(f"  ESCALATED: Scan detected BEFORE brute force = targeted attack")

    print(f"  MITRE:     {alert.get('mitre_technique', 'N/A')}")
    print(f"  Action:    {alert.get('recommended_action', 'Investigate')[:80]}...")
    print(f"  {'*'*58}\n")


# =============================================================================
# SCENARIO RUNNER
# =============================================================================

def run_scenario(scenario_name, attack_logs, normal_logs=None, show_events=True):
    """
    Core pipeline runner: takes raw log lines, parses them, runs detection.

    PIPELINE:
    raw log lines -> parse_log_line() -> detection rules -> alerts

    Args:
        scenario_name: label for this scenario
        attack_logs:   list of raw log line strings (from simulators)
        normal_logs:   list of normal traffic log lines (optional noise)
        show_events:   if True, print each event as it's processed
    """
    print(f"\n  {'='*58}")
    print(f"  SCENARIO: {scenario_name}")
    print(f"  {'='*58}")

    # Combine and shuffle normal + attack logs to simulate real mixed traffic
    # (In reality, logs arrive interleaved — not attack then normal)
    all_raw_logs = list(attack_logs)
    if normal_logs:
        all_raw_logs.extend(normal_logs)
        random.shuffle(all_raw_logs)

    print(f"\n  Total raw log lines: {len(all_raw_logs)}")
    print(f"  (attack + normal traffic mixed together — as in real life)\n")

    # -- Initialize detectors (fresh state for each scenario)
    brute_force_det = BruteForceDetector(threshold=5, window_seconds=60)
    port_scan_det = PortScanDetector(threshold=5, window_seconds=15)
    alert_mgr = AlertManager()

    alerts_fired = []
    events_shown = 0

    # -- Process each log line through the pipeline
    for raw_line in all_raw_logs:

        # STEP 1: Parse raw log → structured event
        event = parse_log_line(raw_line)
        if not event:
            continue

        # STEP 2: Show event in "live monitoring" style (if enabled)
        if show_events and events_shown < 15:
            print_event(event)
            events_shown += 1
        elif show_events and events_shown == 15:
            remaining = len(all_raw_logs) - 15
            print(f"    [...] {remaining} more events processing silently...")
            events_shown += 1

        # STEP 3: Feed to each detection rule
        bf_alert = brute_force_det.analyze_event(event)
        ps_alert = port_scan_det.analyze_event(event)

        # STEP 4: Process through alert manager (dedup + correlation)
        for raw_alert in [bf_alert, ps_alert]:
            if raw_alert:
                processed = alert_mgr.receive_alert(raw_alert)
                if processed:
                    alerts_fired.append(processed)
                    # Print the alert IMMEDIATELY — this is the "live" feel
                    print_blue(f"ALERT FIRED -> {processed['rule_name']} | {processed['source_ip']}")
                    print_alert_live(processed)

    # -- Scenario summary
    print(f"\n  SCENARIO COMPLETE: {scenario_name}")
    print(f"  Alerts fired: {len(alerts_fired)}")
    for a in alerts_fired:
        print(f"    [{a['severity']}] {a['alert_id']} | {a['rule_name']} | {a['source_ip']}")

    return alerts_fired


# =============================================================================
# MAIN SCENARIOS
# =============================================================================

def main():
    print_banner()

    print("  Choose a scenario to run:")
    print("  1. Standard Brute Force       — Classic attack, easily detected")
    print("  2. Full Kill Chain            — Port scan + brute force (correlated)")
    print("  3. Password Spray             — Harder to detect variation")
    print("  4. Low-and-Slow Attack        — Evasion technique (may escape detection!)")
    print("  5. Run ALL scenarios          — See all attack types and detection results")

    choice = input("\n  Enter 1-5: ").strip()

    # Generate some normal traffic as background noise for all scenarios
    print("\n  [+] Generating normal background traffic...")
    normal_log_file = os.path.join(PHASE1_DIR, "sample_auth.log")
    normal_base = datetime.datetime.now().replace(hour=0, minute=0, second=0)
    from log_generator import simulate_normal_traffic
    normal_lines = simulate_normal_traffic(normal_base, duration_minutes=60)
    print(f"  [OK] {len(normal_lines)} normal traffic entries generated")

    # ─────────────────────────────────────────────────────────────────────────
    if choice == "1" or choice == "5":
        print(f"\n{'#'*60}")
        print("  SCENARIO 1: Standard Brute Force Attack")
        print("  What you'll see: Single IP hammers root with many passwords")
        print(f"{'#'*60}")
        print_red("Launching Hydra brute force against root account...")

        sim = BruteForceSimulator(attacker_ip="185.220.101.42")
        attack_logs = sim.classic_brute_force(
            target_username="root",
            num_attempts=40,
            attempts_per_second=4,
            success_probability=0.05,
            verbose=False  # Suppress attacker-side output, show SOC side
        )

        print_blue("Monitoring auth.log for suspicious patterns...")
        run_scenario("Standard Brute Force", attack_logs, normal_lines)

    # ─────────────────────────────────────────────────────────────────────────
    if choice == "2" or choice == "5":
        print(f"\n{'#'*60}")
        print("  SCENARIO 2: Full Kill Chain (Recon + Exploitation)")
        print("  What you'll see: Port scan THEN brute force — correlated!")
        print(f"{'#'*60}")

        attack_ip = "45.142.212.100"
        base_time = datetime.datetime.now().replace(hour=2, minute=14, second=0)

        print_red("Phase 1 of attack: Running nmap port scan...")
        scan_logs, scan_end = simulate_port_scan(
            attacker_profile="script_kiddie",
            base_time=base_time,
            verbose=False
        )

        # Brief pause (attacker reviews scan results)
        attack_base = scan_end + datetime.timedelta(seconds=10)

        print_red("Phase 2 of attack: nmap found SSH open. Launching Hydra...")
        sim = BruteForceSimulator(attacker_ip=attack_ip, base_time=attack_base)
        brute_logs = sim.classic_brute_force(
            target_username="root",
            num_attempts=40,
            attempts_per_second=3,
            success_probability=0.05,
            verbose=False
        )

        all_attack_logs = scan_logs + brute_logs
        print_blue("SOC monitoring — watching for correlated multi-stage attack...")
        alerts = run_scenario("Full Kill Chain (Recon + Brute Force)",
                              all_attack_logs, normal_lines)

        # Check if correlation fired
        escalated = [a for a in alerts if a.get("escalation_reason")]
        if escalated:
            print(f"\n  [LESSON]: Correlation escalated attack from HIGH to CRITICAL!")
            print(f"  Because the port scan PRECEDED the brute force — this is deliberate.")
        else:
            print(f"\n  [NOTE]: No escalation this run. Adjust timing for correlation to fire.")

    # ─────────────────────────────────────────────────────────────────────────
    if choice == "3" or choice == "5":
        print(f"\n{'#'*60}")
        print("  SCENARIO 3: Password Spray")
        print("  What you'll see: Same IP, DIFFERENT usernames, 1 attempt each")
        print(f"{'#'*60}")
        print_red("Spraying 'Password123' across all accounts...")

        sim = BruteForceSimulator(attacker_ip="203.0.113.88")
        spray_logs = sim.password_spray(
            password="Password123!",
            usernames=["root", "admin", "alice", "bob", "postgres",
                       "git", "ubuntu", "test", "oracle", "pi"],
            delay_between_users=4.0,
            verbose=False
        )

        print_blue("SOC monitoring — looking for IP with multiple account attempts...")
        alerts = run_scenario("Password Spray", spray_logs, normal_lines)

        if not alerts:
            print("\n  [IMPORTANT LESSON]: Password spray may evade detection!")
            print("  Each username only has 1 failure — below lockout threshold.")
            print("  But same IP with many different usernames = still suspicious.")
            print("  Phase 4 ML detection catches this with behavioral baseline.")
        else:
            print("\n  [DETECTED]: Spray caught via IP-level failure threshold.")
            print("  Note: unique_usernames list in alert shows the spray pattern.")

    # ─────────────────────────────────────────────────────────────────────────
    if choice == "4" or choice == "5":
        print(f"\n{'#'*60}")
        print("  SCENARIO 4: Low-and-Slow Evasion Attack")
        print("  What you'll see: Attacker slows down to evade 60s window")
        print(f"{'#'*60}")
        print_red("Launching slow brute force (1 attempt per 70 seconds)...")
        print_red("This is the LOW-AND-SLOW evasion technique.")

        # Generate manually with slow timing
        attacker_ip = "198.51.100.73"
        slow_logs = []
        base = datetime.datetime.now().replace(hour=3, minute=0, second=0)

        from log_generator import SERVER_NAME, COMMON_ATTACK_USERS
        for i in range(20):
            # Key: 70 seconds between attempts = OUTSIDE the 60s detection window!
            offset = i * random.uniform(65, 90)
            event_time = base + datetime.timedelta(seconds=offset)
            timestamp = event_time.strftime("%b %d %H:%M:%S")
            pid = random.randint(10000, 65535)
            port = random.randint(1024, 65535)
            user = random.choice(COMMON_ATTACK_USERS)
            slow_logs.append(
                f"{timestamp} {SERVER_NAME} sshd[{pid}]: "
                f"Failed password for {user} from {attacker_ip} port {port} ssh2"
            )

        print_blue("Monitoring... (this attacker waits 70s between attempts)")
        alerts = run_scenario("Low-and-Slow Evasion", slow_logs, [], show_events=True)

        if not alerts:
            print(f"\n  [DETECTION FAILED] Low-and-slow attack was NOT detected!")
            print(f"\n  WHY?: Each attempt is >65 seconds apart.")
            print(f"        Our window is 60 seconds.")
            print(f"        The sliding window NEVER accumulates 5 failures!")
            print(f"\n  REAL SOC SOLUTIONS:")
            print(f"        1. Extend window to 24h (catches it but more false positives)")
            print(f"        2. Use ML anomaly detection (Phase 4 — coming next)")
            print(f"        3. Historical baseline: 'this IP never appeared before'")
            print(f"        4. Threat intelligence: 'this IP is in a blocklist'")
        else:
            print(f"\n  Low-and-slow detected! (Timing variance put some in the window)")

    # ─────────────────────────────────────────────────────────────────────────
    print(f"\n{'='*60}")
    print(f"  PHASE 3 COMPLETE — RED TEAM vs BLUE TEAM")
    print(f"{'='*60}")
    print(f"""
  WHAT YOU LEARNED:
  -----------------
  1. HOW attackers think (nmap -> Hydra -> full kill chain)
  2. HOW detection works event-by-event (Phase 2 rules)
  3. WHERE detection FAILS (low-and-slow evasion)

  KEY INSIGHT:
  Rule-based detection has a fundamental limitation:
  It can only detect what you KNOW to look for.

  New attack patterns, evasion techniques, and slow attacks
  require a DIFFERENT approach: Machine Learning anomaly detection.

  --> That's exactly what Phase 4 builds.

  FILES GENERATED:
  - phase3/port_scanner_sim.py   (attacker recon tool)
  - phase3/brute_force_sim.py    (attacker exploit tool)
  - phase3/red_vs_blue.py        (this file — full pipeline)
    """)


if __name__ == "__main__":
    main()
