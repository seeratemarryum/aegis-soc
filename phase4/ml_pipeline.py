"""
=============================================================================
SOC ANALYST TRAINING -- PHASE 4: ML PIPELINE
=============================================================================

This file ties everything together and runs the KEY experiment:

  CAN ML CATCH WHAT RULES CANNOT?

Specifically:
  1. Run LOW-AND-SLOW attack (Phase 2 rules miss this completely)
  2. Run ML anomaly detection on the SAME data
  3. Compare: does ML catch it when rules don't?

Also runs:
  - Standard attack (both rules AND ML catch it -- see the overlap)
  - Evasion comparison table (rules vs ML side by side)

RUN: python phase4/ml_pipeline.py
=============================================================================
"""

import sys
import os
import json
import datetime
import random

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PHASE1_DIR = os.path.join(BASE_DIR, "phase1")
PHASE2_DIR = os.path.join(BASE_DIR, "phase2")
PHASE3_DIR = os.path.join(BASE_DIR, "phase3")
PHASE4_DIR = os.path.join(BASE_DIR, "phase4")

sys.path.insert(0, BASE_DIR)
sys.path.insert(0, PHASE1_DIR)
sys.path.insert(0, PHASE2_DIR)
sys.path.insert(0, PHASE3_DIR)
sys.path.insert(0, PHASE4_DIR)

from log_parser import parse_log_line
from log_generator import simulate_normal_traffic, SERVER_NAME, COMMON_ATTACK_USERS
from rules.brute_force import BruteForceDetector
from rules.port_scan import PortScanDetector
from alert_manager import AlertManager
from anomaly_detector import SOCAnomalyDetector, print_anomaly_report
from feature_engineer import build_feature_matrix, print_feature_table


# =============================================================================
# ATTACK LOG GENERATORS (LOW-AND-SLOW)
# =============================================================================

def generate_low_and_slow_logs(attacker_ip, num_attempts=20):
    """
    Generate a low-and-slow brute force attack.

    TIMING: 70-90 seconds between each attempt.
    Phase 2 window = 60 seconds -> NEVER catches it.
    But ML sees: 100% failure rate, root username, external IP, 2am.
    THOSE features are anomalous regardless of speed.
    """
    logs = []
    base = datetime.datetime.now().replace(hour=2, minute=0, second=0)

    for i in range(num_attempts):
        # Key: interval > 60 seconds = outside Phase 2 detection window
        offset = i * random.uniform(70, 95)
        event_time = base + datetime.timedelta(seconds=offset)
        timestamp = event_time.strftime("%b %d %H:%M:%S")
        pid = random.randint(10000, 65535)
        port = random.randint(1024, 65535)
        username = random.choice(["root", "admin", "postgres"])
        logs.append(
            f"{timestamp} {SERVER_NAME} sshd[{pid}]: "
            f"Failed password for {username} from {attacker_ip} port {port} ssh2"
        )
    return logs


def generate_credential_stuffing_logs(attacker_ip, num_pairs=15):
    """
    Credential stuffing: real breach username:password pairs.
    One attempt per credential pair, widely spread in time.
    Speed: 1 attempt every 5 minutes (very slow, human-like).

    Why it evades rules:
    - Spread = well outside any time window
    - One attempt per account = no lockout
    - Timing looks human

    Why ML catches it:
    - Still 100% failure rate from external IP
    - Still multiple usernames (breach data has many accounts)
    - Still external IP at odd hours
    """
    # Simulated breach credential pairs (public breach data is anonymized here)
    stuffed_users = [
        "james.wilson", "sarah.jones", "mike_92", "admin", "user1",
        "john.doe", "alex_k", "root", "postgres", "test_user",
        "deploy", "jenkins", "git", "ubuntu", "pi"
    ]

    logs = []
    base = datetime.datetime.now().replace(hour=1, minute=0, second=0)

    for i, username in enumerate(stuffed_users[:num_pairs]):
        # 5 minutes between each stuffing attempt (very slow, looks human)
        offset = i * random.uniform(280, 340)
        event_time = base + datetime.timedelta(seconds=offset)
        timestamp = event_time.strftime("%b %d %H:%M:%S")
        pid = random.randint(10000, 65535)
        port = random.randint(1024, 65535)

        # Is this a real username on our system?
        real_users = {"alice", "bob", "sysadmin", "ubuntu"}
        if username in real_users:
            log_type = "Failed password for"
        else:
            log_type = "Invalid user"
            # Invalid user format is slightly different
            logs.append(
                f"{timestamp} {SERVER_NAME} sshd[{pid}]: "
                f"Invalid user {username} from {attacker_ip} port {port}"
            )
            continue

        logs.append(
            f"{timestamp} {SERVER_NAME} sshd[{pid}]: "
            f"{log_type} {username} from {attacker_ip} port {port} ssh2"
        )

    return logs


# =============================================================================
# CORE COMPARISON: RULES vs ML
# =============================================================================

def run_rules_detection(events):
    """Run Phase 2 rule-based detection and return alert count."""
    bf = BruteForceDetector(threshold=5, window_seconds=60)
    ps = PortScanDetector(threshold=5, window_seconds=15)
    mgr = AlertManager()
    alert_count = 0

    for event in events:
        for alert in [bf.analyze_event(event), ps.analyze_event(event)]:
            if alert and mgr.receive_alert(alert):
                alert_count += 1

    return alert_count


def run_ml_detection(events, detector):
    """Run ML anomaly detection and return flagged IPs."""
    results = detector.score_events(events)
    flagged = [r for r in results if r["is_anomaly"]]
    return flagged


def parse_log_lines(raw_lines):
    """Convert list of raw log strings to parsed event dicts."""
    events = []
    for line in raw_lines:
        event = parse_log_line(line)
        if event:
            events.append(event)
    return events


# =============================================================================
# MAIN PIPELINE
# =============================================================================

def main():
    print("\n")
    print("  ##########################################################")
    print("  ##  PHASE 4: ML ANOMALY DETECTION PIPELINE              ##")
    print("  ##  Testing: Can ML catch what rules MISS?              ##")
    print("  ##########################################################")

    # ── STEP 1: Build training dataset from Phase 1 normal traffic ───────────
    print("\n[STEP 1] Loading and preparing training data...")
    print("         Training = normal behavior the model learns from")

    events_path = os.path.join(PHASE1_DIR, "parsed_events.json")
    if not os.path.exists(events_path):
        print("[ERROR] Run phase1 scripts first to generate parsed_events.json")
        sys.exit(1)

    with open(events_path) as f:
        phase1_events = json.load(f)

    # Generate extra CLEAN normal traffic for a richer training baseline
    # (more normal = model learns the boundary better)
    print("[+] Generating additional normal traffic for training baseline...")
    base = datetime.datetime.now().replace(hour=8, minute=0, second=0)
    extra_normal_raw = simulate_normal_traffic(base, duration_minutes=480)

    extra_normal_events = parse_log_lines(extra_normal_raw)

    # We need MORE normal IPs for a useful training baseline.
    # In production: 30 days of logs gives hundreds of normal IPs.
    # Here we synthetically generate diverse normal behavior.
    from log_generator import LEGITIMATE_IPS, VALID_USERS
    import random

    # Expand the pool of normal IPs to give the model a richer baseline
    extra_normal_ips = [
        "10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5",
        "10.0.0.10", "10.0.0.11", "10.0.0.15", "10.0.0.20",
        "192.168.1.10", "192.168.1.20", "192.168.1.30", "192.168.1.40",
        "192.168.1.50", "192.168.1.60", "192.168.2.5", "192.168.2.10",
    ]

    import datetime as _dt
    extra_raw = []
    base_t = _dt.datetime.now().replace(hour=8, minute=0, second=0)
    for ip in extra_normal_ips:
        for j in range(random.randint(3, 8)):
            offset = random.uniform(0, 28800)  # spread over 8 hours
            ts = (base_t + _dt.timedelta(seconds=offset)).strftime("%b %d %H:%M:%S")
            user = random.choice(["alice", "bob", "sysadmin", "ubuntu"])
            pid = random.randint(10000, 65535)
            port = random.randint(1024, 65535)
            # 95% success, 5% typo
            if random.random() < 0.95:
                extra_raw.append(
                    f"{ts} prod-webserver-01 sshd[{pid}]: "
                    f"Accepted password for {user} from {ip} port {port} ssh2"
                )
            else:
                extra_raw.append(
                    f"{ts} prod-webserver-01 sshd[{pid}]: "
                    f"Failed password for {user} from {ip} port {port} ssh2"
                )

    extra_normal_events2 = parse_log_lines(extra_raw)

    KNOWN_ATTACK_IPS = {"185.220.101.42", "45.142.212.100",
                        "203.0.113.88", "198.51.100.73"}
    training_events = (
        [e for e in phase1_events if e.get("source_ip") not in KNOWN_ATTACK_IPS]
        + extra_normal_events
        + extra_normal_events2
    )
    print(f"[OK] Training dataset: {len(training_events)} events "
          f"across {len(extra_normal_ips)+3} normal IPs (attack IPs excluded)")

    # ── STEP 2: Train the Isolation Forest ───────────────────────────────────
    print("\n[STEP 2] Training Isolation Forest model...")
    print("         Model learns what 'normal' SSH behavior looks like")

    detector = SOCAnomalyDetector(
        contamination=0.08,  # Expect ~8% of training IPs to be anomalous
        n_estimators=100,
        random_state=42
    )
    trained = detector.train(training_events)
    if not trained:
        print("[ERROR] Training failed -- not enough data. Run Phase 1 to generate more logs.")
        sys.exit(1)

    # ── STEP 3: Generate three test attack scenarios ──────────────────────────
    print("\n[STEP 3] Generating test attack scenarios...")

    normal_base = datetime.datetime.now().replace(hour=9, minute=0, second=0)
    normal_raw = simulate_normal_traffic(normal_base, duration_minutes=240)
    normal_events = parse_log_lines(normal_raw)

    # Scenario A: Fast brute force (both rules AND ML should catch)
    fast_raw = []
    base_fast = datetime.datetime.now().replace(hour=2, minute=14, second=0)
    for i in range(40):
        offset = i * random.uniform(0.3, 0.8)
        ts = (base_fast + datetime.timedelta(seconds=offset)).strftime("%b %d %H:%M:%S")
        pid = random.randint(10000, 65535)
        fast_raw.append(
            f"{ts} {SERVER_NAME} sshd[{pid}]: "
            f"Failed password for root from 185.220.101.42 port {random.randint(1024,65535)} ssh2"
        )
    fast_events = parse_log_lines(fast_raw)

    # Scenario B: Low-and-slow (rules MISS, ML should catch)
    slow_raw = generate_low_and_slow_logs("45.142.212.100", num_attempts=18)
    slow_events = parse_log_lines(slow_raw)

    # Scenario C: Credential stuffing (rules MISS, ML may catch)
    stuff_raw = generate_credential_stuffing_logs("203.0.113.88", num_pairs=12)
    stuff_events = parse_log_lines(stuff_raw)

    # ── STEP 4: Run both detectors on each scenario ───────────────────────────
    print("\n[STEP 4] Running both detection systems on each scenario...")

    scenarios = [
        ("Fast Brute Force",       fast_events,  "185.220.101.42"),
        ("Low-and-Slow Attack",    slow_events,  "45.142.212.100"),
        ("Credential Stuffing",    stuff_events, "203.0.113.88"),
    ]

    # Summary table data
    comparison_rows = []

    for name, attack_events, attack_ip in scenarios:
        # Combine with normal traffic (realistic -- attackers hide in noise)
        combined_events = normal_events + attack_events
        random.shuffle(combined_events)

        # Rules-based detection
        rule_alerts = run_rules_detection(combined_events)

        # ML detection
        ml_results = run_ml_detection(combined_events, detector)
        ml_flagged_ips = [r["ip_address"] for r in ml_results]
        ml_caught = attack_ip in ml_flagged_ips

        ml_score = next(
            (r["anomaly_score"] for r in ml_results if r["ip_address"] == attack_ip),
            None
        )
        ml_severity = next(
            (r["severity"] for r in ml_results if r["ip_address"] == attack_ip),
            "NOT FLAGGED"
        )

        comparison_rows.append({
            "scenario": name,
            "attack_ip": attack_ip,
            "rule_alerts": rule_alerts,
            "rules_detected": rule_alerts > 0,
            "ml_detected": ml_caught,
            "ml_score": ml_score,
            "ml_severity": ml_severity,
        })

    # ── STEP 5: Print the comparison table ────────────────────────────────────
    print(f"\n{'='*70}")
    print(f"  DETECTION COMPARISON: RULES vs ML")
    print(f"{'='*70}")
    print(f"\n  {'SCENARIO':<26} {'RULE ALERTS':>11} {'RULES':>8} {'ML':>8} {'ML SEVERITY':>12}")
    print(f"  {'-'*70}")

    for row in comparison_rows:
        rule_sym = "[CAUGHT]" if row["rules_detected"] else "[MISSED]"
        ml_sym   = "[CAUGHT]" if row["ml_detected"]    else "[MISSED]"
        alerts   = str(row["rule_alerts"]) if row["rule_alerts"] > 0 else "0"

        print(f"  {row['scenario']:<26} {alerts:>11} {rule_sym:>8} {ml_sym:>8} {row['ml_severity']:>12}")

    print(f"\n  LEGEND: [CAUGHT] = detected | [MISSED] = evaded detection")

    # ── STEP 6: Deep dive on the low-and-slow result ──────────────────────────
    print(f"\n{'='*70}")
    print(f"  DEEP DIVE: Low-and-Slow Attack (The Key Lesson)")
    print(f"{'='*70}")

    slow_combined = normal_events + slow_events
    slow_ml_results = detector.score_events(slow_combined)
    slow_result = next(
        (r for r in slow_ml_results if r["ip_address"] == "45.142.212.100"), None
    )

    rule_result = run_rules_detection(slow_combined)

    print(f"\n  Attack IP: 45.142.212.100 (low-and-slow, 70-95s between attempts)")
    print(f"\n  PHASE 2 (Rules):  {rule_result} alerts fired")
    print(f"  [WHY]: 70s interval > 60s window = counter never reaches threshold")
    print(f"         The rule literally never sees 5 failures in 60 seconds.")

    if slow_result:
        print(f"\n  PHASE 4 (ML):     {'ANOMALY DETECTED' if slow_result['is_anomaly'] else 'NOT DETECTED'}")
        print(f"  Anomaly score:    {slow_result['anomaly_score']:.4f}")
        print(f"  ML Severity:      {slow_result['severity']}")
        print(f"\n  [WHY ML {'CAUGHT' if slow_result['is_anomaly'] else 'MISSED'} IT]:")

        if slow_result["is_anomaly"]:
            print(f"  ML sees these features REGARDLESS of speed:")
            f = slow_result["features"]
            print(f"    failure_rate        = {f['failure_rate']*100:.0f}%   (training normal: ~5%)")
            print(f"    is_external_ip      = {f['is_external_ip']}      (external IP = elevated risk)")
            print(f"    unique_usernames    = {f['unique_username_count']}      (multiple accounts tried)")
            print(f"    dominant_hour       = {f['dominant_hour']}:00   (2am -- low monitoring period)")
            print(f"\n  ALL of these deviate from normal simultaneously.")
            print(f"  Isolation Forest isolates this point QUICKLY.")
            print(f"  The attack speed is IRRELEVANT to these features.")
            if slow_result["anomaly_reasons"]:
                print(f"\n  Top anomaly reasons:")
                for r in slow_result["anomaly_reasons"][:3]:
                    print(f"    [{r['deviation']:.1f}x deviation] {r['human_explanation']}")
        else:
            print(f"  ML did not flag this IP this run.")
            print(f"  TRY: increase num_attempts to 25, or lower contamination to 0.03")

    # ── STEP 7: Full report on all combined events ────────────────────────────
    print(f"\n[STEP 7] Full ML scan on all events combined...")
    all_events = normal_events + fast_events + slow_events + stuff_events
    all_results = detector.score_events(all_events)
    print_anomaly_report(all_results)

    # Save combined results
    # Convert numpy bools to Python bools for JSON serialization
    def make_serializable(obj):
        if isinstance(obj, dict):
            return {k: make_serializable(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [make_serializable(i) for i in obj]
        elif hasattr(obj, 'item'):  # numpy scalar
            return obj.item()
        elif isinstance(obj, bool):
            return bool(obj)
        return obj

    output = make_serializable({
        "comparison_table": comparison_rows,
        "ml_results": all_results,
        "model_config": {
            "contamination": detector.contamination,
            "n_estimators": detector.n_estimators,
        }
    })
    out_path = os.path.join(PHASE4_DIR, "ml_pipeline_results.json")
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\n[OK] Full results saved: {out_path}")

    # ── Experiments ───────────────────────────────────────────────────────────
    print(f"\n{'='*60}")
    print(f"  EXPERIMENTS FOR PHASE 4")
    print(f"{'='*60}")
    print("""
  1. CHANGE CONTAMINATION:
     In SOCAnomalyDetector(contamination=0.08)
     Try contamination=0.30  -- more IPs flagged (more false positives)
     Try contamination=0.01  -- only extreme anomalies flagged
     Watch how the comparison table changes.

  2. REMOVE RANDOM STATE:
     Change random_state=42 to random_state=None
     Re-run several times. Notice results vary slightly.
     This shows why reproducibility (fixed seed) matters in SOC.

  3. ADD A FEATURE:
     In feature_engineer.py, open extract_ip_features().
     Add a new feature: "is_root_targeted" = 1 if "root" in usernames
     Add it to ML_FEATURE_NAMES list and re-run.
     Does detection improve?

  4. TEST PURE NORMAL TRAFFIC:
     Comment out fast_events and slow_events in STEP 3.
     Run only normal traffic through ML.
     Goal: zero or near-zero anomaly detections (false positive test).
    """)


if __name__ == "__main__":
    main()
