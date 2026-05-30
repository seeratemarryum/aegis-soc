"""
=============================================================================
SOC ANALYST TRAINING -- PHASE 4: FEATURE ENGINEER
=============================================================================

CORE TEACHING: Why Feature Engineering is the Hardest Part of ML

ML models don't understand "May 30 02:14:37 sshd[12345]: Failed password..."
They only understand NUMBERS.

Feature engineering = converting raw security events into numbers that
capture the MEANING of what's happening.

This is where domain expertise meets data science.
A data scientist with no security background might miss critical features.
A SOC analyst with no ML background can't turn observations into numbers.
You need BOTH -- and this file teaches you how.


WHAT IS A FEATURE?
------------------
A feature is a single measurable property of an observation.

Bad feature (useless for ML):
  raw_log_text = "May 30 sshd Failed password root 185.220.101.42"
  (ML cannot find patterns in raw text without NLP preprocessing)

Good features (ML can work with these):
  failure_rate        = 0.95    (95% of this IP's logins are failures)
  unique_usernames    = 7       (tried 7 different usernames)
  events_per_minute   = 4.2     (very fast -- automated)
  hour_of_day         = 2       (2am -- suspicious)
  is_external_ip      = 1       (not from internal network)


WHAT EACH FEATURE CAPTURES (SOC reasoning behind each number):
--------------------------------------------------------------
1. failure_rate:
   Normal user: 0.05 (1 typo per 20 logins)
   Brute force: 0.98 (attacker fails almost every attempt)
   KEY SIGNAL: High failure rate = strong attack indicator

2. unique_usernames_tried:
   Normal user: 1 (they know their own username)
   Wordlist attack: 5-20 (rotating through common usernames)
   KEY SIGNAL: Many usernames = credential stuffing / spray

3. events_per_minute:
   Normal user: 0.1 (logs in once, works for hours)
   Hydra default: 16+ (parallel threads, very fast)
   KEY SIGNAL: High velocity = automated tool

4. hour_of_day (0-23):
   Normal business user: 8-18 (business hours)
   Attacker: 2-4 (midnight -- fewest eyes watching)
   KEY SIGNAL: 2-4am activity from external IP = suspicious

5. is_external_ip:
   Normal user: often internal (10.x.x.x, 192.168.x.x)
   Attacker: external (random public IPs, VPS, Tor exits)
   KEY SIGNAL: External IP doing high failure rate = red flag

6. success_after_failure_count:
   Normal user: 0 (succeeds first try, or resets password)
   Brute forcer: >3 failures then success = account compromised
   KEY SIGNAL: Success after many failures = worst case scenario

7. connection_spread_seconds:
   Normal user: large spread (logs in morning, evening)
   Fast attacker: tiny spread (all 60 attempts in 30 seconds)
   Slow attacker: large spread (1 attempt per 10 minutes)
   KEY SIGNAL: Tiny OR very regular spread = automated

REAL SOC TOOLS THAT DO THIS:
  Splunk MLTK: uses SPL to compute statistics then feeds to ML
  Microsoft Sentinel: KQL aggregations feed Azure ML
  QRadar User Behavior Analytics: same concept, proprietary
=============================================================================
"""

import sys
import os
import json
import math
import datetime
from collections import defaultdict

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE_DIR, "phase1"))

TRUSTED_IP_PREFIXES = ("10.", "192.168.", "172.16.", "172.17.", "172.18.")


def is_internal_ip(ip):
    return ip.startswith(TRUSTED_IP_PREFIXES)


def parse_hour(timestamp_str):
    """
    Extract the hour-of-day from a syslog timestamp string.

    SOC INSIGHT: Time-of-day is one of the most powerful features.
    An external IP with 50 failures at 2am is VERY different from
    the same IP doing the same thing at 2pm during business hours.
    """
    try:
        year = datetime.datetime.now().year
        dt = datetime.datetime.strptime(f"{year} {timestamp_str}", "%Y %b %d %H:%M:%S")
        return dt.hour
    except ValueError:
        return 12  # Default to midday if parse fails


def parse_datetime(timestamp_str):
    """Convert syslog timestamp to datetime for time-delta calculations."""
    try:
        year = datetime.datetime.now().year
        return datetime.datetime.strptime(f"{year} {timestamp_str}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return datetime.datetime.now()


# =============================================================================
# FEATURE EXTRACTION
# =============================================================================

def extract_ip_features(events, ip_address):
    """
    Extract a feature vector for a single IP address from all its events.

    This aggregates ALL events from one IP into a fixed-size numeric vector.
    Each IP becomes ONE ROW in our ML dataset.

    AGGREGATION CONCEPT:
    We cannot feed 60 separate "Failed password" events to the model.
    We SUMMARIZE those 60 events into 10 numbers that capture the behavior.

    That summary (the feature vector) is what the model learns from.
    """
    # Filter events for this IP
    ip_events = [e for e in events if e.get("source_ip") == ip_address]

    if not ip_events:
        return None

    # -- Count event types
    failed_count = sum(1 for e in ip_events if e.get("event_type") == "FAILED_LOGIN")
    success_count = sum(1 for e in ip_events if e.get("event_type") == "SUCCESSFUL_LOGIN")
    invalid_count = sum(1 for e in ip_events if e.get("event_type") == "INVALID_USER")
    closed_count = sum(1 for e in ip_events if e.get("event_type") == "CONNECTION_CLOSED")
    total = len(ip_events)

    # -- Feature 1: Failure Rate
    # What percentage of this IP's login attempts FAILED?
    # Normal: ~5%. Attacker: ~95-100%.
    auth_attempts = failed_count + success_count + invalid_count
    failure_rate = (failed_count + invalid_count) / max(auth_attempts, 1)

    # -- Feature 2: Unique Usernames Tried
    # How many DIFFERENT usernames did this IP attempt?
    # Normal: 1-2. Wordlist attack: 5-20.
    usernames = set(
        e["username"] for e in ip_events
        if "username" in e
    )
    unique_username_count = len(usernames)

    # -- Feature 3: High-Risk Username Ratio
    # What fraction of username attempts were high-risk accounts (root, admin)?
    HIGH_RISK = {"root", "admin", "administrator", "postgres", "oracle", "test", "guest", "pi"}
    high_risk_attempts = sum(
        1 for e in ip_events
        if e.get("username", "") in HIGH_RISK
    )
    high_risk_ratio = high_risk_attempts / max(auth_attempts, 1)

    # -- Feature 4: Events Per Minute (velocity)
    # How fast is this IP generating log events?
    # Normal: 0.01-0.5/min. Hydra: 16-240/min.
    timestamps = [parse_datetime(e["timestamp"]) for e in ip_events]
    timestamps.sort()
    if len(timestamps) >= 2:
        duration_seconds = (timestamps[-1] - timestamps[0]).total_seconds()
        events_per_minute = (total / max(duration_seconds, 1)) * 60
    else:
        events_per_minute = 0.0

    # -- Feature 5: Connection Spread (seconds between first and last event)
    # Fast brute force: 30-60 seconds total. Normal: hours.
    # Low-and-slow: thousands of seconds but very REGULAR intervals.
    connection_spread_seconds = (
        (timestamps[-1] - timestamps[0]).total_seconds()
        if len(timestamps) >= 2 else 0.0
    )

    # -- Feature 6: Timing Regularity (standard deviation of inter-event intervals)
    # KEY FEATURE FOR LOW-AND-SLOW DETECTION:
    # Automated tools fire at REGULAR intervals (low std dev).
    # Humans are IRREGULAR (high std dev -- you don't type at exactly 3.000s intervals).
    if len(timestamps) >= 3:
        intervals = [
            (timestamps[i+1] - timestamps[i]).total_seconds()
            for i in range(len(timestamps) - 1)
        ]
        mean_interval = sum(intervals) / len(intervals)
        variance = sum((x - mean_interval)**2 for x in intervals) / len(intervals)
        interval_std_dev = math.sqrt(variance)
    else:
        interval_std_dev = 0.0

    # -- Feature 7: Hour of Day (0-23)
    # Night activity (0-6) from external IPs = suspicious.
    hours = [parse_hour(e["timestamp"]) for e in ip_events]
    dominant_hour = max(set(hours), key=hours.count) if hours else 12

    # -- Feature 8: Is External IP
    # 0 = internal (trusted), 1 = external (untrusted)
    is_external = 0 if is_internal_ip(ip_address) else 1

    # -- Feature 9: Success After Failure Count
    # Were there failures BEFORE a success? How many?
    # This is the "brute force succeeded" signal.
    failures_before_success = 0
    found_success = False
    for e in sorted(ip_events, key=lambda x: parse_datetime(x["timestamp"])):
        if e.get("event_type") == "FAILED_LOGIN":
            if not found_success:
                failures_before_success += 1
        elif e.get("event_type") == "SUCCESSFUL_LOGIN":
            found_success = True

    # -- Feature 10: Rapid Connection Closes
    # High closed_count / total = port scanning behavior.
    rapid_close_ratio = closed_count / max(total, 1)

    # -- Build the feature vector (the actual ML input)
    feature_vector = {
        "ip_address": ip_address,          # Identifier (NOT fed to ML)
        "total_events": total,             # Context field

        # === ACTUAL ML FEATURES (these become the numpy array) ===
        "failure_rate": round(failure_rate, 4),
        "unique_username_count": unique_username_count,
        "high_risk_ratio": round(high_risk_ratio, 4),
        "events_per_minute": round(events_per_minute, 4),
        "connection_spread_seconds": round(connection_spread_seconds, 2),
        "interval_std_dev": round(interval_std_dev, 4),
        "dominant_hour": dominant_hour,
        "is_external_ip": is_external,
        "failures_before_success": failures_before_success,
        "rapid_close_ratio": round(rapid_close_ratio, 4),
    }

    return feature_vector


# Feature names in exact order (must match extract_ip_features output)
ML_FEATURE_NAMES = [
    "failure_rate",
    "unique_username_count",
    "high_risk_ratio",
    "events_per_minute",
    "connection_spread_seconds",
    "interval_std_dev",
    "dominant_hour",
    "is_external_ip",
    "failures_before_success",
    "rapid_close_ratio",
]


def build_feature_matrix(events, min_events_per_ip=2):
    """
    Build a complete feature matrix from all events.

    Each ROW = one IP address.
    Each COLUMN = one feature (failure_rate, events_per_minute, etc.)

    This is the standard ML input format.

    Args:
        events: list of parsed log event dicts (from Phase 1 parser)
        min_events_per_ip: filter out IPs with too few events (insufficient data)

    Returns:
        List of feature vectors (one per IP), list of IP labels
    """
    # Find all unique IPs in the event stream
    all_ips = set(
        e.get("source_ip") for e in events
        if e.get("source_ip")
    )

    feature_rows = []
    ip_labels = []

    for ip in sorted(all_ips):
        ip_count = sum(1 for e in events if e.get("source_ip") == ip)

        # Skip IPs with too few events -- not enough data to judge behavior
        if ip_count < min_events_per_ip:
            continue

        features = extract_ip_features(events, ip)
        if features:
            feature_rows.append(features)
            ip_labels.append(ip)

    return feature_rows, ip_labels


def features_to_numpy(feature_rows):
    """
    Convert list of feature dicts to a numpy array for scikit-learn.

    ML models need a 2D matrix: shape = (n_samples, n_features)
    n_samples = number of IPs
    n_features = 10 (the features we engineered above)

    TEACHING: This is called 'feature matrix' or 'design matrix' in ML.
    """
    import numpy as np
    X = []
    for row in feature_rows:
        feature_values = [row[fname] for fname in ML_FEATURE_NAMES]
        X.append(feature_values)
    return np.array(X, dtype=float)


def print_feature_table(feature_rows):
    """Print features in a readable SOC-analyst-friendly table."""
    if not feature_rows:
        print("  No features to display.")
        return

    print(f"\n  {'IP ADDRESS':<20} {'FAIL%':>6} {'UNIQ_USR':>9} {'EVT/MIN':>8} "
          f"{'HOUR':>5} {'EXT':>4} {'FAIL_B4_OK':>11} {'ANOMALY?':>9}")
    print(f"  {'-'*80}")

    for row in feature_rows:
        ip = row["ip_address"]
        fail_pct = f"{row['failure_rate']*100:.0f}%"
        uniq_usr = row["unique_username_count"]
        epm = f"{row['events_per_minute']:.1f}"
        hour = row["dominant_hour"]
        ext = "YES" if row["is_external_ip"] else "no"
        fbs = row["failures_before_success"]

        # Simple heuristic annotation for humans reading the table
        # (The ML model does this properly)
        if row["failure_rate"] > 0.7 and row["is_external_ip"]:
            annotation = "SUSPICIOUS"
        elif row["unique_username_count"] >= 4 and row["is_external_ip"]:
            annotation = "SUSPICIOUS"
        else:
            annotation = "normal"

        print(f"  {ip:<20} {fail_pct:>6} {uniq_usr:>9} {epm:>8} "
              f"{hour:>5} {ext:>4} {fbs:>11} {annotation:>9}")


if __name__ == "__main__":
    events_path = os.path.join(BASE_DIR, "phase1", "parsed_events.json")

    if not os.path.exists(events_path):
        print("[ERROR] Run phase1 first to generate parsed_events.json")
        sys.exit(1)

    with open(events_path) as f:
        events = json.load(f)

    print(f"\n[+] Loaded {len(events)} events from Phase 1")
    print("[+] Extracting features per IP address...")

    feature_rows, ip_labels = build_feature_matrix(events, min_events_per_ip=2)

    print(f"[OK] Built feature matrix: {len(feature_rows)} IPs x {len(ML_FEATURE_NAMES)} features\n")
    print_feature_table(feature_rows)

    print(f"""
  WHAT YOU ARE SEEING:
  Each row = one IP address, summarized into 10 numbers.
  The ML model learns which combination of numbers = "normal".

  NOTICE:
  - Internal IPs (10.x.x.x, 192.168.x.x): low fail%, 1 username, business hours
  - Attacker IP: high fail%, many usernames, 2am, external

  EXPERIMENT: Open parsed_events.json and find a FAILED_LOGIN entry.
  Look at the IP. Find that IP's row in this table.
  Do the feature values match what you'd expect?
    """)
