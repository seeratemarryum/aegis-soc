"""
=============================================================================
SOC ANALYST TRAINING — PHASE 2: BRUTE FORCE DETECTION RULE
=============================================================================

CONCEPT: What is Brute Force Detection?
-----------------------------------------
A brute force attack is when an attacker tries many passwords rapidly
against a login service (SSH, RDP, web login, etc.) hoping to guess correctly.

THE DETECTION LOGIC — explained step by step:

  STEP 1: Watch every "Failed Login" event
  STEP 2: Group events by SOURCE IP (same attacker = same IP)
  STEP 3: Count failures per IP within a TIME WINDOW (e.g., last 60 seconds)
  STEP 4: If count > THRESHOLD → fire alert

  This is called "sliding window detection" or "frequency analysis"

PSEUDOCODE (read this before looking at Python):
-------------------------------------------------
  For each new failed_login event:
      ip = event.source_ip
      window_start = now - 60 seconds

      recent_failures = count of failures from ip since window_start

      if recent_failures >= THRESHOLD:
          fire_alert("BRUTE_FORCE", ip, recent_failures)

WHY 60 SECONDS? WHY 5 FAILURES? (Threshold Tuning)
-----------------------------------------------------
  Too LOW a threshold  → Too many false positives (alert fatigue)
                         "Every user who mistyped password twice = alert"
                         SOC analysts ignore alerts → DANGEROUS

  Too HIGH a threshold → Attacker gets in before you detect
                         "5000 attempts needed to alert" = too late

  REAL WORLD:
  - Splunk default SSH rule: 6 failures in 60 seconds
  - Microsoft Sentinel: 10 failures in 5 minutes
  - We use 5 failures in 60 seconds (educational, easily observable)

WHAT REAL TOOLS DO:
  - Fail2ban (Linux): Uses same logic → automatically blocks the IP
  - Splunk ES: "Access - Brute Force Access Behavior Detected" correlation search
  - Microsoft Sentinel: "Potential Password Spray attack" analytic rule
  - CrowdStrike: Behavioral detection with ML threshold adjustment

FAILURE CASES (what breaks this detection):
--------------------------------------------
  1. LOW-AND-SLOW attack: Attacker tries 1 password every 10 minutes
     → Never triggers 60-second window. Solution: extend window to 24h
  2. DISTRIBUTED attack: 1000 IPs each try 1 password (botnet)
     → No single IP crosses threshold. Solution: username-based detection
  3. VPN/Proxy rotation: Attacker changes IP each attempt
     → Each IP looks innocent. Solution: username + ASN correlation
=============================================================================
"""

from collections import defaultdict
import datetime


# =============================================================================
# RULE CONFIGURATION
# These are the values SOC engineers "tune" based on their environment.
# EXPERIMENT: Change these and observe what happens to detection rate.
# =============================================================================

# How many failures from the SAME IP before we fire an alert?
# Lower = more sensitive (more false positives)
# Higher = less sensitive (more false negatives)
BRUTE_FORCE_THRESHOLD = 5

# How many seconds to look back when counting failures?
# This is the "sliding window" — we only care about RECENT events
BRUTE_FORCE_WINDOW_SECONDS = 60

# How many UNIQUE usernames tried = additional signal of wordlist attack?
# Real brute force tools cycle through common usernames (root, admin, test...)
WORDLIST_USERNAME_THRESHOLD = 3

# Severity escalation: if the attacker eventually SUCCEEDS → CRITICAL
SUCCESS_AFTER_FAILURE_THRESHOLD = 3  # If >3 failures before success = suspicious


class BruteForceDetector:
    """
    Stateful SSH brute force detection using sliding window analysis.

    STATEFULNESS EXPLAINED:
    This class remembers events over time (it has "memory").
    Unlike simple if/else rules, it tracks history.

    In real SIEMs, this state is stored in:
    - Splunk: statistical commands (streamstats, eventstats)
    - QRadar: flow data accumulation
    - Elasticsearch: bucket aggregations
    - We store it in Python dictionaries (equivalent concept)

    ARCHITECTURE:
    The class maintains two dictionaries:
    1. failure_log:  { ip_address → [list of failure timestamps] }
    2. success_log:  { ip_address → [list of success timestamps] }

    On each new event, we:
    1. Prune old entries outside the time window
    2. Add the new event
    3. Check if threshold is exceeded
    4. Return alert if yes, None if no
    """

    def __init__(self,
                 threshold=BRUTE_FORCE_THRESHOLD,
                 window_seconds=BRUTE_FORCE_WINDOW_SECONDS):
        """
        Initialize the detector with configurable thresholds.

        TEACHING POINT: Making thresholds configurable (not hardcoded)
        is critical in SOC tools. Every environment is different.
        A bank SSH server vs a developer's test server have different
        "normal" behavior baselines.
        """
        self.threshold = threshold
        self.window_seconds = window_seconds

        # failure_log: tracks timestamps of each failure per IP
        # defaultdict(list) auto-creates an empty list for new IPs
        self.failure_log = defaultdict(list)

        # username_log: tracks WHICH usernames each IP tried
        # Used for wordlist attack detection
        self.username_log = defaultdict(set)

        # success_log: tracks successful logins per IP
        # For detecting "success AFTER many failures" = attacker got in!
        self.success_log = defaultdict(list)

        # Alert deduplication: track which IPs we've already alerted on
        # Without this, we'd fire 1000 alerts for 1000 failures from same IP
        self.alerted_ips = set()

        # Statistics for post-analysis
        self.total_events_processed = 0
        self.total_alerts_fired = 0

    def _parse_timestamp(self, timestamp_str):
        """
        Convert log timestamp string to a datetime object.

        WHY WE NEED THIS:
        Log timestamps are strings ("May 30 02:14:37").
        To compare "is this event within the last 60 seconds?",
        we need actual datetime objects that support math (subtraction).

        datetime1 - datetime2 = timedelta (a duration)
        We can then check: timedelta.seconds < 60
        """
        # Add current year (syslog format omits year — a known limitation)
        # In production, you'd track year transitions carefully
        current_year = datetime.datetime.now().year
        full_timestamp = f"{current_year} {timestamp_str}"

        try:
            return datetime.datetime.strptime(full_timestamp, "%Y %b %d %H:%M:%S")
        except ValueError:
            # Fallback: return current time if parsing fails
            # SOC TIP: Never let a parse error stop your detection pipeline
            return datetime.datetime.now()

    def _prune_old_events(self, ip_address, reference_time):
        """
        Remove events older than the time window for a given IP.

        This implements the "sliding window" — we only keep events
        that are recent enough to be relevant.

        VISUALIZATION:
        Time →
        [old events] [window_start ←───60 seconds───→ now]
           pruned           only these events count

        Without pruning:
        - Memory grows forever (production systems would crash)
        - Counts would include ancient failures from weeks ago
        """
        window_start = reference_time - datetime.timedelta(seconds=self.window_seconds)

        # Keep only timestamps that are >= window_start
        self.failure_log[ip_address] = [
            ts for ts in self.failure_log[ip_address]
            if ts >= window_start
        ]

    def analyze_event(self, event):
        """
        Process a single parsed log event and check if it triggers brute force rule.

        This is called once per event as logs stream in.
        In a real SIEM, this runs in real-time (streaming) or batch (every N seconds).

        Returns:
            dict: Alert object if rule triggers, None otherwise

        DETECTION FLOW:
        event → Is it a failed login? → Yes → Add to history
                                              → Count recent failures for this IP
                                              → Count > threshold? → Fire alert
                                      → No  → Is it a success? → Check if suspicious
        """
        self.total_events_processed += 1
        event_type = event.get("event_type")
        source_ip = event.get("source_ip", "")

        # ── HANDLE FAILED LOGIN ──────────────────────────────────────────────
        if event_type == "FAILED_LOGIN" and source_ip:

            event_time = self._parse_timestamp(event["timestamp"])

            # Prune stale events outside our window first
            self._prune_old_events(source_ip, event_time)

            # Record this failure
            self.failure_log[source_ip].append(event_time)

            # Track the username tried (wordlist detection)
            if "username" in event:
                self.username_log[source_ip].add(event["username"])

            # COUNT recent failures in window
            recent_failure_count = len(self.failure_log[source_ip])
            unique_usernames_tried = len(self.username_log[source_ip])

            # ── THRESHOLD CHECK ──────────────────────────────────────────────
            if recent_failure_count >= self.threshold:

                # Determine if this is a WORDLIST attack (multiple usernames)
                # vs TARGETED attack (one username, trying many passwords)
                is_wordlist_attack = unique_usernames_tried >= WORDLIST_USERNAME_THRESHOLD

                # Severity escalation logic:
                # Base: HIGH (brute force always serious)
                # Escalate to CRITICAL if also using a wordlist
                severity = "CRITICAL" if is_wordlist_attack else "HIGH"

                # Build the alert object
                # Note: We include enough context for the analyst to ACT immediately
                alert = {
                    "rule_name": "SSH_BRUTE_FORCE",
                    "severity": severity,
                    "source_ip": source_ip,
                    "failure_count": recent_failure_count,
                    "unique_usernames": list(self.username_log[source_ip]),
                    "unique_username_count": unique_usernames_tried,
                    "is_wordlist_attack": is_wordlist_attack,
                    "window_seconds": self.window_seconds,
                    "threshold": self.threshold,
                    "detection_timestamp": event_time.strftime("%Y-%m-%d %H:%M:%S"),
                    "is_internal_ip": event.get("is_internal_ip", False),
                    "mitre_tactic": "Credential Access",
                    "mitre_technique": "T1110.001 - Brute Force: Password Guessing",
                    "recommended_action": (
                        f"Block IP {source_ip} at firewall. "
                        f"Check if any account was compromised. "
                        f"Review auth logs for success after failure."
                    ),
                    # Was this a repeat alert for same IP? (dedup tracking)
                    "is_repeat_alert": source_ip in self.alerted_ips,
                }

                # Track that we've alerted on this IP
                self.alerted_ips.add(source_ip)
                self.total_alerts_fired += 1

                return alert

        # ── HANDLE SUCCESSFUL LOGIN ──────────────────────────────────────────
        # KEY DETECTION: Success AFTER many failures = attacker got in!
        elif event_type == "SUCCESSFUL_LOGIN" and source_ip:

            event_time = self._parse_timestamp(event["timestamp"])
            prior_failures = len(self.failure_log.get(source_ip, []))

            if prior_failures >= SUCCESS_AFTER_FAILURE_THRESHOLD:
                # This is a CRITICAL incident: brute force succeeded
                self.total_alerts_fired += 1
                return {
                    "rule_name": "BRUTE_FORCE_SUCCESS",
                    "severity": "CRITICAL",
                    "source_ip": source_ip,
                    "prior_failures": prior_failures,
                    "successful_username": event.get("username", "unknown"),
                    "detection_timestamp": event_time.strftime("%Y-%m-%d %H:%M:%S"),
                    "is_internal_ip": event.get("is_internal_ip", False),
                    "mitre_tactic": "Initial Access",
                    "mitre_technique": "T1078 - Valid Accounts (obtained via brute force)",
                    "recommended_action": (
                        f"IMMEDIATE ACTION: Lock account '{event.get('username')}'. "
                        f"Block IP {source_ip}. "
                        f"Assume host is compromised. Begin IR process."
                    ),
                }

        # No alert — this event is normal
        return None

    def get_statistics(self):
        """
        Return detector health statistics.

        SOC CONTEXT: Detection systems need to prove they're working.
        This is called "detector telemetry" — metrics that show:
        - How many events were processed?
        - How many alerts fired?
        - Alert rate (alerts/events) — if 100%, something is wrong
        """
        return {
            "total_events_processed": self.total_events_processed,
            "total_alerts_fired": self.total_alerts_fired,
            "tracked_ips": len(self.failure_log),
            "alerted_ips": list(self.alerted_ips),
            "alert_rate_pct": round(
                (self.total_alerts_fired / max(self.total_events_processed, 1)) * 100, 2
            )
        }
