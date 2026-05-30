"""
=============================================================================
SOC ANALYST TRAINING — PHASE 2: ALERT MANAGER
=============================================================================

CONCEPT: What is Alert Management?
-------------------------------------
Raw detection rules fire alerts. But firing 1000 copies of the same alert
every second is USELESS — it creates "alert fatigue."

Alert fatigue is one of the #1 problems in real SOCs:
  - Teams get 500+ alerts per day
  - 90% are false positives or duplicates
  - Analysts stop caring → miss the real incident

The alert manager solves this with:
  1. DEDUPLICATION — don't fire same alert twice for same IP within cooldown
  2. PRIORITIZATION — sort alerts so HIGH severity appears first
  3. CORRELATION — link related alerts (scan + brute force = same attacker)
  4. PERSISTENCE — save alerts to disk so they survive system restarts

REAL SOC EQUIVALENT:
  - Splunk: "Notable Events" with deduplication policies
  - ServiceNow: Incident deduplication and grouping
  - PagerDuty: Alert suppression and grouping
  - QRadar: "Offenses" (groups related alerts into one case)
=============================================================================
"""

import json
import os
import datetime
from collections import defaultdict


# =============================================================================
# ALERT DEDUPLICATION SETTINGS
# =============================================================================

# Don't re-fire the same rule for the same IP within this many seconds
# Without this: 75 brute force attempts = 71 duplicate alerts (after first fires at attempt 5)
DEDUP_COOLDOWN_SECONDS = 300   # 5 minutes

# Alert severity ordering (for sorting and display)
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


class AlertManager:
    """
    Centralized alert collection, deduplication, and reporting.

    ARCHITECTURE CONCEPT:
    Detection rules are "producers" — they generate raw alerts.
    The Alert Manager is the "consumer" — it decides what to do with them.

    This producer/consumer pattern appears in:
    - Kafka (message queuing in enterprise SOC)
    - Splunk alert actions
    - SOAR playbook triggers (Phase 6)

    STATE IT MAINTAINS:
    - alert_store: list of ALL alerts (full history)
    - dedup_tracker: { (rule_name, source_ip) → last_alert_time }
    - correlation_map: { source_ip → list of rule_names fired }
    """

    def __init__(self, output_file="alerts.json"):
        self.alert_store = []
        self.dedup_tracker = {}           # key: (rule_name, ip) → timestamp
        self.correlation_map = defaultdict(list)  # ip → [rule names fired]
        self.output_file = output_file
        self.alert_counter = 0            # sequential ID for each alert

    def _is_duplicate(self, rule_name, source_ip, detection_timestamp):
        """
        Check if this alert is a duplicate within the cooldown window.

        EXAMPLE WITHOUT DEDUP:
        Attacker tries 75 passwords. Rule fires at attempt #5.
        Attempts 6-75 also trigger the threshold → 70 MORE ALERTS.
        Same IP, same rule, same attacker = alert flood.

        WITH DEDUP (5-min cooldown):
        Only fires once. Next alert from same IP+rule only after 5 min.
        Analyst gets 1 clear alert instead of 70 noisy ones.
        """
        dedup_key = (rule_name, source_ip)

        if dedup_key in self.dedup_tracker:
            last_alert_time = self.dedup_tracker[dedup_key]

            # Parse detection timestamp
            try:
                current_time = datetime.datetime.strptime(
                    detection_timestamp, "%Y-%m-%d %H:%M:%S"
                )
            except (ValueError, TypeError):
                current_time = datetime.datetime.now()

            time_since_last = (current_time - last_alert_time).total_seconds()

            if time_since_last < DEDUP_COOLDOWN_SECONDS:
                return True  # It's a duplicate — suppress it

        return False  # Not a duplicate — let it through

    def receive_alert(self, alert):
        """
        Receive an alert from a detection rule and process it.

        Steps:
        1. Deduplication check
        2. Assign unique ID and metadata
        3. Correlation check (has this IP triggered other rules?)
        4. Escalation (should severity be raised due to multiple rules?)
        5. Store the alert
        6. Return processed alert (or None if suppressed)
        """
        if alert is None:
            return None

        rule_name = alert.get("rule_name", "UNKNOWN")
        source_ip = alert.get("source_ip", "")
        detection_timestamp = alert.get("detection_timestamp",
                                        datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

        # ── STEP 1: Deduplication ────────────────────────────────────────────
        if self._is_duplicate(rule_name, source_ip, detection_timestamp):
            return None  # Suppressed — not a new unique alert

        # ── STEP 2: Assign unique ID and enrichment ──────────────────────────
        self.alert_counter += 1
        alert["alert_id"] = f"SOC-{self.alert_counter:05d}"
        alert["alert_received_at"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        alert["status"] = "OPEN"   # Lifecycle: OPEN → INVESTIGATING → CLOSED

        # ── STEP 3: Correlation — link this alert to prior alerts from same IP ──
        prior_rules = self.correlation_map[source_ip]

        if prior_rules:
            alert["correlated_with"] = prior_rules.copy()
            alert["is_correlated"] = True

            # ESCALATION: if this IP already triggered port scan AND now brute force
            # → we KNOW this is a multi-stage attack (recon → exploitation)
            if "PORT_SCAN_DETECTED" in prior_rules and rule_name == "SSH_BRUTE_FORCE":
                alert["severity"] = "CRITICAL"
                alert["escalation_reason"] = (
                    "ESCALATED: Same IP performed port scan BEFORE brute force. "
                    "This indicates a deliberate, targeted attack — not random scanning."
                )
                alert["mitre_tactic"] = "Reconnaissance then Credential Access (multi-stage)"
        else:
            alert["is_correlated"] = False
            alert["correlated_with"] = []

        # ── STEP 4: Record this rule fired for this IP ───────────────────────
        self.correlation_map[source_ip].append(rule_name)

        # ── STEP 5: Update dedup tracker ────────────────────────────────────
        try:
            last_time = datetime.datetime.strptime(detection_timestamp, "%Y-%m-%d %H:%M:%S")
        except (ValueError, TypeError):
            last_time = datetime.datetime.now()

        self.dedup_tracker[(rule_name, source_ip)] = last_time

        # ── STEP 6: Store ────────────────────────────────────────────────────
        self.alert_store.append(alert)

        return alert

    def get_alerts(self, severity_filter=None, status_filter=None):
        """
        Retrieve alerts with optional filtering.

        SOC USE CASE: Analysts filter alerts by:
        - Severity: "Show me only CRITICAL and HIGH"
        - Status: "Show me only OPEN alerts (not yet investigated)"
        - Rule: "Show me only brute force alerts"
        """
        alerts = self.alert_store.copy()

        if severity_filter:
            alerts = [a for a in alerts if a.get("severity") in severity_filter]

        if status_filter:
            alerts = [a for a in alerts if a.get("status") == status_filter]

        # Sort by severity (CRITICAL first) then by time
        alerts.sort(key=lambda a: SEVERITY_ORDER.get(a.get("severity", "INFO"), 99))

        return alerts

    def print_alert_console(self, alert):
        """
        Print a single alert in a formatted SOC console style.

        In real SOC tools, alerts display with:
        - Color coding (red=critical, orange=high)
        - Ticket number for tracking
        - One-click remediation actions
        We simulate this in plain text.
        """
        severity = alert.get("severity", "INFO")
        alert_id = alert.get("alert_id", "SOC-XXXXX")

        # Visual severity indicators (ASCII-safe for Windows)
        severity_banner = {
            "CRITICAL": "!!! CRITICAL !!!",
            "HIGH":     ">> HIGH",
            "MEDIUM":   "-- MEDIUM",
            "LOW":      "   LOW",
            "INFO":     "   INFO",
        }.get(severity, severity)

        print(f"\n  [{severity_banner}] Alert ID: {alert_id}")
        print(f"  Rule:        {alert.get('rule_name')}")
        print(f"  Source IP:   {alert.get('source_ip')}")
        print(f"  Time:        {alert.get('detection_timestamp')}")

        # Rule-specific details
        if alert.get("rule_name") == "SSH_BRUTE_FORCE":
            print(f"  Failures:    {alert.get('failure_count')} in {alert.get('window_seconds')}s window")
            print(f"  Usernames:   {', '.join(alert.get('unique_usernames', []))}")
            if alert.get("is_wordlist_attack"):
                print(f"  Attack Type: WORDLIST (multiple usernames tried)")

        elif alert.get("rule_name") == "PORT_SCAN_DETECTED":
            print(f"  Connections: {alert.get('rapid_connection_count')} rapid closes in {alert.get('window_seconds')}s")

        elif alert.get("rule_name") == "BRUTE_FORCE_SUCCESS":
            print(f"  *** ACCOUNT COMPROMISED: {alert.get('successful_username')} ***")
            print(f"  Prior failures before success: {alert.get('prior_failures')}")

        # Correlation notice
        if alert.get("is_correlated"):
            print(f"  Correlated:  YES — Prior alerts: {alert.get('correlated_with')}")

        if alert.get("escalation_reason"):
            print(f"  ESCALATION:  {alert.get('escalation_reason')}")

        print(f"  MITRE:       {alert.get('mitre_technique', 'N/A')}")
        print(f"  Action:      {alert.get('recommended_action', 'Investigate')}")
        print(f"  {'-'*58}")

    def save_alerts(self):
        """Persist all alerts to JSON file for dashboard and reporting."""
        output_path = os.path.join(os.path.dirname(__file__), self.output_file)
        with open(output_path, "w") as f:
            json.dump(self.alert_store, f, indent=2)
        print(f"\n[OK] {len(self.alert_store)} alerts saved to: {output_path}")
        return output_path

    def print_summary(self):
        """
        Print a shift-end summary report.
        This is what a Tier 1 analyst sends to Tier 2 at shift handoff.
        """
        print("\n" + "="*60)
        print("  ALERT MANAGER SUMMARY REPORT")
        print("="*60)

        total = len(self.alert_store)
        print(f"\n  Total Alerts Generated: {total}")

        if total == 0:
            print("  No alerts. All traffic appears normal.")
            return

        # Count by severity
        print("\n  By Severity:")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = sum(1 for a in self.alert_store if a.get("severity") == sev)
            if count:
                print(f"    {sev:<10}: {count}")

        # Count by rule
        print("\n  By Rule:")
        rule_counts = defaultdict(int)
        for a in self.alert_store:
            rule_counts[a.get("rule_name", "?")] += 1
        for rule, count in sorted(rule_counts.items(), key=lambda x: -x[1]):
            print(f"    {rule:<30}: {count}")

        # Correlated alerts (multi-stage attacks)
        correlated = [a for a in self.alert_store if a.get("is_correlated")]
        if correlated:
            print(f"\n  Multi-stage attacks detected: {len(correlated)}")
            for a in correlated:
                print(f"    -> {a['alert_id']}: {a['source_ip']} | {a['rule_name']}")

        print("\n" + "="*60)
