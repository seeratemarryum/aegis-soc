"""
=============================================================================
SOC ANALYST TRAINING — PHASE 2: PORT SCAN DETECTION RULE
=============================================================================

CONCEPT: What is Port Scanning?
---------------------------------
Before attacking a server, hackers ALWAYS run reconnaissance.
The most common recon technique is port scanning — probing which
network services (ports) are open on a target machine.

  PORT 22  = SSH (remote shell)
  PORT 80  = HTTP (web server)
  PORT 443 = HTTPS (secure web)
  PORT 3306 = MySQL database
  PORT 3389 = RDP (Windows remote desktop)

THE ATTACKER'S WORKFLOW:
  1. Scan target → find open ports (which services are running?)
  2. Look up vulnerabilities for those services
  3. Exploit the vulnerable service
  4. Gain access

What we see in SSH logs during a scan:
  - Rapid "Connection closed" events from same IP
  - These happen in milliseconds (automated, not human)
  - No successful logins — just open/close probing

TOOL USED BY ATTACKERS: nmap
  nmap -sS 192.168.1.1 (SYN scan — most common)
  This sends a connection "knock" and records which ports respond.

DETECTION LOGIC:
-----------------
PSEUDOCODE:
  For each new CONNECTION_CLOSED event:
      ip = event.source_ip
      window_start = now - 10 seconds

      recent_closes = count of closes from ip since window_start

      if recent_closes >= THRESHOLD:
          fire_alert("PORT_SCAN", ip, recent_closes)

WHY SHORTER WINDOW THAN BRUTE FORCE?
  Port scans are FASTER than brute force:
  - nmap default: 1000 ports in ~10 seconds
  - Brute force: 1 attempt per 0.5-3 seconds (slower)
  So we use a 10-second window for scan detection vs 60-second for brute force.

LIMITATIONS OF THIS APPROACH:
  We're detecting port scans based on SSH log "connection closed" events.
  In a real SOC, you'd use FIREWALL or NETFLOW logs for this
  (because port scans hit many ports, not just SSH port 22).
  We're simplifying for the purposes of teaching with what we have.
=============================================================================
"""

from collections import defaultdict
import datetime


# =============================================================================
# RULE CONFIGURATION — tune these and observe the difference
# =============================================================================

# How many rapid connection closes trigger a scan alert?
PORT_SCAN_CONNECTION_THRESHOLD = 5

# How tight is the time window (seconds)?
# Port scans are fast — nmap can scan 1000 ports in 10 seconds
PORT_SCAN_WINDOW_SECONDS = 15

# After a scan, if the same IP later appears in brute force → ESCALATE
# This correlates two separate events into one attack timeline
ESCALATE_IF_PRIOR_SCAN = True


class PortScanDetector:
    """
    Detects rapid connection probing behavior from SSH logs.

    TEACHING NOTE ON DETECTION TYPES:
    There are two families of detection:

    1. SIGNATURE-BASED:  "Does this event EXACTLY match a known bad pattern?"
       → Example: "If log contains 'exploit attempt', alert"
       → Pros: Low false positives, fast
       → Cons: Misses NEW attack patterns (zero-days)

    2. ANOMALY-BASED:   "Does this behavior DEVIATE from normal?"
       → Example: "This IP opened 50 connections in 5 seconds — unusual"
       → Pros: Catches new attacks
       → Cons: More false positives, needs baseline

    This detector is ANOMALY-BASED: rapid connections deviate from normal
    behavior, regardless of whether we've "seen this attack before."
    Phase 4 extends this with ML-based anomaly detection.
    """

    def __init__(self,
                 threshold=PORT_SCAN_CONNECTION_THRESHOLD,
                 window_seconds=PORT_SCAN_WINDOW_SECONDS):

        self.threshold = threshold
        self.window_seconds = window_seconds

        # connection_log tracks timestamps of connection closes per IP
        self.connection_log = defaultdict(list)

        # Track IPs that have been flagged for scanning
        # This feeds into the correlation engine later
        self.known_scanners = set()

        self.total_events_processed = 0
        self.total_alerts_fired = 0

    def _parse_timestamp(self, timestamp_str):
        """Convert syslog timestamp to datetime (same as brute force detector)."""
        current_year = datetime.datetime.now().year
        full_timestamp = f"{current_year} {timestamp_str}"
        try:
            return datetime.datetime.strptime(full_timestamp, "%Y %b %d %H:%M:%S")
        except ValueError:
            return datetime.datetime.now()

    def _prune_old_events(self, ip_address, reference_time):
        """Remove events outside the sliding window for this IP."""
        window_start = reference_time - datetime.timedelta(seconds=self.window_seconds)
        self.connection_log[ip_address] = [
            ts for ts in self.connection_log[ip_address]
            if ts >= window_start
        ]

    def analyze_event(self, event):
        """
        Check a single event for port scan indicators.

        WHAT WE LOOK FOR:
        - Rapid CONNECTION_CLOSED events from the same IP
        - These appear when an automated tool opens connections
          and immediately closes them (characteristic of scanning tools)

        What a legitimate user's connection looks like:
          [connect] → [login prompt] → [wait for user input ~5-30s] → [disconnect]

        What a scanner looks like:
          [connect] → [immediate close] → [connect] → [close] (milliseconds apart)
        """
        self.total_events_processed += 1
        event_type = event.get("event_type")
        source_ip = event.get("source_ip", "")

        if event_type == "CONNECTION_CLOSED" and source_ip:

            event_time = self._parse_timestamp(event["timestamp"])

            # Prune old events outside our window
            self._prune_old_events(source_ip, event_time)

            # Record this connection close
            self.connection_log[source_ip].append(event_time)

            # Count how many rapid closes we've seen from this IP
            rapid_close_count = len(self.connection_log[source_ip])

            # ── THRESHOLD CHECK ──────────────────────────────────────────────
            if rapid_close_count >= self.threshold:

                # Mark as known scanner for correlation with brute force
                self.known_scanners.add(source_ip)

                # Severity: scanning alone = MEDIUM
                # But if internal IP scanning = HIGH (insider threat or compromised machine)
                severity = "HIGH" if event.get("is_internal_ip") else "MEDIUM"

                self.total_alerts_fired += 1

                return {
                    "rule_name": "PORT_SCAN_DETECTED",
                    "severity": severity,
                    "source_ip": source_ip,
                    "rapid_connection_count": rapid_close_count,
                    "window_seconds": self.window_seconds,
                    "threshold": self.threshold,
                    "detection_timestamp": event_time.strftime("%Y-%m-%d %H:%M:%S"),
                    "is_internal_ip": event.get("is_internal_ip", False),
                    "mitre_tactic": "Discovery",
                    "mitre_technique": "T1046 - Network Service Discovery",
                    "recommended_action": (
                        f"Investigate IP {source_ip} for reconnaissance. "
                        f"Check firewall logs for wider port sweep. "
                        f"Likely precursor to a targeted attack — watch for follow-up."
                    ),
                    # Cross-reference: was this IP already flagged for brute force?
                    "is_known_attacker": source_ip in self.known_scanners,
                }

        return None

    def is_known_scanner(self, ip_address):
        """
        Check if an IP has been flagged as a scanner.
        Used by the correlation engine to escalate brute force alerts
        when the same IP previously scanned.

        SOC CONCEPT: This is basic CORRELATION — linking two separate
        events into a single attack timeline. Phase 5 builds a full
        correlation engine. Here we do a simple version.
        """
        return ip_address in self.known_scanners

    def get_statistics(self):
        return {
            "total_events_processed": self.total_events_processed,
            "total_alerts_fired": self.total_alerts_fired,
            "tracked_ips": len(self.connection_log),
            "known_scanners": list(self.known_scanners),
        }
