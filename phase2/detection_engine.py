"""
=============================================================================
SOC ANALYST TRAINING — PHASE 2: DETECTION ENGINE
=============================================================================

CONCEPT: What is a Detection Engine?
---------------------------------------
The detection engine is the ORCHESTRATOR — it loads rules, feeds events
through them, collects results, and hands off alerts.

Think of it like a factory assembly line:

  [Log Events] -> [Rule 1: Brute Force?] -----+
              -> [Rule 2: Port Scan?]    ----> [Alert Manager] -> [Output]
              -> [Rule 3: ...future...] -----+

WHY A SEPARATE ENGINE CLASS?
  Each rule only knows ONE thing (e.g., brute force logic).
  The engine knows which rules exist, runs them all, handles output.
  This is called "separation of concerns" — good software design.
  Adding a new rule = create the rule file + register it in the engine.
  No other code changes needed.

REAL SOC EQUIVALENT:
  Splunk: "Correlation Search" runs your SPL (detection language) rules
  QRadar: "Custom Rules Engine" (CRE) evaluates events against rule sets
  Microsoft Sentinel: KQL Analytics Rules
  We are building a simplified version of the same concept.

HOW TO RUN THIS FILE:
  python detection_engine.py
  It will auto-detect the Phase 1 parsed_events.json and run all rules.
=============================================================================
"""

import json
import os
import sys
import datetime

# ── Add Phase 1 to path so we can import the parser ──────────────────────────
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PHASE1_DIR = os.path.join(BASE_DIR, "phase1")
PHASE2_DIR = os.path.join(BASE_DIR, "phase2")
sys.path.insert(0, BASE_DIR)
sys.path.insert(0, PHASE1_DIR)
sys.path.insert(0, PHASE2_DIR)

# ── Import our detection modules ──────────────────────────────────────────────
from rules.brute_force import BruteForceDetector
from rules.port_scan import PortScanDetector
from alert_manager import AlertManager


class DetectionEngine:
    """
    Orchestrates multiple detection rules over a stream of parsed log events.

    PROCESSING MODEL:
    We process events SEQUENTIALLY — one by one, in order.
    This simulates REAL-TIME streaming detection (events arrive one at a time).

    The alternative is BATCH processing (look at all events at once).
    Real SIEMs do both:
    - Real-time: low-latency alerts (seconds after event)
    - Batch: daily correlation reports (complex multi-day analysis)

    We use sequential processing here so rules maintain proper time-ordering.
    """

    def __init__(self):
        # Initialize all detection rules
        # TEACHING MOMENT: Each detector is STATEFUL — it remembers history.
        # This is why we instantiate them ONCE and reuse them across all events.
        self.brute_force_detector = BruteForceDetector(
            threshold=5,           # EXPERIMENT: change to 2 or 20
            window_seconds=60      # EXPERIMENT: change to 10 or 300
        )
        self.port_scan_detector = PortScanDetector(
            threshold=5,           # EXPERIMENT: change to 3 or 10
            window_seconds=15
        )

        # Alert manager collects outputs from all rules
        self.alert_manager = AlertManager(output_file="alerts.json")

        # Keep a local list of all alerts for this run
        self.all_alerts = []

        # Engine statistics
        self.events_processed = 0
        self.start_time = None

    def run(self, events):
        """
        Run all detection rules over a list of parsed events.

        PROCESSING PIPELINE:
        For each event:
          1. Feed to brute force detector → collect alert if any
          2. Feed to port scan detector → collect alert if any
          3. Send any alerts to alert manager (dedup + correlation)
          4. Print alert to console immediately (real-time feel)

        This is called "streaming detection" — we process each event
        as if it's arriving in real time, not all at once.
        """
        self.start_time = datetime.datetime.now()

        print("\n" + "="*60)
        print("  SOC ANALYST TRAINING — DETECTION ENGINE")
        print("  Phase 2: Rule-Based Detection")
        print("="*60)
        print(f"\n[+] Processing {len(events)} events through detection rules...")
        print(f"    Rules loaded: BruteForceDetector, PortScanDetector")
        print(f"    Brute Force threshold: >=5 failures in 60s window")
        print(f"    Port Scan threshold:   >=5 rapid closes in 15s window")
        print(f"\n{'-'*60}")
        print(f"  LIVE ALERT STREAM (alerts appear as rules trigger):")
        print(f"{'-'*60}")

        for event in events:
            self.events_processed += 1

            # -- Run each rule against this event ----------------------------────

            # Rule 1: Brute Force Detection
            bf_alert = self.brute_force_detector.analyze_event(event)
            if bf_alert:
                processed = self.alert_manager.receive_alert(bf_alert)
                if processed:  # Not suppressed by dedup
                    self.all_alerts.append(processed)
                    self.alert_manager.print_alert_console(processed)

            # Rule 2: Port Scan Detection
            ps_alert = self.port_scan_detector.analyze_event(event)
            if ps_alert:
                processed = self.alert_manager.receive_alert(ps_alert)
                if processed:
                    self.all_alerts.append(processed)
                    self.alert_manager.print_alert_console(processed)

        # ── Post-processing ──────────────────────────────────────────────────
        self._print_engine_report()
        self.alert_manager.print_summary()
        self.alert_manager.save_alerts()

        return self.all_alerts

    def _print_engine_report(self):
        """Print engine performance statistics."""
        elapsed = (datetime.datetime.now() - self.start_time).total_seconds()

        print("\n" + "="*60)
        print("  ENGINE PERFORMANCE REPORT")
        print("="*60)
        print(f"\n  Events processed:   {self.events_processed}")
        print(f"  Alerts generated:   {len(self.all_alerts)}")
        print(f"  Processing time:    {elapsed:.3f} seconds")

        if elapsed > 0:
            eps = self.events_processed / elapsed
            print(f"  Throughput:         {eps:,.0f} events/second")
            print(f"\n  [CONTEXT] Enterprise SIEMs handle 100,000-1M events/sec")
            print(f"            We processed {eps:.0f} — good for learning!")

        # Show per-rule stats
        print(f"\n  Per-Rule Statistics:")
        bf_stats = self.brute_force_detector.get_statistics()
        ps_stats = self.port_scan_detector.get_statistics()

        print(f"    BruteForce:  {bf_stats['total_events_processed']} events, "
              f"{bf_stats['total_alerts_fired']} alerts fired, "
              f"alert rate: {bf_stats['alert_rate_pct']}%")

        print(f"    PortScan:    {ps_stats['total_events_processed']} events, "
              f"{ps_stats['total_alerts_fired']} alerts fired")

        if bf_stats['alerted_ips']:
            print(f"\n  Flagged IPs (Brute Force):")
            for ip in bf_stats['alerted_ips']:
                print(f"    -> {ip}")

        if ps_stats['known_scanners']:
            print(f"\n  Flagged IPs (Port Scan):")
            for ip in ps_stats['known_scanners']:
                print(f"    -> {ip}")


# =============================================================================
# ENTRY POINT — load Phase 1 data and run detection
# =============================================================================

def main():
    """
    Main execution: load parsed log events from Phase 1 and run detection.

    DATA FLOW:
    phase1/parsed_events.json → DetectionEngine.run() → phase2/alerts.json

    TEACHING NOTE: In production, this wouldn't read from a file.
    Events would stream in from:
    - Kafka topic (real-time message queue)
    - Elasticsearch query (batch from index)
    - Syslog UDP listener (direct log ingestion)

    File-based processing is fine for learning the detection logic.
    """

    # ── Locate the parsed events file from Phase 1 ──────────────────────────
    events_file = os.path.join(PHASE1_DIR, "parsed_events.json")

    if not os.path.exists(events_file):
        print("\n[ERROR] Phase 1 data not found!")
        print(f"  Expected: {events_file}")
        print("  Run Phase 1 first:")
        print("    python phase1/log_generator.py")
        print("    python phase1/log_parser.py")
        return

    # ── Load events ──────────────────────────────────────────────────────────
    print(f"\n[+] Loading parsed events from Phase 1...")
    with open(events_file, "r") as f:
        events = json.load(f)
    print(f"[OK] Loaded {len(events)} events")

    # ── Sort events by timestamp (critical for sliding window accuracy) ──────
    # Real SIEM systems enforce strict time ordering for detection accuracy.
    # Out-of-order events cause incorrect window calculations.
    def sort_key(e):
        ts = e.get("timestamp", "Jan  1 00:00:00")
        try:
            year = datetime.datetime.now().year
            return datetime.datetime.strptime(f"{year} {ts}", "%Y %b %d %H:%M:%S")
        except ValueError:
            return datetime.datetime.min

    events_sorted = sorted(events, key=sort_key)
    print(f"[OK] Events sorted chronologically for accurate detection")

    # ── Run the detection engine ─────────────────────────────────────────────
    engine = DetectionEngine()
    alerts = engine.run(events_sorted)

    # ── Final guidance ───────────────────────────────────────────────────────
    print("\n" + "="*60)
    print("  EXPERIMENTS FOR PHASE 2")
    print("="*60)
    print("""
  1. TUNE BRUTE FORCE THRESHOLD:
     In DetectionEngine.__init__(), change:
       BruteForceDetector(threshold=5)  -->  threshold=20
     Re-run. Does the alert still fire? At what count?
     This teaches you about FALSE NEGATIVES (missed attacks).

  2. MAKE THRESHOLD TOO LOW:
     Change threshold=5 to threshold=2
     Re-run. Do legitimate users now get flagged?
     This teaches you about FALSE POSITIVES (alert fatigue).

  3. OBSERVE CORRELATION:
     The port scan fires FIRST (earlier timestamps).
     Then brute force fires.
     See how the brute force alert shows "Correlated with: PORT_SCAN_DETECTED"?
     That's multi-stage attack detection.

  4. BREAK THE DETECTION (important!):
     In phase1/log_generator.py, change the brute force:
       offset = i * random.uniform(0.5, 3.0)
     to:
       offset = i * random.uniform(60, 120)  # 1-2 MINUTES between attempts
     Re-run both phases. Does brute force get detected?
     This is the LOW-AND-SLOW attack technique!

  5. OPEN alerts.json and read the structure.
     This is the input to Phase 5 (AI explanation engine).
    """)


if __name__ == "__main__":
    main()
