"""
=============================================================================
SOC ANALYST TRAINING -- PHASE 7: DASHBOARD SERVER
=============================================================================
Flask backend serving live data from all previous phases.
Run: python phase7/dashboard_server.py
Then open: http://localhost:5000
=============================================================================
"""

import json
import os
import sys
import datetime
from flask import Flask, jsonify, render_template, Response
import threading
import time

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Load pipeline modules from prior phases
sys.path.insert(0, os.path.join(BASE_DIR, "phase1"))
sys.path.insert(0, os.path.join(BASE_DIR, "phase2"))
sys.path.insert(0, os.path.join(BASE_DIR, "phase4"))
sys.path.insert(0, os.path.join(BASE_DIR, "phase5"))
sys.path.insert(0, os.path.join(BASE_DIR, "phase6"))

from log_parser import parse_log_line
from rules.brute_force import BruteForceDetector
from rules.port_scan import PortScanDetector
from alert_manager import AlertManager
from anomaly_detector import SOCAnomalyDetector
from playbook_engine import PlaybookEngine
from report_generator import generate_incident_report

# Paths to all phase data files
DATA_PATHS = {
    "alerts":       os.path.join(BASE_DIR, "phase2", "alerts.json"),
    "parsed":       os.path.join(BASE_DIR, "phase1", "parsed_events.json"),
    "ml_results":   os.path.join(BASE_DIR, "phase4", "ml_pipeline_results.json"),
    "report":       os.path.join(BASE_DIR, "phase5", "incident_report.json"),
    "incidents":    os.path.join(BASE_DIR, "phase6", "incidents.json"),
    "blocked_ips":  os.path.join(BASE_DIR, "phase6", "blocked_ips.json"),
    "audit_log":    os.path.join(BASE_DIR, "phase6", "soar_audit.log"),
    "soar_results": os.path.join(BASE_DIR, "phase6", "soar_results.json"),
}

class LiveSOCSimulator(threading.Thread):
    def __init__(self):
        super().__init__()
        self.daemon = True
        self.running = True
        self.base_dir = BASE_DIR
        
        # Reset data files on startup for a clean live demo starting point
        self.parsed_events = []
        self.alerts = []
        self.incidents = []
        self.blocked_ips = {}
        self.soar_results = []
        
        # Reset log file
        log_file_path = os.path.join(self.base_dir, "phase1", "sample_auth.log")
        try:
            with open(log_file_path, "w", encoding="utf-8") as f:
                f.write("")
        except Exception:
            pass
            
        # Write clean baseline JSON files
        self.save_json_atomic(DATA_PATHS["parsed"], self.parsed_events)
        self.save_json_atomic(DATA_PATHS["alerts"], self.alerts)
        self.save_json_atomic(DATA_PATHS["incidents"], self.incidents)
        self.save_json_atomic(DATA_PATHS["blocked_ips"], self.blocked_ips)
        self.save_json_atomic(DATA_PATHS["soar_results"], self.soar_results)
        
        # Clear SOAR audit log
        try:
            with open(DATA_PATHS["audit_log"], "w", encoding="utf-8") as f:
                f.write("")
        except Exception:
            pass
            
        # Initialize an empty incident report
        self.save_json_atomic(DATA_PATHS["report"], {"available": False})
        
        # Initialize detectors and engines
        self.bf_detector = BruteForceDetector(threshold=5, window_seconds=60)
        self.ps_detector = PortScanDetector(threshold=5, window_seconds=15)
        self.alert_manager = AlertManager(output_file=DATA_PATHS["alerts"])
        self.ml_detector = SOCAnomalyDetector(contamination=0.08, n_estimators=100)
        self.playbook_engine = PlaybookEngine(dry_run=True, require_approval=False, analyst="AEGIS-AUTO")
        
        # Simulation state
        self.tick_count = 0
        self.current_ip_index = 0
        self.suspicious_ips = ["185.220.101.42", "45.142.212.100", "103.75.190.200", "198.51.100.73", "203.0.113.88"]
        self.normal_ips = ["10.0.0.5", "10.0.0.12", "192.168.1.50"]
        self.valid_users = ["alice", "bob", "sysadmin", "ubuntu"]
        self.attack_users = ["root", "admin", "test", "guest", "postgres"]
        
    def save_json_atomic(self, path, data):
        """Save JSON data to path safely using a temporary file."""
        temp_path = f"{path}.tmp"
        try:
            with open(temp_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            os.replace(temp_path, path)
        except Exception as e:
            print(f"[LiveSOCSimulator] Error writing to {path}: {e}")

    def add_log_line(self, log_line):
        """Append log line to sample_auth.log."""
        log_file_path = os.path.join(self.base_dir, "phase1", "sample_auth.log")
        try:
            with open(log_file_path, "a", encoding="utf-8") as f:
                f.write(log_line + "\n")
        except Exception as e:
            print(f"[LiveSOCSimulator] Error writing log file: {e}")

    def run(self):
        import random
        print("[LiveSOCSimulator] Live log simulation thread running...")
        while self.running:
            try:
                time.sleep(3.0) # Tick every 3 seconds
                self.tick_count += 1
                
                state_cycle = self.tick_count % 30
                attacker_ip = self.suspicious_ips[self.current_ip_index % len(self.suspicious_ips)]
                
                new_logs = []
                timestamp = datetime.datetime.now().strftime("%b %d %H:%M:%S")
                pid = random.randint(10000, 65535)
                port = random.randint(1024, 65535)
                
                # Check for active blocks on attacker IP
                self.blocked_ips = safe_load_json(DATA_PATHS["blocked_ips"], {})
                is_attacker_blocked = attacker_ip in self.blocked_ips
                
                # State 0: Normal Traffic (ticks 1-10, 21-30)
                if state_cycle <= 10 or state_cycle >= 21:
                    user = random.choice(self.valid_users)
                    ip = random.choice(self.normal_ips)
                    if random.random() < 0.95:
                        new_logs.append(f"{timestamp} prod-webserver-01 sshd[{pid}]: Accepted password for {user} from {ip} port {port} ssh2")
                    else:
                        new_logs.append(f"{timestamp} prod-webserver-01 sshd[{pid}]: Failed password for {user} from {ip} port {port} ssh2")
                        
                # State 1: Port Scan Reconnaissance (ticks 11-12)
                elif state_cycle in (11, 12):
                    if is_attacker_blocked:
                        new_logs.append(f"{timestamp} prod-webserver-01 sshd[{pid}]: Connection closed by {attacker_ip} [FIREWALL_BLOCKED]")
                    else:
                        # Attacker probes ports
                        for _ in range(3):
                            scan_pid = random.randint(10000, 65535)
                            new_logs.append(f"{timestamp} prod-webserver-01 sshd[{scan_pid}]: Connection closed by {attacker_ip}")
                            
                # State 2: Brute Force Attack (ticks 13-17)
                elif state_cycle in (13, 14, 15, 16, 17):
                    if is_attacker_blocked:
                        new_logs.append(f"{timestamp} prod-webserver-01 sshd[{pid}]: Connection closed by {attacker_ip} [FIREWALL_BLOCKED]")
                    else:
                        # Generate failed login attempts
                        for _ in range(2):
                            bf_pid = random.randint(10000, 65535)
                            bf_port = random.randint(1024, 65535)
                            user = random.choice(self.attack_users)
                            new_logs.append(f"{timestamp} prod-webserver-01 sshd[{bf_pid}]: Failed password for {user} from {attacker_ip} port {bf_port} ssh2")
                            
                # State 3: Compromise Success (tick 18)
                elif state_cycle == 18:
                    if is_attacker_blocked:
                        new_logs.append(f"{timestamp} prod-webserver-01 sshd[{pid}]: Connection closed by {attacker_ip} [FIREWALL_BLOCKED]")
                    else:
                        # Accepted password (compromise)
                        user = random.choice(self.attack_users)
                        new_logs.append(f"{timestamp} prod-webserver-01 sshd[{pid}]: Accepted password for {user} from {attacker_ip} port {port} ssh2")
                        
                # State 4: Attacker Blocked Post-compromise (ticks 19-20)
                elif state_cycle in (19, 20):
                    new_logs.append(f"{timestamp} prod-webserver-01 sshd[{pid}]: Connection closed by {attacker_ip} [FIREWALL_BLOCKED]")
                
                # Reset cycle
                if state_cycle == 0 and self.tick_count > 0:
                    self.current_ip_index += 1
                    
                # Process generated logs
                for log_line in new_logs:
                    self.add_log_line(log_line)
                    
                    event = parse_log_line(log_line)
                    if not event:
                        continue
                    
                    event["line_number"] = len(self.parsed_events) + 1
                    self.parsed_events.append(event)
                    
                    bf_alert = self.bf_detector.analyze_event(event)
                    ps_alert = self.ps_detector.analyze_event(event)
                    
                    for raw_alert in (bf_alert, ps_alert):
                        if raw_alert:
                            processed_alert = self.alert_manager.receive_alert(raw_alert)
                            if processed_alert:
                                self.alerts.append(processed_alert)
                                
                                # Run SOAR response
                                playbook_res = self.playbook_engine.run_playbook(processed_alert)
                                self.soar_results.append(playbook_res.to_dict())
                                self.save_json_atomic(DATA_PATHS["soar_results"], make_serializable(self.soar_results))
                                
                                # Read back incidents & blocks updated by SOAR
                                self.blocked_ips = safe_load_json(DATA_PATHS["blocked_ips"], {})
                                self.incidents = safe_load_json(DATA_PATHS["incidents"], [])
                
                # Capping rolling sizes
                self.parsed_events = self.parsed_events[-100:]
                self.alerts = self.alerts[-15:]
                self.incidents = self.incidents[-15:]
                self.soar_results = self.soar_results[-15:]
                
                # Update ML Anomaly detection
                if len(self.parsed_events) >= 4:
                    try:
                        self.ml_detector.train(self.parsed_events)
                        ml_predictions = self.ml_detector.score_events(self.parsed_events)
                        ml_data = {
                            "ml_results": ml_predictions,
                            "config": {
                                "contamination": self.ml_detector.contamination,
                                "n_estimators": self.ml_detector.n_estimators
                            }
                        }
                        self.save_json_atomic(DATA_PATHS["ml_results"], make_serializable(ml_data))
                    except Exception:
                        pass
                
                # Update Incident Report if a breach occurred
                breach_alerts = [a for a in self.alerts if a.get("rule_name") == "BRUTE_FORCE_SUCCESS"]
                if breach_alerts:
                    ml_data = safe_load_json(DATA_PATHS["ml_results"], {})
                    ml_results = ml_data.get("ml_results", [])
                    report = generate_incident_report(
                        alerts=self.alerts,
                        ml_results=ml_results,
                        analyst_name="Aegis Incident Response Engine"
                    )
                    self.save_json_atomic(DATA_PATHS["report"], make_serializable(report))
                
                # Write state files
                self.save_json_atomic(DATA_PATHS["parsed"], make_serializable(self.parsed_events))
                self.save_json_atomic(DATA_PATHS["alerts"], make_serializable(self.alerts))
                
            except Exception as e:
                print(f"[LiveSOCSimulator] Simulation error: {e}")


app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["JSON_SORT_KEYS"] = False


def safe_load_json(path, default=None):
    if default is None:
        default = {}
    if not os.path.exists(path):
        return default
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def make_serializable(obj):
    if isinstance(obj, dict):
        return {k: make_serializable(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [make_serializable(i) for i in obj]
    elif hasattr(obj, "item"):
        return obj.item()
    elif isinstance(obj, bool):
        return bool(obj)
    return obj


# =============================================================================
# API ENDPOINTS
# =============================================================================

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/stats")
def api_stats():
    """System-wide stats for the header KPI cards."""
    alerts = safe_load_json(DATA_PATHS["alerts"], [])
    parsed = safe_load_json(DATA_PATHS["parsed"], [])
    ml_data = safe_load_json(DATA_PATHS["ml_results"], {})
    incidents = safe_load_json(DATA_PATHS["incidents"], [])
    blocked = safe_load_json(DATA_PATHS["blocked_ips"], {})

    ml_results = ml_data.get("ml_results", []) if isinstance(ml_data, dict) else []
    anomaly_count = sum(1 for r in ml_results if r.get("is_anomaly"))

    critical = sum(1 for a in alerts if a.get("severity") == "CRITICAL")
    high = sum(1 for a in alerts if a.get("severity") == "HIGH")
    medium = sum(1 for a in alerts if a.get("severity") == "MEDIUM")

    breach = any(a.get("rule_name") == "BRUTE_FORCE_SUCCESS" for a in alerts)

    return jsonify({
        "events_processed": len(parsed),
        "total_alerts": len(alerts),
        "critical_alerts": critical,
        "high_alerts": high,
        "medium_alerts": medium,
        "ml_anomalies": anomaly_count,
        "incidents_open": len(incidents),
        "blocked_ips": len(blocked),
        "breach_detected": breach,
        "system_status": "BREACH DETECTED" if breach else "MONITORING",
        "last_updated": datetime.datetime.now().strftime("%H:%M:%S"),
    })


@app.route("/api/alerts")
def api_alerts():
    """All Phase 2 alerts with enrichment."""
    alerts = safe_load_json(DATA_PATHS["alerts"], [])
    return jsonify(make_serializable(alerts))


@app.route("/api/alert_timeline")
def api_alert_timeline():
    """Alert counts by hour for the timeline chart."""
    alerts = safe_load_json(DATA_PATHS["alerts"], [])
    by_hour = {}
    for a in alerts:
        ts = a.get("detection_timestamp", "")
        try:
            hour = ts[11:16]  # "HH:MM"
        except Exception:
            hour = "?"
        by_hour[hour] = by_hour.get(hour, 0) + 1

    sorted_hours = sorted(by_hour.items())
    return jsonify({
        "labels": [h for h, _ in sorted_hours],
        "values": [v for _, v in sorted_hours],
    })


@app.route("/api/severity_distribution")
def api_severity_distribution():
    alerts = safe_load_json(DATA_PATHS["alerts"], [])
    dist = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for a in alerts:
        sev = a.get("severity", "LOW")
        dist[sev] = dist.get(sev, 0) + 1
    return jsonify(dist)


@app.route("/api/ml")
def api_ml():
    """ML anomaly detection results."""
    ml_data = safe_load_json(DATA_PATHS["ml_results"], {})
    ml_results = ml_data.get("ml_results", []) if isinstance(ml_data, dict) else []
    comparison = ml_data.get("comparison_table", []) if isinstance(ml_data, dict) else []
    return jsonify(make_serializable({
        "results": ml_results,
        "comparison": comparison,
    }))


@app.route("/api/kill_chain")
def api_kill_chain():
    """MITRE ATT&CK kill chain from Phase 5 report."""
    report = safe_load_json(DATA_PATHS["report"], {})
    chain = report.get("mitre_attack", {}).get("kill_chain", [])
    techniques = report.get("mitre_attack", {}).get("techniques_observed", [])
    return jsonify(make_serializable({
        "chain": chain,
        "techniques": techniques,
    }))


@app.route("/api/incidents")
def api_incidents():
    """SOAR incident records from Phase 6."""
    incidents = safe_load_json(DATA_PATHS["incidents"], [])
    blocked = safe_load_json(DATA_PATHS["blocked_ips"], {})
    return jsonify(make_serializable({
        "incidents": incidents,
        "blocked_ips": list(blocked.values()),
    }))


@app.route("/api/audit_log")
def api_audit_log():
    """Last 20 lines of the SOAR audit log."""
    path = DATA_PATHS["audit_log"]
    if not os.path.exists(path):
        return jsonify({"lines": []})
    with open(path, encoding="utf-8") as f:
        lines = f.readlines()
    return jsonify({"lines": [l.rstrip() for l in lines[-20:]]})


@app.route("/api/soar_results")
def api_soar_results():
    """Detailed playbook execution steps."""
    results = safe_load_json(DATA_PATHS["soar_results"], [])
    return jsonify(make_serializable(results))


@app.route("/api/parsed")
def api_parsed():
    """All parsed events from the log stream."""
    parsed = safe_load_json(DATA_PATHS["parsed"], [])
    return jsonify(make_serializable(parsed))


@app.route("/api/event_types")
def api_event_types():
    """Event type breakdown for donut chart."""
    parsed = safe_load_json(DATA_PATHS["parsed"], [])
    types = {}
    for e in parsed:
        t = e.get("event_type", "UNKNOWN")
        types[t] = types.get(t, 0) + 1
    return jsonify(types)


@app.route("/api/report_summary")
def api_report_summary():
    """Phase 5 incident report summary."""
    report = safe_load_json(DATA_PATHS["report"], {})
    if not report:
        return jsonify({"available": False})
    summary = report.get("incident_summary", {})
    meta = report.get("report_metadata", {})
    response = report.get("response", {})
    return jsonify(make_serializable({
        "available": True,
        "incident_id": meta.get("incident_id", "N/A"),
        "priority": summary.get("priority", "N/A"),
        "breach": summary.get("is_confirmed_breach", False),
        "compromised_account": summary.get("compromised_account"),
        "source_ips": summary.get("source_ips", []),
        "narrative": summary.get("attack_description", ""),
        "immediate_actions": response.get("immediate_actions", []),
        "escalate_to": response.get("escalate_to", ""),
    }))


if __name__ == "__main__":
    print("\n  ============================================================")
    print("  PHASE 7: AEGIS SOC PLATFORM CONSOLE")
    print("  ============================================================")
    print(f"\n  [+] Starting real-time simulation engine...")
    simulator = LiveSOCSimulator()
    simulator.start()
    
    print(f"\n  [+] Starting Flask server...")
    print(f"  [+] Dashboard URL: http://localhost:5000")
    print(f"\n  [+] Data sources initialized:")
    for name, path in DATA_PATHS.items():
        status = "[OK]" if os.path.exists(path) else "[--] (not yet generated)"
        short = path.replace(BASE_DIR, ".")
        print(f"      {status} {name:<15} {short}")
    print(f"\n  Press Ctrl+C to stop the server.")
    print(f"  ============================================================\n")

    app.run(debug=False, port=5000, host="0.0.0.0", use_reloader=False)
