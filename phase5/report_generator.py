"""
=============================================================================
SOC ANALYST TRAINING -- PHASE 5: INCIDENT REPORT GENERATOR
=============================================================================

CONCEPT: What is an Incident Report?
--------------------------------------
When an attack is detected, a SOC analyst writes an Incident Report.
This document answers:

  WHO:   Which IP address? Which user account?
  WHAT:  What attack technique was used?
  WHEN:  Timeline of events (first seen, escalation, breach)
  WHERE: Which system was targeted?
  HOW:   Technical details (failure counts, ports, methods)
  WHY:   MITRE ATT&CK classification (attacker's goal)
  ACTION: What must be done RIGHT NOW?

SOC TIER SYSTEM:
  Tier 1: Monitors alerts, creates incident tickets, basic triage
  Tier 2: Investigates complex incidents, writes detailed reports
  Tier 3: Threat hunters, advanced forensics, attribution

This engine does what Tier 1 SHOULD do before escalating to Tier 2:
create a complete, structured report from raw alert data.

REAL TOOLS:
  ServiceNow   -- Incident ticketing and report templates
  Jira         -- Used by many SecOps teams for case tracking
  Splunk SOAR  -- Auto-generates incident reports from playbooks
  IBM QRadar   -- "Offense" reports are the equivalent
=============================================================================
"""

import json
import datetime
import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PHASE5_DIR = os.path.join(BASE_DIR, "phase5")
sys.path.insert(0, PHASE5_DIR)

from mitre_mapper import (
    get_techniques_for_rule, get_tactic_for_rule,
    get_attack_chain_from_alerts, ATTACK_TECHNIQUES
)


# =============================================================================
# INCIDENT SEVERITY CALCULATOR
# =============================================================================

SEVERITY_SCORES = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 2, "INFO": 1}

def calculate_incident_priority(alerts, ml_results=None):
    """
    Calculate the overall incident priority from multiple alerts.

    Real SOC concept: individual alerts have severity, but the INCIDENT
    severity considers:
    1. Highest individual alert severity
    2. Number of correlated alerts (more = more confident)
    3. Whether brute force SUCCEEDED (account compromised = always CRITICAL)
    4. ML anomaly score (if available)

    Returns: (priority_label, priority_score, reasoning)
    """
    if not alerts:
        return "LOW", 2, "No alerts"

    highest_sev_score = max(SEVERITY_SCORES.get(a.get("severity", "LOW"), 0) for a in alerts)
    alert_count_bonus = min(len(alerts) - 1, 3)  # Up to +3 for multiple alerts

    # Check for account compromise (worst case)
    has_compromise = any(a.get("rule_name") == "BRUTE_FORCE_SUCCESS" for a in alerts)

    # Check for multi-stage (scan + brute = targeted attack)
    rule_names = {a.get("rule_name") for a in alerts}
    is_multi_stage = "PORT_SCAN_DETECTED" in rule_names and "SSH_BRUTE_FORCE" in rule_names

    # Base score
    score = highest_sev_score + alert_count_bonus
    reasoning = []

    if has_compromise:
        score = 10  # Always CRITICAL
        reasoning.append("Account compromise detected -- maximum priority")

    if is_multi_stage:
        score = min(score + 2, 10)
        reasoning.append("Multi-stage attack (recon + exploitation) = deliberate, targeted")

    if ml_results:
        anomalous = [r for r in ml_results if r.get("is_anomaly")]
        if anomalous:
            reasoning.append(f"ML confirmed {len(anomalous)} anomalous IP(s)")

    if score >= 9:
        label = "CRITICAL"
    elif score >= 7:
        label = "HIGH"
    elif score >= 4:
        label = "MEDIUM"
    else:
        label = "LOW"

    if not reasoning:
        reasoning.append(f"Base score from {len(alerts)} alert(s), highest severity: "
                         f"{max((a.get('severity','LOW') for a in alerts), key=lambda s: SEVERITY_SCORES.get(s,0))}")

    return label, score, "; ".join(reasoning)


# =============================================================================
# TIMELINE BUILDER
# =============================================================================

def build_attack_timeline(alerts, ml_results=None):
    """
    Reconstruct the attack timeline from alerts and ML findings.

    CONCEPT: "Timeline Analysis" is one of the most important skills in SOC.
    By ordering events chronologically, you reconstruct the attacker's actions:

    02:14:00 - Port scan begins (reconnaissance)
    02:14:15 - SSH brute force starts (exploitation)
    02:14:37 - Brute force alert fires (detection)
    02:14:41 - Account compromised (breach)
    02:14:41 - Incident response must begin

    This narrative is what gets presented to management and IR teams.
    """
    timeline = []

    for alert in alerts:
        ts = alert.get("detection_timestamp", "Unknown")
        rule = alert.get("rule_name", "Unknown")
        ip = alert.get("source_ip", "Unknown")
        sev = alert.get("severity", "?")

        # Human-readable event description
        if rule == "PORT_SCAN_DETECTED":
            desc = (f"Port scan detected from {ip}. "
                    f"{alert.get('rapid_connection_count', '?')} rapid connection probes.")
            phase = "RECONNAISSANCE"
        elif rule == "SSH_BRUTE_FORCE":
            n_fail = alert.get("failure_count", "?")
            users = alert.get("unique_usernames", [])
            desc = (f"SSH brute force from {ip}. "
                    f"{n_fail} failures in {alert.get('window_seconds', 60)}s. "
                    f"Usernames tried: {', '.join(str(u) for u in users[:5])}.")
            phase = "CREDENTIAL ATTACK"
        elif rule == "BRUTE_FORCE_SUCCESS":
            user = alert.get("successful_username", "?")
            prior = alert.get("prior_failures", "?")
            desc = (f"ACCOUNT COMPROMISED: '{user}' from {ip}. "
                    f"{prior} failures before success.")
            phase = "BREACH"
        else:
            desc = f"Alert: {rule} from {ip}"
            phase = "UNKNOWN"

        timeline.append({
            "timestamp": ts,
            "phase": phase,
            "severity": sev,
            "description": desc,
            "alert_id": alert.get("alert_id", "?"),
            "source_ip": ip,
            "mitre_tactic": get_tactic_for_rule(rule),
        })

    # Add ML findings to timeline
    if ml_results:
        for result in ml_results:
            if result.get("is_anomaly"):
                reasons = result.get("anomaly_reasons", [])
                top_reason = reasons[0]["human_explanation"] if reasons else "Behavioral anomaly"
                timeline.append({
                    "timestamp": "ML Scan",
                    "phase": "ML DETECTION",
                    "severity": result.get("severity", "MEDIUM"),
                    "description": (f"ML anomaly: {result['ip_address']} "
                                   f"(score: {result['anomaly_score']:.3f}). "
                                   f"{top_reason[:80]}"),
                    "alert_id": "ML",
                    "source_ip": result["ip_address"],
                    "mitre_tactic": "Behavioral Analysis",
                })

    # Sort by timestamp (ML entries go last since they're batch analysis)
    def sort_key(item):
        if item["timestamp"] == "ML Scan":
            return "Z"  # Sort ML findings after rule alerts
        return item["timestamp"]

    timeline.sort(key=sort_key)
    return timeline


# =============================================================================
# REPORT GENERATOR
# =============================================================================

def generate_incident_report(alerts, ml_results=None, analyst_name="SOC Tier 1 Analyst"):
    """
    Generate a complete structured SOC incident report.

    This is the main output of Phase 5 -- converting raw technical alerts
    into a document that can be:
    1. Read by a Tier 2 analyst for deeper investigation
    2. Sent to management for awareness
    3. Used in a post-incident review
    4. Filed for compliance/legal purposes

    Args:
        alerts:      List of alert dicts from Phase 2 AlertManager
        ml_results:  List of anomaly results from Phase 4 (optional)
        analyst_name: Who is writing this report

    Returns:
        dict: Structured incident report
    """
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if not alerts:
        return {"error": "No alerts to report on"}

    # Deduplicate IPs involved
    source_ips = list(set(a.get("source_ip", "") for a in alerts))
    target_systems = list(set(a.get("hostname", "prod-webserver-01") for a in alerts))

    # Incident priority
    priority, score, priority_reasoning = calculate_incident_priority(alerts, ml_results)

    # ATT&CK kill chain
    kill_chain = get_attack_chain_from_alerts(alerts)

    # Timeline
    timeline = build_attack_timeline(alerts, ml_results)

    # Collect all techniques mentioned
    all_techniques = {}
    for alert in alerts:
        for tech in get_techniques_for_rule(alert.get("rule_name", "")):
            all_techniques[tech["id"]] = tech

    # Determine if breach occurred
    breach_alert = next(
        (a for a in alerts if a.get("rule_name") == "BRUTE_FORCE_SUCCESS"), None
    )
    is_breach = breach_alert is not None
    compromised_account = breach_alert.get("successful_username") if breach_alert else None

    # Build immediate action list (context-aware)
    immediate_actions = []
    for ip in source_ips:
        immediate_actions.append(
            f"Block IP {ip} at perimeter firewall and cloud security groups"
        )

    if is_breach:
        immediate_actions.insert(0, f"URGENT: Lock account '{compromised_account}' immediately")
        immediate_actions.append(f"Reset all passwords for account '{compromised_account}'")
        immediate_actions.append("Initiate host forensics on prod-webserver-01")
        immediate_actions.append("Preserve auth logs before any rotation")
        immediate_actions.append("Notify CISO and legal team (possible data breach)")

    if any(a.get("rule_name") == "SSH_BRUTE_FORCE" for a in alerts):
        immediate_actions.append("Add Fail2ban or equivalent to auto-block brute force IPs")
        immediate_actions.append("Review sshd_config: set PermitRootLogin no, MaxAuthTries 3")

    # Long-term recommendations
    long_term_recs = [
        "Implement MFA on all SSH access (eliminates brute force entirely)",
        "Switch to SSH key authentication, disable password auth",
        "Deploy SIEM alerting on this detection rule with lower threshold",
        "Add attacker IP(s) to threat intelligence blocklist",
        "Conduct tabletop exercise based on this attack scenario",
    ]

    # Assemble the report
    report = {
        "report_metadata": {
            "incident_id": f"INC-{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}",
            "generated_at": now,
            "analyst": analyst_name,
            "detection_system": "Autonomous SOC Analyst v1.0 (Phases 1-5)",
            "report_version": "1.0",
        },
        "incident_summary": {
            "priority": priority,
            "priority_score": score,
            "priority_reasoning": priority_reasoning,
            "total_alerts": len(alerts),
            "is_confirmed_breach": is_breach,
            "compromised_account": compromised_account,
            "source_ips": source_ips,
            "target_systems": target_systems,
            "first_seen": timeline[0]["timestamp"] if timeline else "Unknown",
            "attack_description": _build_narrative(alerts, kill_chain, is_breach),
        },
        "attack_timeline": timeline,
        "mitre_attack": {
            "kill_chain": kill_chain,
            "techniques_observed": [
                {
                    "id": tech["id"],
                    "name": tech["name"],
                    "tactic": tech["tactic_name"],
                    "severity_weight": tech["severity_weight"],
                    "real_world_examples": tech.get("real_world_examples", [])[:2],
                    "mitigations": tech.get("mitigations", [])[:3],
                }
                for tech in all_techniques.values()
            ],
        },
        "ml_analysis": {
            "anomalies_detected": len([r for r in (ml_results or []) if r.get("is_anomaly")]),
            "anomalous_ips": [
                {
                    "ip": r["ip_address"],
                    "score": r["anomaly_score"],
                    "severity": r["severity"],
                    "top_reason": r["anomaly_reasons"][0]["human_explanation"]
                        if r.get("anomaly_reasons") else "Behavioral deviation",
                }
                for r in (ml_results or []) if r.get("is_anomaly")
            ],
        },
        "response": {
            "immediate_actions": immediate_actions,
            "long_term_recommendations": long_term_recs,
            "escalation_required": priority in ("CRITICAL", "HIGH"),
            "escalate_to": "Tier 2 SOC Analyst + CISO" if is_breach else "Tier 2 SOC Analyst",
        },
        "raw_alerts": alerts,
    }

    return report


def _build_narrative(alerts, kill_chain, is_breach):
    """
    Build a plain-English narrative description of the attack.

    TEACHING CONCEPT:
    This is what a SOC analyst writes in the "Executive Summary" box.
    It must be readable by non-technical stakeholders (managers, legal, HR).
    NOT: "SSH_BRUTE_FORCE alert fired with threshold=5 in 60s window"
    YES: "An external IP address systematically attempted to guess the root
          password on the production web server at 2am..."
    """
    ips = list(set(a.get("source_ip", "?") for a in alerts))
    ip_str = ips[0] if len(ips) == 1 else f"{len(ips)} external IP addresses"

    has_scan = any(a.get("rule_name") == "PORT_SCAN_DETECTED" for a in alerts)
    has_brute = any(a.get("rule_name") == "SSH_BRUTE_FORCE" for a in alerts)

    parts = []

    if has_scan:
        parts.append(
            f"The attacker ({ip_str}) began with reconnaissance, probing "
            f"the target server's open ports to identify available services."
        )

    if has_brute:
        brute_alert = next((a for a in alerts if a.get("rule_name") == "SSH_BRUTE_FORCE"), {})
        n = brute_alert.get("failure_count", "multiple")
        users = brute_alert.get("unique_usernames", [])
        parts.append(
            f"The attacker then launched an SSH brute force attack, making {n} "
            f"failed login attempts in rapid succession. "
            f"The attack targeted {'multiple accounts' if len(users) > 1 else 'the root account'} "
            f"using an automated tool consistent with Hydra or Medusa."
        )

    if is_breach:
        breach_alert = next((a for a in alerts if a.get("rule_name") == "BRUTE_FORCE_SUCCESS"), {})
        user = breach_alert.get("successful_username", "a system account")
        parts.append(
            f"The brute force attack succeeded: the attacker gained access to "
            f"the '{user}' account. The system must be treated as fully compromised. "
            f"Immediate incident response is required."
        )
    else:
        parts.append(
            "The attack was detected before a successful breach. "
            "However, immediate blocking and review are still required."
        )

    return " ".join(parts)


# =============================================================================
# PRINT FUNCTIONS
# =============================================================================

def print_incident_report(report):
    """Print a formatted incident report to console."""
    meta = report["report_metadata"]
    summary = report["incident_summary"]
    response = report["response"]
    chain = report["mitre_attack"]["kill_chain"]
    timeline = report["attack_timeline"]

    priority = summary["priority"]
    priority_banner = {
        "CRITICAL": "!!! CRITICAL INCIDENT !!!",
        "HIGH":     ">> HIGH PRIORITY INCIDENT <<",
        "MEDIUM":   "> MEDIUM PRIORITY INCIDENT <",
    }.get(priority, priority + " INCIDENT")

    print(f"\n{'#'*62}")
    print(f"  SOC INCIDENT REPORT")
    print(f"  {priority_banner}")
    print(f"{'#'*62}")

    print(f"\n  Incident ID:  {meta['incident_id']}")
    print(f"  Generated:    {meta['generated_at']}")
    print(f"  Analyst:      {meta['analyst']}")
    print(f"  Priority:     {priority} (score: {summary['priority_score']}/10)")
    print(f"  Breach:       {'YES -- ACCOUNT COMPROMISED' if summary['is_confirmed_breach'] else 'No'}")

    print(f"\n  {'='*58}")
    print(f"  EXECUTIVE SUMMARY")
    print(f"  {'='*58}")
    # Word-wrap the narrative
    narrative = summary["attack_description"]
    words = narrative.split()
    line = "  "
    for word in words:
        if len(line) + len(word) > 60:
            print(line)
            line = "  " + word + " "
        else:
            line += word + " "
    if line.strip():
        print(line)

    print(f"\n  {'='*58}")
    print(f"  ATTACK TIMELINE")
    print(f"  {'='*58}")
    for entry in timeline:
        sev_tag = {"CRITICAL": "[!!!]", "HIGH": "[HI ]", "MEDIUM": "[MED]",
                   "LOW": "[LOW]", "INFO": "[   ]"}.get(entry["severity"], "[?]")
        phase_tag = f"[{entry['phase'][:12]:<12}]"
        ts = entry["timestamp"][:19] if entry["timestamp"] != "ML Scan" else "ML Scan         "
        print(f"  {sev_tag} {ts}  {phase_tag}")
        # Word-wrap description
        desc = entry["description"]
        print(f"       {desc[:72]}")
        if len(desc) > 72:
            print(f"       {desc[72:144]}")

    print(f"\n  {'='*58}")
    print(f"  MITRE ATT&CK KILL CHAIN")
    print(f"  {'='*58}")
    seen = set()
    for step_num, step in enumerate(chain, 1):
        key = (step["tactic_id"], step["technique_id"])
        if key in seen:
            continue
        seen.add(key)
        print(f"  Step {step_num}: [{step['tactic_name'].upper():<20}] "
              f"{step['technique_id']} - {step['technique_name']}")

    print(f"\n  {'='*58}")
    print(f"  IMMEDIATE RESPONSE ACTIONS")
    print(f"  {'='*58}")
    for i, action in enumerate(response["immediate_actions"], 1):
        print(f"  {i}. {action}")

    if response["escalation_required"]:
        print(f"\n  ESCALATE TO: {response['escalate_to']}")

    print(f"\n  {'='*58}")
    print(f"  LONG-TERM RECOMMENDATIONS")
    print(f"  {'='*58}")
    for rec in response["long_term_recommendations"]:
        print(f"  * {rec}")

    print(f"\n{'#'*62}")


def save_report(report, filename="incident_report.json"):
    """Save report to JSON file."""
    out_path = os.path.join(PHASE5_DIR, filename)

    def make_serializable(obj):
        if isinstance(obj, dict):
            return {k: make_serializable(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [make_serializable(i) for i in obj]
        elif hasattr(obj, "item"):
            return obj.item()
        return obj

    with open(out_path, "w") as f:
        json.dump(make_serializable(report), f, indent=2)

    # Also generate a plain-text version (easier to read)
    txt_path = os.path.join(PHASE5_DIR, filename.replace(".json", ".txt"))
    with open(txt_path, "w", encoding="utf-8") as f:
        meta = report["report_metadata"]
        summary = report["incident_summary"]
        f.write(f"SOC INCIDENT REPORT\n")
        f.write(f"{'='*60}\n")
        f.write(f"Incident ID: {meta['incident_id']}\n")
        f.write(f"Priority: {summary['priority']}\n")
        f.write(f"Generated: {meta['generated_at']}\n\n")
        f.write(f"SUMMARY:\n{summary['attack_description']}\n\n")
        f.write(f"SOURCE IPs: {', '.join(summary['source_ips'])}\n")
        f.write(f"BREACH: {'YES' if summary['is_confirmed_breach'] else 'No'}\n\n")

        f.write(f"IMMEDIATE ACTIONS:\n")
        for i, action in enumerate(report["response"]["immediate_actions"], 1):
            f.write(f"  {i}. {action}\n")

    print(f"\n[OK] Report saved: {out_path}")
    print(f"[OK] Text report:  {txt_path}")
    return out_path
