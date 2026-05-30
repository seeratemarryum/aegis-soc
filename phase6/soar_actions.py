"""
=============================================================================
SOC ANALYST TRAINING -- PHASE 6: SOAR RESPONSE ACTIONS
=============================================================================

CONCEPT: What is SOAR?
-----------------------
SOAR = Security Orchestration, Automation, and Response

It answers the question: "After we DETECT something, what do we DO?"

Without SOAR:
  Alert fires at 2am -> On-call analyst wakes up -> reads alert -> 
  manually blocks IP -> 25 minutes later. Attacker had 25 minutes.

With SOAR:
  Alert fires at 2am -> Playbook executes instantly -> IP blocked ->
  Incident ticket created -> Analyst notified with context -> 
  3 seconds total. Attacker never got in.

THE RISK OF AUTOMATION (CRITICAL LESSON):
------------------------------------------
SOAR is powerful. It is also DANGEROUS if built wrong.

REAL INCIDENT: In 2020, a major bank's SOAR system auto-blocked an IP
that turned out to be a critical payment processor. Tens of thousands of
transactions failed before a human overrode it. The fix took 47 minutes.

Root cause: The detection rule had a false positive. The automation
executed without human verification. The "blast radius" was massive.

LESSON: Automation should follow the PRINCIPLE OF LEAST PRIVILEGE:
  AUTO-EXECUTE:   Low-risk actions (create ticket, send alert, gather logs)
  REQUIRE APPROVAL: High-risk actions (block IP, disable account, isolate host)
  NEVER AUTO:     Irreversible actions (delete data, terminate instances)

THIS IS CALLED "HUMAN IN THE LOOP" (HITL) design.

RISK LADDER FOR SOAR ACTIONS:
  [LOW RISK]   log_incident()    -- just writes a file, fully reversible
  [LOW RISK]   alert_system()    -- sends notification, no system change
  [MEDIUM]     enrich_threat()   -- queries external APIs, no change
  [HIGH RISK]  block_ip()        -- changes firewall rules, may break things
  [HIGH RISK]  disable_account() -- locks out users, may impact business
  [CRITICAL]   isolate_host()    -- takes machine offline, always needs approval

REAL SOAR PLATFORMS:
  Splunk SOAR (formerly Phantom): Python playbooks, 300+ integrations
  Palo Alto XSOAR: incident management + automation
  Microsoft Sentinel Playbooks: Azure Logic Apps
  IBM QRadar SOAR: case management + automation
  Tines: no-code SOAR automation
=============================================================================
"""

import json
import os
import datetime
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PHASE6_DIR = os.path.join(BASE_DIR, "phase6")


# =============================================================================
# AUDIT LOG
# Every SOAR action MUST be logged. This is not optional.
# In a real incident, you'll need to prove EXACTLY what automated actions
# ran, when, and why. Legal and compliance require this.
# =============================================================================

AUDIT_LOG_PATH = os.path.join(PHASE6_DIR, "soar_audit.log")
BLOCKED_IPS_PATH = os.path.join(PHASE6_DIR, "blocked_ips.json")
INCIDENTS_PATH = os.path.join(PHASE6_DIR, "incidents.json")


def _write_audit(action_name, status, details, alert_id="SYSTEM"):
    """
    Write every SOAR action to the audit log.

    WHY IMMUTABLE AUDIT LOGS MATTER:
    In forensics and legal proceedings, you need to prove:
    "At 02:14:42, the system automatically blocked IP 185.220.101.42
     in response to alert SOC-00003, authorized by playbook PB-001."

    Without this, you can't prove your system worked correctly,
    and you can't defend automation decisions in court.

    Real systems write to: SIEM, SYSLOG, immutable S3 buckets, HSMs.
    """
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = (
        f"[{timestamp}] ACTION={action_name} | STATUS={status} | "
        f"ALERT={alert_id} | {details}\n"
    )

    with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as f:
        f.write(log_entry)

    return log_entry.strip()


def _load_json(path, default):
    """Load a JSON file, returning default if not found."""
    if not os.path.exists(path):
        return default
    with open(path) as f:
        return json.load(f)


def _save_json(path, data):
    """Save data to a JSON file."""
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


# =============================================================================
# SOAR ACTION 1: block_ip()
# =============================================================================

def block_ip(ip_address, reason, alert_id, approved_by="AUTOMATION",
             dry_run=True):
    """
    Block a source IP address at the firewall.

    WHAT THIS DOES IN PRODUCTION:
    1. Calls firewall API (pfSense, AWS Security Groups, Azure NSG, Palo Alto)
    2. Adds IP to deny list: "DROP all traffic from 185.220.101.42"
    3. Logs action to SIEM audit trail
    4. Creates a ticket for human review

    SIMULATION (dry_run=True):
    We don't actually change firewall rules (no real firewall here).
    Instead we write to blocked_ips.json and log the action.
    This is called a "dry run" or "simulation mode" -- safe for learning.

    WHY dry_run=True IS THE CORRECT DEFAULT:
    NEVER auto-execute firewall changes without testing first.
    Even experienced engineers use dry runs before live deployment.

    THE RISK OF GETTING THIS WRONG:
    - Blocking a CDN IP (Cloudflare, Akamai) = blocking all your customers
    - Blocking an internal monitoring agent = loss of visibility
    - Blocking a payment gateway = financial losses

    SAFEGUARDS real SOAR systems use:
    1. IP whitelist check before blocking (never block known-good IPs)
    2. Rate limit: max N blocks per hour
    3. Auto-unblock after 24h (temporary block, not permanent)
    4. Require approval for /24 CIDR blocks (network range blocks)

    Args:
        ip_address: IP to block
        reason:     Why it's being blocked (audit trail)
        alert_id:   Which alert triggered this action
        approved_by: "AUTOMATION" or analyst name (human approval)
        dry_run:    If True, simulate only. If False, would write firewall rules.
    """
    action_name = "BLOCK_IP"

    # ── SAFEGUARD 1: Never block private/internal IPs automatically ──────────
    SAFE_INTERNAL_RANGES = ("10.", "192.168.", "172.16.", "127.", "localhost")
    if ip_address.startswith(SAFE_INTERNAL_RANGES):
        msg = (f"BLOCKED from blocking {ip_address} -- internal IP. "
               f"Internal IP blocking requires manual approval and investigation.")
        _write_audit(action_name, "REJECTED_SAFE_GUARD", msg, alert_id)
        print(f"\n  [SAFEGUARD] Cannot auto-block internal IP: {ip_address}")
        print(f"             Reason: Internal IPs may be legitimate users or systems.")
        print(f"             Action: Escalate to Tier 2 for investigation.")
        return {"status": "rejected", "reason": "internal_ip_protection", "ip": ip_address}

    # ── SAFEGUARD 2: Check if already blocked (idempotency) ─────────────────
    blocked_ips = _load_json(BLOCKED_IPS_PATH, {})
    if ip_address in blocked_ips:
        msg = f"IP {ip_address} already in block list (blocked at {blocked_ips[ip_address]['blocked_at']})"
        _write_audit(action_name, "ALREADY_BLOCKED", msg, alert_id)
        print(f"\n  [INFO] IP {ip_address} was already blocked.")
        return {"status": "already_blocked", "ip": ip_address}

    # ── EXECUTE (or simulate) the block ──────────────────────────────────────
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    block_record = {
        "ip": ip_address,
        "blocked_at": timestamp,
        "reason": reason,
        "alert_id": alert_id,
        "approved_by": approved_by,
        "dry_run": dry_run,
        "auto_unblock_at": (
            datetime.datetime.now() + datetime.timedelta(hours=24)
        ).strftime("%Y-%m-%d %H:%M:%S"),
        "firewall_rule": f"iptables -A INPUT -s {ip_address} -j DROP",
    }

    if dry_run:
        print(f"\n  [DRY RUN] Would execute: {block_record['firewall_rule']}")
        print(f"           In production, this calls: firewall_api.block('{ip_address}')")
        status = "SIMULATED"
    else:
        # In real deployment: call firewall API here
        # e.g.: requests.post(FIREWALL_API, json={"action": "block", "ip": ip_address})
        print(f"\n  [LIVE] Blocking IP: {ip_address}")
        status = "EXECUTED"

    # Save to our simulated block list
    blocked_ips[ip_address] = block_record
    _save_json(BLOCKED_IPS_PATH, blocked_ips)

    # Audit log
    detail = (f"IP={ip_address} | reason={reason} | approved_by={approved_by} | "
              f"dry_run={dry_run} | auto_unblock=24h")
    audit_entry = _write_audit(action_name, status, detail, alert_id)

    print(f"  [{status}] block_ip({ip_address})")
    print(f"  Reason:    {reason}")
    print(f"  Alert:     {alert_id}")
    print(f"  Approved:  {approved_by}")
    print(f"  Unblocks:  {block_record['auto_unblock_at']} (auto)")
    print(f"  Audit:     {audit_entry}")

    return {"status": status.lower(), "ip": ip_address, "record": block_record}


# =============================================================================
# SOAR ACTION 2: log_incident()
# =============================================================================

def log_incident(alert, report=None, severity_override=None):
    """
    Create a formal incident record in the incident tracking system.

    WHAT THIS IS:
    Every security event that requires investigation becomes an "Incident."
    The incident record is the single source of truth for:
    - What happened
    - What actions were taken
    - Who was involved
    - Current status

    INCIDENT LIFECYCLE:
    NEW -> INVESTIGATING -> CONTAINMENT -> ERADICATION -> RECOVERY -> CLOSED

    REAL TOOLS:
    ServiceNow: auto-creates incident tickets from SIEM alerts
    Jira Service Management: used by many SecOps teams
    PagerDuty: incident management with on-call routing
    We simulate this by writing to incidents.json

    Args:
        alert:            The triggering alert dict from Phase 2
        report:           Optional Phase 5 incident report for richer context
        severity_override: Override the alert severity if needed
    """
    incidents = _load_json(INCIDENTS_PATH, [])

    incident_id = f"INC-{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}-{len(incidents)+1:03d}"
    severity = severity_override or alert.get("severity", "MEDIUM")
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    incident = {
        "incident_id": incident_id,
        "created_at": timestamp,
        "status": "NEW",
        "severity": severity,
        "alert_source": alert.get("alert_id", "unknown"),
        "rule_triggered": alert.get("rule_name", "unknown"),
        "source_ip": alert.get("source_ip", "unknown"),
        "mitre_technique": alert.get("mitre_technique", "unknown"),
        "description": alert.get("recommended_action", "Investigate"),
        "assigned_to": "Unassigned",
        "timeline": [
            {
                "time": timestamp,
                "action": "INCIDENT_CREATED",
                "by": "SOAR_AUTOMATION",
                "note": f"Auto-created from alert {alert.get('alert_id')}",
            }
        ],
        # Include the full report if provided
        "report_summary": {
            "priority": report["incident_summary"]["priority"] if report else severity,
            "narrative": report["incident_summary"]["attack_description"][:200] if report else "",
        } if report else {},
    }

    incidents.append(incident)
    _save_json(INCIDENTS_PATH, incidents)

    detail = (f"incident_id={incident_id} | severity={severity} | "
              f"rule={alert.get('rule_name')} | ip={alert.get('source_ip')}")
    _write_audit("LOG_INCIDENT", "SUCCESS", detail, alert.get("alert_id", "?"))

    print(f"\n  [ACTION] log_incident()")
    print(f"  Incident ID: {incident_id}")
    print(f"  Severity:    {severity}")
    print(f"  Status:      NEW (assigned: Unassigned)")
    print(f"  Rule:        {alert.get('rule_name')}")
    print(f"  IP:          {alert.get('source_ip')}")

    return incident


# =============================================================================
# SOAR ACTION 3: alert_system()
# =============================================================================

def alert_system(incident_id, severity, message, channels=None):
    """
    Send notifications through configured alert channels.

    WHAT REAL ALERT CHANNELS LOOK LIKE:
    - EMAIL:   smtp.send() to security-team@company.com
    - SLACK:   requests.post(SLACK_WEBHOOK, json={"text": message})
    - PAGERDUTY: pagerduty_api.create_incident(severity, message)
    - SMS:     Twilio API for CRITICAL alerts
    - TEAMS:   Microsoft Teams webhook

    ALERT FATIGUE WARNING:
    Sending too many alerts makes analysts numb to them.
    In a real SOC, these rules govern notifications:
    - CRITICAL: Page on-call analyst immediately (PagerDuty)
    - HIGH:     Slack + email to SOC team
    - MEDIUM:   Email only, batched hourly
    - LOW:      Dashboard only, no notification
    - INFO:     Log silently, no alert

    Args:
        incident_id: The incident to notify about
        severity:    Alert severity level
        message:     Human-readable message
        channels:    List of channels to notify (default: auto-select by severity)
    """
    # Auto-select channels based on severity (real SOAR logic)
    if channels is None:
        channels = {
            "CRITICAL": ["PAGERDUTY", "SLACK", "EMAIL", "SMS"],
            "HIGH":     ["SLACK", "EMAIL"],
            "MEDIUM":   ["EMAIL"],
            "LOW":      ["DASHBOARD"],
        }.get(severity, ["DASHBOARD"])

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    notifications_sent = []

    print(f"\n  [ACTION] alert_system()")
    print(f"  Incident: {incident_id}")
    print(f"  Severity: {severity}")
    print(f"  Channels: {', '.join(channels)}")
    print(f"  Message:  {message[:80]}...")
    print()

    for channel in channels:
        # Simulate each notification channel
        if channel == "PAGERDUTY":
            print(f"  [PAGERDUTY]  On-call analyst paged. Response SLA: 5 minutes.")
            print(f"               Would POST to: https://events.pagerduty.com/v2/enqueue")
        elif channel == "SLACK":
            print(f"  [SLACK]      Posted to #soc-alerts channel.")
            print(f"               Would POST to: SLACK_WEBHOOK_URL with payload:")
            print(f"               {{text: '[{severity}] {incident_id}: {message[:40]}...'}}")
        elif channel == "EMAIL":
            print(f"  [EMAIL]      Sent to: security-team@company.com")
            print(f"               Subject: [{severity}] Security Incident {incident_id}")
        elif channel == "SMS":
            print(f"  [SMS]        Sent via Twilio to on-call mobile: +1-555-SOC-TEAM")
        elif channel == "DASHBOARD":
            print(f"  [DASHBOARD]  Alert visible in SOC dashboard (Phase 7).")

        notifications_sent.append(channel)

    _write_audit(
        "ALERT_SYSTEM", "SUCCESS",
        f"incident={incident_id} | severity={severity} | channels={channels}",
        incident_id
    )

    return {"notifications_sent": notifications_sent, "incident_id": incident_id}


# =============================================================================
# SOAR ACTION 4: enrich_threat() -- gather intelligence
# =============================================================================

def enrich_threat(ip_address, alert_id):
    """
    Gather threat intelligence about a suspicious IP.

    WHAT REAL ENRICHMENT DOES:
    Queries multiple threat intelligence sources:
    - AbuseIPDB:  Is this IP in the abuse database?
    - VirusTotal: Has this IP been flagged by security vendors?
    - Shodan:     What services does this IP expose to the internet?
    - MaxMind:    What country/org/ASN is this IP from?
    - AlienVault OTX: Any known threat indicators?

    WHY ENRICHMENT BEFORE BLOCKING:
    Before auto-blocking, you want to know:
    1. Is this a known malicious IP? (confidence in blocking it)
    2. Is this a cloud provider IP? (blocking AWS may hurt legitimate traffic)
    3. What country is it from? (helps with attribution and compliance)
    4. Has it been seen in other incidents? (part of a campaign?)

    We SIMULATE this with realistic-looking data for education.
    """
    # Simulate threat intelligence lookup results
    # Real implementation: requests.get(f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}")

    known_malicious = {
        "185.220.101.42": {
            "abuse_score": 98,
            "country": "DE",
            "isp": "Frantech Solutions",
            "known_as": "Tor exit node / scanning infrastructure",
            "reports": 1247,
            "last_seen": "2026-05-30",
            "tags": ["ssh", "brute-force", "tor-exit"],
        },
        "45.142.212.100": {
            "abuse_score": 87,
            "country": "RU",
            "isp": "Selectel Ltd",
            "known_as": "VPS commonly used for attacks",
            "reports": 342,
            "last_seen": "2026-05-29",
            "tags": ["scanner", "brute-force"],
        },
        "203.0.113.88": {
            "abuse_score": 45,
            "country": "CN",
            "isp": "Example ISP (RFC 5737 test address)",
            "known_as": "Credential stuffing source",
            "reports": 88,
            "last_seen": "2026-05-28",
            "tags": ["credential-stuffing"],
        },
    }

    # Default for unknown IPs
    intel = known_malicious.get(ip_address, {
        "abuse_score": 0,
        "country": "??",
        "isp": "Unknown",
        "known_as": "No threat intel available",
        "reports": 0,
        "last_seen": "Never seen",
        "tags": [],
    })

    intel["ip"] = ip_address
    intel["enriched_at"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Threat confidence calculation
    if intel["abuse_score"] >= 80:
        confidence = "HIGH"
        recommendation = "Block immediately -- confirmed malicious IP"
    elif intel["abuse_score"] >= 40:
        confidence = "MEDIUM"
        recommendation = "Block with monitoring -- likely malicious"
    else:
        confidence = "LOW"
        recommendation = "Monitor only -- insufficient threat data"

    intel["block_confidence"] = confidence
    intel["recommendation"] = recommendation

    _write_audit("ENRICH_THREAT", "SUCCESS",
                 f"ip={ip_address} | abuse_score={intel['abuse_score']} | confidence={confidence}",
                 alert_id)

    print(f"\n  [ACTION] enrich_threat({ip_address})")
    print(f"  Abuse Score:  {intel['abuse_score']}/100")
    print(f"  Country:      {intel['country']}")
    print(f"  ISP:          {intel['isp']}")
    print(f"  Known As:     {intel['known_as']}")
    print(f"  Reports:      {intel['reports']}")
    print(f"  Tags:         {', '.join(intel['tags']) or 'none'}")
    print(f"  Confidence:   {confidence}")
    print(f"  Recommend:    {recommendation}")

    return intel
