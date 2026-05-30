"""
=============================================================================
SOC ANALYST TRAINING -- PHASE 6: PLAYBOOK ENGINE
=============================================================================

CONCEPT: What is a Playbook?
------------------------------
A playbook is a pre-approved, step-by-step response procedure.

Think of it like a recipe:
  TRIGGER: "If I see SSH_BRUTE_FORCE alert"
  STEPS:
    1. Enrich the source IP (gather threat intel)
    2. Log an incident ticket
    3. Notify the SOC team
    4. IF abuse score > 80: auto-block the IP
    5. IF abuse score < 80: require human approval before blocking

Playbooks make SOC response:
  - CONSISTENT: Every analyst follows the same steps
  - FAST: Automation handles steps 1-3 in <1 second
  - AUDITABLE: Every step is logged with timestamps
  - SCALABLE: One playbook handles 1000 identical alerts

WITHOUT PLAYBOOKS:
  - Analyst A blocks the IP immediately
  - Analyst B investigates for 20 minutes then blocks
  - Analyst C (new) doesn't know what to do, escalates
  - No consistent evidence trail

PLAYBOOK DESIGN PRINCIPLES:
  1. TRIGGER is specific (don't use one playbook for everything)
  2. LOWEST RISK FIRST (enrich before acting, alert before blocking)
  3. HUMAN CHECKPOINTS for irreversible actions (block, isolate)
  4. EXPLICIT EXIT CONDITIONS (what stops the playbook?)
  5. ROLLBACK PLAN (what happens if an action fails?)

REAL PLAYBOOK TOOLS:
  Splunk SOAR: Python code playbooks with visual flow editor
  Palo Alto XSOAR: YAML-defined playbooks + Python actions
  Tines: No-code playbooks (click + configure)
  D3 SOAR: Drag-and-drop workflow builder
=============================================================================
"""

import sys
import os
import json
import datetime
import time

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PHASE6_DIR = os.path.join(BASE_DIR, "phase6")
sys.path.insert(0, PHASE6_DIR)

from soar_actions import (
    block_ip, log_incident, alert_system, enrich_threat,
    _write_audit, AUDIT_LOG_PATH
)


# =============================================================================
# PLAYBOOK DEFINITIONS
# =============================================================================

class PlaybookResult:
    """Container for playbook execution results."""
    def __init__(self, playbook_name):
        self.playbook_name = playbook_name
        self.started_at = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.completed_at = None
        self.steps_executed = []
        self.status = "RUNNING"
        self.human_approval_required = False
        self.actions_taken = []
        self.actions_blocked = []

    def add_step(self, step_name, status, output=None):
        self.steps_executed.append({
            "step": step_name,
            "status": status,
            "output": output,
            "time": datetime.datetime.now().strftime("%H:%M:%S"),
        })

    def complete(self, status="COMPLETED"):
        self.completed_at = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.status = status

    def to_dict(self):
        return {
            "playbook": self.playbook_name,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "status": self.status,
            "steps_executed": self.steps_executed,
            "human_approval_required": self.human_approval_required,
            "actions_taken": self.actions_taken,
            "actions_blocked": self.actions_blocked,
        }


class PlaybookEngine:
    """
    Executes SOAR playbooks based on alert triggers.

    DESIGN PATTERN: "Chain of Responsibility"
    Each playbook is a function that receives an alert and executes steps.
    The engine routes alerts to the correct playbook based on rule_name.

    HUMAN-IN-THE-LOOP (HITL) IMPLEMENTATION:
    For high-risk actions, the playbook PAUSES and asks the analyst.
    If running in automated mode (cron job, no terminal), defaults to DENY.
    If running interactively, prompts for Y/N approval.

    This is the correct design for production SOAR systems.
    """

    def __init__(self, dry_run=True, require_approval=True, analyst="SOC-AUTO"):
        """
        Args:
            dry_run:          If True, simulate firewall changes (safe for learning)
            require_approval: If True, pause and ask human before high-risk actions
            analyst:          Name of analyst running this session
        """
        self.dry_run = dry_run
        self.require_approval = require_approval
        self.analyst = analyst

        # Route: rule_name -> playbook function
        self.playbook_registry = {
            "PORT_SCAN_DETECTED":   self.playbook_port_scan,
            "SSH_BRUTE_FORCE":      self.playbook_brute_force,
            "BRUTE_FORCE_SUCCESS":  self.playbook_account_compromise,
        }

    def _request_human_approval(self, action_description, risk_level="HIGH"):
        """
        Pause playbook and request analyst approval for a high-risk action.

        TEACHING: This is called a "Human Approval Gate" in SOAR design.
        Without these gates, automation can cause irreversible damage.

        In production:
        - Interactive SOC console: pop-up dialog
        - Unattended automation: auto-deny + create ticket for human review
        - PagerDuty integration: page on-call analyst who approves via app
        """
        if not self.require_approval:
            print(f"\n  [AUTO-APPROVED] {action_description}")
            print(f"  (require_approval=False -- no human gate)")
            return True

        print(f"\n  {'!'*58}")
        print(f"  HUMAN APPROVAL REQUIRED")
        print(f"  Risk Level: {risk_level}")
        print(f"  Action: {action_description}")
        print(f"  {'!'*58}")
        print(f"\n  TEACHING: Why do we stop here?")
        print(f"  This action modifies firewall rules / system state.")
        print(f"  If the alert was a FALSE POSITIVE, this causes damage.")
        print(f"  A human must verify before proceeding.")
        print()

        try:
            response = input(f"  Approve this action? (y/n): ").strip().lower()
            approved = response == "y"
        except (EOFError, KeyboardInterrupt):
            # Non-interactive mode (pipe, cron): default to DENY
            approved = False
            print(f"  Non-interactive mode: DENIED by default (safe choice)")

        if approved:
            print(f"  [APPROVED] by {self.analyst}")
            _write_audit("HUMAN_APPROVAL", "APPROVED",
                        f"action={action_description[:60]} | analyst={self.analyst}", "MANUAL")
        else:
            print(f"  [DENIED] Action blocked. Ticket escalated to Tier 2.")
            _write_audit("HUMAN_APPROVAL", "DENIED",
                        f"action={action_description[:60]} | analyst={self.analyst}", "MANUAL")

        return approved

    # =========================================================================
    # PLAYBOOK 1: Port Scan Response
    # =========================================================================

    def playbook_port_scan(self, alert, report=None):
        """
        Response playbook for PORT_SCAN_DETECTED alerts.

        LOGIC:
        Port scans are reconnaissance -- serious but not yet an attack.
        We WATCH and ENRICH but don't auto-block (too many false positives).
        Port scans can come from: nmap users, vulnerability scanners,
        monitoring tools, load balancers. Auto-blocking causes disruption.

        STEPS:
        1. Enrich the IP (threat intel)
        2. Log incident ticket
        3. Alert SOC dashboard
        4. If threat intel score is very high: request approval to block
        """
        result = PlaybookResult("PB-001: Port Scan Response")
        ip = alert.get("source_ip", "unknown")

        print(f"\n  {'='*58}")
        print(f"  PLAYBOOK: PB-001 -- Port Scan Response")
        print(f"  Trigger: {alert.get('alert_id')} | IP: {ip}")
        print(f"  {'='*58}")

        # STEP 1: Enrich
        print(f"\n  [STEP 1/4] Enriching threat intelligence for {ip}...")
        intel = enrich_threat(ip, alert.get("alert_id"))
        result.add_step("ENRICH_THREAT", "SUCCESS", intel)

        # STEP 2: Log incident
        print(f"\n  [STEP 2/4] Creating incident ticket...")
        incident = log_incident(alert, report, severity_override="MEDIUM")
        result.add_step("LOG_INCIDENT", "SUCCESS", incident["incident_id"])
        result.actions_taken.append(f"Incident {incident['incident_id']} created")

        # STEP 3: Alert
        print(f"\n  [STEP 3/4] Notifying SOC team...")
        alert_system(
            incident["incident_id"], "MEDIUM",
            f"Port scan from {ip} (abuse score: {intel['abuse_score']}/100)",
            channels=["SLACK", "DASHBOARD"]
        )
        result.add_step("ALERT_SYSTEM", "SUCCESS", "SLACK + DASHBOARD")
        result.actions_taken.append("SOC team notified via Slack")

        # STEP 4: Conditional block (only if very high confidence)
        print(f"\n  [STEP 4/4] Evaluating block decision...")
        if intel["abuse_score"] >= 90:
            print(f"  Abuse score {intel['abuse_score']}/100 >= 90 threshold.")
            print(f"  Elevated confidence justifies blocking.")

            approved = self._request_human_approval(
                f"Block IP {ip} (port scanner, abuse score: {intel['abuse_score']})",
                risk_level="MEDIUM"
            )
            if approved:
                block_result = block_ip(
                    ip, reason=f"Port scanner: {intel['known_as']}",
                    alert_id=alert.get("alert_id"), dry_run=self.dry_run
                )
                result.add_step("BLOCK_IP", block_result["status"], ip)
                result.actions_taken.append(f"IP {ip} blocked")
            else:
                result.add_step("BLOCK_IP", "DENIED_BY_HUMAN", ip)
                result.actions_blocked.append(f"Block {ip} (analyst denied)")
        else:
            print(f"  Abuse score {intel['abuse_score']}/100 < 90 threshold.")
            print(f"  Recommendation: Monitor only. Do not auto-block.")
            print(f"  [LESSON]: Low abuse score = could be legitimate scanner (Qualys, Nessus)")
            result.add_step("BLOCK_IP", "SKIPPED_LOW_CONFIDENCE", ip)

        result.complete()
        return result

    # =========================================================================
    # PLAYBOOK 2: Brute Force Response
    # =========================================================================

    def playbook_brute_force(self, alert, report=None):
        """
        Response playbook for SSH_BRUTE_FORCE alerts.

        LOGIC:
        Brute force is an active attack. We have higher confidence.
        Still enrich first -- confirm it's not a security scanner.
        Block with human approval if abuse score is high.

        STEPS:
        1. Enrich IP
        2. Log CRITICAL incident
        3. Alert SOC + management
        4. Enrich: check if success was detected (account compromise?)
        5. Request approval to block
        """
        result = PlaybookResult("PB-002: SSH Brute Force Response")
        ip = alert.get("source_ip", "unknown")
        is_wordlist = alert.get("is_wordlist_attack", False)

        print(f"\n  {'='*58}")
        print(f"  PLAYBOOK: PB-002 -- SSH Brute Force Response")
        print(f"  Trigger: {alert.get('alert_id')} | IP: {ip}")
        print(f"  Wordlist attack: {is_wordlist}")
        print(f"  {'='*58}")

        # STEP 1: Enrich
        print(f"\n  [STEP 1/5] Enriching threat intelligence...")
        intel = enrich_threat(ip, alert.get("alert_id"))
        result.add_step("ENRICH_THREAT", "SUCCESS", intel)

        # STEP 2: Log incident (HIGH severity -- active attack)
        print(f"\n  [STEP 2/5] Creating HIGH severity incident...")
        incident = log_incident(alert, report, severity_override="HIGH")
        result.add_step("LOG_INCIDENT", "SUCCESS", incident["incident_id"])
        result.actions_taken.append(f"Incident {incident['incident_id']} created (HIGH)")

        # STEP 3: Alert through multiple channels
        print(f"\n  [STEP 3/5] Alerting SOC team (multiple channels)...")
        channels = ["SLACK", "EMAIL", "DASHBOARD"]
        if is_wordlist:
            # Wordlist attack = higher urgency = add PagerDuty
            channels.append("PAGERDUTY")
            print(f"  Wordlist attack detected -- escalating to PagerDuty")
        alert_system(
            incident["incident_id"], "HIGH",
            f"Active SSH brute force from {ip}. "
            f"{'Wordlist attack -- multiple accounts targeted.' if is_wordlist else ''}",
            channels=channels
        )
        result.add_step("ALERT_SYSTEM", "SUCCESS", str(channels))

        # STEP 4: Contextual enrichment check
        print(f"\n  [STEP 4/5] Checking for correlated compromise...")
        correlated = alert.get("correlated_alert_ids", [])
        if correlated:
            print(f"  Correlated alerts found: {correlated}")
            print(f"  Multi-stage attack confirmed. Elevating urgency.")
            result.add_step("CORRELATION_CHECK", "ESCALATED", str(correlated))

        # STEP 5: Block decision
        print(f"\n  [STEP 5/5] Evaluating IP block...")
        print(f"  Abuse score: {intel['abuse_score']}/100")
        print(f"  Block confidence: {intel['block_confidence']}")

        block_reason = (
            f"SSH brute force: {alert.get('failure_count', '?')} failures. "
            f"Threat intel: {intel.get('known_as', 'unknown')}"
        )

        approved = self._request_human_approval(
            f"Block IP {ip} at firewall (active brute force attacker)",
            risk_level="HIGH"
        )
        if approved:
            block_result = block_ip(
                ip, reason=block_reason,
                alert_id=alert.get("alert_id"),
                approved_by=self.analyst,
                dry_run=self.dry_run
            )
            result.add_step("BLOCK_IP", block_result["status"], ip)
            result.actions_taken.append(f"IP {ip} blocked ({block_result['status']})")
        else:
            result.add_step("BLOCK_IP", "DENIED_BY_HUMAN", ip)
            result.actions_blocked.append(f"Block {ip} denied -- manual investigation required")
            print(f"\n  NOTE: IP not blocked. Incident ticket open for manual investigation.")

        result.complete()
        return result

    # =========================================================================
    # PLAYBOOK 3: Account Compromise Response
    # =========================================================================

    def playbook_account_compromise(self, alert, report=None):
        """
        Response playbook for BRUTE_FORCE_SUCCESS -- the most critical scenario.

        LOGIC:
        Account compromise is a CONFIRMED BREACH. Every second counts.
        This playbook is the most aggressive:
        - Multiple notifications simultaneously
        - Block IP immediately (still with approval, but faster flow)
        - Explicit IR escalation
        - Preserve evidence instructions

        INCIDENT RESPONSE (IR) PHASES:
        1. CONTAINMENT: Stop the bleeding (block IP, lock account)
        2. ERADICATION: Remove attacker access (rotate creds, kill sessions)
        3. RECOVERY: Restore normal operations
        4. LESSONS LEARNED: Post-incident review

        This playbook handles CONTAINMENT only.
        Eradication and Recovery require human IR teams.
        """
        result = PlaybookResult("PB-003: Account Compromise Response")
        ip = alert.get("source_ip", "unknown")
        compromised_user = alert.get("successful_username", "unknown")

        print(f"\n  {'='*58}")
        print(f"  PLAYBOOK: PB-003 -- ACCOUNT COMPROMISE RESPONSE")
        print(f"  *** THIS IS THE MOST CRITICAL PLAYBOOK ***")
        print(f"  Trigger: {alert.get('alert_id')} | IP: {ip}")
        print(f"  Compromised Account: {compromised_user}")
        print(f"  {'='*58}")
        print(f"\n  [!!!] CONFIRMED BREACH. Every second of delayed response")
        print(f"        increases attacker dwell time and potential damage.")

        # STEP 1: Simultaneous notifications (don't wait -- time critical)
        print(f"\n  [STEP 1/5] Immediate multi-channel alerting...")
        incident_id = f"INC-CRITICAL-{datetime.datetime.now().strftime('%H%M%S')}"
        alert_system(
            incident_id, "CRITICAL",
            f"CONFIRMED BREACH: Account '{compromised_user}' compromised "
            f"from {ip} after brute force attack. Immediate IR required.",
            channels=["PAGERDUTY", "SLACK", "EMAIL", "SMS"]
        )
        result.add_step("EMERGENCY_ALERT", "SUCCESS", "All channels notified")
        result.actions_taken.append("Emergency alerts sent (PagerDuty + Slack + Email + SMS)")

        # STEP 2: Log CRITICAL incident with full context
        print(f"\n  [STEP 2/5] Creating CRITICAL incident record...")
        incident = log_incident(alert, report, severity_override="CRITICAL")
        result.add_step("LOG_INCIDENT", "SUCCESS", incident["incident_id"])
        result.actions_taken.append(f"Critical incident {incident['incident_id']} created")

        # STEP 3: Enrich threat intel
        print(f"\n  [STEP 3/5] Enriching attacker IP for attribution...")
        intel = enrich_threat(ip, alert.get("alert_id"))
        result.add_step("ENRICH_THREAT", "SUCCESS", intel)

        # STEP 4: Block IP -- high confidence, account already compromised
        print(f"\n  [STEP 4/5] IP block -- active attacker with confirmed access...")
        print(f"  NOTE: Account already compromised. Blocking IP prevents")
        print(f"        further exploitation (lateral movement, persistence).")

        approved = self._request_human_approval(
            f"URGENT: Block {ip} -- active attacker has compromised '{compromised_user}'",
            risk_level="CRITICAL"
        )
        if approved:
            block_result = block_ip(
                ip,
                reason=f"Account compromise: {compromised_user} accessed by attacker. CRITICAL.",
                alert_id=alert.get("alert_id"),
                approved_by=self.analyst,
                dry_run=self.dry_run
            )
            result.add_step("BLOCK_IP", block_result["status"], ip)
            result.actions_taken.append(f"Attacker IP {ip} BLOCKED")
        else:
            result.add_step("BLOCK_IP", "DENIED", ip)
            result.actions_blocked.append(f"IP not blocked -- manual IR team must block immediately")

        # STEP 5: IR handoff checklist
        print(f"\n  [STEP 5/5] IR handoff and evidence preservation checklist...")
        ir_checklist = [
            f"Lock account '{compromised_user}' in Active Directory / IAM",
            "Kill all active SSH sessions from this IP: 'pkill -u root -9'",
            f"Preserve auth logs: cp /var/log/auth.log /secure-storage/incident-{incident['incident_id']}.log",
            "Run 'last' and 'w' commands to check active sessions",
            "Check /root/.ssh/authorized_keys for backdoors",
            "Check crontab -l for persistence mechanisms",
            "Review /tmp and /var/tmp for malicious files",
            "Capture memory image if host forensics required",
            "Notify CISO + Legal + HR if PII may be at risk",
        ]

        print(f"\n  IR HANDOFF CHECKLIST (for human responder):")
        for i, item in enumerate(ir_checklist, 1):
            print(f"  {i:2}. {item}")

        result.add_step("IR_HANDOFF", "CHECKLIST_PROVIDED", ir_checklist)

        result.complete()
        return result

    # =========================================================================
    # MAIN DISPATCH
    # =========================================================================

    def run_playbook(self, alert, report=None):
        """
        Route an alert to the correct playbook and execute it.

        This is the main entry point for the SOAR engine.
        In production, this runs every time a new alert arrives.
        """
        rule_name = alert.get("rule_name", "UNKNOWN")
        playbook_fn = self.playbook_registry.get(rule_name)

        if not playbook_fn:
            print(f"\n  [SOAR] No playbook registered for rule: {rule_name}")
            print(f"         Logging incident and alerting for manual triage.")
            # Fallback: log + alert for manual handling
            log_incident(alert, report)
            return PlaybookResult(f"PB-UNKNOWN: {rule_name}")

        _write_audit("PLAYBOOK_START", "RUNNING",
                    f"rule={rule_name} | ip={alert.get('source_ip')} | "
                    f"alert={alert.get('alert_id')}", alert.get("alert_id", "?"))

        result = playbook_fn(alert, report)

        _write_audit("PLAYBOOK_COMPLETE", result.status,
                    f"playbook={result.playbook_name} | "
                    f"steps={len(result.steps_executed)} | "
                    f"actions_taken={len(result.actions_taken)}",
                    alert.get("alert_id", "?"))

        return result

    def run_all_alerts(self, alerts, report=None):
        """
        Process all alerts from a detection run through the SOAR engine.
        Sorts by severity (CRITICAL first) to prioritize response.
        """
        # Sort CRITICAL first, then HIGH, MEDIUM, LOW
        priority_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_alerts = sorted(
            alerts,
            key=lambda a: priority_order.get(a.get("severity", "INFO"), 99)
        )

        results = []
        for alert in sorted_alerts:
            print(f"\n{'#'*62}")
            print(f"  Processing: {alert.get('alert_id')} | "
                  f"{alert.get('rule_name')} | {alert.get('severity')}")
            print(f"{'#'*62}")
            result = self.run_playbook(alert, report)
            results.append(result.to_dict())

        return results
