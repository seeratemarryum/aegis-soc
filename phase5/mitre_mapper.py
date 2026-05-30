"""
=============================================================================
SOC ANALYST TRAINING -- PHASE 5: MITRE ATT&CK MAPPER
=============================================================================

WHAT IS MITRE ATT&CK?
----------------------
ATT&CK = Adversarial Tactics, Techniques, and Common Knowledge

It is the global standard knowledge base of how real attackers operate.
Published by MITRE Corporation, used by every major SOC, vendor, and
government security team on Earth.

STRUCTURE:
  Tactic    = The "WHY" (what goal is the attacker trying to achieve?)
  Technique = The "HOW" (what specific method are they using?)
  Sub-tech  = A specific variant of a technique

EXAMPLE:
  Tactic:    TA0006 - Credential Access  (attacker wants passwords)
  Technique: T1110   - Brute Force       (how they get passwords)
  Sub-tech:  T1110.001 - Password Guessing (specific variant)

WHY EVERY SOC USES ATT&CK:
  1. COMMON LANGUAGE: "T1110.001" means the same thing in the US, UK, Singapore
  2. THREAT INTELLIGENCE: "APT28 uses T1566 (Phishing)" helps prioritize defenses
  3. DETECTION GAPS: "We have no rules for T1059.003" = blind spot in detection
  4. REPORTING: Executives understand "credential access" better than log details
  5. COMPLIANCE: Many frameworks (NIST, ISO 27001) reference ATT&CK

THE 14 TACTICS (the attack lifecycle):
  TA0043 Reconnaissance        -- Learning about the target
  TA0042 Resource Development  -- Setting up attack infrastructure
  TA0001 Initial Access        -- Getting first foothold
  TA0002 Execution             -- Running malicious code
  TA0003 Persistence           -- Staying in the system
  TA0004 Privilege Escalation  -- Getting higher permissions
  TA0005 Defense Evasion       -- Hiding from detection
  TA0006 Credential Access     -- Stealing passwords/tokens
  TA0007 Discovery             -- Learning the internal network
  TA0008 Lateral Movement      -- Moving to other systems
  TA0009 Collection            -- Gathering data to steal
  TA0010 Exfiltration          -- Sending stolen data out
  TA0011 Command and Control   -- Remote control of compromised system
  TA0040 Impact                -- Destroying/encrypting/disrupting data

IN OUR SIMULATION:
  The attack we've been detecting maps to:
  1. TA0043/T1046  -- Reconnaissance (port scan)
  2. TA0006/T1110  -- Credential Access (brute force)
  3. TA0001/T1078  -- Initial Access (if brute force succeeded)
=============================================================================
"""


# =============================================================================
# THE ATT&CK KNOWLEDGE BASE
# This is a subset of the real ATT&CK matrix, focused on SSH/network attacks.
# Full matrix: https://attack.mitre.org/
# =============================================================================

ATTACK_TECHNIQUES = {
    "T1046": {
        "id": "T1046",
        "name": "Network Service Discovery",
        "tactic": "TA0007",
        "tactic_name": "Discovery",
        "description": (
            "Adversaries may attempt to get a listing of services running on "
            "remote hosts and local network infrastructure devices. Common methods "
            "include port scanning with tools like nmap."
        ),
        "detection_in_logs": "Rapid 'Connection closed' entries from one IP in SSH logs.",
        "real_world_examples": [
            "APT28 uses nmap for initial network reconnaissance",
            "FIN7 performs port scanning before targeting POS systems",
        ],
        "mitigations": [
            "Network segmentation (reduce what attacker can see)",
            "Firewall rules to block port scanning",
            "IDS/IPS with scan detection signatures",
        ],
        "data_sources": ["Network Traffic", "Process creation logs"],
        "severity_weight": 3,  # Out of 10
    },

    "T1110": {
        "id": "T1110",
        "name": "Brute Force",
        "tactic": "TA0006",
        "tactic_name": "Credential Access",
        "description": (
            "Adversaries may use brute force techniques to gain access to accounts "
            "when passwords are unknown or when password hashes are obtained. "
            "Without knowledge of the password, an adversary may opt to "
            "systematically guess the password using a repetitive or iterative mechanism."
        ),
        "detection_in_logs": "Multiple 'Failed password' entries from same IP in short time window.",
        "real_world_examples": [
            "Iranian APT groups use Hydra for SSH brute forcing",
            "Multiple ransomware groups brute force RDP (port 3389)",
            "Mirai botnet uses brute force to compromise IoT devices",
        ],
        "mitigations": [
            "Account lockout policies (lock after 5 failures)",
            "Multi-factor authentication (MFA) -- brute force useless with MFA",
            "SSH key authentication (disable password auth entirely)",
            "Fail2ban -- automatically block IPs after N failures",
            "Rate limiting at the network level",
        ],
        "data_sources": ["Authentication logs (/var/log/auth.log)", "Windows Event ID 4625"],
        "severity_weight": 7,
    },

    "T1110.001": {
        "id": "T1110.001",
        "name": "Brute Force: Password Guessing",
        "parent": "T1110",
        "tactic": "TA0006",
        "tactic_name": "Credential Access",
        "description": (
            "Adversaries with no prior knowledge of legitimate credentials within "
            "the system may guess passwords to attempt access to accounts. "
            "Without knowledge of the password, an adversary may opt to "
            "systematically guess using common passwords (password, 123456, admin)."
        ),
        "detection_in_logs": "Same username, many failed passwords. Wordlists like rockyou.txt.",
        "real_world_examples": [
            "Script kiddies use Hydra with rockyou.txt wordlist",
            "Lazarus Group password spray against financial institutions",
        ],
        "mitigations": ["Same as T1110 plus: block common passwords via password policy"],
        "data_sources": ["SSH auth logs", "Windows Event ID 4625"],
        "severity_weight": 7,
    },

    "T1110.003": {
        "id": "T1110.003",
        "name": "Brute Force: Password Spraying",
        "parent": "T1110",
        "tactic": "TA0006",
        "tactic_name": "Credential Access",
        "description": (
            "Adversaries may use a single or small list of commonly used passwords "
            "against many different accounts to attempt to acquire valid account "
            "credentials. Password spraying avoids lockout by trying one password "
            "across many accounts."
        ),
        "detection_in_logs": "One IP, many different usernames, 1-2 attempts per username.",
        "real_world_examples": [
            "NOBELIUM (SolarWinds attackers) used password spray against Microsoft 365",
            "APT33 used password spray against aerospace sector",
        ],
        "mitigations": [
            "MFA (most important defense)",
            "Detect by username diversity per source IP",
            "Block common passwords organization-wide",
        ],
        "data_sources": ["Authentication logs", "Azure AD Sign-in logs"],
        "severity_weight": 8,  # Higher because harder to detect
    },

    "T1078": {
        "id": "T1078",
        "name": "Valid Accounts",
        "tactic": "TA0001",
        "tactic_name": "Initial Access",
        "description": (
            "Adversaries may obtain and abuse credentials of existing accounts as "
            "a means of gaining Initial Access, Persistence, Privilege Escalation, "
            "or Defense Evasion. Compromised credentials may be used to bypass "
            "access controls placed on various resources on systems."
        ),
        "detection_in_logs": "Successful login AFTER multiple failures. Or login from unusual IP.",
        "real_world_examples": [
            "Most ransomware groups gain access via stolen/brute-forced credentials",
            "2021 Colonial Pipeline attack started with compromised VPN credentials",
        ],
        "mitigations": [
            "MFA on all accounts",
            "Behavioral analytics on logins (unusual time, location)",
            "Privileged access management (PAM)",
            "Regular credential audits",
        ],
        "data_sources": ["Authentication logs", "VPN logs", "Windows Event ID 4624"],
        "severity_weight": 10,  # Maximum -- attacker has valid access
    },

    "T1021.004": {
        "id": "T1021.004",
        "name": "Remote Services: SSH",
        "tactic": "TA0008",
        "tactic_name": "Lateral Movement",
        "description": (
            "Adversaries may use Valid Accounts to log into remote machines using "
            "Secure Shell (SSH). The adversary may then perform actions as the "
            "logged-on user."
        ),
        "detection_in_logs": "Successful SSH login from unexpected IP or at unusual time.",
        "real_world_examples": [
            "APT41 uses SSH for lateral movement in compromised networks",
        ],
        "mitigations": [
            "Restrict SSH to known IPs via firewall/security groups",
            "Use jump hosts / bastion hosts for SSH access",
            "Log and alert on all SSH connections",
        ],
        "data_sources": ["SSH auth logs", "Network connection logs"],
        "severity_weight": 8,
    },
}

# Map our internal rule names to ATT&CK technique IDs
RULE_TO_ATTACK_MAP = {
    "PORT_SCAN_DETECTED":   ["T1046"],
    "SSH_BRUTE_FORCE":      ["T1110", "T1110.001"],
    "BRUTE_FORCE_SUCCESS":  ["T1078", "T1021.004"],
    "PASSWORD_SPRAY":       ["T1110", "T1110.003"],
}

# Map rule names to MITRE Tactics
RULE_TO_TACTIC = {
    "PORT_SCAN_DETECTED":   "TA0007 - Discovery",
    "SSH_BRUTE_FORCE":      "TA0006 - Credential Access",
    "BRUTE_FORCE_SUCCESS":  "TA0001 - Initial Access",
    "PASSWORD_SPRAY":       "TA0006 - Credential Access",
}


def get_techniques_for_rule(rule_name):
    """
    Return ATT&CK technique objects for a given detection rule name.

    This is the "mapping" function that connects our detection output
    to the global ATT&CK framework language.
    """
    technique_ids = RULE_TO_ATTACK_MAP.get(rule_name, [])
    return [ATTACK_TECHNIQUES[tid] for tid in technique_ids if tid in ATTACK_TECHNIQUES]


def get_tactic_for_rule(rule_name):
    return RULE_TO_TACTIC.get(rule_name, "Unknown Tactic")


def get_attack_chain_from_alerts(alerts):
    """
    Given a list of alerts, construct the ATT&CK kill chain they represent.

    CONCEPT: "Kill Chain" = ordered sequence of tactics an attacker uses.
    By mapping each alert to a tactic, we reconstruct the attack narrative.

    Returns an ordered list of (tactic, technique, alert) tuples.
    """
    chain = []
    tactic_order = [
        "TA0043", "TA0007",  # Recon, Discovery
        "TA0006",            # Credential Access
        "TA0001",            # Initial Access
        "TA0008",            # Lateral Movement
    ]

    tactic_alerts = {}
    for alert in alerts:
        rule = alert.get("rule_name", "")
        techs = get_techniques_for_rule(rule)
        for tech in techs:
            tactic = tech["tactic"]
            if tactic not in tactic_alerts:
                tactic_alerts[tactic] = []
            tactic_alerts[tactic].append((tech, alert))

    # Build chain in correct tactic order
    for tactic in tactic_order:
        if tactic in tactic_alerts:
            for tech, alert in tactic_alerts[tactic]:
                chain.append({
                    "tactic_id": tactic,
                    "tactic_name": tech["tactic_name"],
                    "technique_id": tech["id"],
                    "technique_name": tech["name"],
                    "alert_id": alert.get("alert_id", "?"),
                    "severity": alert.get("severity", "?"),
                    "source_ip": alert.get("source_ip", "?"),
                    "timestamp": alert.get("detection_timestamp", "?"),
                })

    return chain
