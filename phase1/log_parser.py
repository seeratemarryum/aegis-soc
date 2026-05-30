"""
=============================================================================
SOC ANALYST TRAINING — PHASE 1: LOG PARSER
=============================================================================

WHAT THIS FILE DOES:
    Takes raw, unstructured log text and converts it into structured JSON.
    This is called "log normalization" — a foundational step in every SIEM.

WHY PARSING MATTERS IN SOC:
    Raw log:  "May 29 02:14:37 prod-webserver-01 sshd[44231]: Failed password for root from 185.220.101.42 port 52341 ssh2"
    
    After parsing:
    {
        "timestamp": "May 29 02:14:37",
        "hostname": "prod-webserver-01",
        "process": "sshd",
        "pid": 44231,
        "event_type": "FAILED_LOGIN",
        "username": "root",
        "source_ip": "185.220.101.42",
        "source_port": 52341,
        "protocol": "ssh2",
        "severity": "MEDIUM",
        "is_suspicious_user": true
    }
    
    WHY STRUCTURE MATTERS:
    - You cannot run "GROUP BY source_ip" on raw text efficiently
    - Detection rules need field-level access (if ip == X and count > 5)
    - ML models need numbers, not strings
    - Dashboards need structured data to display correctly
    
    REAL-WORLD TOOL THAT DOES THIS:
    - Logstash (part of ELK Stack) — uses "grok" patterns for parsing
    - Splunk — uses "field extraction" with regex
    - We're building the same thing from scratch so you understand it deeply.

HOW PARSING WORKS (The Technical Concept):
    We use REGULAR EXPRESSIONS (regex) — a pattern matching language.
    Think of regex like a template: "Find text that looks like [timestamp] [hostname] sshd..."
    
    Example regex breakdown:
    (\\w{3}\\s+\\d{1,2}\\s\\d{2}:\\d{2}:\\d{2})   <- matches "May 29 14:23:01"
    \\s+(\\S+)                                  <- matches hostname
    \\s+sshd\\[(\\d+)\\]                          <- matches "sshd[12345]"
=============================================================================
"""

import re
import json
import datetime
from collections import defaultdict


# =============================================================================
# KNOWN SUSPICIOUS INDICATORS
# SOC Concept: We encode "threat intelligence" directly into the parser.
# This is called "indicator enrichment" — adding context to raw events.
# =============================================================================

# Users that should NEVER be logging in remotely
# SOC TIP: "root" via SSH should be disabled entirely (PermitRootLogin no)
HIGH_RISK_USERNAMES = {
    "root", "admin", "administrator", "guest", "test",
    "oracle", "postgres", "mysql", "ftpuser", "pi"
}

# Usernames that definitely don't exist on our server (from VALID_USERS in generator)
# In a real SOC, you'd pull this from your Active Directory or /etc/passwd
KNOWN_VALID_USERS = {"alice", "bob", "sysadmin", "ubuntu"}

# Internal IP ranges — logins from these are inherently more trusted
# CIDR ranges: 10.x.x.x and 192.168.x.x are private (RFC 1918)
TRUSTED_IP_PREFIXES = ("10.", "192.168.", "172.16.", "172.17.", "172.18.")


# =============================================================================
# REGEX PATTERNS
# Each pattern matches a specific SSH log format.
# We define multiple patterns because log formats can vary slightly.
# =============================================================================

# Pattern 1: Failed password attempt
# Matches: "May 29 02:14:37 hostname sshd[PID]: Failed password for USERNAME from IP port PORT ssh2"
PATTERN_FAILED_PASSWORD = re.compile(
    r"(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"   # timestamp group
    r"\s+(?P<hostname>\S+)"                                     # hostname
    r"\s+sshd\[(?P<pid>\d+)\]"                                 # process ID
    r":\s+Failed password for (?P<username>\S+)"               # username
    r"\s+from (?P<source_ip>[\d.]+)"                           # source IP
    r"\s+port (?P<source_port>\d+)"                            # source port
    r"\s+(?P<protocol>\S+)"                                    # protocol (ssh2)
)

# Pattern 2: Successful login
# Matches: "May 29 09:05:12 hostname sshd[PID]: Accepted password for USERNAME from IP port PORT ssh2"
PATTERN_ACCEPTED_PASSWORD = re.compile(
    r"(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
    r"\s+(?P<hostname>\S+)"
    r"\s+sshd\[(?P<pid>\d+)\]"
    r":\s+Accepted password for (?P<username>\S+)"
    r"\s+from (?P<source_ip>[\d.]+)"
    r"\s+port (?P<source_port>\d+)"
    r"\s+(?P<protocol>\S+)"
)

# Pattern 3: Invalid user attempt
# Matches: "May 29 02:14:38 hostname sshd[PID]: Invalid user USERNAME from IP port PORT"
PATTERN_INVALID_USER = re.compile(
    r"(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
    r"\s+(?P<hostname>\S+)"
    r"\s+sshd\[(?P<pid>\d+)\]"
    r":\s+Invalid user (?P<username>\S+)"
    r"\s+from (?P<source_ip>[\d.]+)"
    r"\s+port (?P<source_port>\d+)"
)

# Pattern 4: Connection closed (rapid connect/disconnect = scan behavior)
PATTERN_CONNECTION_CLOSED = re.compile(
    r"(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
    r"\s+(?P<hostname>\S+)"
    r"\s+sshd\[(?P<pid>\d+)\]"
    r":\s+Connection closed by (?P<source_ip>[\d.]+)"
)


# =============================================================================
# ENRICHMENT FUNCTIONS
# SOC Concept: Raw events become "enriched" with context and risk scores.
# This is what makes alerts actionable vs just noise.
# =============================================================================

def is_internal_ip(ip_address):
    """
    Check if an IP address is from a private/trusted network range.
    
    SOC INSIGHT: Internal IP attackers are WORSE than external ones (insider threat),
    but the CONTEXT changes. An external IP brute forcing SSH = script kiddie.
    An internal IP doing it = compromised machine or malicious insider.
    """
    return ip_address.startswith(TRUSTED_IP_PREFIXES)


def calculate_severity(event_type, username, source_ip):
    """
    Assign a severity level to a log event.
    
    SOC INSIGHT: Not all failed logins are equal.
    - A regular user mistyping their password = LOW severity
    - "root" login attempt from unknown external IP at 3am = CRITICAL
    
    This function implements simple "risk scoring" — Phase 4 will do this with ML.
    
    Severity levels follow industry standard:
    CRITICAL > HIGH > MEDIUM > LOW > INFO
    """
    severity = "LOW"
    
    if event_type == "FAILED_LOGIN":
        severity = "LOW"  # Single failure is normal
        
        # Elevated risk: trying high-privilege accounts
        if username in HIGH_RISK_USERNAMES:
            severity = "MEDIUM"
        
        # External IP trying to brute force a privileged account = HIGH
        if username in HIGH_RISK_USERNAMES and not is_internal_ip(source_ip):
            severity = "HIGH"
    
    elif event_type == "INVALID_USER":
        # Invalid user from external = ALWAYS at least MEDIUM
        # (No legitimate external user would have a wrong username)
        severity = "MEDIUM"
        if not is_internal_ip(source_ip):
            severity = "HIGH"
    
    elif event_type == "SUCCESSFUL_LOGIN":
        # Successful login is INFO unless from external suspicious source
        severity = "INFO"
        if not is_internal_ip(source_ip):
            severity = "MEDIUM"  # External login: verify it's expected
    
    elif event_type == "CONNECTION_CLOSED":
        severity = "LOW"  # Alone it's low; patterns make it HIGH (Phase 2)
    
    return severity


def enrich_event(parsed_event):
    """
    Add contextual intelligence to a parsed log event.
    
    SOC CONCEPT: "Enrichment" = adding meaning beyond raw data.
    
    Real SIEM enrichment includes:
    - GeoIP lookup (what country is this IP from?)
    - Threat intelligence (is this IP in a blocklist?)
    - User directory lookup (what department is this user in?)
    - Historical behavior (has this IP connected before?)
    
    We do simple versions of these here. Phase 4 does it with ML.
    """
    if "source_ip" in parsed_event:
        parsed_event["is_internal_ip"] = is_internal_ip(parsed_event["source_ip"])
        parsed_event["is_trusted_source"] = parsed_event["is_internal_ip"]
    
    if "username" in parsed_event:
        parsed_event["is_known_valid_user"] = parsed_event["username"] in KNOWN_VALID_USERS
        parsed_event["is_high_risk_username"] = parsed_event["username"] in HIGH_RISK_USERNAMES
    
    # Add severity score
    if "event_type" in parsed_event:
        parsed_event["severity"] = calculate_severity(
            parsed_event["event_type"],
            parsed_event.get("username", ""),
            parsed_event.get("source_ip", "")
        )
    
    return parsed_event


# =============================================================================
# CORE PARSER FUNCTION
# =============================================================================

def parse_log_line(raw_line):
    """
    Parse a single raw log line into a structured dictionary.
    
    This is the HEART of the log parser. It tries each regex pattern
    and returns the first match, enriched with context.
    
    Returns:
        dict: Structured event data, or None if line doesn't match any pattern
    
    SOC PARALLEL: This is what Logstash's "grok" filter does.
    Grok patterns look like: %{SYSLOGTIMESTAMP:timestamp} %{HOSTNAME:hostname}...
    We're implementing the same concept in pure Python.
    """
    raw_line = raw_line.strip()
    
    if not raw_line:
        return None  # Skip empty lines
    
    # --- Try each pattern in order of specificity ---
    
    # Try: Failed password
    match = PATTERN_FAILED_PASSWORD.search(raw_line)
    if match:
        event = match.groupdict()
        event["event_type"] = "FAILED_LOGIN"
        event["raw_log"] = raw_line
        event["pid"] = int(event["pid"])
        event["source_port"] = int(event["source_port"])
        return enrich_event(event)
    
    # Try: Accepted password
    match = PATTERN_ACCEPTED_PASSWORD.search(raw_line)
    if match:
        event = match.groupdict()
        event["event_type"] = "SUCCESSFUL_LOGIN"
        event["raw_log"] = raw_line
        event["pid"] = int(event["pid"])
        event["source_port"] = int(event["source_port"])
        return enrich_event(event)
    
    # Try: Invalid user
    match = PATTERN_INVALID_USER.search(raw_line)
    if match:
        event = match.groupdict()
        event["event_type"] = "INVALID_USER"
        event["raw_log"] = raw_line
        event["pid"] = int(event["pid"])
        event["source_port"] = int(event["source_port"])
        return enrich_event(event)
    
    # Try: Connection closed
    match = PATTERN_CONNECTION_CLOSED.search(raw_line)
    if match:
        event = match.groupdict()
        event["event_type"] = "CONNECTION_CLOSED"
        event["raw_log"] = raw_line
        event["pid"] = int(event["pid"])
        return enrich_event(event)
    
    # If nothing matches — log it as unparsed (don't silently drop it!)
    # SOC TIP: Unknown log formats should NEVER be silently ignored.
    # They might be new attack vectors your parser doesn't recognize yet.
    return {
        "event_type": "UNPARSED",
        "raw_log": raw_line,
        "severity": "INFO",
        "parse_error": "No matching pattern found"
    }


def parse_log_file(log_file_path):
    """
    Parse an entire log file, returning list of structured events.
    
    Also generates a SUMMARY STATISTICS report — exactly what a
    SOC analyst looks at first when investigating a log file.
    
    Returns:
        tuple: (list of parsed events, summary statistics dict)
    """
    parsed_events = []
    stats = defaultdict(int)   # Automatic counter dictionary
    
    print("\n" + "="*60)
    print("  SOC ANALYST TRAINING — LOG PARSER")
    print("="*60)
    print(f"\n[+] Parsing log file: {log_file_path}")
    
    with open(log_file_path, "r") as f:
        for line_number, raw_line in enumerate(f, start=1):
            
            event = parse_log_line(raw_line)
            
            if event:
                event["line_number"] = line_number  # Track line for debugging
                parsed_events.append(event)
                
                # Track statistics
                stats[event["event_type"]] += 1
                if "severity" in event:
                    stats[f"severity_{event['severity']}"] += 1
    
    # Print parsing summary
    print(f"[OK] Parsed {len(parsed_events)} log entries")
    print(f"\n--- EVENT TYPE BREAKDOWN ---")
    for event_type in ["FAILED_LOGIN", "SUCCESSFUL_LOGIN", "INVALID_USER", "CONNECTION_CLOSED", "UNPARSED"]:
        count = stats.get(event_type, 0)
        bar = "|" * min(count, 40)
        print(f"  {event_type:<20} {count:>4}  {bar}")
    
    print(f"\n--- SEVERITY BREAKDOWN ---")
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = stats.get(f"severity_{severity}", 0)
        bar = "|" * min(count, 40)
        print(f"  {severity:<10} {count:>4}  {bar}")
    
    return parsed_events, dict(stats)


def save_parsed_events(events, output_file="parsed_events.json"):
    """
    Save structured events to JSON file.
    
    SOC INSIGHT: JSON is the universal language of SIEM systems.
    Splunk, Elasticsearch, QRadar all ingest JSON.
    Once you have structured JSON, you can:
    - Index it in a database for fast search
    - Feed it to ML models (Phase 4)
    - Display it on dashboards (Phase 7)
    - Run detection rules (Phase 2)
    """
    import os
    output_path = os.path.join(os.path.dirname(__file__), output_file)
    
    with open(output_path, "w") as f:
        json.dump(events, f, indent=2)
    
    print(f"\n[OK] Structured events saved: {output_path}")
    return output_path


# =============================================================================
# ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    import os
    
    log_file = os.path.join(os.path.dirname(__file__), "sample_auth.log")
    
    # Check if log file exists — if not, generate it first
    if not os.path.exists(log_file):
        print("[!] Log file not found. Run log_generator.py first!")
        print("    Command: python log_generator.py")
        exit(1)
    
    # Parse the file
    events, stats = parse_log_file(log_file)
    
    # Show first 5 parsed events so you can see what structured data looks like
    print("\n--- SAMPLE PARSED EVENTS (first 5) ---")
    for event in events[:5]:
        print(json.dumps(event, indent=2))
        print("---")
    
    # Show HIGH severity events — these are the ones SOC analysts investigate first
    print("\n--- HIGH/CRITICAL SEVERITY EVENTS ---")
    high_severity = [e for e in events if e.get("severity") in ("HIGH", "CRITICAL")]
    print(f"Found {len(high_severity)} high/critical events")
    for event in high_severity[:5]:
        print(f"  [{event['severity']}] {event['event_type']} | "
              f"User: {event.get('username', 'N/A')} | "
              f"IP: {event.get('source_ip', 'N/A')}")
    
    # Save structured JSON
    save_parsed_events(events)
    
    print("\n" + "="*60)
    print("  EXPERIMENTS FOR YOU TO TRY")
    print("="*60)
    print("""
  1. MODIFY severity thresholds:
     Open this file and change HIGH_RISK_USERNAMES set.
     Add "ubuntu" to it and re-run. Watch severity counts change.

  2. ADD YOUR OWN REGEX:
     Add a pattern for "Disconnected from" log entries.
     Hint: The pattern will look like PATTERN_CONNECTION_CLOSED but different keyword.

  3. EXAMINE THE JSON OUTPUT:
     Open parsed_events.json and look at the structure.
     Find an event where is_high_risk_username = true AND is_internal_ip = false.
     That's exactly what Phase 2 detection rules will automate.

  4. COUNT EVENTS PER IP:
     Using the JSON, manually count how many FAILED_LOGIN events
     come from a single IP. In Phase 2, we automate this detection.
    """)
