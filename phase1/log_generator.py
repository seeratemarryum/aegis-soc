"""
=============================================================================
SOC ANALYST TRAINING — PHASE 1: LOG GENERATOR
=============================================================================

WHAT THIS FILE DOES:
    Generates realistic SSH authentication logs — the kind you'd see on any
    Linux server running OpenSSH. These logs are the PRIMARY data source for
    detecting brute force attacks, credential stuffing, and unauthorized access.

WHY WE START HERE:
    You cannot detect attacks without data. In a real SOC, logs flow in from
    hundreds of sources (SIEM ingestion). We simulate that data first so we
    can build detection on top of it.

REAL-WORLD EQUIVALENT:
    This simulates what you'd see in: /var/log/auth.log (Ubuntu/Debian)
    Or in: /var/log/secure (CentOS/RHEL)

FORMAT OF A REAL SSH LOG LINE:
    May 29 14:23:01 webserver sshd[12345]: Failed password for root from 192.168.1.105 port 52341 ssh2
    │              │          │             │                                │             │
    │              │          │             │                                │             └─ port attacker used
    │              │          │             │                                └─ attacker IP
    │              │          │             └─ what happened
    │              │          └─ process ID of SSH daemon
    │              └─ hostname of YOUR server being attacked
    └─ timestamp
=============================================================================
"""

import random
import datetime
import json
import os


# =============================================================================
# CONFIGURATION — The variables you will EXPERIMENT with
# =============================================================================
# These control what your simulated environment looks like.
# Try changing these and observe how the log output changes.

# The hostname of the server being "attacked" in our simulation
# In real life, this comes from your actual server's hostname
SERVER_NAME = "prod-webserver-01"

# Legitimate users that actually exist on the system
# SOC TIP: Failed logins for NON-EXISTENT users are a BIG red flag
VALID_USERS = ["alice", "bob", "sysadmin", "ubuntu"]

# Users attackers commonly try (wordlist attacks)
# These are in every hacker's wordlist — attackers try them first
COMMON_ATTACK_USERS = ["root", "admin", "test", "guest", "oracle", "postgres", "ftpuser"]

# A mix of IPs: some are "normal" users, some are "attackers"
# In real detection, we'll learn to separate these
LEGITIMATE_IPS = ["10.0.0.5", "10.0.0.12", "192.168.1.50"]   # Internal trusted IPs
SUSPICIOUS_IPS = [
    "185.220.101.42",   # Known Tor exit node range (real attackers use Tor)
    "45.142.212.100",   # Eastern European VPS range (common attack source)
    "103.75.190.200",   # Asian botnets frequently use these ranges
    "198.51.100.73",    # TEST-NET (RFC 5737) — safe for simulation
    "203.0.113.88",     # TEST-NET (RFC 5737) — safe for simulation
]


# =============================================================================
# LOG EVENT TYPES
# SOC Concept: We categorize log events by outcome. This is called "event classification"
# =============================================================================

def generate_timestamp(base_time=None, offset_seconds=0):
    """
    Generate a realistic timestamp for a log entry.
    
    SOC INSIGHT: Timestamps are CRITICAL for:
    1. Correlating events across multiple systems (did the firewall block this IP
       before or after the SSH attempt?)
    2. Detecting time-based patterns (attacks at 3am = automated, not human)
    3. Legal/forensic chain of evidence
    
    Format: "May 29 14:23:01" — this is the standard syslog timestamp format
    """
    if base_time is None:
        base_time = datetime.datetime.now()
    
    event_time = base_time + datetime.timedelta(seconds=offset_seconds)
    
    # strftime formats the datetime into syslog format
    # %b = abbreviated month (May), %d = day, %H:%M:%S = time
    return event_time.strftime("%b %d %H:%M:%S")


def generate_failed_login(timestamp, username, source_ip):
    """
    Generate a FAILED authentication log entry.
    
    SOC INSIGHT: "Failed password" entries are the PRIMARY indicator of:
    - Brute force attacks (hundreds of failures in short time)
    - Credential stuffing (using leaked password lists)
    - Insider threats (legitimate user forgetting password)
    
    One failure = normal. 500 failures = INCIDENT.
    
    This is exactly what appears in /var/log/auth.log on real Linux systems.
    """
    # process_id simulates the SSH daemon's process ID
    # Each connection gets a unique PID — useful for correlation
    process_id = random.randint(10000, 65535)
    
    # Port is the SOURCE port on the attacker's machine (ephemeral port)
    # Note: This is NOT port 22 (that's the destination). Attackers connect FROM a random port.
    source_port = random.randint(1024, 65535)
    
    return (
        f"{timestamp} {SERVER_NAME} sshd[{process_id}]: "
        f"Failed password for {username} from {source_ip} port {source_port} ssh2"
    )


def generate_successful_login(timestamp, username, source_ip):
    """
    Generate a SUCCESSFUL authentication log entry.
    
    SOC INSIGHT: Successful logins from:
    - Known IPs at business hours = NORMAL
    - Unknown IPs at 3am = SUSPICIOUS (even if password correct!)
    - After 50 failures = DEFINITELY AN INCIDENT (attacker guessed password)
    
    This is why we correlate success AFTER failure — that's the key detection logic.
    """
    process_id = random.randint(10000, 65535)
    source_port = random.randint(1024, 65535)
    
    return (
        f"{timestamp} {SERVER_NAME} sshd[{process_id}]: "
        f"Accepted password for {username} from {source_ip} port {source_port} ssh2"
    )


def generate_invalid_user(timestamp, username, source_ip):
    """
    Generate an INVALID USER log entry.
    
    SOC INSIGHT: This is DIFFERENT from "Failed password"!
    - "Failed password for root" = user EXISTS, wrong password
    - "Invalid user hacker123" = user DOESN'T EXIST at all
    
    Invalid user attempts are ALWAYS suspicious because:
    1. Legitimate users know what account they have
    2. Attackers try random usernames from wordlists
    3. Zero false positives if you alert on unknown usernames
    """
    process_id = random.randint(10000, 65535)
    source_port = random.randint(1024, 65535)
    
    return (
        f"{timestamp} {SERVER_NAME} sshd[{process_id}]: "
        f"Invalid user {username} from {source_ip} port {source_port}"
    )


def generate_connection_closed(timestamp, source_ip):
    """
    Generate a connection closed log entry.
    
    SOC INSIGHT: Rapid open→fail→close cycles = automated attack tool
    A human typing a password takes 5-30 seconds. 
    A script can try 1000 passwords per second.
    """
    process_id = random.randint(10000, 65535)
    
    return (
        f"{timestamp} {SERVER_NAME} sshd[{process_id}]: "
        f"Connection closed by {source_ip}"
    )


# =============================================================================
# SCENARIO GENERATORS
# SOC Concept: Real-world attacks follow predictable PATTERNS (TTPs)
# TTP = Tactics, Techniques, and Procedures — used in MITRE ATT&CK framework
# =============================================================================

def simulate_brute_force_attack(base_time, source_ip, attempts=50):
    """
    Simulate a brute force SSH attack.
    
    WHAT AN ATTACKER IS DOING:
    - They have a tool (Hydra, Medusa, Ncrack) firing passwords automatically
    - The tool tries username/password combos from a wordlist
    - Speed: 10-1000 attempts per minute depending on network
    
    WHAT SOC SEES:
    - Hundreds of "Failed password" entries from same IP
    - Attempts happen in rapid succession (seconds apart)
    - Username rotates through common wordlist
    
    MITRE ATT&CK: T1110.001 — Brute Force: Password Guessing
    """
    logs = []
    
    for i in range(attempts):
        # Attacks happen FAST — typically 1-5 seconds between attempts
        # Real Hydra tool default: ~4 attempts per second
        offset = i * random.uniform(0.5, 3.0)  # 0.5 to 3 seconds between attempts
        timestamp = generate_timestamp(base_time, offset)
        
        # Attacker rotates through common usernames
        username = random.choice(COMMON_ATTACK_USERS)
        
        # 98% failure rate — realistic for brute force
        # Only 2% succeed (if they get lucky with common passwords)
        if random.random() < 0.98:
            logs.append(generate_failed_login(timestamp, username, source_ip))
        else:
            logs.append(generate_successful_login(timestamp, username, source_ip))
    
    return logs


def simulate_normal_traffic(base_time, duration_minutes=60):
    """
    Simulate legitimate user activity.
    
    WHY WE SIMULATE NORMAL TRAFFIC TOO:
    This is crucial for ML training in Phase 4. You cannot teach a model
    what's "anomalous" without showing it what's "normal" first.
    
    Normal traffic characteristics:
    - Low frequency (1-5 logins per hour per user)
    - Known usernames only
    - Consistent source IPs
    - Business hours pattern (8am-6pm)
    - High success rate
    """
    logs = []
    
    for _ in range(random.randint(10, 30)):  # 10-30 normal login events
        offset = random.uniform(0, duration_minutes * 60)
        timestamp = generate_timestamp(base_time, offset)
        
        username = random.choice(VALID_USERS)
        source_ip = random.choice(LEGITIMATE_IPS)
        
        # Normal users succeed 95% of the time (occasional typos)
        if random.random() < 0.95:
            logs.append(generate_successful_login(timestamp, username, source_ip))
        else:
            logs.append(generate_failed_login(timestamp, username, source_ip))
    
    return logs


def simulate_port_scan_precursor(base_time, source_ip):
    """
    Simulate connection probing before SSH attack.
    
    SOC INSIGHT: Real attackers typically:
    1. Port scan first (find what's open)
    2. Then target specific services
    
    This generates the "rapid connection/close" pattern that
    appears BEFORE a brute force when attacker is probing.
    
    MITRE ATT&CK: T1046 — Network Service Discovery
    """
    logs = []
    
    for i in range(random.randint(5, 15)):
        offset = i * random.uniform(0.1, 0.5)  # Very fast — it's automated
        timestamp = generate_timestamp(base_time, offset)
        logs.append(generate_connection_closed(timestamp, source_ip))
    
    return logs


# =============================================================================
# MAIN LOG GENERATION FUNCTION
# =============================================================================

def generate_log_file(output_file="sample_auth.log", include_attack=True):
    """
    Generate a complete log file mixing normal and attack traffic.
    
    This is the MASTER function that creates your training dataset.
    
    WHAT A REAL SIEM DOES:
    Tools like Splunk or QRadar ingest logs like this in real-time.
    They parse millions of lines per second, correlate events, and
    run detection rules on top. We're building a simplified version
    of exactly that pipeline.
    """
    print("\n" + "="*60)
    print("  SOC ANALYST TRAINING — LOG GENERATOR")
    print("="*60)
    
    all_logs = []
    
    # Set a base time (simulate logs from "today at midnight")
    base_time = datetime.datetime.now().replace(hour=0, minute=0, second=0)
    
    # --- NORMAL TRAFFIC (what a quiet business day looks like) ---
    print("\n[+] Generating normal user traffic (business hours)...")
    normal_logs = simulate_normal_traffic(base_time, duration_minutes=480)  # 8 hours
    all_logs.extend(normal_logs)
    print(f"    Generated {len(normal_logs)} normal log entries")
    
    if include_attack:
        # --- ATTACK SCENARIO ---
        # Attacker probes first, then brute forces
        
        # Phase 1 of attack: Reconnaissance (port probing)
        print("\n[+] Generating attack scenario: Port probing phase...")
        attack_ip = random.choice(SUSPICIOUS_IPS)
        attack_start = base_time + datetime.timedelta(hours=2, minutes=14)  # 2:14 AM — attackers love odd hours
        
        probe_logs = simulate_port_scan_precursor(attack_start, attack_ip)
        all_logs.extend(probe_logs)
        print(f"    Attacker IP: {attack_ip}")
        print(f"    Generated {len(probe_logs)} probe connection entries")
        
        # Phase 2 of attack: Brute force
        print("\n[+] Generating attack scenario: SSH brute force phase...")
        brute_start = attack_start + datetime.timedelta(seconds=30)
        brute_logs = simulate_brute_force_attack(brute_start, attack_ip, attempts=75)
        all_logs.extend(brute_logs)
        print(f"    Generated {len(brute_logs)} brute force attempt entries")
    
    # Sort all logs by their appearance order
    # (In real systems, logs arrive with timestamps and must be sorted for correlation)
    # Note: We keep insertion order here for simplicity; Phase 2 will sort by timestamp
    
    # Write to file
    output_path = os.path.join(os.path.dirname(__file__), output_file)
    with open(output_path, "w") as f:
        for log_line in all_logs:
            f.write(log_line + "\n")
    
    print(f"\n[OK] Log file written: {output_path}")
    print(f"[OK] Total log entries: {len(all_logs)}")
    print(f"\n[>>] Open the file and read 10 random lines.")
    print("[>>] Notice: Can you spot the attack entries vs normal ones?")
    print("[>>] That's what you'll automate in Phase 2.\n")
    
    return output_path


# =============================================================================
# ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    # Generate the log file
    log_file = generate_log_file(output_file="sample_auth.log", include_attack=True)
    
    print("\n" + "="*60)
    print("  WHAT TO OBSERVE (Your first experiment)")
    print("="*60)
    print("""
  1. Open sample_auth.log in any text editor
  2. Find lines with "Failed password" — count them from ONE IP
  3. Find lines with "Invalid user" — what usernames are being tried?
  4. Find lines with "Accepted password" — what IP did it come from?

  EXPERIMENT: Change attempts=75 to attempts=5 in simulate_brute_force_attack()
  Then re-run and compare the file. At what number is it obvious it's an attack?

  This is exactly the question Phase 2 answers with DETECTION RULES.
    """)
