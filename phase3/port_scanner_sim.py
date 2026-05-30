"""
=============================================================================
SOC ANALYST TRAINING — PHASE 3: PORT SCANNER SIMULATOR
=============================================================================

YOU ARE NOW THE ATTACKER. READ THIS CAREFULLY.

WHAT IS PORT SCANNING?
-----------------------
Before an attacker touches your password prompt, they MUST answer:
"What services is this machine even running?"

They do this with a port scanner. The most famous tool: nmap (Network Mapper)

HOW nmap WORKS (conceptually):
  For port 22 (SSH):
    Attacker → sends TCP SYN packet to target:22
    Target   → responds SYN-ACK  (port OPEN — SSH is running!)
    or
    Target   → responds RST      (port CLOSED)
    or
    Nothing  → (port FILTERED by firewall)

  nmap does this for 1000+ ports in seconds.

WHAT THE ATTACKER LEARNS:
  Port 22 OPEN  → "SSH is running, I can try to brute force it"
  Port 80 OPEN  → "Web server, I can look for web vulnerabilities"
  Port 3306     → "MySQL database exposed! Try default credentials"

WHAT APPEARS IN THE SSH LOGS:
  When nmap hits port 22, the SSH daemon logs:
  "Connection closed by [attacker_ip]"
  — because nmap connects but doesn't authenticate (just probing)

THIS SCRIPT SIMULATES:
  The log entries that a port scan of port 22 would create.
  These are exactly the CONNECTION_CLOSED entries Phase 2 detects.

REAL ATTACK COMMAND (DO NOT RUN WITHOUT PERMISSION):
  nmap -sS -p 22 192.168.1.1          # SYN scan port 22
  nmap -sV -p 1-1000 192.168.1.0/24  # version scan whole subnet
=============================================================================
"""

import random
import datetime
import os
import sys

# Shared path setup
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE_DIR, "phase1"))
from log_generator import generate_timestamp, SERVER_NAME


# =============================================================================
# ATTACKER PROFILE
# Real attackers have different profiles. We simulate 3 common ones.
# =============================================================================

ATTACKER_PROFILES = {
    "script_kiddie": {
        # Unskilled attacker running tools without understanding them
        # Characteristics: fast, noisy, easily detected
        "description": "Script Kiddie — fast, noisy, no evasion",
        "scan_speed_seconds": (0.05, 0.3),  # Very fast scans
        "num_probe_connections": (8, 15),   # Many probes (doesn't care about detection)
        "attacker_ip": "198.51.100.73",
        "evasion": False,
    },
    "professional": {
        # Skilled attacker (penetration tester or APT member)
        # Characteristics: measured, some evasion, harder to detect
        "description": "Professional — measured speed, some evasion",
        "scan_speed_seconds": (1.0, 4.0),  # Slower to avoid rate-limiting
        "num_probe_connections": (3, 7),   # Fewer connections
        "attacker_ip": "45.142.212.100",
        "evasion": True,
    },
    "apt": {
        # Advanced Persistent Threat — nation-state level actor
        # Characteristics: extremely slow, blends with traffic, hardest to detect
        "description": "APT — very slow, mimics legitimate traffic",
        "scan_speed_seconds": (10.0, 30.0),  # Very slow — evades most detection
        "num_probe_connections": (2, 4),      # Minimal footprint
        "attacker_ip": "203.0.113.88",
        "evasion": True,
    }
}


def simulate_port_scan(
    target_ip="prod-webserver-01",
    attacker_profile="script_kiddie",
    base_time=None,
    verbose=True
):
    """
    Simulate the log entries generated when an attacker runs a port scan.

    WHAT THIS PRODUCES:
    Multiple "Connection closed" entries in rapid succession from one IP.
    This is exactly the pattern the Phase 2 PortScanDetector looks for.

    TEACHING — ATTACK STAGES:
    ─────────────────────────────────────────────────────
    Stage 1: Initial probe — attacker connects, checks if port 22 is alive
    Stage 2: Service banner grab — "what version of SSH?"
    Stage 3: Disconnect — attacker now knows SSH is open, moves to next step
    ─────────────────────────────────────────────────────

    Args:
        attacker_profile: one of "script_kiddie", "professional", "apt"
        base_time: datetime when scan starts (None = now)
    """
    profile = ATTACKER_PROFILES[attacker_profile]
    attacker_ip = profile["attacker_ip"]

    if base_time is None:
        # Attackers prefer odd hours — 2am to 4am (least monitoring)
        base_time = datetime.datetime.now().replace(
            hour=random.choice([2, 3, 14, 15]),
            minute=random.randint(0, 59),
            second=0
        )

    if verbose:
        print(f"\n{'='*58}")
        print(f"  [RED TEAM] PORT SCAN SIMULATION")
        print(f"{'='*58}")
        print(f"\n  Attacker Profile: {profile['description']}")
        print(f"  Attacker IP:      {attacker_ip}")
        print(f"  Target:           {SERVER_NAME}")
        print(f"  Scan Start:       {base_time.strftime('%H:%M:%S')}")
        print(f"\n  [ATTACKER THINKING]:")
        print(f"  'I need to find what ports are open on this server.'")
        print(f"  'I will probe port 22 to confirm SSH is running.'")
        print(f"  'Then I will run Hydra to brute force it.'\n")

    log_entries = []
    current_offset = 0.0

    # Number of probe connections depends on attacker profile
    min_probes, max_probes = profile["num_probe_connections"]
    num_probes = random.randint(min_probes, max_probes)

    for probe_num in range(num_probes):
        # Speed between probes depends on profile
        min_speed, max_speed = profile["scan_speed_seconds"]
        current_offset += random.uniform(min_speed, max_speed)

        # Generate the timestamp for this probe
        probe_time = base_time + datetime.timedelta(seconds=current_offset)
        timestamp = probe_time.strftime("%b %d %H:%M:%S")

        # Each probe generates a "Connection closed" in SSH logs
        pid = random.randint(10000, 65535)
        log_line = (
            f"{timestamp} {SERVER_NAME} sshd[{pid}]: "
            f"Connection closed by {attacker_ip}"
        )
        log_entries.append(log_line)

        if verbose:
            print(f"  [PROBE {probe_num+1:02d}] {timestamp} | "
                  f"Connect -> immediate close | {attacker_ip}")

    if verbose:
        total_time = current_offset
        print(f"\n  Scan complete in {total_time:.1f} seconds")
        print(f"  Generated {len(log_entries)} log entries")
        print(f"\n  [SOC VIEW]: Phase 2 sees {len(log_entries)} rapid 'Connection closed'")
        print(f"  events from {attacker_ip} in {total_time:.0f}s")

        # Will this trigger our detection?
        threshold = 5
        window = 15
        if len(log_entries) >= threshold and total_time <= window:
            print(f"  [DETECTION]: YES - exceeds threshold ({threshold} in {window}s)")
        else:
            print(f"  [DETECTION]: POSSIBLY NO - below threshold or too slow")
            print(f"  [LESSON]: APT actors specifically tune scan speed to evade detection")

    # Return the final offset so the brute force can start AFTER the scan
    return log_entries, base_time + datetime.timedelta(seconds=current_offset)


if __name__ == "__main__":
    print("\n  PORT SCANNER SIMULATOR — Choose an attacker profile:")
    print("  1. script_kiddie  (fast, noisy — easily detected)")
    print("  2. professional   (measured — partially detectable)")
    print("  3. apt            (very slow — may evade detection!)")

    choice = input("\n  Enter 1, 2, or 3: ").strip()
    profiles = {"1": "script_kiddie", "2": "professional", "3": "apt"}
    profile = profiles.get(choice, "script_kiddie")

    logs, end_time = simulate_port_scan(attacker_profile=profile)

    print(f"\n  Generated log lines (what SOC sees in auth.log):")
    print(f"  {'-'*54}")
    for line in logs:
        print(f"  {line}")

    print(f"\n  EXPERIMENT: Run all 3 profiles and compare scan speed.")
    print(f"  Which one does Phase 2 detect? Which one evades it?")
    print(f"  Answer: APT profile (30s between probes) may evade 15s window!")
