"""
=============================================================================
SOC ANALYST TRAINING — PHASE 3: BRUTE FORCE SIMULATOR (Hydra perspective)
=============================================================================

YOU ARE STILL THE ATTACKER. THIS IS THE MAIN ATTACK.

WHAT IS HYDRA?
--------------
THC-Hydra is the most popular brute force tool used by:
  - Penetration testers (authorized)
  - Script kiddies (unauthorized)
  - Advanced threat actors (nation-state)

HOW HYDRA ATTACKS SSH:
  hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.1.1

  Translation:
  -l root          : try username "root"
  -P rockyou.txt   : use this password wordlist (14 million passwords)
  ssh://...        : target SSH on that IP

  Hydra fires these attempts in PARALLEL — multiple threads simultaneously.
  Default: 16 parallel threads = 16 attempts per second minimum.

WORDLISTS — The Attacker's Secret Weapon:
  rockyou.txt contains real passwords from data breaches:
  → 123456, password, 12345678, qwerty, abc123...
  → These are the MOST COMMON PASSWORDS IN THE WORLD
  
  If your server uses any of these → you WILL be compromised.

WHAT APPEARS IN SSH LOGS:
  Each Hydra attempt creates one "Failed password" log entry.
  A SUCCESS creates "Accepted password" — the worst outcome.

ATTACK TECHNIQUES WE SIMULATE:
  1. PASSWORD SPRAY  — try 1 password against MANY usernames
  2. BRUTE FORCE     — try MANY passwords against 1 username
  3. CREDENTIAL STUFFING — try real breach data (email:password pairs)

DETECTION EVASION TECHNIQUES:
  1. SLOW DOWN — reduce thread count (fewer attempts per second)
  2. ROTATE IPs — use botnet (each IP makes 1-2 attempts)
  3. COMMON VALID USERS — only try known usernames to reduce noise
=============================================================================
"""

import random
import datetime
import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE_DIR, "phase1"))
from log_generator import SERVER_NAME


# =============================================================================
# COMMON PASSWORD WORDLISTS (subset of real rockyou.txt)
# =============================================================================

# Top passwords from rockyou.txt breach data (real, anonymized for education)
COMMON_PASSWORDS = [
    "123456", "password", "12345678", "qwerty", "abc123",
    "monkey", "1234567", "letmein", "trustno1", "dragon",
    "baseball", "iloveyou", "master", "sunshine", "ashley",
    "bailey", "passw0rd", "shadow", "123123", "654321",
    "superman", "qazwsx", "michael", "football", "password1",
    "admin", "admin123", "root", "toor", "changeme",
]

# SSH-specific wordlists (attackers know these work on SSH servers)
SSH_SPECIFIC_PASSWORDS = [
    "root", "toor", "raspberry", "ubuntu", "admin",
    "password", "123456", "raspberry", "alpine", "test",
]

# Common usernames tried in SSH attacks (same as Phase 1)
ATTACK_USERNAMES = [
    "root", "admin", "test", "guest", "oracle",
    "postgres", "ftpuser", "pi", "ubuntu", "vagrant",
    "ansible", "deploy", "jenkins", "git", "www",
]

# "Valid" usernames on our target system (from Phase 1)
TARGET_VALID_USERS = ["alice", "bob", "sysadmin", "ubuntu"]


# =============================================================================
# ATTACK TECHNIQUES
# =============================================================================

class BruteForceSimulator:
    """
    Simulates Hydra-style brute force SSH attacks generating realistic log data.

    TEACHING — THREE ATTACK MODES:

    MODE 1: CLASSIC BRUTE FORCE
    ────────────────────────────
    One username, many passwords.
    Attacker: "I know the username is 'root'. Let me try every password."
    Speed: Fast (automated). Detectable: Yes (same username, many failures).

    MODE 2: PASSWORD SPRAY
    ───────────────────────
    One password, many usernames.
    Attacker: "Let me try 'Password123' against every account."
    Why? Account lockout policies lock after N failures PER USER.
    Password spray avoids lockouts by spreading across users.
    Detectable: Harder! Each username only has 1-2 failures (below lockout).

    MODE 3: CREDENTIAL STUFFING
    ────────────────────────────
    Real username:password pairs from breach data.
    Attacker: "I bought 10 million breach records. Let me try them all."
    Detectable: Very hard — attempts look like real login patterns.
    """

    def __init__(self, attacker_ip, base_time=None):
        self.attacker_ip = attacker_ip

        if base_time is None:
            self.base_time = datetime.datetime.now().replace(
                hour=2, minute=14, second=0
            )
        else:
            self.base_time = base_time

        self.log_entries = []
        self.success_occurred = False
        self.success_username = None
        self.success_password = None

    def _make_failed_entry(self, timestamp_str, username):
        """Generate a Failed password log entry."""
        pid = random.randint(10000, 65535)
        port = random.randint(1024, 65535)
        return (
            f"{timestamp_str} {SERVER_NAME} sshd[{pid}]: "
            f"Failed password for {username} from {self.attacker_ip} port {port} ssh2"
        )

    def _make_invalid_user_entry(self, timestamp_str, username):
        """
        Generate an Invalid user log entry.
        This fires when the USERNAME doesn't exist on the system.
        Failed password fires when username EXISTS but password is wrong.
        Attackers see Invalid user = 'this user doesn't exist, skip it'
        """
        pid = random.randint(10000, 65535)
        port = random.randint(1024, 65535)
        return (
            f"{timestamp_str} {SERVER_NAME} sshd[{pid}]: "
            f"Invalid user {username} from {self.attacker_ip} port {port}"
        )

    def _make_success_entry(self, timestamp_str, username):
        """Generate an Accepted password log entry — the worst outcome."""
        pid = random.randint(10000, 65535)
        port = random.randint(1024, 65535)
        return (
            f"{timestamp_str} {SERVER_NAME} sshd[{pid}]: "
            f"Accepted password for {username} from {self.attacker_ip} port {port} ssh2"
        )

    def classic_brute_force(
        self,
        target_username="root",
        num_attempts=60,
        attempts_per_second=3,
        success_probability=0.05,
        verbose=True
    ):
        """
        Simulate classic brute force: one username, many passwords.

        HYDRA EQUIVALENT:
          hydra -l root -P rockyou.txt -t 4 ssh://target
          (-t 4 = 4 threads = ~4 attempts/second)

        WHAT THE SOC SEES:
          Dozens of "Failed password for root" from same IP in seconds.
          This is the MOST DETECTABLE attack pattern.

        PARAMETERS YOU CAN TUNE:
          num_attempts:       total password attempts (60 = very obvious)
          attempts_per_second: speed (3/sec = Hydra default with -t 4)
          success_probability: chance attacker hits the right password
        """
        if verbose:
            print(f"\n  {'='*56}")
            print(f"  [RED TEAM] CLASSIC BRUTE FORCE")
            print(f"  {'='*56}")
            print(f"\n  Attacker IP:     {self.attacker_ip}")
            print(f"  Target username: {target_username}")
            print(f"  Speed:           {attempts_per_second} attempts/second")
            print(f"  Total attempts:  {num_attempts}")
            print(f"\n  [ATTACKER COMMAND]: hydra -l {target_username} \\")
            print(f"    -P rockyou.txt -t {attempts_per_second} \\")
            print(f"    ssh://{self.attacker_ip}\n")

        current_offset = 0.0

        for attempt in range(num_attempts):
            # Calculate timing: 1/rate seconds between attempts
            interval = 1.0 / attempts_per_second
            # Add slight jitter — real tools aren't perfectly regular
            jitter = random.uniform(-0.1, 0.1) * interval
            current_offset += interval + jitter

            event_time = self.base_time + datetime.timedelta(seconds=current_offset)
            timestamp = event_time.strftime("%b %d %H:%M:%S")

            # Rare success — attacker guessed correctly
            if not self.success_occurred and random.random() < success_probability:
                entry = self._make_success_entry(timestamp, target_username)
                self.success_occurred = True
                self.success_username = target_username
                self.success_password = random.choice(SSH_SPECIFIC_PASSWORDS)
                if verbose:
                    print(f"  [ATTEMPT {attempt+1:03d}] SUCCESS! Password guessed for '{target_username}'")
            else:
                # Invalid user = username doesn't exist; Failed = username exists
                if target_username in TARGET_VALID_USERS:
                    entry = self._make_failed_entry(timestamp, target_username)
                else:
                    # root/admin don't exist as regular users — but sshd still
                    # says "Failed password" for root (special handling)
                    entry = self._make_failed_entry(timestamp, target_username)

                if verbose and attempt < 5:
                    print(f"  [ATTEMPT {attempt+1:03d}] FAIL  | {timestamp} | "
                          f"Trying '{COMMON_PASSWORDS[attempt % len(COMMON_PASSWORDS)]}'")
                elif verbose and attempt == 5:
                    print(f"  [...]  (continuing {num_attempts - 6} more attempts...)")

            self.log_entries.append(entry)

        if verbose:
            if self.success_occurred:
                print(f"\n  [!!!] ATTACK SUCCEEDED — Account '{self.success_username}' COMPROMISED")
                print(f"        SOC must treat this as an ACTIVE INCIDENT")
            else:
                print(f"\n  [---] Attack completed without success this run")
            print(f"\n  Total log entries generated: {len(self.log_entries)}")

        # Update base_time for any subsequent simulation
        self.base_time = self.base_time + datetime.timedelta(seconds=current_offset)
        return self.log_entries

    def password_spray(
        self,
        password="Password123",
        usernames=None,
        delay_between_users=5.0,
        verbose=True
    ):
        """
        Simulate password spray attack: one password, many usernames.

        WHY THIS EVADES DETECTION:
          Most account lockout policies trigger after 5 failures PER ACCOUNT.
          Password spray tries 1 password per account → never triggers lockout.
          Also evades brute force detection if threshold is per-username.

        OUR DETECTION WEAKNESS:
          Phase 2 detects by SOURCE IP threshold (5 failures from same IP).
          Password spray will STILL be caught because all attempts come from
          one IP — just with different usernames.

          BUT: if attacker distributes spray across 50 IPs (botnet),
          each IP only makes 1 attempt → completely evades threshold detection.
          That's why Phase 4 ML detection is needed.

        HYDRA EQUIVALENT:
          hydra -L userlist.txt -p Password123 ssh://target
        """
        if usernames is None:
            usernames = ATTACK_USERNAMES[:8]  # Try 8 usernames

        if verbose:
            print(f"\n  {'='*56}")
            print(f"  [RED TEAM] PASSWORD SPRAY ATTACK")
            print(f"  {'='*56}")
            print(f"\n  Password tried:  '{password}'")
            print(f"  Usernames list:  {usernames}")
            print(f"  Delay between:   {delay_between_users}s (evades per-user lockout)")
            print(f"\n  [ATTACKER THINKING]:")
            print(f"  'If I try Password123 on EVERY account, I won't lock")
            print(f"  any single account out. And maybe someone uses it!'\n")

        current_offset = 0.0

        for username in usernames:
            current_offset += delay_between_users + random.uniform(-1, 1)

            event_time = self.base_time + datetime.timedelta(seconds=current_offset)
            timestamp = event_time.strftime("%b %d %H:%M:%S")

            # If username doesn't exist: "Invalid user"
            # If username exists: "Failed password"
            if username in TARGET_VALID_USERS:
                entry = self._make_failed_entry(timestamp, username)
                log_type = "Failed password"
            else:
                entry = self._make_invalid_user_entry(timestamp, username)
                log_type = "Invalid user"

            self.log_entries.append(entry)

            if verbose:
                print(f"  Trying {username:<12} -> {log_type}")

        if verbose:
            print(f"\n  Spray complete. {len(usernames)} accounts targeted.")
            print(f"  Per-user failures: 1 each — account lockout NOT triggered!")
            print(f"  But all from same IP — Phase 2 still detects it via IP threshold.")

        self.base_time = self.base_time + datetime.timedelta(seconds=current_offset)
        return self.log_entries


def run_full_attack_chain(attacker_ip="185.220.101.42", verbose=True):
    """
    Simulate the FULL attack kill chain an attacker would execute:

    KILL CHAIN PHASES:
    1. Reconnaissance (port scan) — find what's open
    2. Credential Attack (brute force) — try to get in
    3. Escalation (if success) — what does attacker do next?

    This is modeled after MITRE ATT&CK framework:
    Reconnaissance -> Initial Access -> (Privilege Escalation if needed)
    """
    from port_scanner_sim import simulate_port_scan

    all_logs = []
    base_time = datetime.datetime.now().replace(hour=2, minute=14, second=0)

    if verbose:
        print(f"\n{'#'*60}")
        print(f"  [RED TEAM] FULL ATTACK CHAIN SIMULATION")
        print(f"  Attacker IP: {attacker_ip}")
        print(f"  Time: {base_time.strftime('%Y-%m-%d %H:%M:%S')} (2am — low monitoring)")
        print(f"{'#'*60}")

    # ── PHASE 1 OF ATTACK: Reconnaissance ────────────────────────────────────
    if verbose:
        print(f"\n  [STAGE 1 of 2] Reconnaissance — Port Scan")
        print(f"  'Finding what services are open on the target...'")

    scan_logs, scan_end_time = simulate_port_scan(
        attacker_profile="script_kiddie",
        base_time=base_time,
        verbose=verbose
    )
    all_logs.extend(scan_logs)

    # Brief pause — attacker reviews scan results
    recon_end = scan_end_time + datetime.timedelta(seconds=random.uniform(5, 15))

    # ── PHASE 2 OF ATTACK: Credential Attack ─────────────────────────────────
    if verbose:
        print(f"\n  [STAGE 2 of 2] Credential Attack — SSH Brute Force")
        print(f"  'Port 22 is open. Starting Hydra against root account...'")

    sim = BruteForceSimulator(attacker_ip=attacker_ip, base_time=recon_end)
    brute_logs = sim.classic_brute_force(
        target_username="root",
        num_attempts=60,
        attempts_per_second=3,
        success_probability=0.04,
        verbose=verbose
    )
    all_logs.extend(brute_logs)

    if verbose:
        print(f"\n{'='*60}")
        print(f"  [RED TEAM] ATTACK CHAIN COMPLETE")
        print(f"  Total log entries generated: {len(all_logs)}")
        print(f"  These logs are what the BLUE TEAM sees in auth.log")
        print(f"\n  [BLUE TEAM CHALLENGE]: Which log entries are attack vs normal?")
        print(f"  Run red_vs_blue.py to see Phase 2 detect this automatically.")
        print(f"{'='*60}")

    return all_logs, attacker_ip


if __name__ == "__main__":
    print("\n  BRUTE FORCE SIMULATOR — Choose attack mode:")
    print("  1. Classic Brute Force (one username, many passwords)")
    print("  2. Password Spray (one password, many usernames)")
    print("  3. Full Attack Chain (recon + brute force)")

    choice = input("\n  Enter 1, 2, or 3: ").strip()

    if choice == "1":
        sim = BruteForceSimulator(attacker_ip="185.220.101.42")
        sim.classic_brute_force(target_username="root", num_attempts=20, verbose=True)

    elif choice == "2":
        sim = BruteForceSimulator(attacker_ip="45.142.212.100")
        sim.password_spray(password="Password123!", verbose=True)

    elif choice == "3":
        logs, ip = run_full_attack_chain()
        print(f"\n  First 5 log entries (what auth.log shows):")
        for line in logs[:5]:
            print(f"  {line}")
    else:
        print("  Invalid choice. Running full chain by default.")
        run_full_attack_chain()
