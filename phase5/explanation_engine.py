"""
=============================================================================
SOC ANALYST TRAINING -- PHASE 5: EXPLANATION ENGINE (MAIN)
=============================================================================

This is the intelligence layer that converts raw detection output into
human-readable, actionable SOC intelligence.

PIPELINE:
  Phase 2 alerts.json  -->+
                          +--> Explanation Engine --> Incident Report
  Phase 4 ml_results   -->+

HOW LLMs WOULD ENHANCE THIS:
  This system uses template-based explanation (deterministic).
  Adding an LLM (GPT-4, Claude, Gemini) would allow:
  - Free-form narrative generation
  - Analyst Q&A ("What should I check first?")
  - Automatic OSINT about attacker IPs
  - Custom report style (executive vs technical)

  The INPUT to the LLM would be exactly our structured report dict.
  The LLM OUTPUT would replace our template narrative.

  Example prompt (if using OpenAI API):
    system: "You are a Tier 2 SOC analyst writing an incident report."
    user:   json.dumps(report_dict)

  Our current system gives the same STRUCTURE without needing an API key.
  This is called "template-based NLG" (Natural Language Generation).

RUN: python phase5/explanation_engine.py
=============================================================================
"""

import sys
import os
import json

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PHASE2_DIR = os.path.join(BASE_DIR, "phase2")
PHASE4_DIR = os.path.join(BASE_DIR, "phase4")
PHASE5_DIR = os.path.join(BASE_DIR, "phase5")

sys.path.insert(0, BASE_DIR)
sys.path.insert(0, PHASE5_DIR)

from report_generator import generate_incident_report, print_incident_report, save_report
from mitre_mapper import get_techniques_for_rule, ATTACK_TECHNIQUES


def load_phase2_alerts():
    """Load alert data produced by Phase 2 detection engine."""
    path = os.path.join(PHASE2_DIR, "alerts.json")
    if not os.path.exists(path):
        print(f"[!] Phase 2 alerts not found at {path}")
        print("    Run: python phase2/detection_engine.py")
        return []
    with open(path) as f:
        return json.load(f)


def load_phase4_ml_results():
    """Load ML anomaly results from Phase 4."""
    path = os.path.join(PHASE4_DIR, "ml_pipeline_results.json")
    if not os.path.exists(path):
        print(f"[!] Phase 4 ML results not found. Running without ML context.")
        return None
    with open(path) as f:
        data = json.load(f)
    # ml_pipeline_results has nested structure
    return data.get("ml_results", [])


def demo_mitre_lookup():
    """
    Interactive demo: look up any ATT&CK technique by ID.

    TEACHING: This shows how SOC analysts use ATT&CK as a reference.
    In real tools (Splunk ES, Sentinel), clicking an alert shows the
    ATT&CK technique page automatically.
    """
    print("\n  MITRE ATT&CK TECHNIQUE LOOKUP")
    print("  Available: T1046, T1110, T1110.001, T1110.003, T1078, T1021.004")
    tid = input("\n  Enter technique ID (or Enter to skip): ").strip().upper()

    if tid in ATTACK_TECHNIQUES:
        tech = ATTACK_TECHNIQUES[tid]
        print(f"\n  {'-'*58}")
        print(f"  {tech['id']} -- {tech['name']}")
        print(f"  Tactic: {tech['tactic_name']}")
        print(f"  Severity Weight: {tech['severity_weight']}/10")
        print(f"\n  Description:")
        words = tech["description"].split()
        line = "    "
        for w in words:
            if len(line) + len(w) > 62:
                print(line)
                line = "    " + w + " "
            else:
                line += w + " "
        if line.strip():
            print(line)
        print(f"\n  Detected in logs: {tech['detection_in_logs']}")
        print(f"\n  Real-world examples:")
        for ex in tech.get("real_world_examples", []):
            print(f"    * {ex}")
        print(f"\n  Mitigations:")
        for mit in tech.get("mitigations", []):
            print(f"    - {mit}")
        print(f"  {'-'*58}")


def main():
    print("\n")
    print("  ##########################################################")
    print("  ##  PHASE 5: INCIDENT EXPLANATION ENGINE                ##")
    print("  ##  Converting alerts -> actionable SOC intelligence    ##")
    print("  ##########################################################")

    # -- Load data from previous phases
    print("\n[+] Loading Phase 2 alerts...")
    alerts = load_phase2_alerts()
    print(f"[OK] Loaded {len(alerts)} alerts from Phase 2")

    print("[+] Loading Phase 4 ML results...")
    ml_results = load_phase4_ml_results()
    if ml_results:
        anomalies = [r for r in ml_results if r.get("is_anomaly")]
        print(f"[OK] Loaded ML results: {len(anomalies)} anomalies")
    else:
        print("[--] ML results not available -- running report without ML context")
        print("     (Run python phase4/ml_pipeline.py first for full context)")

    if not alerts:
        print("\n[!] No alerts to generate report from.")
        print("    Run these first:")
        print("    python phase1/log_generator.py")
        print("    python phase1/log_parser.py")
        print("    python phase2/detection_engine.py")
        return

    # -- Generate the incident report
    print("\n[+] Generating incident report...")
    report = generate_incident_report(
        alerts=alerts,
        ml_results=ml_results,
        analyst_name="SOC Analyst (Automated - Phase 5)",
    )

    # -- Print to console
    print_incident_report(report)

    # -- Save report files
    save_report(report, filename="incident_report.json")

    # -- MITRE lookup demo
    print("\n" + "="*62)
    print("  INTERACTIVE MITRE ATT&CK LOOKUP")
    print("  (understand the techniques in this incident)")
    print("="*62)
    demo_mitre_lookup()

    # -- Show how LLM would plug in
    print("\n" + "="*62)
    print("  HOW AN LLM API WOULD ENHANCE THIS")
    print("="*62)
    print("""
  Current system:  Template-based generation (deterministic)
  LLM-enhanced:    Free-form, conversational, context-aware

  To add GPT-4/Claude, replace _build_narrative() with:

    import openai
    client = openai.OpenAI(api_key="YOUR_KEY")

    response = client.chat.completions.create(
        model="gpt-4",
        messages=[
            {"role": "system",
             "content": "You are a Tier 2 SOC analyst. "
                        "Write a clear incident report narrative."},
            {"role": "user",
             "content": json.dumps(report_dict, indent=2)}
        ]
    )
    narrative = response.choices[0].message.content

  The structured report dict we generate is the perfect LLM input.
  It contains all context: alerts, timeline, ATT&CK IDs, IP addresses.

  INPUTS we send to LLM:      OUTPUTS we get back:
  - Alert list (JSON)         - Executive summary paragraph
  - ATT&CK techniques         - Q&A answers ("What happened first?")
  - Timeline of events        - Investigation recommendations
  - ML anomaly scores         - Risk assessment in plain English
    """)

    print("="*62)
    print("  EXPERIMENTS FOR PHASE 5")
    print("="*62)
    print("""
  1. READ THE GENERATED REPORT FILES:
     Open phase5/incident_report.txt -- this is what you'd email to management.
     Open phase5/incident_report.json -- this feeds into Phase 7 dashboard.

  2. CHANGE THE ANALYST NAME:
     In explanation_engine.py, change analyst_name="Your Name Here"
     Re-run -- see it appear in the report header.

  3. ADD A NEW ATT&CK TECHNIQUE:
     In mitre_mapper.py, add a new entry to ATTACK_TECHNIQUES dict.
     Add "T1562" (Impair Defenses -- attacker disables logging).
     Add it to RULE_TO_ATTACK_MAP for "BRUTE_FORCE_SUCCESS".
     Re-run -- see it appear in the kill chain.

  4. SIMULATE DIFFERENT INCIDENTS:
     Edit phase2/alerts.json manually -- remove the BRUTE_FORCE_SUCCESS alert.
     Re-run phase5 -- watch priority drop from CRITICAL to HIGH.
     This teaches how incident priority is calculated.
    """)


if __name__ == "__main__":
    main()
