"""
=============================================================================
SOC PIPELINE RUNNER -- ORCHESTRATION SCRIPT
=============================================================================
Runs all simulation and analysis phases sequentially to generate data
for the Phase 7 dashboard.
=============================================================================
"""

import os
import sys
import subprocess

def run_script(script_path, input_data=None, args=None):
    """Run a python script as a subprocess, feeding it optional input data."""
    cmd = [sys.executable, script_path]
    if args:
        cmd.extend(args)
    
    print(f"\n>>> Running: {' '.join(cmd)}")
    
    try:
        process = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=os.path.dirname(os.path.abspath(script_path))
        )
        
        stdout, stderr = process.communicate(input=input_data)
        
        print(stdout.decode('utf-8', errors='ignore'))
        if stderr:
            print("[STDERR]", stderr.decode('utf-8', errors='ignore'))
            
        if process.returncode != 0:
            print(f"[ERROR] Script failed with exit code {process.returncode}")
            return False
        return True
    except Exception as e:
        print(f"[EXCEPTION] Failed to run {script_path}: {e}")
        return False

def main():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    
    scripts = [
        # (script relative path, input bytes)
        ("phase1/log_generator.py", None),
        ("phase1/log_parser.py", None),
        ("phase2/detection_engine.py", None),
        ("phase4/ml_pipeline.py", None),
        ("phase5/explanation_engine.py", b"\n"),  # Press Enter to skip interactive lookup
        ("phase6/response_console.py", b"2\n"),   # Press 2 to run in automated dry-run mode
    ]
    
    print("=============================================================================")
    print("  SOC ANALYST CHALLENGE -- FULL SIMULATION PIPELINE")
    print("=============================================================================")
    
    for rel_path, stdin_data in scripts:
        full_path = os.path.join(base_dir, rel_path)
        if not os.path.exists(full_path):
            print(f"[ERROR] Script not found: {full_path}")
            sys.exit(1)
            
        success = run_script(full_path, input_data=stdin_data)
        if not success:
            print(f"\n[FATAL] Pipeline stopped due to failure in {rel_path}")
            sys.exit(1)
            
    print("\n=============================================================================")
    print("  [SUCCESS] All phases executed successfully!")
    print("  All data sources regenerated for the Dashboard Server.")
    print("=============================================================================")

if __name__ == "__main__":
    main()
