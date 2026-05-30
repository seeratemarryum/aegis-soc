"""
=============================================================================
SOC ANALYST TRAINING -- PHASE 4: ISOLATION FOREST ANOMALY DETECTOR
=============================================================================

CONCEPT: How Isolation Forest Works (No Math Degree Required)
--------------------------------------------------------------

Imagine you have a crowd of people in a field.

NORMAL people cluster together -- they share common behaviors.
To find a NORMAL person, you'd need to ask many questions to isolate them:
  "Are you from Europe?" -> "Are you 20-40?" -> "Do you have glasses?" -> ...

An ANOMALY stands alone. One question isolates them:
  "Are you the only one wearing a purple hat?" -> Found.

Isolation Forest does exactly this, but with data:
  1. Pick a RANDOM FEATURE (e.g., failure_rate)
  2. Pick a RANDOM SPLIT POINT (e.g., 0.5)
  3. Everything > 0.5 goes right, <= 0.5 goes left
  4. Repeat until each data point is alone (isolated)
  5. Count how many splits it took to isolate each point

SHORT PATH (few splits) = ANOMALY (it was already alone)
LONG PATH (many splits) = NORMAL (it was surrounded by similar points)

The final ANOMALY SCORE = average path length across many trees.
Score close to -1 = strong anomaly.
Score close to +1 = clearly normal.

WHY THIS IS PERFECT FOR SOC:
  1. No labeled data needed -- you don't need "attack" labels
  2. Adapts to YOUR environment's normal behavior
  3. Can catch NOVEL attacks you've never seen before
  4. Fast to train and fast to predict

THE CONTAMINATION PARAMETER:
  This is the one parameter you MUST understand.
  contamination = 0.1 means "I expect ~10% of my data to be anomalous"
  
  Set it too LOW: only the most extreme anomalies get flagged
  Set it too HIGH: too many false positives
  
  SOC rule of thumb: Start at 0.05-0.10, tune based on your alert volume.
  This is the equivalent of "threshold tuning" from Phase 2, but for ML.

WHAT REAL TOOLS USE:
  Microsoft Sentinel: UEBA (User Entity Behavior Analytics) -- similar concept
  Splunk MLTK: density function anomaly detection
  Darktrace: proprietary neural net (same principle, different model)
  QRadar UBA: user behavior analytics
=============================================================================
"""

import sys
import os
import json
import numpy as np
import datetime
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE_DIR, "phase4"))
sys.path.insert(0, os.path.join(BASE_DIR, "phase1"))

from feature_engineer import (
    build_feature_matrix, features_to_numpy, print_feature_table,
    ML_FEATURE_NAMES, extract_ip_features
)


class SOCAnomalyDetector:
    """
    Isolation Forest-based anomaly detector for SSH log behavior.

    DESIGN DECISION: Why one model per time window?
    In production, you'd retrain daily on the last 30 days of normal traffic.
    Here we train on a combined normal+labeled dataset and test on new data.

    MODEL LIFECYCLE:
    1. TRAIN on known-normal behavior (business hours, internal IPs, low failures)
    2. SCORE new events -- model outputs anomaly scores
    3. THRESHOLD score to produce binary alert (anomaly yes/no)
    4. EXPLAIN why the point was flagged (which features drove the score)
    """

    def __init__(self, contamination=0.08, n_estimators=100, random_state=42):
        """
        Initialize the detector.

        Args:
            contamination: Expected fraction of anomalies in training data (0.0 to 0.5)
                          EXPERIMENT: Change this from 0.08 to 0.20 and see more alerts.
                          Change to 0.01 and see fewer (only extreme anomalies flagged).

            n_estimators:  Number of isolation trees in the forest.
                          More trees = more stable predictions, slower training.
                          100 is a good default for datasets under 10,000 samples.

            random_state:  Fix randomness for reproducibility.
                          Remove this to get different results each run.
        """
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.random_state = random_state

        # The actual Isolation Forest model (sklearn)
        self.model = IsolationForest(
            contamination=contamination,
            n_estimators=n_estimators,
            random_state=random_state,
            # max_samples: how many samples each tree sees
            # 'auto' = min(256, n_samples) -- good default
            max_samples='auto',
        )

        # StandardScaler normalizes features to same scale
        # WHY: failure_rate is 0-1, events_per_minute can be 0-500
        # Without scaling, large-magnitude features dominate
        # After scaling: all features have mean=0, std=1 (equal influence)
        self.scaler = StandardScaler()

        self.is_trained = False
        self.training_feature_rows = []
        self.training_stats = {}

    def train(self, events, label="NORMAL"):
        """
        Train the model on a set of events.

        TRAINING DATA PHILOSOPHY:
        Ideally, train ONLY on known-normal events.
        If you train on attack data too, the model learns attacks as "normal."

        In practice:
        - Real SOC: train on 30-day historical baseline (mostly normal)
        - Our setup: train on simulated normal traffic + a small contamination
                     fraction of attack data (realistic -- you rarely have
                     perfectly clean training data)

        After training, the model has learned:
        "Normal IPs have failure_rate < 0.05, events_per_minute < 1,
         unique_username_count = 1, is_external_ip = 0..."

        Any deviation from that learned baseline gets flagged.
        """
        print(f"\n[ML] Building feature matrix from {len(events)} training events...")

        feature_rows, ip_labels = build_feature_matrix(events, min_events_per_ip=2)

        if len(feature_rows) < 4:
            print(f"[WARNING] Only {len(feature_rows)} IPs in training data.")
            print(f"         Need at least 4 for reliable training.")
            print(f"         Generate more logs with phase1/log_generator.py first.")
            return False

        self.training_feature_rows = feature_rows
        X = features_to_numpy(feature_rows)

        # Scale features (fit_transform learns mean/std AND applies them)
        X_scaled = self.scaler.fit_transform(X)

        # Compute training statistics for later anomaly explanation
        self.training_stats = {
            fname: {
                "mean": float(np.mean(X[:, i])),
                "std": float(np.std(X[:, i])),
                "min": float(np.min(X[:, i])),
                "max": float(np.max(X[:, i])),
            }
            for i, fname in enumerate(ML_FEATURE_NAMES)
        }

        # Train the model
        print(f"[ML] Training Isolation Forest on {len(feature_rows)} IP profiles...")
        print(f"     n_estimators={self.n_estimators}, contamination={self.contamination}")
        self.model.fit(X_scaled)

        self.is_trained = True
        print(f"[OK] Model trained successfully!")
        print(f"     Training IPs: {len(feature_rows)}")
        print(f"     Features used: {len(ML_FEATURE_NAMES)}")

        # Print what "normal" looks like to the model
        print(f"\n  WHAT THE MODEL LEARNED AS 'NORMAL':")
        for fname in ["failure_rate", "unique_username_count",
                      "events_per_minute", "is_external_ip"]:
            stat = self.training_stats[fname]
            print(f"    {fname:<28}: mean={stat['mean']:.3f}, "
                  f"range=[{stat['min']:.2f}, {stat['max']:.2f}]")

        return True

    def score_events(self, events):
        """
        Score a set of events and return anomaly results per IP.

        SCORING PROCESS:
        1. Extract features for each IP (same as training)
        2. Scale features using the SAME scaler fitted during training
           (IMPORTANT: use transform, not fit_transform -- don't relearn scale)
        3. Get anomaly score from model: -1 (anomaly) or +1 (normal)
        4. Get decision_function score: more negative = more anomalous

        Returns:
            List of dicts with IP, anomaly flag, score, and explanation
        """
        if not self.is_trained:
            print("[ERROR] Model not trained. Call train() first.")
            return []

        feature_rows, ip_labels = build_feature_matrix(events, min_events_per_ip=1)

        if not feature_rows:
            print("[WARNING] No IPs with enough events to score.")
            return []

        X = features_to_numpy(feature_rows)

        # Scale using the FITTED scaler (do NOT re-fit on test data)
        X_scaled = self.scaler.transform(X)

        # Predict: -1 = anomaly, +1 = normal
        predictions = self.model.predict(X_scaled)

        # Decision function: more negative = more anomalous
        # This gives a continuous score, not just binary
        anomaly_scores = self.model.decision_function(X_scaled)

        results = []
        for i, (row, pred, score) in enumerate(
            zip(feature_rows, predictions, anomaly_scores)
        ):
            is_anomaly = (pred == -1)

            result = {
                "ip_address": row["ip_address"],
                "is_anomaly": is_anomaly,
                "anomaly_score": round(float(score), 4),
                "prediction": "ANOMALY" if is_anomaly else "NORMAL",
                "features": {k: row[k] for k in ML_FEATURE_NAMES},
                "total_events": row["total_events"],
            }

            # EXPLANATION: which features deviate most from training normal?
            if is_anomaly:
                result["anomaly_reasons"] = self._explain_anomaly(row)
                result["severity"] = self._compute_ml_severity(score, row)
            else:
                result["anomaly_reasons"] = []
                result["severity"] = "INFO"

            results.append(result)

        return results

    def _explain_anomaly(self, feature_row):
        """
        Explain WHY this IP was flagged -- critical for SOC usability.

        TEACHING CONCEPT: "Explainability" in ML
        A model that just says "ANOMALY" is not useful.
        An analyst needs to know WHY to take action.

        Real tools:
        - Splunk MLTK: SHAP values (SHapley Additive exPlanations)
        - Darktrace: "unusual for this device to communicate with this IP"
        - Microsoft Sentinel: "30x more sign-in failures than baseline"

        We compute a simple version: which features are furthest from
        the training mean (in standard deviations)?
        """
        reasons = []

        for fname in ML_FEATURE_NAMES:
            if fname not in self.training_stats:
                continue

            value = feature_row.get(fname, 0)
            stat = self.training_stats[fname]
            mean = stat["mean"]
            std = stat["std"]

            # How many standard deviations away from training mean?
            # > 2 std devs = unusual. > 3 = very unusual.
            if std > 0.001:
                z_score = abs(value - mean) / std
            else:
                z_score = abs(value - mean) * 100  # Flat feature, any difference notable

            # Only report features that deviate significantly
            if z_score > 1.5:
                direction = "ABOVE" if value > mean else "BELOW"
                reasons.append({
                    "feature": fname,
                    "value": value,
                    "training_mean": round(mean, 3),
                    "deviation": round(z_score, 2),
                    "direction": direction,
                    "human_explanation": _feature_explanation(fname, value, mean),
                })

        # Sort by deviation severity (most deviant first)
        reasons.sort(key=lambda x: x["deviation"], reverse=True)
        return reasons[:4]  # Top 4 reasons (concise for SOC)

    def _compute_ml_severity(self, anomaly_score, feature_row):
        """
        Map continuous anomaly score to discrete severity level.

        Anomaly score interpretation:
          score < -0.2: strong anomaly (CRITICAL or HIGH)
          score < -0.1: moderate anomaly (MEDIUM)
          score >= -0.1: borderline (LOW)
        """
        if anomaly_score < -0.15:
            # Escalate if external IP with high failure rate
            if feature_row.get("is_external_ip") and feature_row.get("failure_rate", 0) > 0.6:
                return "CRITICAL"
            return "HIGH"
        elif anomaly_score < -0.05:
            return "MEDIUM"
        else:
            return "LOW"


def _feature_explanation(feature_name, value, baseline_mean):
    """
    Map feature names and values to human-readable SOC explanations.
    This is the "translation layer" between ML output and analyst understanding.
    """
    explanations = {
        "failure_rate": (
            f"Login failure rate is {value*100:.0f}% "
            f"(baseline: {baseline_mean*100:.0f}%). "
            f"{'Extremely high -- consistent with automated brute force.' if value > 0.8 else 'Elevated -- worth investigating.'}"
        ),
        "unique_username_count": (
            f"This IP tried {int(value)} different usernames "
            f"(baseline: {baseline_mean:.1f}). "
            f"{'Classic wordlist/credential stuffing pattern.' if value >= 4 else 'Slightly elevated.'}"
        ),
        "events_per_minute": (
            f"Generating {value:.1f} events/minute "
            f"(baseline: {baseline_mean:.1f}/min). "
            f"{'Speed consistent with automated tool (Hydra, Medusa).' if value > 5 else 'Elevated activity rate.'}"
        ),
        "high_risk_ratio": (
            f"{'High percentage' if value > 0.5 else 'Some'} of attempts target "
            f"privileged accounts (root, admin). Baseline: {baseline_mean*100:.0f}%."
        ),
        "is_external_ip": (
            "IP is from an external (untrusted) network. "
            "All authentication failures from external sources are elevated risk."
            if value == 1 else
            "IP is from internal network -- could indicate insider threat or compromised machine."
        ),
        "dominant_hour": (
            f"Most activity at hour {int(value)}:00 "
            f"({'off-hours -- reduced monitoring' if value < 6 or value > 22 else 'business hours'})."
        ),
        "failures_before_success": (
            f"{int(value)} failures recorded before a successful login. "
            f"{'CRITICAL: brute force likely succeeded.' if value >= 3 else 'Suspicious pattern.'}"
        ),
        "interval_std_dev": (
            f"Event timing regularity (std dev: {value:.1f}s). "
            f"{'Very regular intervals suggest automated tool.' if value < 1.0 else 'Normal variance.'}"
        ),
        "rapid_close_ratio": (
            f"{value*100:.0f}% of events are rapid connection closes. "
            f"{'Consistent with port scanning.' if value > 0.3 else 'Minor.'}"
        ),
        "connection_spread_seconds": (
            f"All activity occurred within {value:.0f} seconds. "
            f"{'Very compressed -- consistent with automated burst.' if value < 120 else 'Spread over time.'}"
        ),
    }
    return explanations.get(feature_name, f"{feature_name}={value} (baseline={baseline_mean:.2f})")


def print_anomaly_report(results):
    """Print a formatted anomaly detection report."""
    anomalies = [r for r in results if r["is_anomaly"]]
    normals = [r for r in results if not r["is_anomaly"]]

    print(f"\n{'='*60}")
    print(f"  ML ANOMALY DETECTION REPORT")
    print(f"  Model: Isolation Forest | Features: {len(ML_FEATURE_NAMES)}")
    print(f"{'='*60}")
    print(f"\n  IPs scored:     {len(results)}")
    print(f"  Anomalies:      {len(anomalies)}")
    print(f"  Normal:         {len(normals)}")

    if not anomalies:
        print("\n  No anomalies detected.")
        return

    print(f"\n  {'='*58}")
    print(f"  ANOMALOUS IPs")
    print(f"  {'='*58}")

    for result in sorted(anomalies, key=lambda x: x["anomaly_score"]):
        severity = result["severity"]
        ip = result["ip_address"]
        score = result["anomaly_score"]
        total = result["total_events"]

        sev_tag = {"CRITICAL": "[!!!]", "HIGH": "[HI ]", "MEDIUM": "[MED]"}.get(severity, "[   ]")
        print(f"\n  {sev_tag} {ip}")
        print(f"       Anomaly Score: {score:.4f} (more negative = more anomalous)")
        print(f"       Total Events:  {total}")
        print(f"       Severity:      {severity}")

        # Key feature values
        f = result["features"]
        print(f"       Features:      failure_rate={f['failure_rate']*100:.0f}%  "
              f"usernames={f['unique_username_count']}  "
              f"events/min={f['events_per_minute']:.1f}  "
              f"external={'YES' if f['is_external_ip'] else 'no'}")

        # Explain the top reasons
        if result["anomaly_reasons"]:
            print(f"       Top anomaly reasons:")
            for reason in result["anomaly_reasons"][:3]:
                print(f"         [{reason['deviation']:.1f}x dev] {reason['human_explanation']}")

    # Normal IPs
    print(f"\n  NORMAL IPs (baseline behavior):")
    for result in normals:
        print(f"    [OK]  {result['ip_address']:<20} "
              f"score={result['anomaly_score']:+.4f}  "
              f"events={result['total_events']}")

    print(f"\n{'='*60}")


if __name__ == "__main__":
    events_path = os.path.join(BASE_DIR, "phase1", "parsed_events.json")

    if not os.path.exists(events_path):
        print("[ERROR] Run phase1 first to generate parsed_events.json")
        sys.exit(1)

    with open(events_path) as f:
        events = json.load(f)

    detector = SOCAnomalyDetector(
        contamination=0.08,   # EXPERIMENT: change to 0.2 for more alerts
        n_estimators=100,
        random_state=42       # EXPERIMENT: remove for random results each run
    )

    # Train and score on the same dataset (for learning purposes)
    # In production: train on LAST 30 days, score on TODAY's events
    trained = detector.train(events)

    if trained:
        results = detector.score_events(events)
        print_anomaly_report(results)

        # Save results for Phase 5 (explanation engine) and Phase 7 (dashboard)
        output_path = os.path.join(BASE_DIR, "phase4", "anomaly_results.json")
        with open(output_path, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\n[OK] Results saved: {output_path}")
