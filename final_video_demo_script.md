# Aegis SOC Platform — Video Demonstration Script & Guide
**Target Duration**: ~3 minutes and 45 seconds (Meets the 3-5 minute hackathon requirement)

This document contains your exact **recording setup**, **visual actions**, and **voiceover script** to record a winning hackathon demonstration.

---

## 🛠️ Step 1: Pre-Recording Setup
1. **Clear Dashboard Telemetry**:
   * Open your terminal and stop the running server by pressing `Ctrl + C`.
   * Start it again fresh: `python phase7/dashboard_server.py`.
   * Open your browser and navigate to **`http://localhost:5000`**.
   * Verify that stats start at `0` events, `0` alerts, and the sidebar dot flashes a green **MONITORING** status.
2. **Setup Recording Tool**:
   * Open Loom, OBS Studio, or Zoom.
   * Configure it to capture your browser tab or your desktop at **1080p**.
   * Ensure your microphone is active and clear.
3. **Browser Zoom**:
   * Set your browser zoom to **110%** or **125%** so the text on charts and tables is easily readable on video.

---

## 🎬 Step 2: Live Video Storyboard & Script

| Timestamp | Visual Actions (What to do on screen) | Voiceover Script (What to say) | Under-the-Hood Logic (Explain to Judges) |
| :--- | :--- | :--- | :--- |
| **0:00 - 0:40** | **1. Welcome & Introduction**<br>• Show the browser displaying the **Overview** dashboard at a clean state (0 alerts, status dot blinking green).<br>• Move your cursor over the **MONITORING** status label.<br>• Move your cursor over the team names in the sidebar. | *"Hello judges, my name is **Seerat Marryum**, and on behalf of my team—including **Ayesha** and **Linh Doan**—I'm proud to present **Aegis SOC** for the SS Hacker Team GLOBAL Challenge 2026.<br><br>Currently, the average time to contain a server breach is hours, giving attackers ample time to steal data. We built Aegis to demonstrate how autonomous SIEM and SOAR pipelines can contain threats in under three seconds. As you can see, the console is currently monitoring standard traffic, displaying a clean, green system status."* | • **Syslog Ingestion**: The system continuously reads unstructured lines from `/var/log/auth.log` and feeds them to the parser. |
| **0:40 - 1:25** | **2. Real-Time Log Ingestion**<br>• Keep your cursor hovering on the **Events Processed** counter as it starts ticking up.<br>• Point your mouse to the right-hand **Normalized SSH Log stream** table as clean events stream in.<br>• Watch the status dot turn red **BREACH DETECTED**. | *"Now, the background simulation begins streaming logs. On the right, unstructured Linux syslog text is ingested, parsed via regular expressions, and normalized into JSON. <br><br>Legitimate users Alice and Bob log in successfully from our trusted local network. But suddenly, the telemetry spikes. An external IP address starts probing our ports and launching an active SSH brute-force attack, triggering a critical red warning status on our console."* | • **Normalization (Phase 1)**: Raw logs are parsed into structured JSON schemas (extracting timestamp, source IP, username, port, and process ID).<br>• **Enrichment**: The parser automatically flags whether the source is external and if the username target is high-risk (e.g., `root`). |
| **1:25 - 2:05** | **3. Rule Detection & Correlation**<br>• Hover over the triggered alerts in the **Live Alert Stream** table.<br>• Click the **Inspect** button next to the `SSH_BRUTE_FORCE` alert to open the JSON inspector modal.<br>• Point out the correlation field in the JSON payload, then click **Dismiss**. | *"Aegis utilizes stateful detection rules with sliding time windows to identify attacks. Here, we see a Port Scan alert followed by an SSH Brute Force alert.<br><br>Because they occurred sequentially from the same IP, our correlation engine links the events, escalating this to a CRITICAL threat level. Inspecting the alert payload reveals the normalized JSON details, tracking the attacker IP, failure count, and targeted usernames."* | • **Correlation (Phase 2)**: Rule windows check for 5 failures in 60s (Brute Force) or 5 closed connections in 15s (Port Scan).<br>• **Escalation**: Multi-stage correlation logic links reconnaissance to exploitation, raising severity dynamically to prioritize responder triage. |
| **2:05 - 2:55** | **4. Behavioral Machine Learning**<br>• Click on the **ML Anomaly Detector** tab in the sidebar.<br>• Scroll to show the **Isolation Forest** scoring table with the attacker's IP marked red as **ANOMALOUS**.<br>• Point to the **Explainable AI (XAI)** table below and hover over the deviation reasons. | *"Static rules fail to catch 'Low-and-Slow' attacks, where an attacker waits over 60 seconds between attempts. Aegis solves this using unsupervised machine learning. <br><br>By profiling multi-variable features, our Isolation Forest model flags anomalous IPs without signature rules. To prevent ML from being a 'black box', our Explainable AI layer calculates statistical Z-score deviations, showing the analyst exactly why the model isolated this IP in plain English."* | • **UEBA (Phase 4)**: Compiles IP feature vectors (failure rates, unique user counts, timing regularity, off-hours activity) and runs them through Scikit-Learn's Isolation Forest.<br>• **XAI (Phase 5)**: Uses standard deviations from the baseline to render user-friendly, transparent explanations. |
| **2:55 - 3:35** | **5. SOAR Playbook Containment**<br>• Click on the **SOAR Response Console** tab.<br>• Point to the blocked attacker IP in the **Perimeter IP Blocks** firewall console.<br>• Click **View Steps** on the playbook row to open the steps modal.<br>• Scroll through the green **SOAR Response Audit Logs** terminal at the bottom. | *"In an active breach, manual response is too slow. Under the SOAR tab, we see that Aegis has automatically executed playbooks. <br><br>The playbook steps show that in under a second, the system enriched the IP, opened an incident ticket, paged the security team, and pushed a drop rule directly to our firewall blocklist. The entire cryptographic containment process is permanently recorded in our immutable audit logs."* | • **SOAR (Phase 6)**: The Playbook Engine executes automated containment playbooks. If an abuse score exceeds threshold, it executes a simulated `iptables -j DROP` block.<br>• **Compliance**: Every orchestration step writes to a read-only audit log file to satisfy forensic and legal compliance. |
| **3:35 - 4:10** | **6. Incident Report & Handoff**<br>• Click on the **Incident Reports** tab in the sidebar.<br>• Scroll through the Generated Summary, the attack timeline flow, and the containment checklist.<br>• Conclude the recording. | *"Finally, Aegis generates a detailed Incident Report. It reconstructs the chronological attack timeline, maps the threat to the MITRE ATT&CK database, and provides a forensic checklist showing what was auto-contained versus what manual eradication steps the human responder needs to take next. <br><br>Aegis SOC compresses containment from hours to seconds. Thank you for your time!"* | • **Report Generation (Phase 5)**: Compiles alert, ML, and SOAR outputs, maps rules to MITRE ATT&CK techniques, and generates a structured incident summary for shift handoff. |

---

## 📌 Step 3: Submission Checklist (Devpost Rules)
Before submitting, make sure you double-check these items:
* [ ] **Public GitHub Repository**: Verify that your repo at [https://github.com/seeratemarryum/aegis-soc](https://github.com/seeratemarryum/aegis-soc) is set to **Public**.
* [ ] **Proper README**: The README is pushed and includes installation/running steps.
* [ ] **Demo Video Length**: Confirm your finished video is between **3 and 5 minutes**.
* [ ] **YouTube Link**: Upload the video to YouTube as **Unlisted** (or Public) and paste the link into the Devpost form.
* [ ] **Team Names**: Ensure you have entered `Seerat Marryum`, `Ayesha`, and `Linh Doan` in the submission form.
* [ ] **On-Time**: Submit before the hackathon deadline closes.
