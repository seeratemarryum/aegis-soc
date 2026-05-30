/**
 * SOC Analyst Training Dashboard - Core Client Logic
 * Handles interactive tabs, API data synchronization, Chart.js rendering, and modal inspection.
 */

document.addEventListener('DOMContentLoaded', () => {
    // State management
    const state = {
        charts: {
            timeline: null,
            severity: null
        },
        refreshInterval: null,
        currentTab: 'overview',
        isSyncing: false
    };

    // DOM Elements
    const elements = {
        // Navigation & Status
        menuItems: document.querySelectorAll('.menu-item'),
        tabPanels: document.querySelectorAll('.tab-panel'),
        pageTitle: document.getElementById('page-title'),
        statusDot: document.getElementById('status-dot'),
        statusLabel: document.getElementById('status-label'),
        syncTime: document.getElementById('sync-time'),
        btnRefresh: document.getElementById('btn-refresh'),

        // KPI values
        kpiEvents: document.getElementById('kpi-events-value'),
        kpiAlerts: document.getElementById('kpi-alerts-value'),
        kpiCritical: document.getElementById('kpi-critical-value'),
        kpiAnomalies: document.getElementById('kpi-anomalies-value'),
        kpiCardCritical: document.getElementById('kpi-critical'),

        // Overview tables
        alertsTable: document.getElementById('alerts-table').querySelector('tbody'),
        alertFeedCount: document.getElementById('alert-feed-count'),
        parsedEventsTable: document.getElementById('parsed-events-table').querySelector('tbody'),
        parsedEventsCount: document.getElementById('parsed-events-count'),

        // MITRE tab
        killChainTimeline: document.getElementById('kill-chain-timeline'),
        mitreTechniquesTable: document.getElementById('mitre-techniques-table').querySelector('tbody'),

        // ML tab
        mlScoringTable: document.getElementById('ml-scoring-table').querySelector('tbody'),
        mlXaiTable: document.getElementById('ml-xai-table').querySelector('tbody'),
        mlContamination: document.getElementById('ml-contamination'),
        mlEstimators: document.getElementById('ml-estimators'),

        // SOAR tab
        soarPlaybooksTable: document.getElementById('soar-playbooks-table').querySelector('tbody'),
        blockedIpsTable: document.getElementById('blocked-ips-table').querySelector('tbody'),
        auditLogTerminal: document.getElementById('audit-log-terminal'),

        // Incident Reports tab
        reportPlaceholder: document.getElementById('report-placeholder'),
        reportContent: document.getElementById('report-content'),
        reportId: document.getElementById('report-id'),
        reportPriority: document.getElementById('report-priority'),
        reportDate: document.getElementById('report-date'),
        reportAnalyst: document.getElementById('report-analyst'),
        reportTarget: document.getElementById('report-target'),
        reportBreach: document.getElementById('report-breach'),
        reportNarrative: document.getElementById('report-narrative'),
        reportTimeline: document.getElementById('report-timeline'),
        reportActions: document.getElementById('report-actions'),
        reportRecommendations: document.getElementById('report-recommendations'),

        // Modal Elements
        modal: document.getElementById('detail-modal'),
        modalTitle: document.getElementById('modal-title'),
        modalJsonDisplay: document.getElementById('modal-json-display'),
        modalCloseBtn: document.getElementById('modal-close-btn'),
        modalCloseAction: document.getElementById('modal-close-action')
    };

    // =========================================================================
    // TAB NAVIGATION
    // =========================================================================
    function initNavigation() {
        elements.menuItems.forEach(item => {
            item.addEventListener('click', (e) => {
                e.preventDefault();
                const targetTab = item.getAttribute('data-tab');
                
                // Update active sidebar item
                elements.menuItems.forEach(mi => mi.classList.remove('active'));
                item.classList.add('active');

                // Update active tab panel
                elements.tabPanels.forEach(panel => panel.classList.remove('active'));
                const targetPanel = document.getElementById(`panel-${targetTab}`);
                if (targetPanel) targetPanel.classList.add('active');

                // Update title
                state.currentTab = targetTab;
                elements.pageTitle.textContent = item.querySelector('span').textContent;
                
                // Immediate refresh of data on tab change
                syncData();
            });
        });
    }

    // =========================================================================
    // MODAL INSPECTION
    // =========================================================================
    function showInspector(title, payload) {
        elements.modalTitle.textContent = title;
        elements.modalJsonDisplay.textContent = JSON.stringify(payload, null, 2);
        elements.modal.classList.add('show');
    }

    function closeInspector() {
        elements.modal.classList.remove('show');
    }

    elements.modalCloseBtn.addEventListener('click', closeInspector);
    elements.modalCloseAction.addEventListener('click', closeInspector);
    window.addEventListener('click', (e) => {
        if (e.target === elements.modal) closeInspector();
    });

    // =========================================================================
    // API CALL HELPERS
    // =========================================================================
    async function fetchJson(url) {
        try {
            const response = await fetch(url);
            if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
            return await response.json();
        } catch (error) {
            console.error(`Failed to fetch from ${url}:`, error);
            return null;
        }
    }

    // =========================================================================
    // CHARTS RENDERING (CHART.JS)
    // =========================================================================
    function updateTimelineChart(data) {
        const ctx = document.getElementById('timelineChart').getContext('2d');
        
        const labels = data.labels || [];
        const values = data.values || [];

        if (state.charts.timeline) {
            state.charts.timeline.destroy();
        }

        state.charts.timeline = new Chart(ctx, {
            type: 'line',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Alert Volume',
                    data: values,
                    borderColor: '#00f0ff',
                    backgroundColor: 'rgba(0, 240, 255, 0.08)',
                    borderWidth: 2,
                    pointBackgroundColor: '#00f0ff',
                    pointBorderColor: '#0e121a',
                    pointHoverRadius: 6,
                    tension: 0.35,
                    fill: true
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    x: {
                        grid: { color: 'rgba(255, 255, 255, 0.02)' },
                        ticks: { color: '#9aa5b5', font: { family: 'JetBrains Mono', size: 10 } }
                    },
                    y: {
                        grid: { color: 'rgba(255, 255, 255, 0.02)' },
                        ticks: { 
                            color: '#9aa5b5', 
                            stepSize: 1,
                            font: { family: 'JetBrains Mono', size: 10 } 
                        }
                    }
                }
            }
        });
    }

    function updateSeverityChart(data) {
        const ctx = document.getElementById('severityChart').getContext('2d');
        
        const labels = Object.keys(data);
        const values = Object.values(data);

        if (state.charts.severity) {
            state.charts.severity.destroy();
        }

        state.charts.severity = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: labels,
                datasets: [{
                    data: values,
                    backgroundColor: ['#ff3366', '#ffaa00', '#00beff', '#5e6b7e'],
                    borderColor: '#0e121a',
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'right',
                        labels: {
                            color: '#f0f4f8',
                            font: { family: 'Outfit', size: 12 }
                        }
                    }
                },
                cutout: '65%'
            }
        });
    }

    // =========================================================================
    // TAB-SPECIFIC SYNCHRONIZERS
    // =========================================================================

    // Tab 1: Dashboard Overview Tab
    async function syncOverviewTab() {
        // Fetch timeline and severity chart data
        const timelineData = await fetchJson('/api/alert_timeline');
        if (timelineData) updateTimelineChart(timelineData);

        const severityData = await fetchJson('/api/severity_distribution');
        if (severityData) updateSeverityChart(severityData);

        // Fetch Alert Stream
        const alerts = await fetchJson('/api/alerts');
        elements.alertsTable.innerHTML = '';
        if (alerts && alerts.length > 0) {
            elements.alertFeedCount.textContent = `${alerts.length} active alerts`;
            alerts.forEach(alert => {
                const tr = document.createElement('tr');
                const badgeClass = `badge-${alert.severity.toLowerCase()}`;
                
                tr.innerHTML = `
                    <td class="mono font-bold">${alert.alert_id}</td>
                    <td>${alert.rule_name}</td>
                    <td class="mono">${alert.source_ip}</td>
                    <td><span class="badge ${badgeClass}">${alert.severity}</span></td>
                    <td class="mono">${alert.detection_timestamp.substring(11, 19)}</td>
                    <td>
                        <button class="btn btn-primary btn-inspect-alert" style="padding: 0.25rem 0.6rem; font-size:0.75rem;">
                            <i class="fa-solid fa-magnifying-glass"></i> Inspect
                        </button>
                    </td>
                `;
                
                // Add click listener to inspect button
                tr.querySelector('.btn-inspect-alert').addEventListener('click', () => {
                    showInspector(`Inspect Alert Payload [${alert.alert_id}]`, alert);
                });
                
                elements.alertsTable.appendChild(tr);
            });
        } else {
            elements.alertFeedCount.textContent = '0 alerts';
            elements.alertsTable.innerHTML = `
                <tr>
                    <td colspan="6" class="text-center py-6 text-muted">No rules triggered yet. System clean.</td>
                </tr>
            `;
        }

        // Fetch Log Event Stream (First 15 parsed logs)
        const parsed = await fetchJson('/api/parsed');
        elements.parsedEventsTable.innerHTML = '';
        if (parsed && parsed.length > 0) {
            elements.parsedEventsCount.textContent = `${parsed.length} total parsed`;
            // Show only first 15 events in dashboard for performance
            parsed.slice(0, 15).forEach(event => {
                const tr = document.createElement('tr');
                const badgeClass = event.severity ? `badge-${event.severity.toLowerCase()}` : 'badge-low';
                
                tr.innerHTML = `
                    <td class="mono text-muted">${event.line_number || '#'}</td>
                    <td class="mono">${event.event_type}</td>
                    <td>${event.username || '<span class="text-muted">N/A</span>'}</td>
                    <td class="mono">${event.source_ip || '<span class="text-muted">N/A</span>'}</td>
                    <td><span class="badge ${badgeClass}">${event.severity || 'INFO'}</span></td>
                `;
                tr.addEventListener('click', () => {
                    showInspector(`Normalized Log Line #${event.line_number}`, event);
                });
                tr.style.cursor = 'pointer';
                elements.parsedEventsTable.appendChild(tr);
            });
        } else {
            elements.parsedEventsCount.textContent = '0 total';
            elements.parsedEventsTable.innerHTML = `
                <tr>
                    <td colspan="5" class="text-center py-6 text-muted">No parsed events available. Run Phase 1 parser!</td>
                </tr>
            `;
        }
    }

    // Tab 2: MITRE ATT&CK Tab
    async function syncMitreTab() {
        const mitreData = await fetchJson('/api/kill_chain');
        
        // Render Timeline Flow
        elements.killChainTimeline.innerHTML = '';
        if (mitreData && mitreData.chain && mitreData.chain.length > 0) {
            mitreData.chain.forEach((step, idx) => {
                const div = document.createElement('div');
                div.className = `timeline-step ${idx === mitreData.chain.length - 1 ? 'active' : 'completed'}`;
                div.innerHTML = `
                    <div class="step-badge">${idx + 1}</div>
                    <div class="step-title">${step.tactic_name}</div>
                    <div class="step-desc">${step.technique_id} - ${step.technique_name}</div>
                `;
                elements.killChainTimeline.appendChild(div);
            });
        } else {
            elements.killChainTimeline.innerHTML = `
                <div class="text-center w-full text-muted py-6">
                    <i class="fa-solid fa-hourglass-start fa-2x mb-2"></i>
                    <p>No attack chain observed. Kill chain inactive.</p>
                </div>
            `;
        }

        // Render detailed techniques table
        elements.mitreTechniquesTable.innerHTML = '';
        if (mitreData && mitreData.techniques && mitreData.techniques.length > 0) {
            mitreData.techniques.forEach(tech => {
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td class="mono font-bold">${tech.id}</td>
                    <td>${tech.name}</td>
                    <td><span class="badge badge-info">${tech.tactic}</span></td>
                    <td class="text-secondary">${tech.real_world_examples ? tech.real_world_examples[0] : 'N/A'}</td>
                    <td class="text-muted">${tech.mitigations ? tech.mitigations[0] : 'N/A'}</td>
                `;
                elements.mitreTechniquesTable.appendChild(tr);
            });
        } else {
            elements.mitreTechniquesTable.innerHTML = `
                <tr>
                    <td colspan="5" class="text-center py-6 text-muted">No observed threat techniques mapped.</td>
                </tr>
            `;
        }
    }

    // Tab 3: Machine Learning Tab
    async function syncMlTab() {
        const mlData = await fetchJson('/api/ml');
        
        // Populate metadata
        if (mlData && mlData.config) {
            elements.mlContamination.textContent = `${(mlData.config.contamination * 100).toFixed(0)}%`;
            elements.mlEstimators.textContent = mlData.config.n_estimators || 100;
        }

        // Render ML scoring table
        elements.mlScoringTable.innerHTML = '';
        if (mlData && mlData.results && mlData.results.length > 0) {
            mlData.results.forEach(res => {
                const tr = document.createElement('tr');
                const isAnomaly = res.is_anomaly;
                const statusBadge = isAnomaly ? 
                    '<span class="badge badge-critical animate-pulse"><i class="fa-solid fa-circle-exclamation"></i> ANOMALOUS</span>' : 
                    '<span class="badge badge-success"><i class="fa-solid fa-circle-check"></i> NORMAL</span>';
                
                const scoreText = res.anomaly_score.toFixed(4);
                
                tr.innerHTML = `
                    <td class="mono font-bold">${res.ip_address}</td>
                    <td class="mono">${scoreText}</td>
                    <td class="mono">${res.decision_boundary.toFixed(4)}</td>
                    <td class="mono">${(res.features.failure_rate * 100).toFixed(0)}%</td>
                    <td class="mono">${res.features.unique_username_count}</td>
                    <td class="mono">${res.features.is_off_hours ? 'YES' : 'NO'}</td>
                    <td>${statusBadge}</td>
                `;
                elements.mlScoringTable.appendChild(tr);
            });
        } else {
            elements.mlScoringTable.innerHTML = `
                <tr>
                    <td colspan="7" class="text-center py-6 text-muted">No Isolation Forest evaluation data. Run Phase 4 ML pipeline.</td>
                </tr>
            `;
        }

        // Render Explainable AI deviation table
        elements.mlXaiTable.innerHTML = '';
        let hasAnomalies = false;
        if (mlData && mlData.results) {
            mlData.results.forEach(res => {
                if (res.is_anomaly && res.anomaly_reasons && res.anomaly_reasons.length > 0) {
                    hasAnomalies = true;
                    res.anomaly_reasons.forEach(reason => {
                        const tr = document.createElement('tr');
                        tr.innerHTML = `
                            <td class="mono font-bold">${res.ip_address}</td>
                            <td><span class="badge badge-outline">${reason.feature}</span></td>
                            <td class="mono text-red font-bold">${reason.deviation.toFixed(1)}x</td>
                            <td class="text-secondary">${reason.human_explanation}</td>
                        `;
                        elements.mlXaiTable.appendChild(tr);
                    });
                }
            });
        }

        if (!hasAnomalies) {
            elements.mlXaiTable.innerHTML = `
                <tr>
                    <td colspan="4" class="text-center py-6 text-muted">No anomalies flagged. Clean behavioral status.</td>
                </tr>
            `;
        }
    }

    // Tab 4: SOAR Responses Tab
    async function syncSoarTab() {
        const soarData = await fetchJson('/api/incidents');

        // Playbook execution list
        elements.soarPlaybooksTable.innerHTML = '';
        const playbooks = await fetchJson('/api/alerts'); // playbooks trigger per alert
        if (playbooks && playbooks.length > 0) {
            playbooks.forEach((p, idx) => {
                const tr = document.createElement('tr');
                
                // Map rule to simulated playbook
                let pbName = "PB-001: Port Scan Response";
                if (p.rule_name === "SSH_BRUTE_FORCE") pbName = "PB-002: SSH Brute Force Response";
                if (p.rule_name === "BRUTE_FORCE_SUCCESS") pbName = "PB-003: Account Compromise Response";

                tr.innerHTML = `
                    <td class="font-bold">${pbName}</td>
                    <td class="mono">${p.detection_timestamp.substring(11, 19)}</td>
                    <td class="mono">Completed (Auto)</td>
                    <td><span class="badge badge-success">ACTIVE</span></td>
                    <td>
                        <button class="btn btn-primary btn-inspect-pb" style="padding: 0.25rem 0.6rem; font-size:0.75rem;">
                            <i class="fa-solid fa-code-fork"></i> View Steps
                        </button>
                    </td>
                `;

                tr.querySelector('.btn-inspect-pb').addEventListener('click', () => {
                    // Load actual SOAR results json to search details
                    fetchJson('/api/soar_results').then(results => {
                        let matched = results ? results.find(r => r.playbook.includes(pbName.substring(0, 6))) : null;
                        showInspector(pbName, matched || p);
                    });
                });
                
                elements.soarPlaybooksTable.appendChild(tr);
            });
        } else {
            elements.soarPlaybooksTable.innerHTML = `
                <tr>
                    <td colspan="5" class="text-center py-6 text-muted">No playbook executions recorded.</td>
                </tr>
            `;
        }

        // Active firewall blocked IPs
        elements.blockedIpsTable.innerHTML = '';
        if (soarData && soarData.blocked_ips && soarData.blocked_ips.length > 0) {
            soarData.blocked_ips.forEach(b => {
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td class="mono font-bold text-red">${b.ip_address}</td>
                    <td>${b.reason}</td>
                    <td class="mono">${b.auto_unblock_at.substring(11, 19)}</td>
                `;
                elements.blockedIpsTable.appendChild(tr);
            });
        } else {
            elements.blockedIpsTable.innerHTML = `
                <tr>
                    <td colspan="3" class="text-center py-6 text-muted">No active firewall blocks active.</td>
                </tr>
            `;
        }

        // Audit Logs text pre
        const auditLogData = await fetchJson('/api/audit_log');
        if (auditLogData && auditLogData.lines && auditLogData.lines.length > 0) {
            elements.auditLogTerminal.textContent = auditLogData.lines.join('\n');
            // Auto scroll console terminal to bottom
            elements.auditLogTerminal.scrollTop = elements.auditLogTerminal.scrollHeight;
        } else {
            elements.auditLogTerminal.textContent = "No audit transactions available.";
        }
    }

    // Tab 5: Incident Report Details Tab
    async function syncReportsTab() {
        const report = await fetchJson('/api/report_summary');
        
        if (!report || !report.available) {
            elements.reportPlaceholder.classList.remove('hidden');
            elements.reportContent.classList.add('hidden');
            return;
        }

        // Populate elements
        elements.reportPlaceholder.classList.add('hidden');
        elements.reportContent.classList.remove('hidden');

        elements.reportId.textContent = report.incident_id;
        elements.reportPriority.textContent = report.priority;
        
        // Severity color styling
        elements.reportPriority.className = 'badge';
        if (report.priority === 'CRITICAL') elements.reportPriority.classList.add('badge-critical');
        else if (report.priority === 'HIGH') elements.reportPriority.classList.add('badge-high');
        else elements.reportPriority.classList.add('badge-medium');

        elements.reportBreach.textContent = report.breach ? 'YES -- COMPROMISED' : 'NO';
        elements.reportBreach.className = report.breach ? 'text-red font-bold' : 'text-muted';
        
        elements.reportNarrative.textContent = report.narrative;

        // Build checklist actions
        elements.reportActions.innerHTML = '';
        if (report.immediate_actions && report.immediate_actions.length > 0) {
            report.immediate_actions.forEach((act, idx) => {
                const li = document.createElement('li');
                // Auto check the first two containment steps to simulate SOAR execution complete
                if (idx < 2) li.className = 'checked';
                li.innerHTML = `<span>${act}</span>`;
                elements.reportActions.appendChild(li);
            });
        }

        // Fetch full incident report to reconstruct timeline
        const fullReport = await fetchJson('/api/report_summary');
        fetchJson('/api/report_summary').then(async () => {
            const rawReport = await fetchJson('/api/stats');
            // Reconstruct report timeline
            const reportDetails = await fetchJson('/api/report_summary');
            // Let's populate the long term recommendations
            elements.reportRecommendations.innerHTML = `
                <li>Implement MFA on all SSH access (eliminates brute force entirely)</li>
                <li>Switch to SSH key authentication, disable password auth</li>
                <li>Deploy SIEM alerting on this detection rule with lower threshold</li>
                <li>Add attacker IP(s) to threat intelligence blocklist</li>
            `;
            
            // Reconstruct the timeline nodes from the API timeline
            const rawIncident = await fetchJson('/api/alerts');
            elements.reportTimeline.innerHTML = '';
            if (rawIncident && rawIncident.length > 0) {
                rawIncident.forEach(node => {
                    const div = document.createElement('div');
                    const sev = node.severity.toLowerCase();
                    div.className = `timeline-node ${sev}`;
                    div.innerHTML = `
                        <span class="timeline-node-time">${node.detection_timestamp}</span>
                        <div class="timeline-node-title">${node.rule_name}</div>
                        <div class="timeline-node-desc">Source IP: ${node.source_ip} | Severity: ${node.severity}</div>
                    `;
                    elements.reportTimeline.appendChild(div);
                });
            } else {
                elements.reportTimeline.innerHTML = '<p class="text-muted p-6">No timeline events.</p>';
            }
        });
    }

    // =========================================================================
    // MASTER SYNCHRONIZER
    // =========================================================================
    async function syncData() {
        if (state.isSyncing) return;
        state.isSyncing = true;
        
        // Spin refresh button
        const refreshIcon = elements.btnRefresh.querySelector('i');
        if (refreshIcon) refreshIcon.classList.add('fa-spin');

        try {
            // 1. Sync header metrics & System-wide status
            const stats = await fetchJson('/api/stats');
            if (stats) {
                elements.kpiEvents.textContent = stats.events_processed;
                elements.kpiAlerts.textContent = stats.total_alerts;
                elements.kpiCritical.textContent = stats.critical_alerts;
                elements.kpiAnomalies.textContent = stats.ml_anomalies;
                elements.syncTime.textContent = stats.last_updated;

                // Breach indicator warning system status
                if (stats.breach_detected) {
                    elements.statusDot.className = 'status-dot red animate-pulse';
                    elements.statusLabel.textContent = 'BREACH DETECTED';
                    elements.statusLabel.className = 'status-label text-red';
                    elements.kpiCardCritical.classList.add('card-glow');
                } else {
                    elements.statusDot.className = 'status-dot green animate-pulse';
                    elements.statusLabel.textContent = 'MONITORING';
                    elements.statusLabel.className = 'status-label';
                    elements.kpiCardCritical.classList.remove('card-glow');
                }
            }

            // 2. Sync active tab panel
            switch (state.currentTab) {
                case 'overview':
                    await syncOverviewTab();
                    break;
                case 'mitre':
                    await syncMitreTab();
                    break;
                case 'ml-anomaly':
                    await syncMlTab();
                    break;
                case 'soar':
                    await syncSoarTab();
                    break;
                case 'reports':
                    await syncReportsTab();
                    break;
            }

        } catch (err) {
            console.error("Synchronization loop failed:", err);
        } finally {
            state.isSyncing = false;
            if (refreshIcon) refreshIcon.classList.remove('fa-spin');
        }
    }

    // =========================================================================
    // INITIALIZATION & LOOP
    // =========================================================================
    initNavigation();
    
    // Initial run
    syncData();

    // Trigger sync on manual refresh button click
    elements.btnRefresh.addEventListener('click', syncData);

    // Setup background synchronization interval (every 5 seconds)
    state.refreshInterval = setInterval(syncData, 5000);
});
