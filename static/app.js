/**
 * Rustaceans Security RMM Dashboard
 * Frontend JavaScript for the security monitoring dashboard
 */

class RMMDashboard {
    constructor() {
        this.apiBase = '/api/v1';
        this.updateInterval = 30000; // 30 seconds
        this.lastUpdate = null;
        this.isConnected = false;
        this.filters = {
            severity: '',
            category: ''
        };
        
        this.init();
    }

    async init() {
        console.log('Initializing RMM Dashboard...');
        
        // Check authentication first
        const authCheck = await this.checkAuthentication();
        if (!authCheck) {
            window.location.href = '/login';
            return;
        }
        
        // Set up event listeners
        this.setupEventListeners();
        
        // Set up periodic updates
        this.setupPeriodicUpdates();
        
        // Initial data load
        await this.loadAllData();
        
        console.log('RMM Dashboard initialized successfully');
    }

    async checkAuthentication() {
        try {
            const response = await fetch('/api/auth/check');
            const result = await response.json();
            
            if (result.authenticated) {
                // Add logout button to header if not exists
                this.addLogoutButton(result.user);
                return true;
            }
            return false;
        } catch (error) {
            console.error('Authentication check failed:', error);
            return false;
        }
    }

    addLogoutButton(user) {
        const header = document.querySelector('.header');
        if (header && !document.querySelector('.user-menu')) {
            const userMenu = document.createElement('div');
            userMenu.className = 'user-menu';
            userMenu.innerHTML = `
                <span class="user-info">Welcome, ${user.username}</span>
                <button onclick="dashboard.logout()" class="logout-btn">Logout</button>
            `;
            header.appendChild(userMenu);
        }
    }

    async logout() {
        try {
            await fetch('/api/auth/logout', { method: 'POST' });
            window.location.href = '/login';
        } catch (error) {
            console.error('Logout failed:', error);
            window.location.href = '/login';
        }
    }

    setupEventListeners() {
        // Tab navigation
        document.querySelectorAll('.tab').forEach(tab => {
            tab.addEventListener('click', (e) => {
                const tabName = e.target.closest('.tab').dataset.tab;
                this.switchTab(tabName);
            });
        });

        // Filter controls
        const severityFilter = document.getElementById('severity-filter');
        const categoryFilter = document.getElementById('category-filter');
        
        if (severityFilter) {
            severityFilter.addEventListener('change', (e) => {
                this.filters.severity = e.target.value;
                this.filterFindings();
            });
        }
        
        if (categoryFilter) {
            categoryFilter.addEventListener('change', (e) => {
                this.filters.category = e.target.value;
                this.filterFindings();
            });
        }

        // Clickable summary cards
        document.querySelectorAll('.summary-card.clickable').forEach(card => {
            card.addEventListener('click', (e) => {
                const section = card.getAttribute('data-navigate');
                if (section) {
                    this.switchTab(section);
                }
            });
        });

        // Refresh on window focus
        window.addEventListener('focus', () => {
            this.loadAllData();
        });

        // Keyboard shortcuts
        document.addEventListener('keydown', (e) => {
            if (e.ctrlKey || e.metaKey) {
                switch (e.key) {
                    case 'r':
                        e.preventDefault();
                        this.loadAllData();
                        break;
                    case '1':
                        e.preventDefault();
                        this.switchTab('dashboard');
                        break;
                    case '2':
                        e.preventDefault();
                        this.switchTab('findings');
                        break;
                    case '3':
                        e.preventDefault();
                        this.switchTab('clients');
                        break;
                    case '4':
                        e.preventDefault();
                        this.switchTab('system');
                        break;
                }
            }
        });
    }

    setupPeriodicUpdates() {
        // Update data every 30 seconds
        setInterval(() => {
            this.loadAllData();
        }, this.updateInterval);

        // Update status indicator
        setInterval(() => {
            this.updateConnectionStatus();
        }, 5000);
    }

    switchTab(tabName) {
        // Update tab buttons
        document.querySelectorAll('.tab').forEach(tab => {
            tab.classList.remove('active');
        });
        document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');

        // Update tab panels
        document.querySelectorAll('.tab-panel').forEach(panel => {
            panel.classList.remove('active');
        });
        document.getElementById(`${tabName}-panel`).classList.add('active');

        // Load tab-specific data if needed
        switch (tabName) {
            case 'system':
                this.loadSystemInfo();
                break;
            case 'clients':
                this.loadClients();
                break;
            case 'findings':
                this.loadScanResults();
                break;
            default:
                break;
        }
    }

    async loadAllData() {
        try {
            this.updateConnectionStatus(true);
            
            // Load all data in parallel
            const promises = [
                this.loadScanResults(),
                this.loadClients(),
                this.loadSystemInfo(),
                this.loadVulnerabilityReport(),
                this.loadVulnerabilities(),
                this.loadPatches(),
                this.loadMisconfigurations(),
                this.loadPIIExposure()
            ];

            await Promise.allSettled(promises);
            
            this.lastUpdate = new Date();
            this.updateLastUpdateTime();
            this.isConnected = true;
            
        } catch (error) {
            console.error('Failed to load data:', error);
            this.isConnected = false;
            this.showError('Failed to load dashboard data');
        } finally {
            this.updateConnectionStatus();
        }
    }

    async loadVulnerabilityReport() {
        try {
            const response = await fetch(`${this.apiBase}/vulnerability-report`);
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            const data = await response.json();
            this.displayVulnerabilityReport(data);
            
        } catch (error) {
            console.error('Failed to load vulnerability report:', error);
            this.showError('Failed to load vulnerability report');
        }
    }

    displayVulnerabilityReport(data) {
        const container = document.getElementById('vulnerability-report');
        if (!container) return;

        const html = `
            <div class="vulnerability-summary">
                <h3>Patch Management Status</h3>
                <div class="patch-stats">
                    <div class="stat-card critical">
                        <h4>Critical Patches</h4>
                        <span class="stat-number">${data.critical_patches || 0}</span>
                    </div>
                    <div class="stat-card high">
                        <h4>High Priority</h4>
                        <span class="stat-number">${data.high_priority_patches || 0}</span>
                    </div>
                    <div class="stat-card">
                        <h4>Total Vulnerabilities</h4>
                        <span class="stat-number">${data.vulnerabilities_found || 0}</span>
                    </div>
                </div>
            </div>

            <div class="patch-recommendations">
                <h3>Recommended Updates</h3>
                ${data.patch_recommendations && data.patch_recommendations.length > 0 ? 
                    data.patch_recommendations.map(patch => `
                        <div class="patch-item ${patch.severity_level.toLowerCase()}">
                            <div class="patch-header">
                                <h4>${patch.package_name}</h4>
                                <span class="severity-badge ${patch.severity_level.toLowerCase()}">${patch.severity_level}</span>
                            </div>
                            <div class="patch-details">
                                <p><strong>Current:</strong> ${patch.current_version}</p>
                                <p><strong>Target:</strong> ${patch.target_version}</p>
                                <p><strong>Vulnerabilities:</strong> ${patch.vulnerability_count}</p>
                                ${patch.requires_reboot ? '<p class="reboot-warning">⚠️ Requires reboot</p>' : ''}
                                ${patch.estimated_downtime ? `<p><strong>Downtime:</strong> ${patch.estimated_downtime}</p>` : ''}
                            </div>
                            <div class="patch-command">
                                <strong>Update Command:</strong>
                                <code>${patch.update_command}</code>
                                <button class="copy-btn" onclick="navigator.clipboard.writeText('${patch.update_command}')">Copy</button>
                            </div>
                        </div>
                    `).join('') : 
                    '<p class="no-patches">No critical patches required at this time.</p>'
                }
            </div>
        `;

        container.innerHTML = html;
    }

    async loadVulnerabilities() {
        try {
            const response = await fetch(`${this.apiBase}/vulnerabilities`);
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            const vulnerabilities = await response.json();
            this.displayVulnerabilities(vulnerabilities);
            
        } catch (error) {
            console.error('Failed to load vulnerabilities:', error);
            this.showError('Failed to load vulnerability data');
        }
    }

    displayVulnerabilities(vulnerabilities) {
        const container = document.getElementById('vulnerabilities-list');
        if (!container) return;

        // Update dashboard summary count
        const criticalCount = vulnerabilities.filter(v => v.severity === 'Critical').length;
        const criticalCountEl = document.getElementById('critical-count');
        if (criticalCountEl) criticalCountEl.textContent = criticalCount;

        const html = `
            <div class="vulnerability-grid">
                ${vulnerabilities.map(vuln => `
                    <div class="vulnerability-card ${vuln.severity.toLowerCase()}" onclick="window.rmm.showCVEDetails('${vuln.cve_id}')">
                        <div class="vuln-header">
                            <h4>${vuln.cve_id}</h4>
                            <span class="severity-badge ${vuln.severity.toLowerCase()}">${vuln.severity}</span>
                            ${vuln.cvss_score ? `<span class="cvss-score">CVSS: ${vuln.cvss_score}</span>` : ''}
                        </div>
                        <p class="vuln-description">${vuln.description}</p>
                        <div class="vuln-details">
                            <div class="detail-row">
                                <strong>Affected Software:</strong>
                                <span>${vuln.affected_software ? `${vuln.affected_software.vendor} ${vuln.affected_software.product}` : vuln.affected_packages?.join(', ') || 'Unknown'}</span>
                            </div>
                            ${vuln.discovery_method ? `
                                <div class="detail-row">
                                    <strong>Detection Method:</strong>
                                    <span class="detection-badge">${vuln.discovery_method.replace('_', ' ')}</span>
                                </div>
                            ` : ''}
                            <div class="detail-row">
                                <strong>Exploitability:</strong>
                                <span class="exploit-level ${vuln.exploitability}">${vuln.exploitability}</span>
                            </div>
                            ${vuln.patch_info ? `
                                <div class="patch-info ${vuln.patch_info.available ? 'available' : 'unavailable'}">
                                    <strong>Patch Status:</strong> 
                                    ${vuln.patch_info.available ? 
                                        `<span class="patch-available">Available (${vuln.patch_info.kb_article})</span>` : 
                                        '<span class="patch-unavailable">Not Available</span>'
                                    }
                                </div>
                            ` : ''}
                        </div>
                        <div class="vuln-actions">
                            <button class="btn-details" onclick="event.stopPropagation(); window.rmm.showCVEDetails('${vuln.cve_id}')">
                                View Details
                            </button>
                            ${vuln.patch_info?.available ? 
                                `<button class="btn-patch" onclick="event.stopPropagation(); window.rmm.applyPatch('${vuln.cve_id}')">Apply Patch</button>` : 
                                ''
                            }
                        </div>
                    </div>
                `).join('')}
            </div>
        `;

        container.innerHTML = html;
        this.currentVulnerabilities = vulnerabilities;
    }

    async loadPatches() {
        try {
            const response = await fetch(`${this.apiBase}/patches`);
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            const patches = await response.json();
            this.displayPatches(patches);
            
        } catch (error) {
            console.error('Failed to load patches:', error);
            this.showError('Failed to load patch data');
        }
    }

    displayPatches(patches) {
        const container = document.getElementById('patches-list');
        if (!container) return;

        // Update dashboard summary count
        const patchesCountEl = document.getElementById('patches-count');
        if (patchesCountEl) patchesCountEl.textContent = patches.length;

        const html = `
            <div class="patches-grid">
                ${patches.map(patch => `
                    <div class="patch-card ${patch.severity_level.toLowerCase()}">
                        <div class="patch-header">
                            <h4>${patch.package_name}</h4>
                            <span class="severity-badge ${patch.severity_level.toLowerCase()}">${patch.severity_level}</span>
                        </div>
                        <div class="patch-details">
                            <p><strong>Current:</strong> ${patch.current_version}</p>
                            <p><strong>Target:</strong> ${patch.target_version}</p>
                            <p><strong>CVEs:</strong> ${patch.vulnerability_ids.join(', ')}</p>
                            ${patch.requires_reboot ? '<p class="reboot-warning">⚠️ Requires reboot</p>' : ''}
                        </div>
                        <div class="patch-command">
                            <code>${patch.update_command}</code>
                            <button class="copy-btn" onclick="navigator.clipboard.writeText('${patch.update_command}')">Copy</button>
                        </div>
                    </div>
                `).join('')}
            </div>
        `;

        container.innerHTML = html;
    }

    async loadMisconfigurations() {
        try {
            const response = await fetch(`${this.apiBase}/misconfigurations`);
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            const data = await response.json();
            this.displayMisconfigurations(data.misconfigurations);
            
        } catch (error) {
            console.error('Failed to load misconfigurations:', error);
            this.showError('Failed to load misconfiguration data');
        }
    }

    displayMisconfigurations(misconfigs) {
        const container = document.getElementById('misconfigs-list');
        if (!container) return;

        // Update dashboard summary count
        const misconfigsCountEl = document.getElementById('misconfigs-count');
        if (misconfigsCountEl) misconfigsCountEl.textContent = misconfigs.length;

        const html = `
            <div class="misconfig-grid">
                ${misconfigs.map(config => `
                    <div class="misconfig-card ${config.severity.toLowerCase()}">
                        <div class="misconfig-header">
                            <h4>${config.type}</h4>
                            <span class="severity-badge ${config.severity.toLowerCase()}">${config.severity}</span>
                        </div>
                        <p class="misconfig-description">${config.description}</p>
                        <div class="misconfig-details">
                            <div class="detail-row">
                                <strong>Affected Hosts:</strong>
                                <span>${config.affected_hosts.join(', ')}</span>
                            </div>
                            <div class="detail-row">
                                <strong>Risk Score:</strong>
                                <span class="risk-score">${config.risk_score}/10</span>
                            </div>
                            <div class="detail-row">
                                <strong>Compliance:</strong>
                                <span>${config.compliance_frameworks.join(', ')}</span>
                            </div>
                        </div>
                        <div class="remediation">
                            <strong>Remediation:</strong>
                            <p>${config.remediation}</p>
                            ${config.auto_fix_available ? 
                                '<button class="auto-fix-btn">Auto-Fix Available</button>' : 
                                '<span class="manual-fix">Manual remediation required</span>'
                            }
                        </div>
                    </div>
                `).join('')}
            </div>
        `;

        container.innerHTML = html;
    }

    async loadPIIExposure() {
        try {
            const response = await fetch(`${this.apiBase}/pii-exposure`);
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            const data = await response.json();
            this.displayPIIExposure(data);
            
        } catch (error) {
            console.error('Failed to load PII exposure data:', error);
            this.showError('Failed to load PII exposure data');
        }
    }

    displayPIIExposure(data) {
        const container = document.getElementById('pii-list');
        if (!container) return;

        // Update dashboard summary count
        const piiCountEl = document.getElementById('pii-count');
        if (piiCountEl) piiCountEl.textContent = data.total_exposures;

        const html = `
            <div class="pii-summary">
                <div class="pii-stats">
                    <div class="stat-card critical">
                        <h4>Total Exposures</h4>
                        <span class="stat-number">${data.total_exposures}</span>
                    </div>
                    <div class="stat-card">
                        <h4>Records at Risk</h4>
                        <span class="stat-number">${data.total_records_at_risk.toLocaleString()}</span>
                    </div>
                    <div class="stat-card">
                        <h4>Regulations</h4>
                        <span class="stat-number">${data.affected_regulations.length}</span>
                    </div>
                </div>
            </div>
            <div class="pii-grid">
                ${data.pii_findings.map(finding => `
                    <div class="pii-card ${finding.severity.toLowerCase()}">
                        <div class="pii-header">
                            <h4>${finding.type}</h4>
                            <span class="severity-badge ${finding.severity.toLowerCase()}">${finding.severity}</span>
                        </div>
                        <div class="pii-details">
                            <div class="detail-row">
                                <strong>Location:</strong>
                                <span>${finding.location}</span>
                            </div>
                            <div class="detail-row">
                                <strong>Host:</strong>
                                <span>${finding.host}</span>
                            </div>
                            <div class="detail-row">
                                <strong>Pattern:</strong>
                                <span class="pattern">${finding.pattern_matched}</span>
                            </div>
                            <div class="detail-row">
                                <strong>Occurrences:</strong>
                                <span class="occurrences">${finding.occurrences}</span>
                            </div>
                            <div class="detail-row">
                                <strong>Regulations:</strong>
                                <span class="regulations">${finding.regulation_impact.join(', ')}</span>
                            </div>
                        </div>
                        <div class="remediation">
                            <strong>Remediation:</strong>
                            <p>${finding.remediation}</p>
                        </div>
                    </div>
                `).join('')}
            </div>
        `;

        container.innerHTML = html;
    }

    async loadScanResults() {
        try {
            const response = await fetch(`${this.apiBase}/scan-results`);
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            const scanResults = await response.json();
            this.displayScanResults(scanResults);
            this.updateSummaryCards(scanResults);
            
        } catch (error) {
            console.error('Failed to load scan results:', error);
            this.showEmptyState('findings-list', 'Failed to load security findings');
        }
    }

    async loadClients() {
        try {
            const response = await fetch(`${this.apiBase}/clients`);
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            const clients = await response.json();
            this.displayClients(clients);
            
            // Update dashboard summary count
            const clientsCountEl = document.getElementById('clients-count');
            if (clientsCountEl) clientsCountEl.textContent = clients.length;
            
        } catch (error) {
            console.error('Failed to load clients:', error);
            this.showEmptyState('clients-list', 'Failed to load client information');
        }
    }

    async loadSystemInfo() {
        try {
            const response = await fetch(`${this.apiBase}/system-info`);
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            const systemInfo = await response.json();
            this.displaySystemInfo(systemInfo);
            this.updateSystemHealth(systemInfo);
            
        } catch (error) {
            console.error('Failed to load system info:', error);
            this.showEmptyState('system-info', 'Failed to load system information');
        }
    }

    displayScanResults(scanResults) {
        const container = document.getElementById('findings-list');
        const recentContainer = document.getElementById('recent-findings');
        
        if (!Array.isArray(scanResults) || scanResults.length === 0) {
            this.showEmptyState('findings-list', 'No security findings available');
            this.showEmptyState('recent-findings', 'No recent findings');
            return;
        }

        // Flatten all findings from all scan results
        const allFindings = [];
        scanResults.forEach(result => {
            if (result.findings && Array.isArray(result.findings)) {
                result.findings.forEach(finding => {
                    allFindings.push({
                        ...finding,
                        clientId: result.client_id,
                        scanType: result.scan_type,
                        timestamp: result.timestamp
                    });
                });
            }
        });

        // Sort by severity and timestamp
        allFindings.sort((a, b) => {
            const severityOrder = { 'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Info': 4 };
            const severityDiff = severityOrder[a.severity] - severityOrder[b.severity];
            if (severityDiff !== 0) return severityDiff;
            return new Date(b.timestamp) - new Date(a.timestamp);
        });

        // Update categories for filter
        this.updateCategoryFilter(allFindings);

        // Display all findings
        container.innerHTML = allFindings.map(finding => this.createFindingHTML(finding)).join('');

        // Display recent findings (last 10)
        const recentFindings = allFindings.slice(0, 10);
        if (recentFindings.length > 0) {
            recentContainer.innerHTML = recentFindings.map(finding => this.createFindingHTML(finding, true)).join('');
        } else {
            this.showEmptyState('recent-findings', 'No recent findings');
        }

        // Store findings for filtering
        this.currentFindings = allFindings;
        this.filterFindings();
    }

    createFindingHTML(finding, compact = false) {
        const severityClass = finding.severity.toLowerCase();
        const timestamp = new Date(finding.timestamp).toLocaleDateString();
        
        return `
            <div class="finding-item" data-severity="${finding.severity}" data-category="${finding.category}">
                <div class="finding-header">
                    <div class="finding-title">${this.escapeHtml(finding.title)}</div>
                    <span class="severity-badge ${severityClass}">${finding.severity}</span>
                </div>
                <div class="finding-description">${this.escapeHtml(finding.description)}</div>
                <div class="finding-meta">
                    <span>📂 ${this.escapeHtml(finding.category)}</span>
                    <span>🖥️ ${this.escapeHtml(finding.clientId)}</span>
                    <span>📅 ${timestamp}</span>
                    ${finding.affected_resource ? `<span>🎯 ${this.escapeHtml(finding.affected_resource)}</span>` : ''}
                </div>
                ${!compact && finding.recommendation ? `
                    <div class="finding-recommendation">
                        <strong>Recommendation:</strong> ${this.escapeHtml(finding.recommendation)}
                    </div>
                ` : ''}
            </div>
        `;
    }

    displayClients(clients) {
        const container = document.getElementById('clients-list');
        
        if (!Array.isArray(clients) || clients.length === 0) {
            this.showEmptyState('clients-list', 'No clients connected');
            return;
        }

        const html = `
            <div class="clients-grid">
                ${clients.map(client => {
                    const lastSeen = new Date(client.last_seen).toLocaleString();
                    const statusClass = client.status.toLowerCase();
                    
                    return `
                        <div class="client-card ${statusClass}" onclick="window.rmm.showClientDetails('${client.id}')">
                            <div class="client-header">
                                <div class="client-name">${this.escapeHtml(client.hostname || client.id)}</div>
                                <span class="status-badge ${statusClass}">${client.status}</span>
                            </div>
                            <div class="client-info">
                                <div class="detail-row">
                                    <strong>IP:</strong> ${this.escapeHtml(client.ip_address)}
                                </div>
                                <div class="detail-row">
                                    <strong>OS:</strong> ${this.escapeHtml(client.os_version)}
                                </div>
                                <div class="detail-row">
                                    <strong>Last seen:</strong> ${lastSeen}
                                </div>
                                <div class="detail-row">
                                    <strong>Agent:</strong> v${client.agent_version}
                                </div>
                            </div>
                            <div class="client-actions">
                                <button class="btn-secondary" onclick="event.stopPropagation(); window.rmm.showClientDetails('${client.id}')">
                                    View Details
                                </button>
                            </div>
                        </div>
                    `;
                }).join('')}
            </div>
        `;

        container.innerHTML = html;
    }

    displaySystemInfo(systemInfo) {
        const container = document.getElementById('system-info');
        
        if (!systemInfo) {
            this.showEmptyState('system-info', 'System information not available');
            return;
        }

        const sections = [
            {
                title: 'System Overview',
                items: [
                    { label: 'Hostname', value: systemInfo.hostname || 'Unknown' },
                    { label: 'Operating System', value: systemInfo.os || 'Unknown' },
                    { label: 'Uptime', value: this.formatUptime(systemInfo.uptime) },
                    { label: 'Boot Time', value: this.formatTimestamp(systemInfo.boot_time) }
                ]
            },
            {
                title: 'Hardware',
                items: [
                    { label: 'CPU Count', value: systemInfo.cpu_count || 'Unknown' },
                    { label: 'Total Memory', value: this.formatBytes(systemInfo.total_memory) },
                    { label: 'Used Memory', value: this.formatBytes(systemInfo.used_memory) },
                    { label: 'Memory Usage', value: systemInfo.total_memory ? 
                        `${((systemInfo.used_memory / systemInfo.total_memory) * 100).toFixed(1)}%` : 'Unknown' }
                ]
            }
        ];

        if (systemInfo.disks && systemInfo.disks.length > 0) {
            sections.push({
                title: 'Disk Usage',
                items: systemInfo.disks.map(disk => ({
                    label: disk.mount_point || disk.name,
                    value: `${this.formatBytes(disk.available_space)} / ${this.formatBytes(disk.total_space)} available`
                })).slice(0, 5) // Limit to 5 disks
            });
        }

        container.innerHTML = sections.map(section => `
            <div class="system-section">
                <h4>${section.title}</h4>
                <div class="system-grid">
                    ${section.items.map(item => `
                        <div class="system-item">
                            <div class="system-item-header">
                                <span class="system-item-title">${this.escapeHtml(item.label)}</span>
                            </div>
                            <div class="system-item-value">${this.escapeHtml(item.value)}</div>
                        </div>
                    `).join('')}
                </div>
            </div>
        `).join('');
    }

    updateSummaryCards(scanResults) {
        const counts = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
        let clientCount = new Set();

        if (Array.isArray(scanResults)) {
            scanResults.forEach(result => {
                if (result.client_id) {
                    clientCount.add(result.client_id);
                }
                
                if (result.findings && Array.isArray(result.findings)) {
                    result.findings.forEach(finding => {
                        if (counts.hasOwnProperty(finding.severity)) {
                            counts[finding.severity]++;
                        }
                    });
                }
            });
        }

        document.getElementById('critical-count').textContent = counts.Critical;
        document.getElementById('high-count').textContent = counts.High;
        document.getElementById('medium-count').textContent = counts.Medium;
        document.getElementById('clients-count').textContent = clientCount.size;
    }

    updateSystemHealth(systemInfo) {
        const cpuUsage = document.getElementById('cpu-usage');
        const memoryUsage = document.getElementById('memory-usage');
        const diskUsage = document.getElementById('disk-usage');

        if (systemInfo.total_memory && systemInfo.used_memory) {
            const memUsagePercent = ((systemInfo.used_memory / systemInfo.total_memory) * 100).toFixed(1);
            memoryUsage.textContent = `${memUsagePercent}%`;
        } else {
            memoryUsage.textContent = '--';
        }

        // CPU usage would need real-time data
        cpuUsage.textContent = '--';

        // Calculate average disk usage
        if (systemInfo.disks && systemInfo.disks.length > 0) {
            const avgDiskUsage = systemInfo.disks.reduce((acc, disk) => {
                const usage = ((disk.total_space - disk.available_space) / disk.total_space) * 100;
                return acc + usage;
            }, 0) / systemInfo.disks.length;
            diskUsage.textContent = `${avgDiskUsage.toFixed(1)}%`;
        } else {
            diskUsage.textContent = '--';
        }
    }

    updateCategoryFilter(findings) {
        const categoryFilter = document.getElementById('category-filter');
        if (!categoryFilter) return;

        const categories = [...new Set(findings.map(f => f.category))].sort();
        
        // Clear existing options except "All Categories"
        categoryFilter.innerHTML = '<option value="">All Categories</option>';
        
        // Add category options
        categories.forEach(category => {
            const option = document.createElement('option');
            option.value = category;
            option.textContent = category;
            categoryFilter.appendChild(option);
        });
    }

    filterFindings() {
        if (!this.currentFindings) return;

        const container = document.getElementById('findings-list');
        const findingItems = container.querySelectorAll('.finding-item');

        findingItems.forEach(item => {
            const severity = item.dataset.severity;
            const category = item.dataset.category;
            
            const severityMatch = !this.filters.severity || severity === this.filters.severity;
            const categoryMatch = !this.filters.category || category === this.filters.category;
            
            if (severityMatch && categoryMatch) {
                item.style.display = 'block';
            } else {
                item.style.display = 'none';
            }
        });

        // Check if any items are visible
        const visibleItems = Array.from(findingItems).filter(item => item.style.display !== 'none');
        if (visibleItems.length === 0 && findingItems.length > 0) {
            this.showEmptyState('findings-list', 'No findings match the current filters');
        }
    }

    updateConnectionStatus(connecting = false) {
        const statusDot = document.querySelector('.status-dot');
        const statusText = document.getElementById('status-text');

        if (connecting) {
            statusDot.className = 'status-dot';
            statusText.textContent = 'Connecting...';
        } else if (this.isConnected) {
            statusDot.className = 'status-dot connected';
            statusText.textContent = 'Connected';
        } else {
            statusDot.className = 'status-dot error';
            statusText.textContent = 'Connection Error';
        }
    }

    updateLastUpdateTime() {
        const element = document.getElementById('last-update-time');
        if (this.lastUpdate && element) {
            element.textContent = this.lastUpdate.toLocaleTimeString();
        }
    }

    showEmptyState(containerId, message) {
        const container = document.getElementById(containerId);
        if (container) {
            container.innerHTML = `
                <div class="empty-state">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <circle cx="12" cy="12" r="10"/>
                        <path d="m9 12 2 2 4-4"/>
                    </svg>
                    <p>${this.escapeHtml(message)}</p>
                    <small>Data will appear here when available</small>
                </div>
            `;
        }
    }

    showError(message) {
        console.error('Dashboard Error:', message);
        
        // You could implement a toast notification system here
        // For now, we'll just log the error
    }

    // Utility functions
    escapeHtml(unsafe) {
        if (typeof unsafe !== 'string') {
            return String(unsafe);
        }
        
        return unsafe
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    formatBytes(bytes) {
        if (!bytes || bytes === 0) return '0 B';
        
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        
        return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
    }

    formatUptime(seconds) {
        if (!seconds) return 'Unknown';
        
        const days = Math.floor(seconds / 86400);
        const hours = Math.floor((seconds % 86400) / 3600);
        const minutes = Math.floor((seconds % 3600) / 60);
        
        if (days > 0) {
            return `${days}d ${hours}h ${minutes}m`;
        } else if (hours > 0) {
            return `${hours}h ${minutes}m`;
        } else {
            return `${minutes}m`;
        }
    }

    formatTimestamp(timestamp) {
        if (!timestamp) return 'Unknown';
        
        try {
            return new Date(timestamp * 1000).toLocaleString();
        } catch (error) {
            return 'Invalid date';
        }
    }

    displaySecurityAlerts(alerts) {
        const container = document.getElementById('security-alerts');
        if (!container) return;

        if (!alerts || alerts.length === 0) {
            container.innerHTML = `
                <div class="empty-state">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M9 12l2 2 4-4"/>
                        <circle cx="12" cy="12" r="10"/>
                    </svg>
                    <p>No active security alerts</p>
                </div>
            `;
            return;
        }

        const html = `
            <div class="alerts-list">
                ${alerts.map(alert => `
                    <div class="alert-item ${alert.severity}">
                        <div class="alert-header">
                            <div class="alert-icon ${alert.severity}">
                                ${this.getAlertIcon(alert.severity)}
                            </div>
                            <div class="alert-content">
                                <h4>${alert.title}</h4>
                                <p>${alert.description}</p>
                            </div>
                            <span class="severity-badge ${alert.severity}">${alert.severity.toUpperCase()}</span>
                        </div>
                        <div class="alert-details">
                            <div class="alert-meta">
                                <span>Affected: ${alert.affected_systems.join(', ')}</span>
                                <span>Time: ${new Date(alert.timestamp).toLocaleString()}</span>
                                ${alert.cve_score ? `<span>CVE Score: ${alert.cve_score}</span>` : ''}
                            </div>
                            <div class="alert-actions">
                                ${alert.patch_available ? 
                                    '<button class="btn-patch">Apply Patch</button>' : 
                                    '<span class="no-patch">No patch available</span>'
                                }
                                ${alert.auto_remediation ? 
                                    '<button class="btn-auto-fix">Auto-Remediate</button>' : ''
                                }
                            </div>
                        </div>
                    </div>
                `).join('')}
            </div>
        `;

        container.innerHTML = html;
    }

    displaySecurityHealthIndicators(indicators) {
        const container = document.getElementById('health-indicators');
        if (!container) return;

        if (!indicators || Object.keys(indicators).length === 0) {
            this.showEmptyState('health-indicators', 'Health indicators not available');
            return;
        }

        const html = `
            <div class="health-indicators-grid">
                ${Object.entries(indicators).map(([key, indicator]) => `
                    <div class="health-indicator ${indicator.status}">
                        <div class="indicator-header">
                            <h4>${this.formatIndicatorName(key)}</h4>
                            <div class="score-circle ${indicator.status}">
                                <span class="score">${indicator.score}</span>
                            </div>
                        </div>
                        <div class="indicator-status">
                            <span class="status-badge ${indicator.status}">${indicator.status.replace('_', ' ').toUpperCase()}</span>
                        </div>
                        <div class="indicator-metrics">
                            ${Object.entries(indicator.metrics || {}).map(([metricKey, value]) => `
                                <div class="metric-row">
                                    <span class="metric-label">${this.formatMetricName(metricKey)}:</span>
                                    <span class="metric-value">${value}</span>
                                </div>
                            `).join('')}
                        </div>
                    </div>
                `).join('')}
            </div>
        `;

        container.innerHTML = html;
    }

    displayCVEDatabaseStatus(data) {
        const container = document.getElementById('cve-status');
        if (!container) return;

        const html = `
            <div class="cve-database-status">
                <div class="cve-info">
                    <div class="info-row">
                        <span class="label">Database Version:</span>
                        <span class="value">${data.cve_database_version || 'Unknown'}</span>
                    </div>
                    <div class="info-row">
                        <span class="label">Last Updated:</span>
                        <span class="value">${new Date().toLocaleDateString()}</span>
                    </div>
                    <div class="info-row">
                        <span class="label">Total CVEs:</span>
                        <span class="value">${data.total_vulnerabilities || 0}</span>
                    </div>
                    <div class="info-row">
                        <span class="label">Baseline Score:</span>
                        <span class="value score-${this.getScoreStatus(data.security_baseline_score)}">${data.security_baseline_score || 0}/100</span>
                    </div>
                </div>
                <div class="cve-actions">
                    <button class="btn-secondary" onclick="window.rmm.updateCVEDatabase()">Update Database</button>
                    <button class="btn-secondary" onclick="window.rmm.runBaselineCheck()">Run Baseline Check</button>
                </div>
            </div>
        `;

        container.innerHTML = html;
    }

    displayComplianceOverview(compliance) {
        const container = document.getElementById('compliance-overview');
        if (!container) return;

        if (!compliance || Object.keys(compliance).length === 0) {
            this.showEmptyState('compliance-overview', 'Compliance data not available');
            return;
        }

        const html = `
            <div class="compliance-grid">
                ${Object.entries(compliance).map(([framework, score]) => `
                    <div class="compliance-item">
                        <div class="compliance-header">
                            <h4>${this.formatComplianceFramework(framework)}</h4>
                            <div class="compliance-score ${this.getScoreStatus(score)}">
                                ${score}/100
                            </div>
                        </div>
                        <div class="compliance-bar">
                            <div class="compliance-fill ${this.getScoreStatus(score)}" style="width: ${score}%"></div>
                        </div>
                    </div>
                `).join('')}
            </div>
            <div class="compliance-actions">
                <button class="btn-secondary" onclick="window.rmm.generateComplianceReport()">Generate Report</button>
            </div>
        `;

        container.innerHTML = html;
    }

    // Utility functions for advanced features
    getAlertIcon(severity) {
        const icons = {
            critical: '<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>',
            high: '<circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>',
            medium: '<path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>',
            low: '<circle cx="12" cy="12" r="10"/><path d="M8 12l4 4 8-8"/>'
        };
        return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">${icons[severity] || icons.medium}</svg>`;
    }

    formatIndicatorName(name) {
        return name.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
    }

    formatMetricName(name) {
        return name.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
    }

    formatComplianceFramework(framework) {
        const frameworks = {
            cis_benchmark: 'CIS Benchmark',
            nist_framework: 'NIST Framework',
            iso27001: 'ISO 27001'
        };
        return frameworks[framework] || framework.toUpperCase();
    }

    getScoreStatus(score) {
        if (score >= 90) return 'excellent';
        if (score >= 80) return 'good';
        if (score >= 60) return 'acceptable';
        if (score >= 40) return 'needs_attention';
        return 'critical';
    }

    // Interactive security actions
    async updateCVEDatabase() {
        try {
            const response = await fetch(`${this.apiBase}/cve/update`, { method: 'POST' });
            if (response.ok) {
                this.showNotification('CVE database update initiated', 'success');
                setTimeout(() => this.loadVulnerabilityReport(), 2000);
            }
        } catch (error) {
            this.showNotification('Failed to update CVE database', 'error');
        }
    }

    async runBaselineCheck() {
        try {
            const response = await fetch(`${this.apiBase}/security/baseline-check`, { method: 'POST' });
            if (response.ok) {
                this.showNotification('Security baseline check started', 'success');
            }
        } catch (error) {
            this.showNotification('Failed to start baseline check', 'error');
        }
    }

    async generateComplianceReport() {
        try {
            const response = await fetch(`${this.apiBase}/compliance/report`);
            if (response.ok) {
                const blob = await response.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `compliance-report-${new Date().toISOString().split('T')[0]}.pdf`;
                a.click();
                this.showNotification('Compliance report downloaded', 'success');
            }
        } catch (error) {
            this.showNotification('Failed to generate compliance report', 'error');
        }
    }

    showNotification(message, type = 'info') {
        const notification = document.createElement('div');
        notification.className = `notification ${type}`;
        notification.textContent = message;
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 1rem 1.5rem;
            border-radius: 8px;
            color: white;
            font-weight: 500;
            z-index: 10000;
            animation: slideIn 0.3s ease;
        `;
        
        const colors = {
            success: '#10b981',
            error: '#ef4444',
            warning: '#f59e0b',
            info: '#3b82f6'
        };
        
        notification.style.backgroundColor = colors[type] || colors.info;
        document.body.appendChild(notification);
        
        setTimeout(() => {
            notification.style.animation = 'slideOut 0.3s ease';
            setTimeout(() => notification.remove(), 300);
        }, 3000);
    }

    // Advanced CVE Scanning Functions
    async performCVEScan() {
        this.updateScanStatus('running', 'Scanning for CVE vulnerabilities...');
        
        try {
            const response = await fetch(`${this.apiBase}/cve/scan`, { method: 'POST' });
            if (response.ok) {
                const scanResults = await response.json();
                this.displayCVEScanResults(scanResults);
                this.updateScanStatus('completed', `Scan completed - ${scanResults.vulnerabilities_discovered.length} vulnerabilities found`);
                this.showNotification('CVE scan completed successfully', 'success');
            } else {
                throw new Error('CVE scan failed');
            }
        } catch (error) {
            console.error('CVE scan error:', error);
            this.updateScanStatus('error', 'Scan failed');
            this.showNotification('CVE scan failed', 'error');
        }
    }

    displayCVEScanResults(scanResults) {
        // Update vulnerability metrics
        const vulns = scanResults.vulnerabilities_discovered || [];
        const criticalCount = vulns.filter(v => v.severity === 'critical').length;
        const highCount = vulns.filter(v => v.severity === 'high').length;
        const mediumCount = vulns.filter(v => v.severity === 'medium').length;
        
        document.getElementById('critical-cve-count').textContent = criticalCount;
        document.getElementById('high-cve-count').textContent = highCount;
        document.getElementById('medium-cve-count').textContent = mediumCount;
        document.getElementById('scan-coverage').textContent = `${scanResults.scan_coverage?.coverage_percentage || 0}%`;

        // Display detailed vulnerabilities
        this.displayVulnerabilities(vulns);
        
        // Update dashboard with scan data
        this.displayCVEDatabaseInfo(scanResults);
    }

    displayCVEDatabaseInfo(scanResults) {
        const container = document.getElementById('cve-status');
        if (!container) return;

        const html = `
            <div class="cve-database-status">
                <div class="scan-summary">
                    <h4>Latest Scan Results</h4>
                    <div class="scan-info">
                        <div class="info-row">
                            <span class="label">Scan Duration:</span>
                            <span class="value">${scanResults.duration_seconds}s</span>
                        </div>
                        <div class="info-row">
                            <span class="label">Systems Scanned:</span>
                            <span class="value">${scanResults.scanned_systems?.join(', ') || 'Unknown'}</span>
                        </div>
                        <div class="info-row">
                            <span class="label">Data Sources:</span>
                            <span class="value">${scanResults.data_sources?.length || 0} sources</span>
                        </div>
                        <div class="info-row">
                            <span class="label">Next Scan:</span>
                            <span class="value">${new Date(scanResults.next_scheduled_scan).toLocaleString()}</span>
                        </div>
                    </div>
                </div>
                <div class="data-sources">
                    <h5>Active Data Sources:</h5>
                    <ul class="sources-list">
                        ${scanResults.data_sources?.map(source => `
                            <li class="source-item">${source}</li>
                        `).join('') || '<li>No sources available</li>'}
                    </ul>
                </div>
            </div>
        `;

        container.innerHTML = html;
    }

    updateScanStatus(status, message) {
        const indicator = document.getElementById('scan-indicator');
        const text = document.getElementById('scan-text');
        
        if (indicator && text) {
            indicator.className = `status-indicator ${status}`;
            text.textContent = message;
        }
    }

    async showCVEDetails(cveId) {
        try {
            const response = await fetch(`${this.apiBase}/vulnerability/detailed/${cveId}`);
            if (response.ok) {
                const cveDetails = await response.json();
                this.displayCVEDetailsModal(cveDetails);
            }
        } catch (error) {
            console.error('Failed to load CVE details:', error);
            this.showNotification('Failed to load CVE details', 'error');
        }
    }

    displayCVEDetailsModal(cve) {
        const modal = document.createElement('div');
        modal.className = 'modal cve-modal';
        modal.innerHTML = `
            <div class="modal-content cve-details">
                <span class="close-modal">&times;</span>
                <div class="cve-header">
                    <h2>${cve.cve_id}</h2>
                    <div class="cve-score ${this.getCVSSClass(cve.cvss_v3?.base_score)}">
                        CVSS ${cve.cvss_v3?.base_score || 'N/A'}
                    </div>
                </div>
                
                <div class="cve-content">
                    <div class="cve-description">
                        <h3>Description</h3>
                        <p>${cve.description}</p>
                    </div>
                    
                    <div class="cve-details-grid">
                        <div class="detail-section">
                            <h4>CVSS v3 Metrics</h4>
                            <div class="cvss-metrics">
                                <div class="metric">
                                    <span>Attack Vector:</span>
                                    <span>${cve.cvss_v3?.attack_vector || 'Unknown'}</span>
                                </div>
                                <div class="metric">
                                    <span>Attack Complexity:</span>
                                    <span>${cve.cvss_v3?.attack_complexity || 'Unknown'}</span>
                                </div>
                                <div class="metric">
                                    <span>Privileges Required:</span>
                                    <span>${cve.cvss_v3?.privileges_required || 'Unknown'}</span>
                                </div>
                                <div class="metric">
                                    <span>User Interaction:</span>
                                    <span>${cve.cvss_v3?.user_interaction || 'Unknown'}</span>
                                </div>
                            </div>
                        </div>
                        
                        <div class="detail-section">
                            <h4>Affected Products</h4>
                            <div class="affected-products">
                                ${cve.affected_products?.map(product => `
                                    <div class="product">
                                        <strong>${product.vendor} ${product.product}</strong>
                                        <div class="versions">${product.versions.join(', ')}</div>
                                    </div>
                                `).join('') || '<p>No product information available</p>'}
                            </div>
                        </div>
                        
                        <div class="detail-section">
                            <h4>Exploit Information</h4>
                            <div class="exploit-info">
                                <div class="info-item">
                                    <span>Exploit Available:</span>
                                    <span class="${cve.exploit_information?.exploit_available ? 'danger' : 'safe'}">
                                        ${cve.exploit_information?.exploit_available ? 'Yes' : 'No'}
                                    </span>
                                </div>
                                <div class="info-item">
                                    <span>Exploit Maturity:</span>
                                    <span>${cve.exploit_information?.exploit_maturity || 'Unknown'}</span>
                                </div>
                                <div class="info-item">
                                    <span>Known Exploited:</span>
                                    <span class="${cve.exploit_information?.known_exploited ? 'danger' : 'safe'}">
                                        ${cve.exploit_information?.known_exploited ? 'Yes' : 'No'}
                                    </span>
                                </div>
                            </div>
                        </div>
                        
                        <div class="detail-section">
                            <h4>Remediation</h4>
                            <div class="remediation-info">
                                ${cve.remediation?.patches_available ? `
                                    <div class="patches">
                                        <h5>Available Patches:</h5>
                                        ${cve.remediation.patch_details.map(patch => `
                                            <div class="patch-item">
                                                <strong>${patch.vendor} ${patch.patch_id}</strong>
                                                <span>Released: ${new Date(patch.release_date).toLocaleDateString()}</span>
                                                <a href="${patch.download_url}" target="_blank" class="btn-download">Download</a>
                                            </div>
                                        `).join('')}
                                    </div>
                                ` : '<p>No patches available</p>'}
                                
                                ${cve.remediation?.workarounds?.length ? `
                                    <div class="workarounds">
                                        <h5>Workarounds:</h5>
                                        <ul>
                                            ${cve.remediation.workarounds.map(w => `<li>${w}</li>`).join('')}
                                        </ul>
                                    </div>
                                ` : ''}
                            </div>
                        </div>
                    </div>
                    
                    <div class="cve-references">
                        <h4>References</h4>
                        <div class="references-list">
                            ${cve.references?.map(ref => `
                                <div class="reference-item">
                                    <a href="${ref.url}" target="_blank">${ref.source}</a>
                                    <span class="ref-type">${ref.type}</span>
                                </div>
                            `).join('') || '<p>No references available</p>'}
                        </div>
                    </div>
                </div>
            </div>
        `;

        document.body.appendChild(modal);
        modal.style.display = 'block';

        // Setup close functionality
        const closeBtn = modal.querySelector('.close-modal');
        closeBtn.addEventListener('click', () => {
            modal.remove();
        });

        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                modal.remove();
            }
        });
    }

    getCVSSClass(score) {
        if (!score) return 'unknown';
        if (score >= 9.0) return 'critical';
        if (score >= 7.0) return 'high';
        if (score >= 4.0) return 'medium';
        return 'low';
    }

    filterVulnerabilities() {
        const severityFilter = document.getElementById('severity-filter')?.value;
        const exploitabilityFilter = document.getElementById('exploitability-filter')?.value;
        
        if (!this.currentVulnerabilities) return;

        let filteredVulns = this.currentVulnerabilities.filter(vuln => {
            const severityMatch = !severityFilter || vuln.severity.toLowerCase() === severityFilter;
            const exploitMatch = !exploitabilityFilter || vuln.exploitability === exploitabilityFilter;
            return severityMatch && exploitMatch;
        });

        this.displayVulnerabilities(filteredVulns);
    }

    searchCVEs(searchTerm) {
        if (!this.currentVulnerabilities) return;

        if (!searchTerm.trim()) {
            this.displayVulnerabilities(this.currentVulnerabilities);
            return;
        }

        const filteredVulns = this.currentVulnerabilities.filter(vuln => 
            vuln.cve_id.toLowerCase().includes(searchTerm.toLowerCase()) ||
            vuln.description.toLowerCase().includes(searchTerm.toLowerCase())
        );

        this.displayVulnerabilities(filteredVulns);
    }

    async applyPatch(cveId) {
        try {
            const response = await fetch(`${this.apiBase}/patch/apply/${cveId}`, { method: 'POST' });
            if (response.ok) {
                this.showNotification(`Patch applied for ${cveId}`, 'success');
                // Refresh vulnerability data
                this.loadVulnerabilities();
            }
        } catch (error) {
            this.showNotification('Failed to apply patch', 'error');
        }
    }

    async showClientDetails(clientId) {
        try {
            const response = await fetch(`${this.apiBase}/client/${clientId}/details`);
            if (!response.ok) {
                throw new Error(`Failed to fetch client details: ${response.status}`);
            }
            
            const clientData = await response.json();
            this.displayClientDetailsModal(clientData);
        } catch (error) {
            console.error('Failed to load client details:', error);
            this.showError('Failed to load client details');
        }
    }

    displayClientDetailsModal(client) {
        const modal = document.getElementById('client-details-modal');
        const content = document.getElementById('client-details-content');

        const healthScore = client.health.overall_score;
        const healthStatus = healthScore >= 80 ? 'excellent' : healthScore >= 60 ? 'good' : healthScore >= 40 ? 'warning' : 'critical';

        content.innerHTML = `
            <div class="client-details-header">
                <div class="client-title">
                    <h2>${client.hostname}</h2>
                    <span class="status-badge ${client.status}">${client.status}</span>
                </div>
                <div class="health-score ${healthStatus}">
                    <span class="score">${healthScore}</span>
                    <span class="label">Health Score</span>
                </div>
            </div>

            <div class="client-tabs">
                <button class="client-tab active" data-tab="overview">Overview</button>
                <button class="client-tab" data-tab="applications">Applications</button>
                <button class="client-tab" data-tab="security">Security Assessment</button>
                <button class="client-tab" data-tab="pii">PII Locations</button>
                <button class="client-tab" data-tab="vnc">Remote Access</button>
            </div>

            <div class="client-tab-content">
                <div class="client-tab-panel active" id="overview-panel">
                    ${this.renderOverviewPanel(client)}
                </div>
                <div class="client-tab-panel" id="applications-panel">
                    ${this.renderApplicationsPanel(client.installed_applications)}
                </div>
                <div class="client-tab-panel" id="security-panel">
                    ${this.renderSecurityPanel(client.security_assessment)}
                </div>
                <div class="client-tab-panel" id="pii-panel">
                    ${this.renderPIIPanel(client.pii_locations)}
                </div>
                <div class="client-tab-panel" id="vnc-panel">
                    ${this.renderVNCPanel(client.vnc_connection)}
                </div>
            </div>
        `;

        // Setup tab switching
        this.setupClientTabs();
        
        // Show modal
        modal.style.display = 'block';
    }

    renderOverviewPanel(client) {
        return `
            <div class="overview-grid">
                <div class="overview-section">
                    <h4>System Information</h4>
                    <div class="info-grid">
                        <div class="info-item">
                            <strong>Hostname:</strong> ${client.hostname}
                        </div>
                        <div class="info-item">
                            <strong>IP Address:</strong> ${client.ip_address}
                        </div>
                        <div class="info-item">
                            <strong>Operating System:</strong> ${client.os_version}
                        </div>
                        <div class="info-item">
                            <strong>Agent Version:</strong> ${client.agent_version}
                        </div>
                        <div class="info-item">
                            <strong>Last Reboot:</strong> ${this.formatTimestamp(client.health.last_reboot)}
                        </div>
                        <div class="info-item">
                            <strong>Uptime:</strong> ${this.formatUptime(client.health.uptime_seconds)}
                        </div>
                    </div>
                </div>

                <div class="overview-section">
                    <h4>Resource Usage</h4>
                    <div class="resource-metrics">
                        <div class="metric">
                            <div class="metric-header">
                                <span>CPU Usage</span>
                                <span class="metric-value">${client.resource_usage.cpu.current}%</span>
                            </div>
                            <div class="progress-bar">
                                <div class="progress-fill" style="width: ${client.resource_usage.cpu.current}%"></div>
                            </div>
                            <div class="metric-details">
                                ${client.resource_usage.cpu.model} (${client.resource_usage.cpu.cores} cores)
                            </div>
                        </div>

                        <div class="metric">
                            <div class="metric-header">
                                <span>Memory Usage</span>
                                <span class="metric-value">${client.resource_usage.memory.usage_percent}%</span>
                            </div>
                            <div class="progress-bar">
                                <div class="progress-fill" style="width: ${client.resource_usage.memory.usage_percent}%"></div>
                            </div>
                            <div class="metric-details">
                                ${client.resource_usage.memory.used_gb} GB / ${client.resource_usage.memory.total_gb} GB
                            </div>
                        </div>

                        ${client.resource_usage.disk.map(disk => `
                            <div class="metric">
                                <div class="metric-header">
                                    <span>Disk ${disk.drive} (${disk.type})</span>
                                    <span class="metric-value">${disk.usage_percent}%</span>
                                </div>
                                <div class="progress-bar">
                                    <div class="progress-fill" style="width: ${disk.usage_percent}%"></div>
                                </div>
                                <div class="metric-details">
                                    ${disk.used_gb} GB / ${disk.total_gb} GB (${disk.health})
                                </div>
                            </div>
                        `).join('')}
                    </div>
                </div>

                <div class="overview-section">
                    <h4>Network Information</h4>
                    <div class="network-info">
                        <div class="info-item">
                            <strong>Interface:</strong> ${client.resource_usage.network.interface}
                        </div>
                        <div class="info-item">
                            <strong>Speed:</strong> ${client.resource_usage.network.speed_mbps} Mbps
                        </div>
                        <div class="info-item">
                            <strong>Bytes Sent:</strong> ${this.formatBytes(parseInt(client.resource_usage.network.bytes_sent))}
                        </div>
                        <div class="info-item">
                            <strong>Bytes Received:</strong> ${this.formatBytes(parseInt(client.resource_usage.network.bytes_received))}
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    renderApplicationsPanel(applications) {
        return `
            <div class="applications-grid">
                ${applications.map(app => `
                    <div class="app-card ${app.vulnerabilities > 0 ? 'vulnerable' : 'secure'}">
                        <div class="app-header">
                            <h4>${app.name}</h4>
                            ${app.vulnerabilities > 0 ? 
                                `<span class="vuln-badge">${app.vulnerabilities} vuln(s)</span>` : 
                                '<span class="secure-badge">Secure</span>'
                            }
                        </div>
                        <div class="app-details">
                            <div class="detail-row">
                                <strong>Version:</strong> ${app.version}
                            </div>
                            <div class="detail-row">
                                <strong>Publisher:</strong> ${app.publisher}
                            </div>
                            <div class="detail-row">
                                <strong>Install Date:</strong> ${app.install_date}
                            </div>
                            <div class="detail-row">
                                <strong>Size:</strong> ${app.size_mb} MB
                            </div>
                            <div class="detail-row">
                                <strong>Auto Update:</strong> ${app.auto_update ? 'Enabled' : 'Disabled'}
                            </div>
                        </div>
                    </div>
                `).join('')}
            </div>
        `;
    }

    renderSecurityPanel(security) {
        return `
            <div class="security-grid">
                <div class="security-section">
                    <h4>Vulnerability Summary</h4>
                    <div class="vuln-summary">
                        <div class="vuln-stat critical">
                            <span class="count">${security.vulnerabilities.critical}</span>
                            <span class="label">Critical</span>
                        </div>
                        <div class="vuln-stat high">
                            <span class="count">${security.vulnerabilities.high}</span>
                            <span class="label">High</span>
                        </div>
                        <div class="vuln-stat medium">
                            <span class="count">${security.vulnerabilities.medium}</span>
                            <span class="label">Medium</span>
                        </div>
                        <div class="vuln-stat low">
                            <span class="count">${security.vulnerabilities.low}</span>
                            <span class="label">Low</span>
                        </div>
                    </div>
                </div>

                <div class="security-section">
                    <h4>Patch Status</h4>
                    <div class="patch-info">
                        <div class="info-item">
                            <strong>Available Patches:</strong> ${security.patches.available}
                        </div>
                        <div class="info-item">
                            <strong>Critical Updates:</strong> ${security.patches.critical}
                        </div>
                        <div class="info-item">
                            <strong>Security Updates:</strong> ${security.patches.security_updates}
                        </div>
                    </div>
                </div>

                <div class="security-section">
                    <h4>Compliance Scores</h4>
                    <div class="compliance-scores">
                        <div class="score-item">
                            <span class="score-label">CIS Score:</span>
                            <span class="score-value">${security.compliance.cis_score}/100</span>
                        </div>
                        <div class="score-item">
                            <span class="score-label">NIST Score:</span>
                            <span class="score-value">${security.compliance.nist_score}/100</span>
                        </div>
                        <div class="score-item">
                            <span class="score-label">PCI Compliant:</span>
                            <span class="compliance-badge ${security.compliance.pci_compliant ? 'compliant' : 'non-compliant'}">
                                ${security.compliance.pci_compliant ? 'Yes' : 'No'}
                            </span>
                        </div>
                        <div class="score-item">
                            <span class="score-label">HIPAA Compliant:</span>
                            <span class="compliance-badge ${security.compliance.hipaa_compliant ? 'compliant' : 'non-compliant'}">
                                ${security.compliance.hipaa_compliant ? 'Yes' : 'No'}
                            </span>
                        </div>
                    </div>
                </div>

                <div class="security-section">
                    <h4>Security Status</h4>
                    <div class="security-status">
                        <div class="status-item">
                            <strong>Firewall:</strong> 
                            <span class="status-badge ${security.firewall_status}">${security.firewall_status}</span>
                        </div>
                        <div class="status-item">
                            <strong>Antivirus:</strong> 
                            <span class="status-badge ${security.antivirus_status}">${security.antivirus_status}</span>
                        </div>
                        <div class="status-item">
                            <strong>Encryption:</strong> 
                            <span class="status-badge enabled">${security.encryption_status.replace('_', ' ')}</span>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    renderPIIPanel(piiLocations) {
        return `
            <div class="pii-locations">
                ${piiLocations.map(pii => `
                    <div class="pii-item ${pii.risk_level}">
                        <div class="pii-header">
                            <h4>${pii.type}</h4>
                            <span class="risk-badge ${pii.risk_level}">${pii.risk_level.toUpperCase()}</span>
                        </div>
                        <div class="pii-details">
                            <div class="detail-row">
                                <strong>Location:</strong> ${pii.location}
                            </div>
                            <div class="detail-row">
                                <strong>Count:</strong> ${pii.count} occurrences
                            </div>
                            <div class="detail-row">
                                <strong>Encrypted:</strong> ${pii.encrypted ? 'Yes' : 'No'}
                            </div>
                        </div>
                    </div>
                `).join('')}
            </div>
        `;
    }

    renderVNCPanel(vncConfig) {
        return `
            <div class="vnc-connection">
                <div class="vnc-status ${vncConfig.available ? 'available' : 'unavailable'}">
                    <h4>Remote Access Status</h4>
                    <span class="status">${vncConfig.available ? 'Available' : 'Unavailable'}</span>
                </div>
                
                ${vncConfig.available ? `
                    <div class="vnc-details">
                        <div class="detail-row">
                            <strong>Port:</strong> ${vncConfig.port}
                        </div>
                        <div class="detail-row">
                            <strong>Encryption:</strong> ${vncConfig.encryption}
                        </div>
                        <div class="detail-row">
                            <strong>Authentication:</strong> ${vncConfig.authentication}
                        </div>
                        <div class="detail-row">
                            <strong>Display Scaling:</strong> ${vncConfig.display_scaling}
                        </div>
                        <div class="detail-row">
                            <strong>Color Depth:</strong> ${vncConfig.color_depth}
                        </div>
                    </div>
                    
                    <div class="vnc-actions">
                        <button class="btn-primary vnc-connect">
                            Connect to Desktop (Backstage)
                        </button>
                        <p class="vnc-note">
                            Backstage connection allows remote access without interrupting the user's current session.
                        </p>
                    </div>
                ` : `
                    <p class="vnc-unavailable">Remote access is not available for this client.</p>
                `}
            </div>
        `;
    }

    setupClientTabs() {
        const modal = document.getElementById('client-details-modal');
        const tabs = modal.querySelectorAll('.client-tab');
        const panels = modal.querySelectorAll('.client-tab-panel');

        // Remove any existing event listeners to prevent duplicates
        tabs.forEach(tab => {
            const newTab = tab.cloneNode(true);
            tab.parentNode.replaceChild(newTab, tab);
        });

        // Get updated tab references after cloning
        const updatedTabs = modal.querySelectorAll('.client-tab');
        const updatedPanels = modal.querySelectorAll('.client-tab-panel');

        updatedTabs.forEach(tab => {
            tab.addEventListener('click', (e) => {
                e.preventDefault();
                e.stopPropagation();
                
                const targetTab = tab.dataset.tab;
                
                // Remove active class from all client modal tabs and panels
                updatedTabs.forEach(t => t.classList.remove('active'));
                updatedPanels.forEach(p => p.classList.remove('active'));
                
                // Add active class to clicked tab and corresponding panel
                tab.classList.add('active');
                const targetPanel = modal.querySelector(`#${targetTab}-panel`);
                if (targetPanel) {
                    targetPanel.classList.add('active');
                }
            });
        });

        // Setup modal close
        const closeBtn = modal.querySelector('.close-modal');
        
        if (closeBtn) {
            // Remove existing event listener if any
            const newCloseBtn = closeBtn.cloneNode(true);
            closeBtn.parentNode.replaceChild(newCloseBtn, closeBtn);
            
            newCloseBtn.addEventListener('click', (e) => {
                e.preventDefault();
                e.stopPropagation();
                modal.style.display = 'none';
            });
        }

        // Close modal when clicking outside (but not when clicking inside modal content)
        const modalClickHandler = (event) => {
            if (event.target === modal) {
                modal.style.display = 'none';
            }
        };
        
        // Remove existing listener and add new one
        window.removeEventListener('click', modalClickHandler);
        window.addEventListener('click', modalClickHandler);
    }
}

// Initialize dashboard when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.rmm = new RMMDashboard();
    window.rmmDashboard = window.rmm; // For backwards compatibility
});

// Export for potential module use
if (typeof module !== 'undefined' && module.exports) {
    module.exports = RMMDashboard;
}
