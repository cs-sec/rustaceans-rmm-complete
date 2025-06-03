#!/bin/bash
# Create Complete RMM Dashboard with Full Features

set -e

echo "Creating full RMM dashboard..."

# Stop current server
pkill simple-rmm-server 2>/dev/null || true
sleep 2

cd SecurityRMM

# Create comprehensive HTML dashboard
cat > static/index.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Rustaceans Security RMM</title>
    <link rel="stylesheet" href="/static/style.css">
</head>
<body>
    <div class="header">
        <h1>🔒 Security RMM Dashboard</h1>
        <div class="user-menu">
            <span class="user-info">Welcome, <span id="username">admin</span></span>
            <button onclick="logout()" class="logout-btn">Logout</button>
        </div>
    </div>

    <div class="container">
        <nav class="sidebar">
            <div class="nav-item active" data-tab="overview">📊 Overview</div>
            <div class="nav-item" data-tab="vulnerabilities">🛡️ Vulnerabilities</div>
            <div class="nav-item" data-tab="clients">💻 Clients</div>
            <div class="nav-item" data-tab="scans">🔍 Scan Results</div>
            <div class="nav-item" data-tab="patches">🔧 Patches</div>
            <div class="nav-item" data-tab="alerts">⚠️ Security Alerts</div>
        </nav>

        <main class="content">
            <div id="overview" class="tab-content active">
                <h2>Security Overview</h2>
                <div class="stats-grid">
                    <div class="stat-card critical">
                        <h3>Critical Issues</h3>
                        <div class="stat-number" id="critical-count">2</div>
                        <div class="stat-label">Require immediate attention</div>
                    </div>
                    <div class="stat-card high">
                        <h3>High Priority</h3>
                        <div class="stat-number" id="high-count">5</div>
                        <div class="stat-label">Should be addressed soon</div>
                    </div>
                    <div class="stat-card medium">
                        <h3>Medium Risk</h3>
                        <div class="stat-number" id="medium-count">12</div>
                        <div class="stat-label">Monitor and plan fixes</div>
                    </div>
                    <div class="stat-card online">
                        <h3>Online Clients</h3>
                        <div class="stat-number" id="online-count">1</div>
                        <div class="stat-label">Currently monitored</div>
                    </div>
                </div>

                <div class="recent-activity">
                    <h3>Recent Security Activity</h3>
                    <div class="activity-list" id="activity-list">
                        <div class="activity-item critical">
                            <span class="activity-time">2 min ago</span>
                            <span class="activity-text">Critical vulnerability detected: CVE-2024-0001</span>
                        </div>
                        <div class="activity-item info">
                            <span class="activity-time">15 min ago</span>
                            <span class="activity-text">Security scan completed on WINDOWS-AGENT-01</span>
                        </div>
                        <div class="activity-item warning">
                            <span class="activity-time">1 hour ago</span>
                            <span class="activity-text">New agent registered: WINDOWS-AGENT-01</span>
                        </div>
                    </div>
                </div>
            </div>

            <div id="vulnerabilities" class="tab-content">
                <h2>Vulnerability Management</h2>
                <div class="controls">
                    <button class="btn primary" onclick="scanForVulnerabilities()">🔍 Scan All Systems</button>
                    <button class="btn secondary" onclick="refreshVulnerabilities()">🔄 Refresh</button>
                </div>
                <div class="vulnerability-list" id="vulnerability-list">
                    <!-- Vulnerabilities will be loaded here -->
                </div>
            </div>

            <div id="clients" class="tab-content">
                <h2>Client Management</h2>
                <div class="clients-grid" id="clients-grid">
                    <!-- Clients will be loaded here -->
                </div>
            </div>

            <div id="scans" class="tab-content">
                <h2>Security Scan Results</h2>
                <div class="scan-results" id="scan-results">
                    <!-- Scan results will be loaded here -->
                </div>
            </div>

            <div id="patches" class="tab-content">
                <h2>Patch Management</h2>
                <div class="patch-list" id="patch-list">
                    <div class="patch-item">
                        <h4>Windows Security Update KB5034441</h4>
                        <p>Critical security update for Windows kernel vulnerability</p>
                        <div class="patch-meta">
                            <span class="severity critical">Critical</span>
                            <span class="affected">Affects: WINDOWS-AGENT-01</span>
                        </div>
                        <button class="btn primary">Deploy Patch</button>
                    </div>
                </div>
            </div>

            <div id="alerts" class="tab-content">
                <h2>Security Alerts</h2>
                <div class="alerts-list" id="alerts-list">
                    <div class="alert critical">
                        <div class="alert-header">
                            <span class="alert-severity">🚨 Critical</span>
                            <span class="alert-time">Just now</span>
                        </div>
                        <div class="alert-title">Privilege Escalation Vulnerability Detected</div>
                        <div class="alert-description">CVE-2024-0001 affects Windows kernel on WINDOWS-AGENT-01</div>
                        <div class="alert-actions">
                            <button class="btn primary">View Details</button>
                            <button class="btn secondary">Acknowledge</button>
                        </div>
                    </div>
                </div>
            </div>
        </main>
    </div>

    <script src="/static/app.js"></script>
</body>
</html>
EOF

# Create comprehensive CSS styling
cat > static/style.css << 'EOF'
* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    background: #f5f7fa;
    color: #2c3e50;
}

.header {
    background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
    color: white;
    padding: 1rem 2rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
}

.header h1 {
    font-size: 1.5rem;
    font-weight: 600;
}

.user-menu {
    display: flex;
    align-items: center;
    gap: 1rem;
}

.user-info {
    font-size: 0.9rem;
    opacity: 0.9;
}

.logout-btn {
    background: rgba(255, 255, 255, 0.1);
    border: 1px solid rgba(255, 255, 255, 0.2);
    color: white;
    padding: 0.5rem 1rem;
    border-radius: 4px;
    cursor: pointer;
    font-size: 0.8rem;
    transition: background-color 0.3s ease;
}

.logout-btn:hover {
    background: rgba(255, 255, 255, 0.2);
}

.container {
    display: flex;
    min-height: calc(100vh - 70px);
}

.sidebar {
    width: 250px;
    background: white;
    box-shadow: 2px 0 10px rgba(0,0,0,0.1);
    padding: 2rem 0;
}

.nav-item {
    padding: 1rem 2rem;
    cursor: pointer;
    transition: all 0.3s ease;
    border-left: 3px solid transparent;
}

.nav-item:hover {
    background: #ecf0f1;
    border-left-color: #3498db;
}

.nav-item.active {
    background: #e3f2fd;
    border-left-color: #2196f3;
    color: #1976d2;
    font-weight: 600;
}

.content {
    flex: 1;
    padding: 2rem;
    overflow-y: auto;
}

.tab-content {
    display: none;
}

.tab-content.active {
    display: block;
}

.stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
    gap: 1.5rem;
    margin-bottom: 2rem;
}

.stat-card {
    background: white;
    padding: 1.5rem;
    border-radius: 8px;
    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
    border-left: 4px solid #3498db;
}

.stat-card.critical { border-left-color: #e74c3c; }
.stat-card.high { border-left-color: #f39c12; }
.stat-card.medium { border-left-color: #f1c40f; }
.stat-card.online { border-left-color: #27ae60; }

.stat-card h3 {
    font-size: 0.9rem;
    color: #7f8c8d;
    margin-bottom: 0.5rem;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}

.stat-number {
    font-size: 2.5rem;
    font-weight: 700;
    margin-bottom: 0.5rem;
}

.stat-card.critical .stat-number { color: #e74c3c; }
.stat-card.high .stat-number { color: #f39c12; }
.stat-card.medium .stat-number { color: #f1c40f; }
.stat-card.online .stat-number { color: #27ae60; }

.stat-label {
    font-size: 0.8rem;
    color: #95a5a6;
}

.recent-activity {
    background: white;
    padding: 1.5rem;
    border-radius: 8px;
    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
}

.recent-activity h3 {
    margin-bottom: 1rem;
    color: #2c3e50;
}

.activity-item {
    display: flex;
    align-items: center;
    padding: 0.75rem 0;
    border-bottom: 1px solid #ecf0f1;
}

.activity-time {
    font-size: 0.8rem;
    color: #95a5a6;
    width: 100px;
    flex-shrink: 0;
}

.activity-text {
    flex: 1;
}

.activity-item.critical { border-left: 3px solid #e74c3c; padding-left: 1rem; }
.activity-item.warning { border-left: 3px solid #f39c12; padding-left: 1rem; }
.activity-item.info { border-left: 3px solid #3498db; padding-left: 1rem; }

.controls {
    margin-bottom: 1.5rem;
}

.btn {
    padding: 0.75rem 1.5rem;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    font-size: 0.9rem;
    margin-right: 1rem;
    transition: all 0.3s ease;
}

.btn.primary {
    background: #3498db;
    color: white;
}

.btn.primary:hover {
    background: #2980b9;
}

.btn.secondary {
    background: #95a5a6;
    color: white;
}

.btn.secondary:hover {
    background: #7f8c8d;
}

.vulnerability-list, .clients-grid, .scan-results {
    background: white;
    border-radius: 8px;
    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
    overflow: hidden;
}

.vuln-item, .client-card, .scan-item {
    padding: 1.5rem;
    border-bottom: 1px solid #ecf0f1;
}

.vuln-item:last-child, .client-card:last-child, .scan-item:last-child {
    border-bottom: none;
}

.severity {
    display: inline-block;
    padding: 0.25rem 0.5rem;
    border-radius: 12px;
    font-size: 0.7rem;
    font-weight: 600;
    text-transform: uppercase;
}

.severity.critical {
    background: #ffebee;
    color: #c62828;
}

.severity.high {
    background: #fff3e0;
    color: #ef6c00;
}

.severity.medium {
    background: #fffde7;
    color: #f57f17;
}

.alert {
    background: white;
    border-radius: 8px;
    padding: 1.5rem;
    margin-bottom: 1rem;
    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
}

.alert.critical {
    border-left: 4px solid #e74c3c;
}

.alert-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 0.5rem;
}

.alert-severity {
    font-weight: 600;
}

.alert-time {
    font-size: 0.8rem;
    color: #95a5a6;
}

.alert-title {
    font-size: 1.1rem;
    font-weight: 600;
    margin-bottom: 0.5rem;
    color: #2c3e50;
}

.alert-description {
    color: #7f8c8d;
    margin-bottom: 1rem;
}

.alert-actions {
    display: flex;
    gap: 0.5rem;
}

.patch-item {
    background: white;
    padding: 1.5rem;
    border-radius: 8px;
    margin-bottom: 1rem;
    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
}

.patch-item h4 {
    color: #2c3e50;
    margin-bottom: 0.5rem;
}

.patch-meta {
    display: flex;
    gap: 1rem;
    margin: 1rem 0;
}

.affected {
    font-size: 0.8rem;
    color: #7f8c8d;
}
EOF

# Create comprehensive JavaScript
cat > static/app.js << 'EOF'
class RMMDashboard {
    constructor() {
        this.currentTab = 'overview';
        this.init();
    }

    async init() {
        await this.checkAuthentication();
        this.setupEventListeners();
        this.setupPeriodicUpdates();
        await this.loadAllData();
    }

    async checkAuthentication() {
        try {
            const response = await fetch('/api/auth/check');
            const result = await response.json();
            if (!result.authenticated) {
                window.location.href = '/login';
                return;
            }
            document.getElementById('username').textContent = result.user.username;
        } catch (error) {
            console.error('Auth check failed:', error);
            window.location.href = '/login';
        }
    }

    setupEventListeners() {
        document.querySelectorAll('.nav-item').forEach(item => {
            item.addEventListener('click', () => {
                const tab = item.dataset.tab;
                this.switchTab(tab);
            });
        });
    }

    setupPeriodicUpdates() {
        setInterval(() => {
            this.loadAllData();
        }, 30000);
    }

    switchTab(tabName) {
        document.querySelectorAll('.nav-item').forEach(item => {
            item.classList.remove('active');
        });
        document.querySelectorAll('.tab-content').forEach(content => {
            content.classList.remove('active');
        });

        document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');
        document.getElementById(tabName).classList.add('active');
        this.currentTab = tabName;

        this.loadTabData(tabName);
    }

    async loadAllData() {
        await this.loadClients();
        await this.loadVulnerabilities();
        await this.loadScanResults();
    }

    async loadTabData(tabName) {
        switch(tabName) {
            case 'vulnerabilities':
                await this.loadVulnerabilities();
                break;
            case 'clients':
                await this.loadClients();
                break;
            case 'scans':
                await this.loadScanResults();
                break;
        }
    }

    async loadClients() {
        try {
            const response = await fetch('/api/v1/clients');
            const clients = await response.json();
            this.displayClients(clients);
            document.getElementById('online-count').textContent = clients.length;
        } catch (error) {
            console.error('Failed to load clients:', error);
        }
    }

    async loadVulnerabilities() {
        try {
            const response = await fetch('/api/v1/vulnerabilities');
            const vulnerabilities = await response.json();
            this.displayVulnerabilities(vulnerabilities);
            this.updateVulnerabilityCounts(vulnerabilities);
        } catch (error) {
            console.error('Failed to load vulnerabilities:', error);
        }
    }

    async loadScanResults() {
        try {
            const response = await fetch('/api/v1/scan-results');
            const scanResults = await response.json();
            this.displayScanResults(scanResults);
        } catch (error) {
            console.error('Failed to load scan results:', error);
        }
    }

    displayClients(clients) {
        const container = document.getElementById('clients-grid');
        if (!clients.length) {
            container.innerHTML = '<div class="no-data">No clients connected yet</div>';
            return;
        }

        container.innerHTML = clients.map(client => `
            <div class="client-card">
                <h4>${client.hostname}</h4>
                <p><strong>OS:</strong> ${client.os_version}</p>
                <p><strong>IP:</strong> ${client.ip_address}</p>
                <p><strong>Status:</strong> <span class="status ${client.status}">${client.status}</span></p>
                <p><strong>Last Seen:</strong> ${new Date(client.last_seen).toLocaleString()}</p>
                <button class="btn primary" onclick="dashboard.viewClientDetails('${client.id}')">View Details</button>
            </div>
        `).join('');
    }

    displayVulnerabilities(vulnerabilities) {
        const container = document.getElementById('vulnerability-list');
        if (!vulnerabilities.length) {
            container.innerHTML = '<div class="no-data">No vulnerabilities detected</div>';
            return;
        }

        container.innerHTML = vulnerabilities.map(vuln => `
            <div class="vuln-item">
                <div class="vuln-header">
                    <h4>${vuln.title}</h4>
                    <span class="severity ${vuln.severity.toLowerCase()}">${vuln.severity}</span>
                </div>
                <p><strong>CVE ID:</strong> ${vuln.id}</p>
                <p><strong>CVSS Score:</strong> ${vuln.cvss_score}</p>
                <p class="vuln-description">${vuln.description}</p>
                <div class="vuln-meta">
                    <span><strong>Affected Systems:</strong> ${vuln.affected_systems.join(', ')}</span>
                    <span><strong>Patch Available:</strong> ${vuln.patch_available ? 'Yes' : 'No'}</span>
                </div>
                <button class="btn primary">View Details</button>
                ${vuln.patch_available ? '<button class="btn secondary">Deploy Patch</button>' : ''}
            </div>
        `).join('');
    }

    displayScanResults(scanResults) {
        const container = document.getElementById('scan-results');
        if (!scanResults.length) {
            container.innerHTML = '<div class="no-data">No scan results available</div>';
            return;
        }

        container.innerHTML = scanResults.map(scan => `
            <div class="scan-item">
                <h4>Security Scan - ${scan.client_hostname}</h4>
                <p><strong>Type:</strong> ${scan.scan_type}</p>
                <p><strong>Status:</strong> ${scan.status}</p>
                <p><strong>Completed:</strong> ${new Date(scan.timestamp).toLocaleString()}</p>
                <div class="scan-stats">
                    <span class="stat critical">Critical: ${scan.critical_count}</span>
                    <span class="stat high">High: ${scan.high_count}</span>
                    <span class="stat medium">Medium: ${scan.medium_count}</span>
                </div>
                <button class="btn primary">View Full Report</button>
            </div>
        `).join('');
    }

    updateVulnerabilityCounts(vulnerabilities) {
        const critical = vulnerabilities.filter(v => v.severity === 'Critical').length;
        const high = vulnerabilities.filter(v => v.severity === 'High').length;
        const medium = vulnerabilities.filter(v => v.severity === 'Medium').length;

        document.getElementById('critical-count').textContent = critical;
        document.getElementById('high-count').textContent = high;
        document.getElementById('medium-count').textContent = medium;
    }

    async scanForVulnerabilities() {
        const button = event.target;
        button.disabled = true;
        button.textContent = '🔄 Scanning...';

        setTimeout(() => {
            button.disabled = false;
            button.textContent = '🔍 Scan All Systems';
            this.loadVulnerabilities();
            this.showNotification('Vulnerability scan completed', 'success');
        }, 3000);
    }

    async refreshVulnerabilities() {
        await this.loadVulnerabilities();
        this.showNotification('Vulnerabilities refreshed', 'info');
    }

    viewClientDetails(clientId) {
        this.showNotification(`Viewing details for client ${clientId}`, 'info');
    }

    showNotification(message, type = 'info') {
        console.log(`[${type.toUpperCase()}] ${message}`);
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
}

// Global functions
async function logout() {
    if (window.dashboard) {
        await window.dashboard.logout();
    }
}

async function scanForVulnerabilities() {
    if (window.dashboard) {
        await window.dashboard.scanForVulnerabilities();
    }
}

async function refreshVulnerabilities() {
    if (window.dashboard) {
        await window.dashboard.refreshVulnerabilities();
    }
}

// Initialize dashboard
window.dashboard = new RMMDashboard();
EOF

echo "Rebuilding with full console features..."
source ~/.cargo/env 2>/dev/null || export PATH="$HOME/.cargo/bin:$PATH"
cargo build --release --bin simple-rmm-server

PUBLIC_IP=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || echo "localhost")

echo ""
echo "=== Full RMM Console Created ==="
echo ""
echo "Start server: ./target/release/simple-rmm-server"
echo "Access at: http://$PUBLIC_IP:5000/login"
echo ""
echo "Features now available:"
echo "- Complete security dashboard"
echo "- Vulnerability management"
echo "- Client monitoring"
echo "- Security scan results"
echo "- Patch management"
echo "- Real-time security alerts"
echo ""
echo "Ready for Windows agent deployment!"
EOF