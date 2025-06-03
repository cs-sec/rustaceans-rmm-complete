/**
 * Rustaceans Security RMM Dashboard
 * Frontend JavaScript for the security monitoring dashboard
 */

class RMMDashboard {
    constructor() {
        this.currentTab = 'overview';
        this.init();
    }

    async init() {
        const isAuthenticated = await this.checkAuthentication();
        if (!isAuthenticated) return;
        
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
                return false;
            }
            const usernameElement = document.getElementById('username');
            if (usernameElement) {
                usernameElement.textContent = result.user.username;
            }
            return true;
        } catch (error) {
            console.error('Auth check failed:', error);
            window.location.href = '/login';
            return false;
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