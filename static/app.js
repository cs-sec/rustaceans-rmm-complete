// Simple RMM Dashboard JavaScript

class RMMDashboard {
    constructor() {
        this.currentTab = 'overview';
        this.updateInterval = null;
    }

    async init() {
        console.log('Initializing RMM Dashboard...');
        
        // Check authentication
        const isAuthenticated = await this.checkAuthentication();
        if (!isAuthenticated) {
            window.location.href = '/login';
            return;
        }

        this.setupEventListeners();
        this.setupPeriodicUpdates();
        this.loadTabData('overview');
    }

    async checkAuthentication() {
        try {
            const response = await fetch('/api/status', {
                credentials: 'include'
            });
            return response.ok;
        } catch (error) {
            console.error('Authentication check failed:', error);
            return false;
        }
    }

    setupEventListeners() {
        // Navigation
        document.querySelectorAll('.nav-item').forEach(item => {
            item.addEventListener('click', () => {
                const tab = item.dataset.tab;
                this.switchTab(tab);
            });
        });

        // Make sure logout function is available globally
        window.logout = () => this.logout();
        window.scanForVulnerabilities = () => this.scanForVulnerabilities();
        window.refreshVulnerabilities = () => this.refreshVulnerabilities();
    }

    setupPeriodicUpdates() {
        // Update dashboard every 30 seconds
        this.updateInterval = setInterval(() => {
            this.loadTabData(this.currentTab);
        }, 30000);
    }

    switchTab(tabName) {
        // Update navigation
        document.querySelectorAll('.nav-item').forEach(item => {
            item.classList.remove('active');
        });
        document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');

        // Update content
        document.querySelectorAll('.tab-content').forEach(content => {
            content.classList.remove('active');
        });
        document.getElementById(tabName).classList.add('active');

        this.currentTab = tabName;
        this.loadTabData(tabName);
    }

    async loadTabData(tabName) {
        switch (tabName) {
            case 'overview':
                // Overview data is static for demo
                break;
            case 'vulnerabilities':
                await this.loadVulnerabilities();
                break;
            case 'clients':
                await this.loadClients();
                break;
            case 'scans':
                await this.loadScanResults();
                break;
            default:
                // Other tabs use static content
                break;
        }
    }

    async loadClients() {
        try {
            const response = await fetch('/api/clients', {
                credentials: 'include'
            });
            
            if (response.ok) {
                const clients = await response.json();
                this.displayClients(clients);
            } else {
                this.showEmptyState('clients-grid', 'No clients connected');
            }
        } catch (error) {
            console.error('Failed to load clients:', error);
            this.showEmptyState('clients-grid', 'Unable to load client data');
        }
    }

    async loadVulnerabilities() {
        try {
            const response = await fetch('/api/vulnerabilities', {
                credentials: 'include'
            });
            
            if (response.ok) {
                const vulnerabilities = await response.json();
                this.displayVulnerabilities(vulnerabilities);
            } else {
                this.showEmptyState('vulnerability-list', 'No vulnerabilities found');
            }
        } catch (error) {
            console.error('Failed to load vulnerabilities:', error);
            this.showEmptyState('vulnerability-list', 'Unable to load vulnerability data');
        }
    }

    async loadScanResults() {
        try {
            const response = await fetch('/api/scan-results', {
                credentials: 'include'
            });
            
            if (response.ok) {
                const scanResults = await response.json();
                this.displayScanResults(scanResults);
            } else {
                this.showEmptyState('scan-results', 'No scan results available');
            }
        } catch (error) {
            console.error('Failed to load scan results:', error);
            this.showEmptyState('scan-results', 'Unable to load scan data');
        }
    }

    displayClients(clients) {
        const container = document.getElementById('clients-grid');
        if (!clients || clients.length === 0) {
            this.showEmptyState('clients-grid', 'No clients connected');
            return;
        }

        container.innerHTML = clients.map(client => `
            <div class="client-card">
                <h4>${client.hostname || 'Unknown Host'}</h4>
                <p><strong>OS:</strong> ${client.os || 'Unknown'}</p>
                <p><strong>IP:</strong> ${client.ip || 'N/A'}</p>
                <p><strong>Last Seen:</strong> ${this.formatTimestamp(client.last_seen)}</p>
                <p><strong>Status:</strong> 
                    <span class="status ${client.online ? 'online' : 'offline'}">
                        ${client.online ? 'Online' : 'Offline'}
                    </span>
                </p>
            </div>
        `).join('');
    }

    displayVulnerabilities(vulnerabilities) {
        const container = document.getElementById('vulnerability-list');
        if (!vulnerabilities || vulnerabilities.length === 0) {
            this.showEmptyState('vulnerability-list', 'No vulnerabilities detected');
            return;
        }

        container.innerHTML = vulnerabilities.map(vuln => `
            <div class="vuln-item">
                <div class="vuln-header">
                    <h4>${vuln.title || 'Unknown Vulnerability'}</h4>
                    <span class="severity ${(vuln.severity || 'medium').toLowerCase()}">${vuln.severity || 'Medium'}</span>
                </div>
                <p><strong>Agent:</strong> ${vuln.agent_id || 'Unknown'}</p>
                <p><strong>Category:</strong> ${vuln.category || 'General'}</p>
                <p><strong>Component:</strong> ${vuln.affected_component || 'Unknown'}</p>
                <p><strong>Description:</strong> ${vuln.description || 'No description available'}</p>
                <p><strong>Remediation:</strong> ${vuln.remediation || 'No remediation available'}</p>
                <p><strong>Confidence:</strong> ${vuln.confidence ? Math.round(vuln.confidence * 100) + '%' : 'N/A'}</p>
                <p><strong>Detected:</strong> ${this.formatTimestamp(vuln.timestamp)}</p>
                ${vuln.cve_id ? `<p><strong>CVE ID:</strong> ${vuln.cve_id}</p>` : ''}
            </div>
        `).join('');
        
        console.log(`Displayed ${vulnerabilities.length} vulnerabilities`);
    }

    displayScanResults(scanResults) {
        const container = document.getElementById('scan-results');
        if (!scanResults || scanResults.length === 0) {
            this.showEmptyState('scan-results', 'No scan results available');
            return;
        }

        container.innerHTML = scanResults.map(scan => `
            <div class="scan-item">
                <h4>Scan: ${scan.hostname || 'Unknown Host'}</h4>
                <p><strong>Scan Type:</strong> ${scan.scan_type || 'General Security Scan'}</p>
                <p><strong>Started:</strong> ${this.formatTimestamp(scan.started_at)}</p>
                <p><strong>Completed:</strong> ${this.formatTimestamp(scan.completed_at)}</p>
                <p><strong>Status:</strong> 
                    <span class="status ${scan.status?.toLowerCase() || 'unknown'}">${scan.status || 'Unknown'}</span>
                </p>
                <p><strong>Findings:</strong> ${scan.findings_count || 0} issues detected</p>
            </div>
        `).join('');
    }

    showEmptyState(containerId, message) {
        const container = document.getElementById(containerId);
        container.innerHTML = `
            <div class="empty-state">
                <p>${message}</p>
            </div>
        `;
    }

    async scanForVulnerabilities() {
        console.log('Starting vulnerability scan...');
        this.showNotification('Starting vulnerability scan...', 'info');
        try {
            const response = await fetch('/api/vulnerabilities/scan', {
                method: 'POST',
                credentials: 'include',
                headers: {
                    'Content-Type': 'application/json'
                }
            });
            
            console.log('Scan response status:', response.status);
            
            if (response.ok) {
                const result = await response.json();
                console.log('Scan result:', result);
                this.showNotification('Vulnerability scan initiated successfully', 'success');
                // Refresh vulnerabilities after a delay
                setTimeout(() => this.loadVulnerabilities(), 3000);
            } else {
                const errorText = await response.text();
                console.error('Scan failed:', response.status, errorText);
                this.showNotification('Failed to start vulnerability scan', 'error');
            }
        } catch (error) {
            console.error('Scan failed:', error);
            this.showNotification('Error starting vulnerability scan', 'error');
        }
    }

    async refreshVulnerabilities() {
        this.showNotification('Refreshing vulnerability data...', 'info');
        await this.loadVulnerabilities();
    }

    async logout() {
        try {
            const response = await fetch('/logout', {
                method: 'POST',
                credentials: 'include'
            });
            
            if (response.ok) {
                window.location.href = '/login';
            } else {
                console.error('Logout failed');
                // Force redirect anyway
                window.location.href = '/login';
            }
        } catch (error) {
            console.error('Logout error:', error);
            // Force redirect on error
            window.location.href = '/login';
        }
    }

    showNotification(message, type = 'info') {
        // Create notification element
        const notification = document.createElement('div');
        notification.className = `notification ${type}`;
        notification.textContent = message;
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            background: ${type === 'success' ? '#27ae60' : type === 'error' ? '#e74c3c' : '#3498db'};
            color: white;
            padding: 1rem;
            border-radius: 4px;
            z-index: 1000;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        `;

        document.body.appendChild(notification);

        // Remove after 3 seconds
        setTimeout(() => {
            if (notification.parentNode) {
                notification.parentNode.removeChild(notification);
            }
        }, 3000);
    }

    formatTimestamp(timestamp) {
        if (!timestamp) return 'Never';
        try {
            return new Date(timestamp).toLocaleString();
        } catch (error) {
            return 'Invalid date';
        }
    }
}

// Initialize dashboard when page loads
document.addEventListener('DOMContentLoaded', () => {
    const dashboard = new RMMDashboard();
    dashboard.init();
});

// Global functions for HTML onclick handlers
async function logout() {
    const dashboard = new RMMDashboard();
    await dashboard.logout();
}

async function scanForVulnerabilities() {
    const dashboard = new RMMDashboard();
    await dashboard.scanForVulnerabilities();
}

async function refreshVulnerabilities() {
    const dashboard = new RMMDashboard();
    await dashboard.refreshVulnerabilities();
}
