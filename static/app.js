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
                await this.loadOverview();
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
            case 'patches':
                await this.loadPatches();
                break;
            case 'alerts':
                await this.loadAlerts();
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

    async loadOverview() {
        try {
            // Load vulnerability summary
            const vulnResponse = await fetch('/api/vulnerabilities/summary', {
                credentials: 'include'
            });
            
            if (vulnResponse.ok) {
                const vulnSummary = await vulnResponse.json();
                document.getElementById('critical-count').textContent = vulnSummary.critical || 0;
                document.getElementById('high-count').textContent = vulnSummary.high || 0;
                document.getElementById('medium-count').textContent = vulnSummary.medium || 0;
            }
            
            // Load client count
            const clientResponse = await fetch('/api/clients', {
                credentials: 'include'
            });
            
            if (clientResponse.ok) {
                const clients = await clientResponse.json();
                const onlineClients = clients.filter(client => client.online).length;
                document.getElementById('online-count').textContent = onlineClients;
            }
            
            // Load recent activity
            await this.loadRecentActivity();
            
        } catch (error) {
            console.error('Failed to load overview data:', error);
        }
    }

    async loadRecentActivity() {
        try {
            // Get recent vulnerabilities for activity feed
            const vulnResponse = await fetch('/api/vulnerabilities', {
                credentials: 'include'
            });
            
            const activityContainer = document.getElementById('activity-list');
            
            if (vulnResponse.ok) {
                const vulnerabilities = await vulnResponse.json();
                
                if (vulnerabilities.length === 0) {
                    activityContainer.innerHTML = '<div class="empty-state">No recent security activity</div>';
                    return;
                }
                
                // Sort by timestamp and take most recent 5
                const recentVulns = vulnerabilities
                    .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
                    .slice(0, 5);
                
                activityContainer.innerHTML = recentVulns.map(vuln => {
                    const timeAgo = this.getTimeAgo(vuln.timestamp);
                    const severityClass = (vuln.severity || 'medium').toLowerCase();
                    
                    return `
                        <div class="activity-item ${severityClass}">
                            <span class="activity-time">${timeAgo}</span>
                            <span class="activity-text">${vuln.severity} vulnerability detected: ${vuln.title}</span>
                        </div>
                    `;
                }).join('');
            } else {
                activityContainer.innerHTML = '<div class="empty-state">No recent activity data available</div>';
            }
        } catch (error) {
            console.error('Failed to load recent activity:', error);
            document.getElementById('activity-list').innerHTML = '<div class="empty-state">Unable to load activity data</div>';
        }
    }

    async loadPatches() {
        const container = document.getElementById('patch-list');
        if (!container) return;
        
        // Show patches based on vulnerabilities
        try {
            const response = await fetch('/api/vulnerabilities', {
                credentials: 'include'
            });
            
            if (response.ok) {
                const vulnerabilities = await response.json();
                const patches = vulnerabilities.map(vuln => ({
                    id: vuln.id,
                    title: `Patch for: ${vuln.title}`,
                    component: vuln.affected_component,
                    severity: vuln.severity,
                    remediation: vuln.remediation,
                    agent_id: vuln.agent_id
                }));
                
                if (patches.length === 0) {
                    this.showEmptyState('patch-list', 'No patches required');
                    return;
                }
                
                container.innerHTML = patches.map(patch => `
                    <div class="patch-item">
                        <div class="patch-header">
                            <h4>${patch.title}</h4>
                            <span class="severity ${(patch.severity || 'medium').toLowerCase()}">${patch.severity}</span>
                        </div>
                        <p><strong>Component:</strong> ${patch.component}</p>
                        <p><strong>Agent:</strong> ${patch.agent_id}</p>
                        <p><strong>Action Required:</strong> ${patch.remediation}</p>
                        <button class="btn secondary" onclick="dashboard.applyPatch('${patch.id}')">Apply Patch</button>
                    </div>
                `).join('');
            } else {
                this.showEmptyState('patch-list', 'Unable to load patch data');
            }
        } catch (error) {
            console.error('Failed to load patches:', error);
            this.showEmptyState('patch-list', 'Error loading patch information');
        }
    }

    async loadAlerts() {
        const container = document.getElementById('alerts-list');
        if (!container) return;
        
        // Show critical and high severity vulnerabilities as alerts
        try {
            const response = await fetch('/api/vulnerabilities', {
                credentials: 'include'
            });
            
            if (response.ok) {
                const vulnerabilities = await response.json();
                const alerts = vulnerabilities.filter(vuln => 
                    vuln.severity === 'Critical' || vuln.severity === 'High'
                );
                
                if (alerts.length === 0) {
                    this.showEmptyState('alerts-list', 'No active security alerts');
                    return;
                }
                
                container.innerHTML = alerts.map(alert => `
                    <div class="alert-item ${(alert.severity || 'medium').toLowerCase()}">
                        <div class="alert-header">
                            <h4>🚨 ${alert.title}</h4>
                            <span class="severity ${(alert.severity || 'medium').toLowerCase()}">${alert.severity}</span>
                        </div>
                        <p><strong>Agent:</strong> ${alert.agent_id}</p>
                        <p><strong>Component:</strong> ${alert.affected_component}</p>
                        <p><strong>Description:</strong> ${alert.description}</p>
                        <p><strong>Action Required:</strong> ${alert.remediation}</p>
                        <p><strong>Detected:</strong> ${this.formatTimestamp(alert.timestamp)}</p>
                        <button class="btn primary" onclick="dashboard.acknowledgeAlert('${alert.id}')">Acknowledge</button>
                    </div>
                `).join('');
            } else {
                this.showEmptyState('alerts-list', 'Unable to load alert data');
            }
        } catch (error) {
            console.error('Failed to load alerts:', error);
            this.showEmptyState('alerts-list', 'Error loading security alerts');
        }
    }

    async applyPatch(patchId) {
        console.log('Applying patch:', patchId);
        this.showNotification('Patch application initiated for: ' + patchId, 'info');
        // In a real implementation, this would trigger the patch application
    }

    async acknowledgeAlert(alertId) {
        console.log('Acknowledging alert:', alertId);
        this.showNotification('Security alert acknowledged: ' + alertId, 'success');
        // In a real implementation, this would mark the alert as acknowledged
        setTimeout(() => this.loadAlerts(), 1000);
    }

    getTimeAgo(timestamp) {
        if (!timestamp) return 'Unknown time';
        
        try {
            const now = new Date();
            const then = new Date(timestamp);
            const diffMs = now - then;
            const diffMins = Math.floor(diffMs / 60000);
            const diffHours = Math.floor(diffMins / 60);
            const diffDays = Math.floor(diffHours / 24);
            
            if (diffMins < 1) return 'Just now';
            if (diffMins < 60) return `${diffMins} min ago`;
            if (diffHours < 24) return `${diffHours} hour${diffHours > 1 ? 's' : ''} ago`;
            return `${diffDays} day${diffDays > 1 ? 's' : ''} ago`;
        } catch (error) {
            return 'Unknown time';
        }
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
let dashboard;
document.addEventListener('DOMContentLoaded', () => {
    dashboard = new RMMDashboard();
    dashboard.init();
    // Make dashboard globally accessible for onclick handlers
    window.dashboard = dashboard;
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
