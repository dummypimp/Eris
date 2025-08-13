class MythicAndroidDashboard {
    constructor() {
        this.agents = new Map();
        this.charts = {};
        this.wsConnection = null;
        this.currentTab = 'overview';
        this.refreshInterval = null;

        this.init();
    }

    init() {
        this.updateTime();
        this.setupWebSocket();
        this.initializeCharts();
        this.startRefreshInterval();
        this.loadMockData();
    }

    updateTime() {
        const now = new Date();
        document.getElementById('current-time').textContent = now.toLocaleString();
        setTimeout(() => this.updateTime(), 1000);
    }

    setupWebSocket() {

        try {
            const wsUrl = `ws:
            this.wsConnection = new WebSocket(wsUrl);

            this.wsConnection.onopen = () => {
                console.log('WebSocket connected to Mythic C2');
                this.updateConnectionStatus('Active', 'status-excellent');
            };

            this.wsConnection.onmessage = (event) => {
                this.handleWebSocketMessage(JSON.parse(event.data));
            };

            this.wsConnection.onclose = () => {
                console.log('WebSocket disconnected');
                this.updateConnectionStatus('Disconnected', 'status-critical');

                setTimeout(() => this.setupWebSocket(), 5000);
            };

            this.wsConnection.onerror = (error) => {
                console.error('WebSocket error:', error);
                this.updateConnectionStatus('Error', 'status-critical');
            };
        } catch (error) {
            console.warn('WebSocket connection failed, using mock data');
            this.updateConnectionStatus('Mock Mode', 'status-warning');
        }
    }

    updateConnectionStatus(status, statusClass) {
        const statusElement = document.getElementById('connection-status');
        const indicatorElement = statusElement.previousElementSibling;

        statusElement.textContent = status;
        indicatorElement.className = `status-indicator ${statusClass}`;
    }

    handleWebSocketMessage(data) {
        switch (data.type) {
            case 'agent_update':
                this.updateAgent(data.payload);
                break;
            case 'health_metrics':
                this.updateHealthMetrics(data.payload);
                break;
            case 'security_alert':
                this.addSecurityAlert(data.payload);
                break;
            case 'performance_data':
                this.updatePerformanceData(data.payload);
                break;
            default:
                console.log('Unknown message type:', data.type);
        }
    }

    initializeCharts() {

        const activityCtx = document.getElementById('activity-chart').getContext('2d');
        this.charts.activity = new Chart(activityCtx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Tasks Completed',
                    data: [],
                    borderColor: '#00d4aa',
                    backgroundColor: 'rgba(0, 212, 170, 0.1)',
                    tension: 0.4
                }, {
                    label: 'Data Collected (MB)',
                    data: [],
                    borderColor: '#ff6b35',
                    backgroundColor: 'rgba(255, 107, 53, 0.1)',
                    tension: 0.4,
                    yAxisID: 'y1'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        labels: { color: '#fff' }
                    }
                },
                scales: {
                    x: {
                        ticks: { color: '#ccc' },
                        grid: { color: '#404040' }
                    },
                    y: {
                        type: 'linear',
                        display: true,
                        position: 'left',
                        ticks: { color: '#ccc' },
                        grid: { color: '#404040' }
                    },
                    y1: {
                        type: 'linear',
                        display: true,
                        position: 'right',
                        ticks: { color: '#ccc' },
                        grid: { drawOnChartArea: false }
                    }
                }
            }
        });

        const performanceCtx = document.getElementById('performance-chart').getContext('2d');
        this.charts.performance = new Chart(performanceCtx, {
            type: 'doughnut',
            data: {
                labels: ['CPU Usage', 'Memory Usage', 'Battery Level', 'Available'],
                datasets: [{
                    data: [25, 40, 85, 15],
                    backgroundColor: ['#e74c3c', '#f39c12', '#27ae60', '#95a5a6'],
                    borderColor: '#2c2c2c',
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        labels: { color: '#fff' }
                    }
                }
            }
        });

        const moduleCtx = document.getElementById('module-performance-chart').getContext('2d');
        this.charts.modulePerformance = new Chart(moduleCtx, {
            type: 'bar',
            data: {
                labels: ['Call Logger', 'Filesystem', 'Stealth Surveillance', 'Social Media'],
                datasets: [{
                    label: 'Success Rate %',
                    data: [95, 88, 92, 87],
                    backgroundColor: '#00d4aa',
                    borderColor: '#00b896',
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        labels: { color: '#fff' }
                    }
                },
                scales: {
                    x: {
                        ticks: { color: '#ccc' },
                        grid: { color: '#404040' }
                    },
                    y: {
                        ticks: { color: '#ccc' },
                        grid: { color: '#404040' },
                        min: 0,
                        max: 100
                    }
                }
            }
        });

        const securityCtx = document.getElementById('security-chart').getContext('2d');
        this.charts.security = new Chart(securityCtx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Detection Risk Score',
                    data: [],
                    borderColor: '#e74c3c',
                    backgroundColor: 'rgba(231, 76, 60, 0.1)',
                    tension: 0.4,
                    fill: true
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        labels: { color: '#fff' }
                    }
                },
                scales: {
                    x: {
                        ticks: { color: '#ccc' },
                        grid: { color: '#404040' }
                    },
                    y: {
                        ticks: { color: '#ccc' },
                        grid: { color: '#404040' },
                        min: 0,
                        max: 100
                    }
                }
            }
        });

        const analyticsCtx = document.getElementById('analytics-chart').getContext('2d');
        this.charts.analytics = new Chart(analyticsCtx, {
            type: 'bar',
            data: {
                labels: ['Week 1', 'Week 2', 'Week 3', 'Week 4'],
                datasets: [{
                    label: 'Tasks Completed',
                    data: [120, 95, 130, 108],
                    backgroundColor: '#00d4aa',
                    borderColor: '#00b896',
                    borderWidth: 1
                }, {
                    label: 'Data Collected (MB)',
                    data: [45, 38, 52, 41],
                    backgroundColor: '#ff6b35',
                    borderColor: '#e55a30',
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        labels: { color: '#fff' }
                    }
                },
                scales: {
                    x: {
                        ticks: { color: '#ccc' },
                        grid: { color: '#404040' }
                    },
                    y: {
                        ticks: { color: '#ccc' },
                        grid: { color: '#404040' }
                    }
                }
            }
        });
    }

    loadMockData() {

        const mockAgents = [
            {
                id: 'agent_001',
                device_id: 'samsung_galaxy_s23',
                status: 'online',
                health_score: 92,
                last_checkin: new Date(),
                location: 'New York, NY',
                android_version: 'Android 13 (API 33)',
                campaign: 'social_media_intel',
                tasks_completed: 45,
                data_collected: 125.6
            },
            {
                id: 'agent_002',
                device_id: 'pixel_7_pro',
                status: 'online',
                health_score: 88,
                last_checkin: new Date(Date.now() - 300000),
                location: 'Los Angeles, CA',
                android_version: 'Android 14 (API 34)',
                campaign: 'corporate_recon',
                tasks_completed: 32,
                data_collected: 87.3
            }
        ];

        mockAgents.forEach(agent => {
            this.agents.set(agent.id, agent);
        });

        this.updateOverviewMetrics();
        this.renderAgents();
        this.updateRecentAlerts();
        this.populateActivityChart();
    }

    updateOverviewMetrics() {
        const activeAgents = Array.from(this.agents.values()).filter(a => a.status === 'online').length;
        const totalTasks = Array.from(this.agents.values()).reduce((sum, a) => sum + a.tasks_completed, 0);
        const totalData = Array.from(this.agents.values()).reduce((sum, a) => sum + a.data_collected, 0);
        const avgHealthScore = Array.from(this.agents.values()).reduce((sum, a) => sum + a.health_score, 0) / this.agents.size;

        document.getElementById('active-agents-count').textContent = activeAgents;
        document.getElementById('success-rate').textContent = `${Math.round(avgHealthScore)}%`;
        document.getElementById('data-collected').textContent = `${totalData.toFixed(1)} MB`;
        document.getElementById('agent-count').textContent = this.agents.size;

        const detectionRisk = avgHealthScore > 90 ? 'Low' : avgHealthScore > 70 ? 'Medium' : 'High';
        const riskClass = avgHealthScore > 90 ? 'text-success' : avgHealthScore > 70 ? 'text-warning' : 'text-danger';

        const detectionElement = document.getElementById('detection-risk');
        detectionElement.textContent = detectionRisk;
        detectionElement.className = riskClass;
    }

    renderAgents() {
        const container = document.getElementById('agents-container');
        container.innerHTML = '';

        this.agents.forEach((agent, id) => {
            const agentCard = this.createAgentCard(agent);
            container.appendChild(agentCard);
        });
    }

    createAgentCard(agent) {
        const card = document.createElement('div');
        card.className = 'card agent-status-card';

        const statusClass = agent.status === 'online' ? 'status-excellent' :
                           agent.status === 'offline' ? 'status-offline' : 'status-warning';

        const timeSinceCheckin = Math.floor((Date.now() - agent.last_checkin.getTime()) / 60000);

        card.innerHTML = `
            <div class="card-header d-flex justify-content-between align-items-center">
                <h6 class="mb-0">
                    <span class="status-indicator ${statusClass}"></span>
                    ${agent.device_id}
                </h6>
                <small class="text-muted">${agent.campaign}</small>
            </div>
            <div class="card-body">
                <div class="row">
                    <div class="col-sm-6">
                        <small class="text-muted">Health Score</small>
                        <div class="d-flex align-items-center mb-2">
                            <div class="progress flex-grow-1 me-2" style="height: 8px;">
                                <div class="progress-bar" style="width: ${agent.health_score}%"></div>
                            </div>
                            <span class="small">${agent.health_score}%</span>
                        </div>
                    </div>
                    <div class="col-sm-6">
                        <small class="text-muted">Tasks Completed</small>
                        <div class="fw-bold text-info">${agent.tasks_completed}</div>
                    </div>
                </div>
                <div class="row mt-2">
                    <div class="col-sm-6">
                        <small class="text-muted">Data Collected</small>
                        <div class="small">${agent.data_collected.toFixed(1)} MB</div>
                    </div>
                    <div class="col-sm-6">
                        <small class="text-muted">Last Checkin</small>
                        <div class="small">${timeSinceCheckin}m ago</div>
                    </div>
                </div>
                <div class="mt-3">
                    <small class="text-muted d-block">Android Version</small>
                    <span class="small">${agent.android_version}</span>
                </div>
                <div class="mt-2">
                    <small class="text-muted d-block">Location</small>
                    <span class="small">${agent.location}</span>
                </div>
                <div class="mt-3">
                    <div class="btn-group w-100">
                        <button class="btn btn-sm btn-outline-info" onclick="dashboard.sendCommand('${agent.id}', 'status')">
                            <i class="fas fa-info-circle"></i> Status
                        </button>
                        <button class="btn btn-sm btn-outline-warning" onclick="dashboard.sendCommand('${agent.id}', 'task_list')">
                            <i class="fas fa-tasks"></i> Tasks
                        </button>
                        <button class="btn btn-sm btn-outline-danger" onclick="dashboard.killswitchAgent('${agent.id}')">
                            <i class="fas fa-power-off"></i> Kill
                        </button>
                    </div>
                </div>
            </div>
        `;

        return card;
    }

    updateRecentAlerts() {
        const alertsContainer = document.getElementById('recent-alerts');
        const mockAlerts = [
            {
                type: 'security',
                severity: 'high',
                message: 'Elevated detection risk detected on agent_001',
                timestamp: new Date(Date.now() - 300000)
            },
            {
                type: 'performance',
                severity: 'medium',
                message: 'Memory usage above threshold on agent_002',
                timestamp: new Date(Date.now() - 600000)
            },
            {
                type: 'connection',
                severity: 'low',
                message: 'Agent_003 connection timeout resolved',
                timestamp: new Date(Date.now() - 900000)
            }
        ];

        alertsContainer.innerHTML = mockAlerts.map(alert => `
            <div class="alert alert-${alert.severity === 'high' ? 'danger' : alert.severity === 'medium' ? 'warning' : 'info'} py-2 mb-2">
                <div class="d-flex justify-content-between">
                    <div>
                        <i class="fas fa-${alert.type === 'security' ? 'shield-alt' : alert.type === 'performance' ? 'chart-line' : 'wifi'}"></i>
                        <small>${alert.message}</small>
                    </div>
                    <small class="text-muted">${Math.floor((Date.now() - alert.timestamp.getTime()) / 60000)}m</small>
                </div>
            </div>
        `).join('');
    }

    populateActivityChart() {
        const labels = [];
        const tasksData = [];
        const dataCollectedData = [];

        for (let i = 11; i >= 0; i--) {
            const time = new Date(Date.now() - i * 3600000);
            labels.push(time.toLocaleTimeString([], {hour: '2-digit', minute: '2-digit'}));
            tasksData.push(Math.floor(Math.random() * 20) + 5);
            dataCollectedData.push(Math.floor(Math.random() * 15) + 2);
        }

        this.charts.activity.data.labels = labels;
        this.charts.activity.data.datasets[0].data = tasksData;
        this.charts.activity.data.datasets[1].data = dataCollectedData;
        this.charts.activity.update();
    }

    startRefreshInterval() {
        this.refreshInterval = setInterval(() => {
            if (this.currentTab === 'overview') {
                this.updateOverviewMetrics();
                this.updateRecentAlerts();
            } else if (this.currentTab === 'agents') {
                this.renderAgents();
            }
        }, 30000);
    }

    sendCommand(agentId, command) {
        const commandData = {
            type: 'agent_command',
            agent_id: agentId,
            command: command,
            timestamp: new Date().toISOString()
        };

        if (this.wsConnection && this.wsConnection.readyState === WebSocket.OPEN) {
            this.wsConnection.send(JSON.stringify(commandData));
        }

        this.addTerminalOutput(`Command sent to ${agentId}: ${command}`, 'terminal-output');
    }

    killswitchAgent(agentId) {
        if (confirm(`Are you sure you want to activate killswitch for ${agentId}? This action cannot be undone.`)) {
            this.sendCommand(agentId, 'killswitch_activate');
            this.addTerminalOutput(`KILLSWITCH ACTIVATED for ${agentId}`, 'terminal-error');
        }
    }

    activateKillswitch() {
        if (confirm('Are you sure you want to activate the global killswitch? This will terminate ALL active agents and cannot be undone.')) {
            const confirmText = prompt('Type "CONFIRM KILLSWITCH" to proceed:');
            if (confirmText === 'CONFIRM KILLSWITCH') {
                if (this.wsConnection && this.wsConnection.readyState === WebSocket.OPEN) {
                    this.wsConnection.send(JSON.stringify({
                        type: 'global_killswitch',
                        timestamp: new Date().toISOString()
                    }));
                }

                document.getElementById('killswitch-btn').innerHTML = '<i class="fas fa-check"></i> KILLSWITCH ACTIVATED';
                document.getElementById('killswitch-btn').disabled = true;

                this.addTerminalOutput('GLOBAL KILLSWITCH ACTIVATED - ALL AGENTS TERMINATED', 'terminal-error');
            }
        }
    }

    generateNewAgent() {

        alert('Agent generation feature will be implemented with Mythic CLI integration');
    }

    generateReport() {
        const reportData = {
            timestamp: new Date().toISOString(),
            agents: Array.from(this.agents.values()),
            summary: {
                total_agents: this.agents.size,
                active_agents: Array.from(this.agents.values()).filter(a => a.status === 'online').length,
                total_tasks: Array.from(this.agents.values()).reduce((sum, a) => sum + a.tasks_completed, 0),
                total_data: Array.from(this.agents.values()).reduce((sum, a) => sum + a.data_collected, 0)
            }
        };

        const blob = new Blob([JSON.stringify(reportData, null, 2)], {type: 'application/json'});
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `mythic-android-report-${new Date().toISOString().split('T')[0]}.json`;
        a.click();
        URL.revokeObjectURL(url);
    }

    addTerminalOutput(text, className = 'terminal-output') {
        const terminal = document.getElementById('terminal-output');
        const line = document.createElement('div');
        line.className = 'terminal-line';
        line.innerHTML = `
            <span class="terminal-prompt">mythic-android$</span>
            <span class="${className}"> ${text}</span>
        `;
        terminal.appendChild(line);
        terminal.scrollTop = terminal.scrollHeight;
    }

    executeCommand() {
        const input = document.getElementById('terminal-input');
        const command = input.value.trim();

        if (!command) return;

        this.addTerminalOutput(command, 'terminal-output');

        this.processTerminalCommand(command);

        input.value = '';
    }

    processTerminalCommand(command) {
        const parts = command.split(' ');
        const cmd = parts[0].toLowerCase();

        switch (cmd) {
            case 'agents':
                this.addTerminalOutput(`Active agents: ${Array.from(this.agents.values()).filter(a => a.status === 'online').length}`, 'terminal-output');
                this.agents.forEach((agent, id) => {
                    this.addTerminalOutput(`  ${id}: ${agent.status} (${agent.health_score}%)`, 'terminal-output');
                });
                break;

            case 'status':
                this.addTerminalOutput('System Status: Operational', 'terminal-output');
                this.addTerminalOutput(`Connection: ${document.getElementById('connection-status').textContent}`, 'terminal-output');
                this.addTerminalOutput(`Total Agents: ${this.agents.size}`, 'terminal-output');
                break;

            case 'clear':
                this.clearTerminal();
                break;

            case 'help':
                this.addTerminalOutput('Available commands:', 'terminal-output');
                this.addTerminalOutput('  agents - List all agents', 'terminal-output');
                this.addTerminalOutput('  status - Show system status', 'terminal-output');
                this.addTerminalOutput('  clear - Clear terminal', 'terminal-output');
                this.addTerminalOutput('  help - Show this help', 'terminal-output');
                break;

            default:
                this.addTerminalOutput(`Unknown command: ${cmd}`, 'terminal-error');
                break;
        }
    }

    clearTerminal() {
        const terminal = document.getElementById('terminal-output');
        terminal.innerHTML = `
            <div class="terminal-line">
                <span class="terminal-prompt">mythic-android$</span>
                <span class="terminal-output"> Welcome to Mythic Android Agent Terminal</span>
            </div>
        `;
    }

    refreshDashboard() {
        this.loadMockData();
        this.addTerminalOutput('Dashboard refreshed', 'terminal-output');
    }

    refreshAgents() {
        this.renderAgents();
        this.addTerminalOutput('Agent list refreshed', 'terminal-output');
    }
}

function showTab(tabName) {

    const tabs = document.querySelectorAll('.tab-content');
    tabs.forEach(tab => tab.style.display = 'none');

    document.getElementById(`${tabName}-tab`).style.display = 'block';

    const navLinks = document.querySelectorAll('.nav-link');
    navLinks.forEach(link => link.classList.remove('active'));
    event.target.classList.add('active');

    dashboard.currentTab = tabName;
}

function handleTerminalInput(event) {
    if (event.key === 'Enter') {
        dashboard.executeCommand();
    }
}

const dashboard = new MythicAndroidDashboard();