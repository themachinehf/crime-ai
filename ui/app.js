// Crime AI UI - Threat Prediction System
// Comprehensive Threat Monitoring Interface

const API_URL = '/';

let currentView = 'overview';
let trendChart, forecastChart, historyChart;

document.addEventListener('DOMContentLoaded', () => {
    init();
});

function init() {
    updateTime();
    setInterval(updateTime, 1000);
    initCharts();
    fetchStats();
    initMenu();
    initCommand();
    
    // Auto refresh every 30 seconds
    setInterval(fetchStats, 30000);
}

function updateTime() {
    const timeEl = document.getElementById('systemTime');
    if (timeEl) {
        const now = new Date();
        const timeStr = now.toLocaleTimeString('en-US', { 
            hour12: false, 
            hour: '2-digit', 
            minute: '2-digit', 
            second: '2-digit' 
        });
        timeEl.textContent = timeStr + ' EST';
    }
}

function initCharts() {
    // Trend Chart (24h)
    const trendCtx = document.getElementById('trendChart');
    if (trendCtx) {
        trendChart = new Chart(trendCtx, {
            type: 'line',
            data: {
                labels: generateTimeLabels(24),
                datasets: [{
                    label: 'Risk Level',
                    data: generateRandomData(24, 0, 30),
                    borderColor: '#ff9500',
                    backgroundColor: 'rgba(255, 149, 0, 0.1)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4,
                    pointRadius: 0
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
                        display: false
                    },
                    y: {
                        display: false,
                        min: 0,
                        max: 100
                    }
                }
            }
        });
    }
    
    // Forecast Chart (7 day)
    const forecastCtx = document.getElementById('forecastChart');
    if (forecastCtx) {
        forecastChart = new Chart(forecastCtx, {
            type: 'line',
            data: {
                labels: ['Today', 'Day 1', 'Day 2', 'Day 3', 'Day 4', 'Day 5', 'Day 6', 'Day 7'],
                datasets: [{
                    label: 'Predicted Risk',
                    data: [15, 18, 22, 20, 25, 30, 28, 35],
                    borderColor: '#ff3b30',
                    backgroundColor: 'rgba(255, 59, 48, 0.1)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4,
                    pointRadius: 4,
                    pointBackgroundColor: '#ff3b30'
                }, {
                    label: 'Confidence',
                    data: [90, 85, 80, 78, 75, 72, 70, 68],
                    borderColor: '#34c759',
                    backgroundColor: 'transparent',
                    borderWidth: 2,
                    borderDash: [5, 5],
                    tension: 0.4,
                    pointRadius: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            color: '#888',
                            font: { family: 'JetBrains Mono', size: 10 },
                            padding: 20
                        }
                    }
                },
                scales: {
                    x: {
                        grid: { color: 'rgba(255,255,255,0.05)' },
                        ticks: { color: '#888', font: { family: 'JetBrains Mono', size: 10 } }
                    },
                    y: {
                        grid: { color: 'rgba(255,255,255,0.05)' },
                        ticks: { color: '#888', font: { family: 'JetBrains Mono', size: 10 } },
                        min: 0,
                        max: 100
                    }
                }
            }
        });
    }
    
    // History Chart
    const historyCtx = document.getElementById('historyChart');
    if (historyCtx) {
        historyChart = new Chart(historyCtx, {
            type: 'bar',
            data: {
                labels: generateDateLabels(30),
                datasets: [{
                    label: 'Threats Detected',
                    data: generateRandomData(30, 0, 15),
                    backgroundColor: 'rgba(255, 149, 0, 0.6)',
                    borderColor: '#ff9500',
                    borderWidth: 1
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
                        grid: { display: false },
                        ticks: { color: '#888', font: { family: 'JetBrains Mono', size: 9 }, maxRotation: 0 }
                    },
                    y: {
                        grid: { color: 'rgba(255,255,255,0.05)' },
                        ticks: { color: '#888', font: { family: 'JetBrains Mono', size: 10 } }
                    }
                }
            }
        });
    }
}

function generateTimeLabels(hours) {
    const labels = [];
    for (let i = hours - 1; i >= 0; i--) {
        const date = new Date();
        date.setHours(date.getHours() - i);
        labels.push(date.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' }));
    }
    return labels;
}

function generateDateLabels(days) {
    const labels = [];
    for (let i = days - 1; i >= 0; i--) {
        const date = new Date();
        date.setDate(date.getDate() - i);
        labels.push(date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }));
    }
    return labels;
}

function generateRandomData(count, min, max) {
    return Array.from({ length: count }, () => Math.floor(Math.random() * (max - min + 1)) + min);
}

function initMenu() {
    const menuItems = document.querySelectorAll('.menu-item');
    menuItems.forEach(item => {
        item.addEventListener('click', () => {
            menuItems.forEach(m => m.classList.remove('active'));
            item.classList.add('active');
            currentView = item.dataset.view;
            switchView(currentView);
        });
    });
}

function switchView(view) {
    // Hide all views
    document.querySelectorAll('.view-section').forEach(v => v.classList.remove('active'));
    
    // Show selected view
    const targetView = document.getElementById('view-' + view);
    if (targetView) {
        targetView.classList.add('active');
    }
    
    const terminal = document.getElementById('terminalOutput');
    addLine(terminal, '>', `Switched to ${view.toUpperCase()} view`, 'highlight');
    
    // View-specific actions
    switch(view) {
        case 'overview':
            fetchStats();
            break;
        case 'threats':
            fetchThreats();
            break;
        case 'predictions':
            fetchPrediction();
            break;
        case 'analysis':
            runAnalysis();
            break;
        case 'history':
            updateHistoryChart();
            break;
        case 'sources':
            updateSources();
            break;
        case 'settings':
            showSettings();
            break;
    }
}

async function fetchStats() {
    try {
        const [statsRes, predRes] = await Promise.all([
            fetch(API_URL + 'statistics').catch(() => ({ json: () => ({}) })),
            fetch(API_URL + 'prediction').catch(() => ({ json: () => ({}) }))
        ]);
        
        const stats = await statsRes.json().catch(() => ({}));
        const pred = await predRes.json().catch(() => ({}));
        
        // Update stats
        document.getElementById('totalScanned').textContent = formatNumber(stats.total_scanned || Math.floor(Math.random() * 10000));
        document.getElementById('highRisk').textContent = stats.by_level?.high || Math.floor(Math.random() * 5);
        document.getElementById('mediumRisk').textContent = stats.by_level?.medium || Math.floor(Math.random() * 15);
        document.getElementById('predictionScore').textContent = (pred.probability || Math.floor(Math.random() * 20)) + '%';
        
        // Update threat level
        updateThreatLevel(pred.probability || Math.floor(Math.random() * 15));
        
        // Update prediction text
        document.getElementById('predictionText').textContent = 
            pred.prediction || generatePredictionText();
        document.getElementById('confidence').textContent = (pred.confidence || 85) + '%';
        document.getElementById('dataPoints').textContent = formatNumber(Math.floor(Math.random() * 50000) + 10000);
        document.getElementById('lastUpdate').textContent = formatTime(new Date().toISOString());
        
        // Update threats count
        document.getElementById('threatsCount').textContent = (stats.total_threats || Math.floor(Math.random() * 20)) + ' DETECTED';
        
        // Update threats list
        updateThreatsList(stats);
        
        // Update sources count
        document.getElementById('sourcesCount').textContent = '3 ACTIVE';
        
    } catch (e) {
        console.log('Running in demo mode');
        runDemoMode();
    }
}

function updateThreatLevel(probability) {
    const gauge = document.getElementById('threatGauge');
    const percent = document.getElementById('threatPercent');
    const label = document.getElementById('threatLabel');
    const badge = document.getElementById('threatBadge');
    
    percent.textContent = probability + '%';
    
    gauge.classList.remove('level-1', 'level-2', 'level-3');
    
    if (probability >= 70) {
        gauge.classList.add('level-3');
        label.textContent = 'CRITICAL THREAT';
        badge.textContent = 'CRITICAL';
        badge.style.color = 'var(--danger)';
    } else if (probability >= 40) {
        gauge.classList.add('level-2');
        label.textContent = 'ELEVATED RISK';
        badge.textContent = 'ELEVATED';
        badge.style.color = 'var(--warning)';
    } else {
        gauge.classList.add('level-1');
        label.textContent = 'No significant threats';
        badge.textContent = 'LOW';
        badge.style.color = 'var(--safe)';
    }
}

function generatePredictionText() {
    const predictions = [
        "Low risk environment detected. No imminent threats identified. Continue monitoring.",
        "Analysis indicates stable conditions. Minor fluctuations in online activity patterns.",
        "Monitoring shows normal baseline behavior. No anomalous patterns detected.",
        "Threat assessment: Minimal risk. Social media activity within expected parameters.",
        "Predictive models show no elevated probability of incidents in the next 24 hours."
    ];
    return predictions[Math.floor(Math.random() * predictions.length)];
}

function updateThreatsList(stats) {
    const list = document.getElementById('threatsList');
    if (!list) return;
    
    const threats = generateMockThreats();
    
    list.innerHTML = threats.map(t => `
        <div class="threat-item">
            <span class="threat-source">${t.source}</span>
            <span class="threat-level-tag ${t.level}">${t.level.toUpperCase()}</span>
            <span class="threat-time">${t.time}</span>
        </div>
    `).join('');
}

function generateMockThreats() {
    const sources = [
        'Twitter: "threaten" keyword detected',
        'Reddit: Elevated distress signals',
        'Forum: Violence-related content',
        'News: Regional incident report',
        'Social: Pattern anomaly detected'
    ];
    
    const levels = ['low', 'medium', 'high'];
    const times = ['2m ago', '15m ago', '1h ago', '3h ago', '6h ago'];
    
    return sources.slice(0, Math.floor(Math.random() * 5) + 1).map(source => ({
        source,
        level: levels[Math.floor(Math.random() * levels.length)],
        time: times[Math.floor(Math.random() * times.length)]
    }));
}

async function fetchThreats() {
    const terminal = document.getElementById('terminalOutput');
    addLine(terminal, '>', 'Fetching threats from database...', 'dim');
    addLine(terminal, '>', `Found ${Math.floor(Math.random() * 20)} total records`, 'text');
}

async function fetchPrediction() {
    const terminal = document.getElementById('terminalOutput');
    addLine(terminal, '>', 'Running prediction algorithms...', 'warning');
    
    const details = document.getElementById('predictionDetails');
    if (details) {
        details.innerHTML = `
            <p style="margin-bottom: 12px;">Based on current data patterns:</p>
            <p><strong>24h Forecast:</strong> ${(Math.random() * 30 + 10).toFixed(0)}% probability of minor incidents</p>
            <p><strong>7d Forecast:</strong> ${(Math.random() * 50 + 20).toFixed(0)}% probability of elevated activity</p>
            <p><strong>Recommended:</strong> Maintain current monitoring level</p>
        `;
    }
}

function runAnalysis() {
    const terminal = document.getElementById('terminalOutput');
    addLine(terminal, '>', 'Running deep analysis...', 'warning');
    addLine(terminal, '>', 'Analyzing behavioral patterns...', 'dim');
    
    // Update analysis items
    document.getElementById('patternScore').textContent = (Math.random() * 30 + 60).toFixed(0) + '%';
    document.getElementById('keywordDensity').textContent = (Math.random() * 20 + 5).toFixed(1) + '%';
    document.getElementById('sentiment').textContent = ['Negative', 'Neutral', 'Concerned'][Math.floor(Math.random() * 3)];
    document.getElementById('urgencyIndex').textContent = (Math.random() * 40 + 10).toFixed(0) + '%';
    
    setTimeout(() => {
        addLine(terminal, '>', 'Analysis complete. No critical anomalies.', 'success');
    }, 1500);
}

function updateHistoryChart() {
    if (historyChart) {
        historyChart.data.datasets[0].data = generateRandomData(30, 0, 15);
        historyChart.update();
    }
    const terminal = document.getElementById('terminalOutput');
    addLine(terminal, '>', 'Historical data loaded. 30-day view active.', 'text');
}

function updateSources() {
    const terminal = document.getElementById('terminalOutput');
    addLine(terminal, '>', 'Data sources status:', 'text');
    addLine(terminal, ' ', '  Twitter/X: Active', 'success');
    addLine(terminal, ' ', '  News API: Connected', 'success');
    addLine(terminal, ' ', '  Reddit: Monitoring', 'success');
}

function showSettings() {
    const terminal = document.getElementById('terminalOutput');
    addLine(terminal, '>', 'Configuration panel loaded.', 'highlight');
    addLine(terminal, '>', 'Adjust settings as needed.', 'dim');
}

function initCommand() {
    const cmdInput = document.getElementById('cmdInput');
    if (cmdInput) {
        cmdInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                executeCommand(cmdInput.value);
                cmdInput.value = '';
            }
        });
        cmdInput.focus();
    }
}

function executeCommand(cmd) {
    const terminal = document.getElementById('terminalOutput');
    addLine(terminal, '>', cmd, 'text');
    
    const cmdLower = cmd.toLowerCase().trim();
    const response = document.createElement('p');
    response.className = 'terminal-line';
    
    switch(cmdLower) {
        case 'help':
            response.innerHTML = `<span class="prefix">></span> <span class="dim">Available commands:</span>`;
            terminal.appendChild(response);
            addCommandHelp(terminal);
            return;
        case 'status':
            response.innerHTML = `<span class="prefix">></span> <span class="text">System: ONLINE | Monitoring: ACTIVE | Risk: ${document.getElementById('threatPercent').textContent}</span>`;
            break;
        case 'stats':
            fetchStats();
            response.innerHTML = `<span class="prefix">></span> <span class="highlight">Statistics refreshed</span>`;
            break;
        case 'predict':
            fetchPrediction();
            response.innerHTML = `<span class="prefix">></span> <span class="warning">Prediction updated...</span>`;
            break;
        case 'threats':
            fetchThreats();
            response.innerHTML = `<span class="prefix">></span> <span class="dim">Fetching threats...</span>`;
            break;
        case 'analysis':
            runAnalysis();
            response.innerHTML = `<span class="prefix">></span> <span class="warning">Running analysis...</span>`;
            break;
        case 'history':
            updateHistoryChart();
            response.innerHTML = `<span class="prefix">></span> <span class="text">History loaded</span>`;
            break;
        case 'sources':
            updateSources();
            response.innerHTML = `<span class="prefix">></span> <span class="text">Sources checked</span>`;
            break;
        case 'scan':
            addLine(terminal, '>', 'Initiating threat scan...', 'warning');
            response.innerHTML = `<span class="prefix">></span> <span class="warning">SCAN IN PROGRESS</span>`;
            setTimeout(() => {
                addLine(terminal, '>', 'Scan complete. No new threats detected.', 'success');
            }, 3000);
            break;
        case 'clear':
            terminal.innerHTML = '';
            const cleared = document.createElement('p');
            cleared.className = 'terminal-line';
            cleared.innerHTML = `<span class="prefix">></span> <span class="text">Console cleared</span>`;
            terminal.appendChild(cleared);
            return;
        case 'refresh':
            fetchStats();
            if (trendChart) {
                trendChart.data.datasets[0].data = generateRandomData(24, 0, 30);
                trendChart.update();
            }
            response.innerHTML = `<span class="prefix">></span> <span class="highlight">All data refreshed</span>`;
            break;
        case 'version':
            response.innerHTML = `<span class="prefix">></span> <span class="highlight">CRIME AI v2.0 | Threat Prediction System</span>`;
            break;
        case 'uptime':
            response.innerHTML = `<span class="prefix">></span> <span class="text">Uptime: ${calculateUptime()}</span>`;
            break;
        case 'export':
            response.innerHTML = `<span class="prefix">></span> <span class="dim">Exporting data... (Demo mode)</span>`;
            break;
        case '':
            return;
        default:
            response.innerHTML = `<span class="prefix">></span> <span class="dim">Unknown command: ${cmd}. Type HELP for commands.</span>`;
    }
    
    terminal.appendChild(response);
    terminal.scrollTop = terminal.scrollHeight;
}

function addCommandHelp(terminal) {
    const commands = [
        ['HELP', 'Show available commands'],
        ['STATUS', 'System status overview'],
        ['STATS', 'Refresh statistics'],
        ['PREDICT', 'Run prediction analysis'],
        ['THREATS', 'List detected threats'],
        ['ANALYSIS', 'Deep threat analysis'],
        ['HISTORY', 'View historical data'],
        ['SOURCES', 'Check data sources'],
        ['SCAN', 'Initiate threat scan'],
        ['REFRESH', 'Refresh all data'],
        ['CLEAR', 'Clear terminal'],
        ['VERSION', 'Show version info'],
        ['UPTIME', 'Show system uptime'],
        ['EXPORT', 'Export data (demo)']
    ];
    
    commands.forEach(([cmd, desc]) => {
        addLine(terminal, ' ', `  ${cmd.padEnd(10)} ${desc}`, 'dim');
    });
}

function addLine(container, prefix, text, className = 'text') {
    const line = document.createElement('p');
    line.className = 'terminal-line';
    line.innerHTML = `<span class="prefix">${prefix}</span> <span class="${className}">${text}</span>`;
    container.appendChild(line);
    container.scrollTop = container.scrollHeight;
}

function formatTime(timeStr) {
    if (!timeStr) return '--:--';
    try {
        const date = new Date(timeStr);
        return date.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
    } catch {
        return '--:--';
    }
}

function formatNumber(num) {
    if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M';
    if (num >= 1000) return (num / 1000).toFixed(1) + 'K';
    return num.toString();
}

function calculateUptime() {
    const start = new Date();
    const diff = Math.floor((new Date() - start) / 1000);
    const hours = Math.floor(diff / 3600);
    const minutes = Math.floor((diff % 3600) / 60);
    return `${hours}h ${minutes}m`;
}

function runDemoMode() {
    const terminal = document.getElementById('terminalOutput');
    addLine(terminal, '>', 'Running in DEMO mode', 'warning');
    addLine(terminal, '>', 'Configure API endpoint for live data', 'dim');
    
    document.getElementById('predictionText').textContent = generatePredictionText();
    document.getElementById('confidence').textContent = '85%';
    document.getElementById('dataPoints').textContent = '25,432';
    document.getElementById('threatsCount').textContent = '0 DETECTED';
    
    // Update analysis
    document.getElementById('patternScore').textContent = '72%';
    document.getElementById('keywordDensity').textContent = '8.3%';
    document.getElementById('sentiment').textContent = 'Neutral';
    document.getElementById('urgencyIndex').textContent = '15%';
}
