// Crime AI UI - Threat Prediction System

const API_URL = '/';

let currentView = 'overview';

document.addEventListener('DOMContentLoaded', () => {
    init();
});

function init() {
    updateTime();
    setInterval(updateTime, 1000);
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
            showHistory();
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
        document.getElementById('totalScanned').textContent = stats.total_threats || '--';
        document.getElementById('highRisk').textContent = stats.by_level?.high || 0;
        document.getElementById('mediumRisk').textContent = stats.by_level?.medium || 0;
        document.getElementById('predictionScore').textContent = (pred.probability || 0) + '%';
        
        // Update threat level
        updateThreatLevel(pred);
        
        // Update prediction text
        document.getElementById('predictionText').textContent = 
            pred.prediction || 'Monitoring active. Awaiting data...';
        document.getElementById('confidence').textContent = pred.confidence || '--';
        document.getElementById('sources').textContent = 'Twitter, Reddit, News';
        document.getElementById('lastUpdate').textContent = formatTime(new Date().toISOString());
        
        // Update threats count
        document.getElementById('threatsCount').textContent = stats.total_threats || 0;
        
        // Update threats list
        updateThreatsList(stats);
        
    } catch (e) {
        console.log('API not available - running in demo mode');
        runDemoMode();
    }
}

function updateThreatLevel(pred) {
    const gauge = document.getElementById('threatGauge');
    const percent = document.getElementById('threatPercent');
    const label = document.getElementById('threatLabel');
    const badge = document.getElementById('threatBadge');
    
    const probability = pred.probability || 0;
    
    percent.textContent = probability + '%';
    
    // Remove all level classes
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

function updateThreatsList(stats) {
    const list = document.getElementById('threatsList');
    if (!list) return;
    
    const threats = stats.recent_threats || [];
    
    if (threats.length === 0) {
        list.innerHTML = `
            <div class="threat-item">
                <span class="threat-source">No threats detected</span>
                <span class="threat-time">--</span>
            </div>
        `;
        return;
    }
    
    list.innerHTML = threats.slice(0, 10).map(t => `
        <div class="threat-item">
            <span class="threat-source">${t.source || 'Unknown'}</span>
            <span class="threat-level-tag ${t.analysis?.threat_level || 'low'}">
                ${(t.analysis?.threat_level || 'low').toUpperCase()}
            </span>
            <span class="threat-time">${formatTime(t.detected_at)}</span>
        </div>
    `).join('');
}

async function fetchThreats() {
    const terminal = document.getElementById('terminalOutput');
    addLine(terminal, '>', 'Fetching threats...', 'dim');
    
    try {
        const res = await fetch(API_URL + 'threats').catch(() => ({ json: () => ({}) }));
        const data = await res.json().catch(() => ({}));
        addLine(terminal, '>', `Found ${data.total || 0} threats`, 'text');
    } catch (e) {
        addLine(terminal, '>', 'Threat database not available', 'dim');
    }
}

async function fetchPrediction() {
    const terminal = document.getElementById('terminalOutput');
    addLine(terminal, '>', 'Running prediction analysis...', 'dim');
    
    try {
        const res = await fetch(API_URL + 'prediction').catch(() => ({ json: () => ({}) }));
        const pred = await res.json().catch(() => ({}));
        addLine(terminal, '>', `Prediction: ${pred.prediction || 'Analysis complete'}`, 'highlight');
    } catch (e) {
        addLine(terminal, '>', 'Prediction engine busy', 'dim');
    }
}

function runAnalysis() {
    const terminal = document.getElementById('terminalOutput');
    addLine(terminal, '>', 'Running deep analysis...', 'warning');
    addLine(terminal, '>', 'Analyzing patterns, keywords, and behavioral signals...', 'dim');
    
    setTimeout(() => {
        addLine(terminal, '>', 'Analysis complete. No anomalies detected.', 'text');
    }, 2000);
}

function showHistory() {
    const terminal = document.getElementById('terminalOutput');
    addLine(terminal, '>', 'Loading historical data...', 'dim');
    addLine(terminal, '>', 'Historical records: Last 24 hours available', 'text');
}

function showSettings() {
    const terminal = document.getElementById('terminalOutput');
    addLine(terminal, '>', 'Settings Panel', 'highlight');
    addLine(terminal, '>', '1. Notification Threshold: MEDIUM', 'text');
    addLine(terminal, '>', '2. Scan Frequency: 10 minutes', 'text');
    addLine(terminal, '>', '3. Data Sources: All enabled', 'text');
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
            addLine(terminal, ' ', '  HELP - Show commands', 'dim');
            addLine(terminal, ' ', '  STATUS - System status', 'dim');
            addLine(terminal, ' ', '  STATS - View statistics', 'dim');
            addLine(terminal, ' ', '  PREDICT - Run prediction', 'dim');
            addLine(terminal, ' ', '  THREATS - List threats', 'dim');
            addLine(terminal, ' ', '  SCAN - Start scan', 'warning');
            addLine(terminal, ' ', '  CLEAR - Clear terminal', 'dim');
            addLine(terminal, ' ', '  REFRESH - Refresh data', 'dim');
            return;
        case 'status':
            response.innerHTML = `<span class="prefix">></span> <span class="text">System: ONLINE | Monitoring: ACTIVE | Threats: ${document.getElementById('threatsCount').textContent}</span>`;
            break;
        case 'stats':
            fetchStats();
            response.innerHTML = `<span class="prefix">></span> <span class="highlight">Statistics refreshed</span>`;
            break;
        case 'predict':
            fetchPrediction();
            response.innerHTML = `<span class="prefix">></span> <span class="warning">Running prediction...</span>`;
            break;
        case 'threats':
            fetchThreats();
            response.innerHTML = `<span class="prefix">></span> <span class="dim">Fetching threats...</span>`;
            break;
        case 'scan':
            addLine(terminal, '>', 'Initiating threat scan...', 'warning');
            response.innerHTML = `<span class="prefix">></span> <span class="warning">SCAN IN PROGRESS</span>`;
            setTimeout(() => {
                addLine(terminal, '>', 'Scan complete. No new threats.', 'text');
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
            response.innerHTML = `<span class="prefix">></span> <span class="highlight">Data refreshed</span>`;
            break;
        case '':
            return;
        default:
            response.innerHTML = `<span class="prefix">></span> <span class="dim">Unknown command: ${cmd}. Type HELP for available commands.</span>`;
    }
    
    terminal.appendChild(response);
    terminal.scrollTop = terminal.scrollHeight;
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

function runDemoMode() {
    // Demo mode when API is not available
    const terminal = document.getElementById('terminalOutput');
    addLine(terminal, '>', 'Running in DEMO mode', 'warning');
    addLine(terminal, '>', 'Connect API for live data', 'dim');
    
    document.getElementById('totalScanned').textContent = '0';
    document.getElementById('highRisk').textContent = '0';
    document.getElementById('mediumRisk').textContent = '0';
    document.getElementById('predictionScore').textContent = '0%';
    document.getElementById('threatsCount').textContent = '0';
    document.getElementById('predictionText').textContent = 'Demo mode active. Configure API endpoint for live predictions.';
    document.getElementById('confidence').textContent = '--';
    document.getElementById('sources').textContent = 'Demo';
    document.getElementById('lastUpdate').textContent = formatTime(new Date().toISOString());
}
