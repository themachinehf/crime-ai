// Crime AI UI - THE MACHINE Style

const API_URL = '/';

document.addEventListener('DOMContentLoaded', () => {
    init();
});

function init() {
    updateTime();
    setInterval(updateTime, 1000);
    fetchStats();
    
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

function updateTime() {
    const timeEl = document.getElementById('systemTime');
    if (timeEl) {
        const now = new Date();
        const timeStr = now.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
        timeEl.textContent = timeStr + ' EST';
    }
}

async function fetchStats() {
    try {
        // Fetch from API
        const [statsRes, predRes] = await Promise.all([
            fetch(API_URL + 'statistics').catch(() => ({ json: () => ({}) })),
            fetch(API_URL + 'prediction').catch(() => ({ json: () => ({}) }))
        ]);
        
        const stats = await statsRes.json().catch(() => ({}));
        const pred = await predRes.json().catch(() => ({}));
        
        // Update UI
        document.getElementById('threatsToday').textContent = stats.total_threats || 0;
        document.getElementById('totalScanned').textContent = '--';
        document.getElementById('highRisk').textContent = stats.by_level?.high || 0;
        document.getElementById('mediumRisk').textContent = stats.by_level?.medium || 0;
        document.getElementById('predictionScore').textContent = (pred.probability || 0) + '%';
        
        // Update city risk
        const cityRisk = document.getElementById('cityRisk');
        const predDetails = document.getElementById('predictionDetails');
        if (cityRisk && predDetails) {
            const risk = pred.citywide_risk || 'minimal';
            cityRisk.textContent = risk.toUpperCase();
            cityRisk.className = 'prediction-badge ' + (risk === 'elevated' ? 'high' : 'low');
            predDetails.textContent = pred.prediction || 'Monitoring active.';
        }
        
        // Update threats list
        updateThreatsList(stats);
        
    } catch (e) {
        console.log('API not available');
    }
}

function updateThreatsList(stats) {
    const list = document.getElementById('threatsList');
    if (!list) return;
    
    const threats = stats.recent_threats || [];
    
    if (threats.length === 0) {
        list.innerHTML = '<div class="threat-item"><span class="threat-source">No threats detected</span><span class="threat-time">--</span></div>';
        return;
    }
    
    list.innerHTML = threats.slice(0, 5).map(t => `
        <div class="threat-item">
            <span class="threat-source">${t.source || 'unknown'}</span>
            <span class="threat-level">${t.analysis?.threat_level?.toUpperCase() || 'LOW'}</span>
            <span class="threat-time">${formatTime(t.detected_at)}</span>
        </div>
    `).join('');
}

function formatTime(timeStr) {
    if (!timeStr) return '--';
    try {
        const date = new Date(timeStr);
        return date.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
    } catch {
        return '--';
    }
}

function executeCommand(cmd) {
    const log = document.getElementById('activityLog');
    const cmdLine = document.createElement('p');
    cmdLine.innerHTML = `<span class="prompt">></span> ${cmd}`;
    log.appendChild(cmdLine);
    
    const cmdLower = cmd.toLowerCase().trim();
    const response = document.createElement('p');
    response.style.marginLeft = '20px';
    
    switch(cmdLower) {
        case 'help':
            response.innerHTML = `<span class="dim">Commands: HELP, STATUS, STATS, PREDICT, THREATS, CLEAR, REFRESH</span>`;
            break;
        case 'status':
            response.innerHTML = `<span class="text">System operational. Monitoring active.</span>`;
            break;
        case 'stats':
            fetchStats();
            response.innerHTML = `<span class="text">Statistics refreshed.</span>`;
            break;
        case 'predict':
            fetchStats();
            response.innerHTML = `<span class="text">Prediction updated.</span>`;
            break;
        case 'threats':
            response.innerHTML = `<span class="text">Check recent threats below.</span>`;
            break;
        case 'clear':
            log.innerHTML = '';
            const cleared = document.createElement('p');
            cleared.innerHTML = `<span class="prompt">></span> <span class="text">Console cleared</span>`;
            log.appendChild(cleared);
            return;
        case 'refresh':
            fetchStats();
            response.innerHTML = `<span class="text">Data refreshed.</span>`;
            break;
        case '':
            return;
        default:
            response.innerHTML = `<span class="dim">Unknown command: ${cmd}</span>`;
    }
    
    log.appendChild(response);
    log.scrollTop = log.scrollHeight;
}

// Auto refresh every 30 seconds
setInterval(fetchStats, 30000);
