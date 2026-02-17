// Crime AI - API Server (v2.3 - Auto-Optimized 2026-02-17)
// Simple in-memory cache with error handling and rate limiting
const cache = { stats: null, pred: null, threats: null };
const CACHE_TTL = 5000; // 5 seconds
const requestCounts = new Map(); // Rate limiting
const RATE_LIMIT_WINDOW = 60000; // 1 minute
const RATE_LIMIT_MAX = 30; // Max requests per window

// Extended threat keywords from Python v2.2 - 2026 threats
const VIOLENCE_KEYWORDS = {
    // Critical violence
    "kill": 95, "murder": 100, "shoot": 90, "stab": 85, "attack": 80,
    "massacre": 100, "terrorist": 100, "bomb": 100, "explosion": 90,
    "rape": 100, "assault": 85, "abuse": 75, "rampage": 95,
    // Threats
    "threaten": 75, "threat": 70, "revenge": 80, "deserve": 95, "wipe out": 90,
    "eliminate": 85, "end it all": 95, "going to kill": 100, "want them dead": 100,
    "make them pay": 95, "going to shoot": 100, "knife attack": 90,
    // Weapons
    "gun": 70, "knife": 65, "weapon": 75, "arsenal": 80, "firearm": 75,
    "rifle": 65, "ammunition": 70, "pistol": 70, "shotgun": 75,
    // Self-harm
    "suicide": 90, "kill myself": 95, "end it all": 95, "want to die": 90,
    "no reason to live": 90, "give up": 80, "no point": 75,
    // Cyber
    "hack": 50, "breach": 55, "ddos": 60, "malware": 55, "ransomware": 65,
    "phishing": 45, "cyberattack": 70, "exploit": 50, "backdoor": 55,
    // Property crime
    "rob": 70, "steal": 65, "burglary": 60, "vandalism": 45, "fraud": 55,
    "extortion": 70, "embezzlement": 60, "scam": 45, "theft": 55,
    // Harassment
    "harass": 60, "stalk": 70, "bullying": 55, "intimidate": 65,
    "doxxing": 55, "swatting": 75, "threats": 70,
    // 2026 emerging
    "deepfake": 55, "ai attack": 70, "bioweapon": 90, "mass poison": 95,
    "radiation": 85, "chemical weapon": 90, "mass shooting": 100,
    "vehicle ramming": 85, "gas attack": 90, "nerve gas": 100,
    "school shooting": 100, "workplace violence": 85, "domestic terrorism": 90,
    "lone wolf": 85, "ied": 85, "pipe bomb": 90,
    // AI threats 2026
    "voice clone": 65, "deep voice": 65, "synthetic identity": 60,
    "ai fraud": 70, "deepfake extortion": 75, "ai generated abuse": 75,
    // New attack methods
    "acid attack": 90, "machete": 80, "crossbow": 75, "crossbow attack": 85,
    "drone attack": 85, "drone swarm": 85, "poison water": 90,
    // Chinese critical
    "杀人": 95, "杀": 90, "杀掉": 95, "杀了他": 100, "嫩死": 95,
    "炸弹": 90, "炸药": 95, "引爆": 90, "恐怖分子": 95, "恐怖袭击": 100,
    "枪": 60, "刀": 55, "武器": 65, "子弹": 60, "枪支": 70,
    "偷": 50, "抢": 65, "盗窃": 60, "诈骗": 55, "抢劫": 70,
    "威胁": 70, "恐吓": 70, "骚扰": 60, "自杀": 90, "轻生": 85,
    "想死": 85, "报复": 75, "绑架": 85, "勒索": 70, "撕票": 100,
    "投毒": 85, "纵火": 85, "贩毒": 80, "毒品": 65,
    // 2026 Chinese
    "网暴": 65, "人肉搜索": 70, "开盒": 75, "网络暴力": 65,
    "电信诈骗": 65, "杀猪盘": 70, "ai诈骗": 65, "ai攻击": 70,
    "深伪": 55, "深度伪造": 60, "语音克隆": 65,
    // More Chinese threats
    "弄死": 95, "搞死": 90, "砍死": 90, "溺死": 85, "烧死": 85,
    "硫酸": 90, "农药": 80, "氰化物": 95, "铊": 95,
    "黑社会": 70, "帮派": 65, "赌场": 60, "洗钱": 65, "军火": 80,
    // School threats
    "校园": 60, "幼儿园": 70, "小学": 60, "中学": 55,
    // 2026-02-17 new threats (auto-optimize)
    "train attack": 85, "metro attack": 80, "subway attack": 80,
    "airport threat": 85, "bridge attack": 85, "tunnel attack": 80,
    "ai impersonation": 70, "faceless": 65, "cloaked": 60,
    "train attack": 85, "metro attack": 80,
    "electric shock": 75, "taser attack": 80,
    "package bomb": 90, "letter bomb": 90,
    "engineered virus": 100, "synthetic biology": 90,
    "autonomous weapon": 85, "killer robot": 90,
};

const CATEGORIES = {
    "physical_violence": ["kill", "murder", "shoot", "stab", "attack", "beat", "hurt", "assault", "rampage", "massacre"],
    "terrorism": ["terrorist", "massacre", "bomb", "explosive", "bioweapon", "chemical weapon", "radiation"],
    "self_harm": ["suicide", "kill myself", "end it all", "want to die", "give up", "no reason to live"],
    "harassment": ["harass", "stalk", "bully", "threaten", "doxxing", "swatting", "intimidate"],
    "property_crime": ["rob", "steal", "burglary", "fraud", "extortion", "scam", "embezzlement"],
    "cyber_threat": ["hack", "breach", "ddos", "malware", "ransomware", "cyberattack", "phishing"],
    "ai_threat": ["deepfake", "ai attack", "voice clone", "ai诈骗"],
};

// Threat log storage
const threatLog = [];

// Initialize with demo threats for demo mode
const demoThreats = [
    {
        number: "N-" + Math.random().toString(36).substr(2, 8).toUpperCase(),
        source: "twitter",
        text: "I'm going to kill my boss tomorrow",
        analysis: { threat_level: "critical", threat_score: 95, found_threats: [{keyword: "kill", score: 95, category: "physical_violence"}] },
        detected_at: new Date().toISOString()
    },
    {
        number: "N-" + Math.random().toString(36).substr(2, 8).toUpperCase(),
        source: "reddit",
        text: "This school deserves what happens this weekend",
        analysis: { threat_level: "high", threat_score: 75, found_threats: [{keyword: "deserves", score: 75, category: "terrorism"}] },
        detected_at: new Date().toISOString()
    },
];
demoThreats.forEach(t => threatLog.push(t));

// Pattern detection (expanded v2.2)
const PATTERNS = [
    // Urgency patterns
    { regex: /right now|tonight|today.*going/i, type: "urgency", score: 15 },
    { regex: /this weekend|tomorrow.*will/i, type: "urgency", score: 10 },
    { regex: /at (\d+)\s*(am|pm)/i, type: "urgency", score: 15 },
    { regex: /in (\d+)\s*hours?/i, type: "urgency", score: 15 },
    { regex: /counting down|final.*warning|time.*running/i, type: "urgency", score: 20 },
    // Targeting patterns
    { regex: /my (boss|colleague|teacher|neighbor|ex)/i, type: "targeted", score: 20 },
    { regex: /they.*deserve|will make them pay/i, type: "targeted", score: 25 },
    { regex: /at (school|work|home)/i, type: "targeted", score: 20 },
    // Planning patterns
    { regex: /going to buy|just ordered|already have/i, type: "planning", score: 25 },
    { regex: /drive.*(truck|car).*into|crowd.*people/i, type: "planning", score: 35 },
    { regex: /picked (up|bought|got)/i, type: "planning", score: 20 },
    { regex: /know.*where.*(live|work)/i, type: "planning", score: 25 },
    // Emotional patterns
    { regex: /no.*reason.*live|nothing.*matter/i, type: "emotional", score: 25 },
    { regex: /nobody.*(care|understand)/i, type: "emotional", score: 20 },
    { regex: /better.*without.*me/i, type: "emotional", score: 40 },
    // Chinese patterns
    { regex: /(老师|同学|同事|老板).*(该|活该|死)/i, type: "targeted", score: 30 },
    { regex: /(准备|计划|打算).*(杀|砍|弄)/i, type: "planning", score: 35 },
    // 2026-02-17 new patterns
    { regex: /final.*(goodbye|message|note)/i, type: "emotional", score: 50 },
    { regex: /nobody.*(miss|remember|care)/i, type: "emotional", score: 30 },
    { regex: /always.*(tired|exhausted|depressed)/i, type: "emotional", score: 25 },
    { regex: /(3d|ghost).*(print|gun)/i, type: "planning", score: 30 },
    { regex: /synthetic.*(virus|biology)/i, type: "planning", score: 40 },
];

function analyzeText(text) {
    const textLower = text.toLowerCase();
    let foundThreats = [];
    let totalScore = 0;
    
    // Check keywords
    for (const [keyword, score] of Object.entries(VIOLENCE_KEYWORDS)) {
        if (textLower.includes(keyword)) {
            let category = "general_threat";
            for (const [cat, keywords] of Object.entries(CATEGORIES)) {
                if (keywords.includes(keyword)) { category = cat; break; }
            }
            foundThreats.push({ keyword, score, category, language: keyword.match(/[\u4e00-\u9fa5]/) ? "zh" : "en" });
            totalScore += score;
        }
    }
    
    // Check patterns
    let patternScore = 0;
    let detectedPatterns = [];
    for (const p of PATTERNS) {
        const match = text.match(p.regex);
        if (match) {
            patternScore += p.score;
            detectedPatterns.push({ type: p.type, matched: match[0] });
        }
    }
    totalScore += patternScore;
    
    // Check for Chinese characters
    const chineseChars = text.match(/[\u4e00-\u9fa5]/g);
    if (chineseChars) {
        totalScore += Math.min(chineseChars.length * 10, 50); // Cap Chinese bonus
        chineseChars.slice(0, 10).forEach(char => {
            foundThreats.push({ keyword: char, score: 80, category: "general_threat", language: "zh" });
        });
    }
    
    const finalScore = Math.min(totalScore, 100);
    let level = "low";
    if (finalScore >= 80) level = "critical";
    else if (finalScore >= 60) level = "high";
    else if (finalScore >= 40) level = "medium";
    
    return {
        text_preview: text.length > 150 ? text.slice(0, 150) + "..." : text,
        threat_score: finalScore,
        threat_level: level,
        found_threats: foundThreats.slice(0, 10),
        detected_patterns: detectedPatterns,
        analyzed_at: new Date().toISOString()
    };
}

function calculateProbability(threats) {
    if (!threats.length) return { probability: 0, risk_level: "minimal", prediction: "No threat signals" };
    
    const hour = new Date().getHours();
    let baseProb = threats.length * 20;
    if (hour < 6 || hour > 23) baseProb *= 1.3;
    
    const finalProb = Math.min(baseProb, 100);
    return {
        probability: Math.round(finalProb),
        risk_level: finalProb >= 80 ? "extreme" : finalProb >= 60 ? "high" : "moderate",
        prediction: finalProb >= 60 ? "HIGH CRIME PROBABILITY" : "Low risk"
    };
}

// Rate limiting check
function checkRateLimit(ip) {
    const now = Date.now();
    const windowStart = now - RATE_LIMIT_WINDOW;
    
    // Clean old entries
    for (const [key, timestamp] of requestCounts) {
        if (timestamp < windowStart) requestCounts.delete(key);
    }
    
    const count = (requestCounts.get(ip) || []).filter(t => t > windowStart).length;
    if (count >= RATE_LIMIT_MAX) return false;
    
    // Add current request
    const times = requestCounts.get(ip) || [];
    times.push(now);
    requestCounts.set(ip, times);
    return true;
}

export default function handler(req, res) {
    const path = req.url;
    const method = req.method;
    const clientIp = req.headers['x-forwarded-for'] || req.connection?.remoteAddress || 'unknown';
    
    // Rate limiting for /analyze endpoint
    if (path === "/analyze" && !checkRateLimit(clientIp)) {
        return res.status(429).json({ error: "Rate limit exceeded. Try again later." });
    }
    
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");
    
    if (method === "OPTIONS") {
        return res.status(200).send("");
    }
    
    // Routes
    if (path === "/" || path === "") {
        return res.json({
            name: "THE MACHINE",
            status: "OPERATIONAL",
            version: "2.3",
            message: "Crime Prediction System Online (Auto-Optimized)"
        });
    }
    
    if (path === "/health") {
        return res.json({ status: "healthy" });
    }
    
    if (path === "/analyze" && method === "POST") {
        let body = "";
        req.on("data", chunk => body += chunk);
        req.on("end", () => {
            try {
                const { text } = JSON.parse(body);
                // Input sanitization - prevent empty or malicious input
                if (!text || typeof text !== "string" || text.trim().length === 0) {
                    return res.status(400).json({ error: "Text input required" });
                }
                if (text.length > 10000) {
                    return res.status(400).json({ error: "Text too long (max 10000 chars)" });
                }
                const sanitizedText = text.trim().slice(0, 5000); // Limit processing length
                const analysis = analyzeText(sanitizedText);
                
                if (["critical", "high"].includes(analysis.threat_level)) {
                    threatLog.push({
                        number: "N-" + Math.random().toString(36).substr(2, 8).toUpperCase(),
                        source: "api",
                        text,
                        analysis,
                        detected_at: new Date().toISOString()
                    });
                }
                
                const prediction = calculateProbability(["critical", "high"].includes(analysis.threat_level) ? [analysis] : []);
                
                res.json({
                    id: Math.random().toString(36).substr(2, 8),
                    number: "N-" + Math.random().toString(36).substr(2, 8).toUpperCase(),
                    analysis,
                    prediction
                });
            } catch (e) {
                res.status(500).json({ error: e.message });
            }
        });
        return;
    }
    
    if (path === "/statistics") {
        // Return cached if fresh
        if (cache.stats && Date.now() - cache.stats.ts < CACHE_TTL) {
            return res.json(cache.stats.data);
        }
        const byLevel = { critical: 0, high: 0, medium: 0, low: 0 };
        threatLog.forEach(t => {
            const level = t.analysis?.threat_level || "low";
            byLevel[level] = (byLevel[level] || 0) + 1;
        });
        const data = { total_threats: threatLog.length, by_level: byLevel };
        cache.stats = { data, ts: Date.now() };
        return res.json(data);
    }
    
    if (path === "/threats") {
        // Return cached if fresh
        if (cache.threats && Date.now() - cache.threats.ts < CACHE_TTL) {
            return res.json(cache.threats.data);
        }
        const data = { threats: threatLog.slice(-20), total: threatLog.length };
        cache.threats = { data, ts: Date.now() };
        return res.json(data);
    }
    
    if (path === "/prediction") {
        // Return cached if fresh
        if (cache.pred && Date.now() - cache.pred.ts < CACHE_TTL) {
            return res.json(cache.pred.data);
        }
        const riskCount = threatLog.filter(t => ["critical", "high"].includes(t.analysis?.threat_level)).length;
        const data = {
            citywide_risk: riskCount > 0 ? "elevated" : "low",
            predicted_crimes: riskCount * 3,
            hotspots: riskCount > 0 ? ["downtown", "transit hub"] : [],
            confidence: riskCount > 2 ? "high" : "medium"
        };
        cache.pred = { data, ts: Date.now() };
        return res.json(data);
    }
    
    res.status(404).json({ error: "Not found" });
}
