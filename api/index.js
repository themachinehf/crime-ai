// Crime AI - API Server (v2.1 - Optimized)
// Simple in-memory cache
const cache = { stats: null, pred: null, threats: null };
const CACHE_TTL = 5000; // 5 seconds

const threatLog = [];

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

// Extended keywords from Python version (v2.1)
const VIOLENCE_KEYWORDS = {
    // Critical violence
    "kill": 95, "murder": 100, "shoot": 90, "stab": 85, "attack": 80,
    "massacre": 100, "terrorist": 100, "bomb": 100, "explosion": 90,
    "rape": 100, "assault": 85, "abuse": 75, "rampage": 95,
    // Threats
    "threaten": 75, "threat": 70, "revenge": 80, "deserve": 95, "wipe out": 90,
    "eliminate": 85, "end it all": 95, "going to kill": 100, "want them dead": 100,
    // Weapons
    "gun": 70, "knife": 65, "weapon": 75, "arsenal": 80, "firearm": 75,
    "rifle": 65, "ammunition": 70,
    // Self-harm
    "suicide": 90, "kill myself": 95, "end it all": 95, "want to die": 90,
    "no reason to live": 90, "give up": 80,
    // Cyber
    "hack": 50, "breach": 55, "ddos": 60, "malware": 55, "ransomware": 65,
    "phishing": 45, "cyberattack": 70, "exploit": 50,
    // Property crime
    "rob": 70, "steal": 65, "burglary": 60, "vandalism": 45, "fraud": 55,
    "extortion": 70, "embezzlement": 60, "scam": 45,
    // Harassment
    "harass": 60, "stalk": 70, "bullying": 55, "intimidate": 65,
    "doxxing": 55, "swatting": 75, "threats": 70,
    // 2026 emerging
    "deepfake": 55, "ai attack": 70, "bioweapon": 90, "mass poison": 95,
    "radiation": 85, "chemical weapon": 90, "mass shooting": 100,
    "vehicle ramming": 85, "gas attack": 90, "nerve gas": 100,
    // Chinese keywords
    "杀人": 95, "杀": 90, "杀掉": 95, "杀了他": 100,
    "炸弹": 90, "炸药": 95, "引爆": 90, "恐怖分子": 95,
    "枪": 60, "刀": 55, "武器": 65, "子弹": 60,
    "偷": 50, "抢": 65, "盗窃": 60, "诈骗": 55,
    "威胁": 70, "恐吓": 70, "骚扰": 60, "自杀": 90,
    "想死": 85, "报复": 75, "绑架": 85, "勒索": 70,
    "投毒": 85, "纵火": 85, "贩毒": 80, "毒品": 65,
    // New 2026
    "网暴": 65, "人肉搜索": 70, "开盒": 75,
    "电信诈骗": 65, "杀猪盘": 70, "ai诈骗": 65,
    "voice clone": 65, "deep voice": 65,
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

// Pattern detection (simplified from Python)
const PATTERNS = [
    { regex: /right now|tonight|today.*going/i, type: "urgency", score: 15 },
    { regex: /this weekend|tomorrow.*will/i, type: "urgency", score: 10 },
    { regex: /my (boss|colleague|teacher|neighbor|ex)/i, type: "targeted", score: 20 },
    { regex: /they.*deserve|will make them pay/i, type: "targeted", score: 25 },
    { regex: /going to buy|just ordered|already have/i, type: "planning", score: 25 },
    { regex: /drive.*(truck|car).*into|crowd.*people/i, type: "planning", score: 35 },
    { regex: /final.*warning|time.*running|counting down/i, type: "urgency", score: 20 },
    { regex: /no.*reason.*live|nothing.*matter/i, type: "emotional", score: 25 },
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

export default function handler(req, res) {
    const path = req.url;
    const method = req.method;
    
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
            version: "2.0",
            message: "Crime Prediction System Online"
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
                const analysis = analyzeText(text);
                
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
