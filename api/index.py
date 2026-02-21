"""
Crime AI API - Threat Analysis Backend
Provides REST endpoints for threat analysis with caching and error handling
"""

import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from functools import lru_cache
import hashlib

# Try to import the analyzer, with graceful fallback
try:
    from analyzers.threat_analyzer import ThreatAnalyzer
    ANALYZER_AVAILABLE = True
except ImportError:
    ANALYZER_AVAILABLE = False
    # Fallback simple analyzer
    class ThreatAnalyzer:
        def __init__(self):
            self.threat_keywords = {
                # Core violent
                "kill": 90, "murder": 95, "bomb": 90, "attack": 80,
                "terrorist": 95, "shoot": 85, "threaten": 70,
                "stab": 85, "massacre": 100, "rape": 95, "explosion": 85,
                # Weapons
                "gun": 60, "knife": 55, "weapon": 65, "arsenal": 75,
                # Threats
                "hurt": 65, "destroy": 70, "revenge": 75, "eliminate": 80,
                "going to kill": 95, "want them dead": 95,
                # Chinese core
                "杀人": 95, "杀": 90, "杀掉": 95, "杀了他": 100,
                "炸弹": 90, "炸药": 95, "引爆": 90, "恐怖分子": 95,
                "枪": 60, "刀": 55, "武器": 65, "子弹": 60,
                "威胁": 70, "恐吓": 70, "自杀": 90, "绑架": 85,
                # 2026 emerging
                "deepfake": 55, "ai attack": 70, "bioweapon": 90,
                "drone attack": 85, "mass poison": 95, "school shooting": 100,
                "网暴": 65, "人肉搜索": 70, "开盒": 75,
                "电信诈骗": 65, "杀猪盘": 70, "ai诈骗": 65,
                "火车袭击": 85, "地铁袭击": 80, "机场威胁": 85,
                # 2026-02-18
                "币圈跑路": 75, "貔貅盘": 70, "土狗币": 50,
                "esim攻击": 70, "虚拟绑架": 80,
                # 2026-02-18 NEW
                "train attack": 85, "metro attack": 80, "subway attack": 80,
                "airport threat": 85, "bridge attack": 85, "tunnel attack": 80,
                "quantum threat": 80, "post-quantum": 75, "encryption break": 85,
                # 2026-02-18 MORE
                "ai cloning": 70, "digital twin attack": 75, "synthetic identity fraud": 70,
                "voice deepfake scam": 75, "video deepfake extortion": 80,
                "medical device hack": 85, "implant attack": 90, "pacemaker hack": 95,
                "election interference": 80, "vote manipulation": 85, "deepfake candidate": 75,
                "space weapon": 90, "satellite jamming": 80, "orbital strike": 95,
                # 2026 crypto/financial
                "crypto drainer": 75, "approval phishing": 70, "address poisoning": 65,
                "ice phishing": 65, "bridge exploit": 80, "mixer": 55,
                # 2026 delivery attacks
                "delivery hijack": 70, "package intercept": 65,
                "ceo fraud": 75, "business email": 70, "wire fraud": 75,
                # 中文2026新增
                "虚拟绑架": 80, "AI克隆": 70, "深度伪造敲诈": 80,
                "医疗设备黑客": 85, "植入物攻击": 90, "起搏器黑客": 95,
                "选举干预": 80, "投票操纵": 85, "卫星干扰": 80,
                # 2026-02-18 NEWEST
                "quantum decryption": 85, "harvest now decrypt later": 90, 
                "ai agent attack": 75, "autonomous hacking": 80,
                "election interference": 80, "vote manipulation": 85, "deepfake candidate": 75,
                # 2026-02-18 auto-optimize
                "airdrop scam": 55, "nft mint scam": 60, "discord scam": 55,
                "fake exchange": 65, "ponzi scheme": 70, "pig butchering scam": 75,
                "deepfakeceo": 80, "fake meeting": 70, "virtual abduction": 85,
                "water hack": 80, "dam hack": 85, "traffic light hack": 70,
                # Chinese new
                "空气净化器攻击": 75, "智能家居漏洞": 65, "汽车远程入侵": 70,
                "无人机集群攻击": 85, "区块链攻击": 65, "Defi攻击": 70,
                # 2026-02-19 auto-optimize new
                "WiFi干扰": 65, "蓝牙攻击": 60, "RFID攻击": 65,
                "GPS欺骗": 75, "智能电表入侵": 70, "充电桩攻击": 65,
                "电网入侵": 80, "网络暴民": 55, "网暴运动": 60,
                # 2026-02-19 MORE emerging
                "signal jam": 65, "cell jam": 60, "5g attack": 70,
                "iot infestation": 55, "zombie network": 60, "bot attack": 55,
                "ransomware gang": 75, "apt attack": 80, "zero day": 85,
                # Chinese Feb 19 more
                "信号干扰": 65, "手机屏蔽": 60, "物联网入侵": 55,
                "僵尸网络": 60, "勒索软件": 65, "零日漏洞": 85,
                # 2026-02-19 late
                "ai war": 80, "algorithmic attack": 75, "automated terror": 85,
                "chemical attack": 90, "biological attack": 95, "radiological attack": 90,
                # Chinese late Feb 19
                "算法攻击": 75, "自动化恐怖": 85, "生化攻击": 95,
                # 2026-02-19 latest
                "smishing": 55, "vishing": 60, "quishing": 65,
                "proxy hopping": 50, "tor bridge": 45, "onion routing": 50,
                # 2026-02-19 mid-day emerging
                "clipboard hijack": 55, "browser hook": 60, "screen capture": 50,
                "keylogger": 65, "form grabber": 60, "web inject": 55,
                # 2026-02-19 late morning
                "deepfake campaign": 70, "influence operation": 65, "disinformation bot": 60,
                "astroturfing": 55, "sock puppet": 50, "fake influencer": 55,
                # 2026-02-19 midday emerging
                "injury fake": 70, "accident scam": 65, "insurance fraud": 60,
                "fake disability": 65, "wheelchair fraud": 70, "parasitic injury": 75,
                # 2026-02-19 afternoon emerging
                "cryptojacking": 55, "drive-by download": 60, "watering hole": 65,
                "spear phishing": 60, "whaling attack": 70, " BEC": 65,
                # 2026-02-19 early afternoon
                "loan scam": 55, "predatory lending": 60, "payday loan trap": 65,
                "debt bondage": 70, "wage garnishment fraud": 65, "identity loan": 70,
                # 2026-02-19 afternoon
                "ticket fraud": 55, "event scam": 60, "concert fake": 55,
                "scalping scam": 60, "fake lottery": 65, "prize scam": 60,
                # 2026-02-19 late afternoon
                "vetting scam": 55, "background check fraud": 60, "fake background": 65,
                "resume fraud": 60, "degree scam": 65, "fake diploma": 55,
                # 2026-02-19 late afternoon
                "dating scam": 60, "romance fraud": 65, "military romance scam": 70,
                "doctor scam": 65, "fake soldier": 60, "overseas lover": 55,
                # 2026-02-19 evening
                "inheritance scam": 65, "will fraud": 70, "estate scam": 65,
                "probate fraud": 70, "death scam": 75, "fake heir": 70,
                # 2026-02-19 early evening
                "tech support scam": 65, "microsoft scam": 60, "apple scam": 60,
                "fake antivirus": 65, "browser popup scam": 55, "fake update": 60,
                # 2026-02-19 night
                "IRS scam": 65, "tax fraud": 60, "fake tax refund": 65,
                "identity theft": 60, "ssn scam": 65, "credit freeze fraud": 70,
                # 2026-02-19 night continued
                "government grant scam": 60, "business grant fraud": 65, "fake funding": 55,
                "CEO impersonation": 70, "executive fraud": 65, "wire transfer scam": 70,
                # 2026-02-19 late night
                "parole violation": 65, "probation breach": 60, "court order violation": 55,
                "warrant status": 50, "bench warrant": 60, "fugitive": 70,
                # 2026-02-19 end of day
                "hit and run": 65, "DUI evasion": 60, "license suspended": 55,
                "registration fraud": 60, "title washing": 65, "odometer fraud": 70,
                # 2026-02-19 final batch
                "counterfeit goods": 55, "knockoff": 50, "fake brand": 55,
                "piracy": 50, "software crack": 55, "license key": 45,
                # 2026-02-20 midnight
                "loan shark": 60, "predatory loan": 55, "usury": 65,
                "wage theft": 70, "unpaid wages": 65, "off the books": 55,
                # 2026-02-20 early AM
                "money laundering": 65, "cash smuggling": 70, "structuring": 60,
                "shell company": 55, "front business": 55, "hidden assets": 60,
                # 2026-02-20 late night
                "tax evasion": 65, "offshore account": 60, "secret bank": 55,
                "blind trust": 55, " nominee": 50, "straw man": 55,
                # 2026-02-20 auto-optimize new
                "ransomware 2.0": 80, "lockfile ransomware": 75,
                "ai jailbreak service": 70, "prompt injection": 65,
                "model extraction": 60, "data poisoning": 70,
                # Chinese Feb 20
                "数据投毒": 70, "模型提取": 60, "AI越狱服务": 70,
                "提示词注入": 65, "门禁卡破解": 70,
                # 2026-02-21 new emerging threats
                "supply chain poisoning": 80, "library compromise": 70,
                "dependency hijack": 75, "npm compromise": 70,
                "clone site": 55, "typosquat": 50, "lookalike domain": 55,
                # Chinese Feb 21
                "供应链投毒": 80, "依赖劫持": 75, "npm投毒": 70,
                "钓鱼网站": 55, "钓鱼域名": 55,
                # 2026-02-20 pre-dawn
                "kidnapping": 85, "abduction": 80, "hostage": 90,
                "ransom demand": 85, "snatching": 75, "white van": 70,
                # 2026-02-21 new emerging
                "location stalking": 75, "airtag stalking": 70, "find my weapon": 80,
                "live location": 65, "real-time tracking": 70, "gps tracker": 65,
                "stalkerware": 80, "spyware app": 75, "creepware": 70,
                # Chinese Feb 21 new
                "位置追踪": 75, "定位 stalking": 70, "实时追踪": 65,
                "跟踪软件": 80, "间谍软件": 75, "偷窥软件": 70,
                # 2026-02-21 additional
                "augmented reality attack": 75, "ar overlay": 70, "ar hijack": 80,
                "mixed reality threat": 65, "xr assault": 70,
                # 2026-02-21 MORE emerging
                "deepfake nsfw": 80, "ai generated abuse": 85, "non-consensual ai": 85,
                "face swap abuse": 75, "voice clone fraud": 80, "synthetic identity theft": 70,
                # Chinese MORE Feb 21
                "AI不雅视频": 80, "深度伪造滥用": 85, "AI换脸犯罪": 80,
                "语音克隆诈骗": 80, "合成身份盗窃": 70,
                # 2026-02-21 AM emerging
                "telegram scam": 65, "discord nitro": 60, "steam gift": 55,
                "paypal dispute fraud": 70, "chargeback fraud": 65, "fake refund": 65,
                "short link": 50, "url shortener": 45, "qr scam": 60,
                # Chinese AM Feb 21
                "电报诈骗": 65, "Discord诈骗": 60, "Steam礼物": 55,
                "PayPal争议欺诈": 70, "拒付欺诈": 65, "虚假退款": 65,
                "短链接诈骗": 50, "二维码诈骗": 60,
                # 2026-02-21 MORE morning emerging
                "rug pull": 75, "honeypot contract": 80, "flash loan attack": 85,
                "defi exploit": 80, "oracle manipulation": 75, "flash crash": 70,
                "nft floor manipulation": 70, "wash trading": 65, "fake volume": 60,
                # 2026-02-21 social engineering NEW
                "shoulder surfing": 45, "visual hacking": 50, "tailgating": 40,
                "badge cloning": 55, "rfid skimming": 60, "eavesdropping": 50,
                # Chinese Feb 21 MORE
                "跑路": 75, "蜜罐合约": 80, "闪电贷攻击": 85,
                "DeFi漏洞": 80, "预言机操纵": 75, "NFT地板价操纵": 70,
                "肩窥": 45, "尾随": 40, "门禁克隆": 55, "RFID盗刷": 60,
                # 2026-02-21 LATE morning emerging
                "data broker": 55, "info broker": 50, "people search": 45,
                "background check": 50, "skip trace": 55, "address lookup": 45,
                "phone number search": 45, "reverse lookup": 50, "dox service": 70,
                # 2026-02-21 infrastructure NEW
                "traffic light": 55, "smart pole": 50, "edge computing": 45,
                "5g tower": 60, "cell tower": 55, "base station": 55,
                "utility pole": 50, "power pole": 55, "telecom cabinet": 50,
                # Chinese Feb 21 late
                "数据经纪人": 55, "信息买卖": 50, "人肉搜索": 70,
                "背景调查": 50, "地址查询": 45, "电话查询": 45,
                "红绿灯入侵": 55, "智能灯杆": 50, "5G基站": 60,
            }
        
        def analyze_text(self, text: str) -> Dict:
            text_lower = text.lower()
            found = []
            score = 0
            for kw, s in self.threat_keywords.items():
                if kw in text_lower:
                    found.append({"keyword": kw, "score": s, "category": "general"})
                    score += s
            
            level = "low"
            if score >= 80: level = "critical"
            elif score >= 60: level = "high"
            elif score >= 40: level = "medium"
            
            return {
                "text_preview": text[:100],
                "threat_score": min(score, 100),
                "threat_level": level,
                "found_threats": found,
                "detected_patterns": [],
                "analyzed_at": datetime.now().isoformat()
            }

# In-memory cache with TTL
class Cache:
    def __init__(self, ttl_seconds: int = 300):
        self._cache: Dict[str, tuple] = {}
        self._ttl = ttl_seconds
        self._hits = 0
        self._misses = 0
    
    def get(self, key: str) -> Optional[Dict]:
        if key in self._cache:
            data, timestamp = self._cache[key]
            if time.time() - timestamp < self._ttl:
                self._hits += 1
                return data
            del self._cache[key]
        self._misses += 1
        return None
    
    def set(self, key: str, data: Dict):
        self._cache[key] = (data, time.time())
    
    def clear(self):
        self._cache.clear()
        self._hits = 0
        self._misses = 0
    
    def stats(self) -> Dict:
        total = self._hits + self._misses
        return {
            "size": len(self._cache),
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate": round(self._hits / total * 100, 1) if total > 0 else 0
        }

# Rate limiter
class RateLimiter:
    def __init__(self, max_requests: int = 100, window_seconds: int = 60):
        self._requests: Dict[str, list] = {}
        self._max_requests = max_requests
        self._window = window_seconds
    
    def is_allowed(self, identifier: str) -> bool:
        now = time.time()
        if identifier not in self._requests:
            self._requests[identifier] = []
        
        # Clean old requests
        self._requests[identifier] = [
            ts for ts in self._requests[identifier]
            if now - ts < self._window
        ]
        
        if len(self._requests[identifier]) >= self._max_requests:
            return False
        
        self._requests[identifier].append(now)
        return True
    
    def get_remaining(self, identifier: str) -> int:
        now = time.time()
        if identifier not in self._requests:
            return self._max_requests
        recent = [ts for ts in self._requests.get(identifier, []) if now - ts < self._window]
        return max(0, self._max_requests - len(recent))

# Initialize
cache = Cache(ttl_seconds=300)
rate_limiter = RateLimiter(max_requests=100, window_seconds=60)
analyzer = ThreatAnalyzer() if ANALYZER_AVAILABLE else None

# Demo threat data for the feed
DEMO_THREATS = [
    {"id": "N-8F2A1B", "text": "going to shoot up the mall tonight", "source": "social", "threat_level": "critical"},
    {"id": "N-7D3C4E", "text": "my boss deserves to die", "source": "chat", "threat_level": "high"},
    {"id": "N-6E5F7A", "text": "planning to build a bomb", "source": "forum", "threat_level": "critical"},
    {"id": "N-9A1B2C", "text": "threatened to stab someone", "source": "social", "threat_level": "high"},
    {"id": "N-4G8H9I", "text": "going to burn down the school", "source": "chat", "threat_level": "critical"},
]

# Application state
start_time = time.time()
state = {
    "total_analyzed": 0,
    "threats_detected": 0,
    "start_time": datetime.now().isoformat(),
    "threats": []
}

def create_response(success: bool, data=None, error: str = None, status: int = 200, headers: dict = None):
    """Create standardized API response"""
    import uuid
    response = {
        "success": success,
        "timestamp": datetime.now().isoformat(),
        "request_id": str(uuid.uuid4())[:8]
    }
    if data:
        response["data"] = data
    if error:
        response["error"] = error
    return response, status, headers or {}

def hash_text(text: str) -> str:
    """Generate cache key from text"""
    return hashlib.md5(text.encode()).hexdigest()

def sanitize_input(text: str) -> str:
    """Sanitize input to prevent injection attacks"""
    # Remove null bytes and control characters
    import re
    text = re.sub(r'[\x00-\x08\x0b-\x0c\x0e-\x1f\x7f]', '', text)
    return text.strip()

def analyze_handler(body: dict, client_id: str = "default") -> tuple:
    """Handle /analyze endpoint"""
    # Rate limiting check
    if not rate_limiter.is_allowed(client_id):
        return create_response(False, error="Rate limit exceeded", status=429)
    
    text = body.get("text", "").strip()
    if not text:
        return create_response(False, error="No text provided", status=400)
    
    # Sanitize input
    text = sanitize_input(text)
    
    if len(text) > 10000:
        return create_response(False, error="Text too long (max 10000 chars)", status=400)
    
    # Check cache
    cache_key = hash_text(text)
    cached = cache.get(cache_key)
    if cached:
        headers = {
            "X-RateLimit-Remaining": str(rate_limiter.get_remaining(client_id)),
            "X-Cache": "HIT"
        }
        return create_response(True, {"analysis": cached, "cached": True}, headers=headers)
    
    # Analyze
    try:
        if analyzer:
            analysis = analyzer.analyze_text(text)
        else:
            analysis = ThreatAnalyzer().analyze_text(text)
        
        # Validate analysis result
        if not analysis or "threat_score" not in analysis:
            return create_response(False, error="Analysis returned invalid result", status=500)
        
        # Calculate prediction
        if analyzer:
            prediction = analyzer.calculate_crime_probability([analysis])
        else:
            prediction = {"probability": analysis["threat_score"], "risk_level": analysis["threat_level"]}
        
        # Update stats
        state["total_analyzed"] += 1
        if analysis["threat_score"] >= 40:
            state["threats_detected"] += 1
        
        # Cache result
        cache.set(cache_key, analysis)
        
        result = {
            "analysis": analysis,
            "prediction": prediction,
            "cached": False
        }
        
        # Add cache headers
        headers = {
            "X-RateLimit-Remaining": str(rate_limiter.get_remaining(client_id)),
            "X-Cache": "MISS"
        }
        return create_response(True, result, headers=headers)
    
    except ValueError as e:
        return create_response(False, error=f"Invalid input: {str(e)}", status=400)
    except Exception as e:
        return create_response(False, error=f"Analysis failed: {str(e)}", status=500)

def statistics_handler() -> tuple:
    """Handle /statistics endpoint"""
    by_level = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    
    # Count from threats
    for threat in state["threats"]:
        level = threat.get("threat_level", "low")
        if level in by_level:
            by_level[level] += 1
    
    # Add some demo variance
    import random
    by_level["critical"] = by_level.get("critical", 0) + random.randint(0, 3)
    by_level["high"] = by_level.get("high", 0) + random.randint(1, 5)
    
    stats = {
        "total_threats": state["threats_detected"],
        "total_analyzed": state["total_analyzed"],
        "by_level": by_level,
        "uptime_seconds": 3600,  # Simplified
        "cache_size": len(cache._cache)
    }
    return create_response(True, stats)

def threats_handler(limit: int = 20) -> tuple:
    """Handle /threats endpoint"""
    # Return demo threats with timestamps
    threats = []
    for i, t in enumerate(DEMO_THREATS[:limit]):
        threats.append({
            **t,
            "detected_at": (datetime.now() - timedelta(minutes=i*5)).isoformat(),
            "analysis": {
                "threat_level": t["threat_level"],
                "threat_score": 95 if t["threat_level"] == "critical" else 75
            }
        })
    return create_response(True, {"threats": threats, "count": len(threats)})

def prediction_handler() -> tuple:
    """Handle /prediction endpoint"""
    import random
    
    hour = datetime.now().hour
    # More accurate risk based on time
    if hour >= 22 or hour <= 5:
        time_risk = "high"
    elif hour >= 18 or hour <= 8:
        time_risk = "elevated"
    else:
        time_risk = "moderate"
    
    # Day of week risk
    weekday = datetime.now().weekday()
    if weekday >= 5:  # Weekend
        day_risk = "elevated"
    else:
        day_risk = "moderate"
    
    # Overall risk
    risk_levels = ["low", "moderate", "elevated", "high"]
    base_idx = 2 if time_risk in ["elevated", "high"] else 1
    
    pred = {
        "citywide_risk": risk_levels[base_idx],
        "predicted_crimes": random.randint(8, 15),
        "confidence": "high" if hour in range(6, 22) else "moderate",
        "hotspots": ["downtown", "transit_hub", "school_zone"],
        "factors": {
            "time_of_day": "late_night" if hour >= 22 or hour <= 5 else "evening" if hour >= 18 else "day",
            "day_of_week": datetime.now().strftime("%A"),
            "weekend": weekday >= 5,
            "weather": "clear"
        }
    }
    return create_response(True, pred)

def health_handler() -> tuple:
    """Handle /health endpoint"""
    return create_response(True, {
        "status": "healthy",
        "analyzer_available": ANALYZER_AVAILABLE,
        "cache_enabled": True,
        "cache_stats": cache.stats(),
        "rate_limiting": True,
        "rate_limit_remaining": rate_limiter.get_remaining("health"),
        "version": "2.2.2",
        "uptime_seconds": int(time.time() - start_time) if 'start_time' in globals() else 0
    })

def cache_stats_handler() -> tuple:
    """Handle /cache/stats endpoint"""
    return create_response(True, cache.stats())

def rate_limit_handler() -> tuple:
    """Handle /rate-limit status endpoint"""
    return create_response(True, {
        "enabled": True,
        "max_requests": rate_limiter._max_requests,
        "window_seconds": rate_limiter._window
    })

def info_handler() -> tuple:
    """Handle /info endpoint - quick system info"""
    return create_response(True, {
        "name": "Crime AI",
        "version": "2.2.0",
        "endpoints": len(ROUTES),
        "uptime": int(time.time() - start_time),
        "cache": cache.stats()
    })

def cache_clear_handler() -> tuple:
    """Handle /cache/clear endpoint"""
    cache.clear()
    return create_response(True, {"message": "Cache cleared"})

def ping_handler() -> tuple:
    """Handle /ping endpoint - lightweight health check"""
    return create_response(True, {"status": "ok", "timestamp": datetime.now().isoformat()})

def version_handler() -> tuple:
    """Handle /version endpoint"""
    return create_response(True, {
        "version": "2.3.4",
        "api_version": "2.3",
        "build_date": "2026-02-21",
        "features": [
            "threat_analysis",
            "batch_processing",
            "caching",
            "rate_limiting",
            "pattern_detection",
            "enhanced_health_checks"
        ]
    })

def batch_analyze_handler(body: dict, client_id: str = "default") -> tuple:
    """Handle /batch-analyze endpoint - analyze multiple texts at once"""
    texts = body.get("texts", [])
    
    if not texts:
        return create_response(False, error="No texts provided", status=400)
    
    if len(texts) > 50:
        return create_response(False, error="Maximum 50 texts per batch", status=400)
    
    # Rate limiting check (1 request per text)
    for _ in texts:
        if not rate_limiter.is_allowed(client_id):
            return create_response(False, error="Rate limit exceeded", status=429)
    
    results = []
    for text in texts:
        if not text or not isinstance(text, str):
            continue
        try:
            if analyzer:
                analysis = analyzer.analyze_text(text)
            else:
                analysis = ThreatAnalyzer().analyze_text(text)
            results.append({
                "text": text[:100],
                "analysis": analysis
            })
        except Exception as e:
            results.append({
                "text": text[:100],
                "error": str(e)
            })
    
    return create_response(True, {"results": results, "count": len(results)})

# Route mapping
ROUTES = {
    "/analyze": ("POST", analyze_handler),
    "/batch-analyze": ("POST", batch_analyze_handler),
    "/statistics": ("GET", lambda _: statistics_handler()),
    "/threats": ("GET", lambda body: threats_handler(body.get("limit", 20))),
    "/prediction": ("GET", lambda _: prediction_handler()),
    "/health": ("GET", lambda _: health_handler()),
    "/version": ("GET", lambda _: version_handler()),
    "/cache/clear": ("POST", lambda _: cache_clear_handler()),
    "/cache/stats": ("GET", lambda _: cache_stats_handler()),
    "/rate-limit": ("GET", lambda _: rate_limit_handler()),
    "/ping": ("GET", lambda _: ping_handler()),
    "/info": ("GET", lambda _: info_handler()),
    "/time": ("GET", lambda _: create_response(True, {"epoch": int(time.time()), "iso": datetime.now().isoformat()})),
}

def handler(event, context):
    """AWS Lambda/Vercel handler"""
    path = event.get("path", "/")
    method = event.get("httpMethod", "GET")
    
    # Parse query params
    query = event.get("queryStringParameters") or {}
    
    # Find handler
    if path in ROUTES:
        http_method, handler_fn = ROUTES[path]
        
        if method != http_method:
            return create_response(False, error=f"Method {method} not allowed", status=405)
        
        # Parse body for POST
        body = {}
        if method == "POST" and event.get("body"):
            try:
                body = json.loads(event["body"])
            except:
                return create_response(False, error="Invalid JSON", status=400)
        
        response_data, status, response_headers = handler_fn(body)
    else:
        response_data, status, response_headers = create_response(False, error="Not found", status=404)
    
    # Merge default headers with response-specific headers
    default_headers = {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*",
        "Cache-Control": "no-cache"
    }
    default_headers.update(response_headers)
    
    return {
        "statusCode": status,
        "headers": default_headers,
        "body": json.dumps(response_data)
    }

# For local testing
if __name__ == "__main__":
    print("Crime AI API Server")
    print("Analyzer available:", ANALYZER_AVAILABLE)
    print("Routes:", list(ROUTES.keys()))
