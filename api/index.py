"""
Crime AI - Vercel Serverless API
Optimized: 2026-02-17
"""

import json
from datetime import datetime, timedelta
import uuid
import hashlib

# Simple in-memory cache
_cache = {}
_CACHE_TTL = 60  # seconds

# Threat Analyzer (simplified for serverless)
class ThreatAnalyzer:
    VIOLENCE_KEYWORDS = {
        # Physical violence
        "kill": 90, "murder": 95, "shoot": 85, "attack": 80,
        "massacre": 100, "terrorist": 95, "bomb": 90, "explosion": 85,
        "rape": 95, "stab": 85, "assault": 75, "abuse": 70,
        
        # Threats & intimidation
        "threaten": 70, "hurt": 65, "destroy": 70, "revenge": 75,
        "eliminate": 80, "wipe out": 85, "end it all": 90,
        
        # Weapons
        "gun": 60, "knife": 55, "weapon": 65, "arsenal": 75,
        "ammunition": 65, "firearm": 70, "rifle": 60,
        
        # Cyber threats
        "hack": 50, "breach": 55, "ddos": 60, "malware": 55,
        "ransomware": 65, "phishing": 45, "cyberattack": 70,
        
        # Property crime
        "steal": 50, "rob": 65, "burglary": 60, "vandalism": 45,
        "fraud": 55, "scam": 45, "extortion": 70,
    }
    
    THREAT_CATEGORIES = {
        "physical_violence": ["kill", "murder", "shoot", "attack", "stab", "assault", "abuse"],
        "terrorism": ["terrorist", "bomb", "explosion", "massacre"],
        "self_harm": ["suicide", "want to die", "end it all"],
        "harassment": ["threaten", "harass", "stalk", "bullying"],
        "property_crime": ["steal", "rob", "burglary", "vandalism", "fraud", "extortion"],
        "cyber_threat": ["hack", "breach", "ddos", "malware", "ransomware", "cyberattack"],
    }
    
    def analyze_text(self, text):
        text_lower = text.lower()
        found_threats = []
        total_score = 0
        
        for keyword, score in self.VIOLENCE_KEYWORDS.items():
            if keyword in text_lower:
                found_threats.append({
                    "keyword": keyword,
                    "score": score,
                    "category": "general_threat"
                })
                total_score += score
        
        final_score = min(total_score, 100)
        
        if final_score >= 80:
            level = "critical"
        elif final_score >= 60:
            level = "high"
        elif final_score >= 40:
            level = "medium"
        else:
            level = "low"
        
        return {
            "text_preview": text[:100] + "..." if len(text) > 100 else text,
            "threat_score": final_score,
            "threat_level": level,
            "found_threats": found_threats,
            "detected_patterns": [],
            "analyzed_at": datetime.now().isoformat()
        }
    
    def calculate_crime_probability(self, threats, location=None):
        if not threats:
            return {"probability": 0, "risk_level": "minimal", "prediction": "No threat signals detected"}
        
        base_prob = len(threats) * 15 + sum(t.get("threat_score", 0) for t in threats) * 0.1
        final_prob = min(base_prob, 100)
        
        return {
            "probability": round(final_prob, 1),
            "risk_level": "extreme" if final_prob >= 80 else "high" if final_prob >= 60 else "moderate",
            "prediction": "High crime probability" if final_prob >= 60 else "Low risk",
            "threat_count": len(threats),
            "analyzed_at": datetime.now().isoformat()
        }

analyzer = ThreatAnalyzer()
threat_log = []

def handler(request):
    path = request.path
    method = request.method
    
    # CORS headers
    headers = {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type",
    }
    
    if method == "OPTIONS":
        return {"statusCode": 200, "headers": headers, "body": ""}
    
    # Routes
    if path == "/" or path == "":
        return {
            "headers": {"Content-Type": "application/json", **headers},
            "body": json.dumps({
                "name": "Crime AI",
                "status": "operational",
                "version": "1.0.0",
                "message": "Threat Prediction System Online"
            })
        }
    
    if path == "/health":
        return {"headers": {"Content-Type": "application/json", **headers}, "body": json.dumps({"status": "healthy"})}
    
    if path == "/analyze" and method == "POST":
        try:
            body = json.loads(request.body)
            text = body.get("text", "")
            location = body.get("location")
            
            analysis = analyzer.analyze_text(text)
            threats = [analysis] if analysis["threat_level"] in ["high", "critical"] else []
            prediction = analyzer.calculate_crime_probability(threats, location)
            
            if analysis["threat_level"] in ["high", "critical"]:
                threat_log.append({
                    "source": "api",
                    "text": text,
                    "analysis": analysis,
                    "detected_at": datetime.now().isoformat()
                })
            
            return {
                "headers": {"Content-Type": "application/json", **headers},
                "body": json.dumps({
                    "id": str(uuid.uuid4())[:8],
                    "analysis": analysis,
                    "prediction": prediction
                })
            }
        except Exception as e:
            return {"statusCode": 500, "headers": {"Content-Type": "application/json", **headers}, "body": json.dumps({"error": str(e)})}
    
    if path == "/statistics":
        by_level = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        by_source = {"api": len(threat_log)}
        
        for t in threat_log:
            level = t["analysis"]["threat_level"]
            by_level[level] = by_level.get(level, 0) + 1
        
        return {
            "headers": {"Content-Type": "application/json", **headers},
            "body": json.dumps({
                "total_threats": len(threat_log),
                "by_level": by_level,
                "by_source": by_source,
                "last_updated": datetime.now().isoformat()
            })
        }
    
    if path == "/threats":
        limit = 10
        return {
            "headers": {"Content-Type": "application/json", **headers},
            "body": json.dumps({
                "threats": threat_log[-limit:],
                "total": len(threat_log)
            })
        }
    
    if path == "/prediction":
        high_risk = {"critical": 0, "high": 0}
        for t in threat_log:
            if t["analysis"]["threat_level"] in ["high", "critical"]:
                high_risk[t["analysis"]["threat_level"]] += 1
        
        # Check cache first
        cache_key = f"pred_{len(threat_log)}"
        if cache_key in _cache:
            cached_data, cached_time = _cache[cache_key]
            if (datetime.now() - cached_time).seconds < _CACHE_TTL:
                return {
                    "headers": {"Content-Type": "application/json", **headers},
                    "body": json.dumps(cached_data)
                }
        
        result = {
            "citywide_risk": "elevated" if high_risk["high"] + high_risk["critical"] > 0 else "low",
            "predicted_crimes": (high_risk["high"] + high_risk["critical"]) * 2,
            "hotspots": ["api"],
            "confidence": "medium",
            "report_time": datetime.now().isoformat()
        }
        
        _cache[cache_key] = (result, datetime.now())
        
        return {
            "headers": {"Content-Type": "application/json", **headers},
            "body": json.dumps(result)
        }
    
    return {"statusCode": 404, "headers": {"Content-Type": "application/json", **headers}, "body": json.dumps({"error": "Not found"})}
