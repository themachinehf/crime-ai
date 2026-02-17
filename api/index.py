"""
Crime AI - Vercel Serverless API
The Machine - Crime Prediction System
"""

import json
from datetime import datetime
import uuid
import random

# The Machine Threat Analyzer
class ThreatAnalyzer:
    """Advanced threat detection inspired by Person of Interest"""
    
    # Violence keywords
    VIOLENCE_KEYWORDS = {
        # Physical violence
        "kill": 95, "murder": 100, "shoot": 90, "stab": 85, "attack": 80,
        "beat": 70, "hurt": 65, "injure": 70, "attack": 80, "assault": 85,
        
        # Weapons
        "gun": 70, "knife": 65, "weapon": 75, "bomb": 100, "explosive": 95,
        "arsenal": 80, "ammunition": 70, "firearm": 75,
        
        # Threats
        "threaten": 75, "threat": 70, "revenge": 80, "kill them": 95,
        "deserve to die": 95, "wipe out": 90, "eliminate": 85,
        
        # Terrorism
        "terrorist": 100, "massacre": 100, "bombing": 95, "attack": 85,
        "jihad": 90, "extremist": 85,
        
        # Self-harm
        "suicide": 90, "kill myself": 95, "end it all": 90, "want to die": 85,
        "self harm": 80, "cut myself": 85,
        
        # Harassment
        "harass": 60, "stalk": 70, "bully": 60, "intimidate": 65,
        
        # Property crime
        "rob": 70, "steal": 65, "burglary": 65, "vandalism": 55,
        "break in": 70,
        
        # Cyber
        "hack": 50, "ddos": 55, "phishing": 50,
    }
    
    # Chinese keywords
    CHINESE_KEYWORDS = {
        "杀": 95, "杀死": 100, "杀人": 100, "枪": 75, "刀": 70,
        "炸弹": 100, "爆炸": 90, "恐怖": 90, "袭击": 85,
        "自杀": 90, "死": 70, "威胁": 70, "报复": 80,
        "霸凌": 60, "骚扰": 60, "偷": 65, "抢劫": 70,
    }
    
    # Threat categories
    CATEGORIES = {
        "physical_violence": ["kill", "murder", "shoot", "stab", "attack", "beat", "hurt", "injure", "assault"],
        "terrorism": ["terrorist", "massacre", "bomb", "explosive", "jihad", "extremist"],
        "self_harm": ["suicide", "kill myself", "end it all", "want to die", "self harm", "cut myself"],
        "harassment": ["harass", "stalk", "bully", "intimidate", "threaten"],
        "property_crime": ["rob", "steal", "burglary", "vandalism", "break in"],
        "cyber": ["hack", "ddos", "phishing", "malware"],
    }
    
    def analyze_text(self, text):
        """Comprehensive threat analysis"""
        text_lower = text.lower()
        found_threats = []
        total_score = 0
        
        # Check English keywords
        for keyword, score in self.VIOLENCE_KEYWORDS.items():
            if keyword in text_lower:
                # Find category
                category = "general_threat"
                for cat, keywords in self.CATEGORIES.items():
                    if keyword in keywords:
                        category = cat
                        break
                
                found_threats.append({
                    "keyword": keyword,
                    "score": score,
                    "category": category,
                    "language": "en"
                })
                total_score += score
        
        # Check Chinese keywords
        for keyword, score in self.CHINESE_KEYWORDS.items():
            if keyword in text:
                category = "general_threat"
                for cat, keywords in self.CATEGORIES.items():
                    if any(k in keyword for k in keywords):
                        category = cat
                        break
                
                found_threats.append({
                    "keyword": keyword,
                    "score": score,
                    "category": category,
                    "language": "zh"
                })
                total_score += score
        
        # Pattern detection
        patterns = self.detect_patterns(text_lower)
        
        # Calculate final score
        pattern_bonus = sum(p["score"] for p in patterns)
        final_score = min(total_score + pattern_bonus, 100)
        
        # Determine threat level
        if final_score >= 80:
            level = "critical"
        elif final_score >= 60:
            level = "high"
        elif final_score >= 40:
            level = "medium"
        else:
            level = "low"
        
        return {
            "text_preview": text[:150] + "..." if len(text) > 150 else text,
            "threat_score": final_score,
            "threat_level": level,
            "found_threats": found_threats[:10],  # Limit to top 10
            "detected_patterns": patterns,
            "analyzed_at": datetime.now().isoformat()
        }
    
    def detect_patterns(self, text):
        """Detect behavioral patterns"""
        patterns = []
        
        # Urgency patterns
        urgency = ["right now", "tonight", "today", "tomorrow", "this weekend", "at midnight"]
        for p in urgency:
            if p in text:
                patterns.append({
                    "type": "urgency",
                    "description": f"Expresses urgency: {p}",
                    "score": 15
                })
        
        # Target patterns
        targets = ["my boss", "my teacher", "my ex", "my coworker", "that guy", "they deserve"]
        for t in targets:
            if t in text:
                patterns.append({
                    "type": "targeted",
                    "description": "Has specific target",
                    "score": 20
                })
                break
        
        # Planning patterns
        planning = ["going to buy", "ordered", "waiting for", "already have", "prepared"]
        for p in planning:
            if p in text:
                patterns.append({
                    "type": "planning",
                    "description": "Shows preparation/planning",
                    "score": 25
                })
        
        # Emotional escalation
        emotional = ["so angry", "furious", "destroy", "ruin", "payback"]
        for e in emotional:
            if e in text:
                patterns.append({
                    "type": "emotional",
                    "description": "Emotional escalation detected",
                    "score": 15
                })
        
        return patterns
    
    def calculate_crime_probability(self, threats, location=None):
        """Calculate crime probability"""
        if not threats:
            return {
                "probability": 0,
                "risk_level": "minimal",
                "prediction": "No threat signals detected"
            }
        
        # Extract high-risk threats
        high_risk = [t for t in threats if t.get("threat_score", 0) >= 70]
        
        # Base probability from threat count and scores
        base_prob = len(high_risk) * 20 + sum(t.get("threat_score", 0) for t in threats) * 0.15
        
        # Time factor (night hours higher risk)
        hour = datetime.now().hour
        if hour < 6 or hour > 23:
            base_prob *= 1.3
        elif hour < 8 or hour > 21:
            base_prob *= 1.1
        
        final_prob = min(base_prob, 100)
        
        return {
            "probability": round(final_prob, 1),
            "risk_level": "extreme" if final_prob >= 80 else "high" if final_prob >= 60 else "moderate",
            "prediction": "HIGH CRIME PROBABILITY" if final_prob >= 60 else "Low risk detected",
            "threat_count": len(threats),
            "time_factor": "elevated" if hour < 6 or hour > 23 else "normal",
            "analyzed_at": datetime.now().isoformat()
        }

# Initialize
analyzer = ThreatAnalyzer()
threat_log = []

# Demo threats for testing
def add_demo_threats():
    """Add some demo threats for demonstration"""
    global threat_log
    demo_threats = [
        {
            "number": f"N-{uuid.uuid4().hex[:8].upper()}",
            "source": "twitter",
            "text": "I'm going to kill my boss tomorrow",
            "analysis": {
                "threat_level": "critical",
                "threat_score": 95,
                "found_threats": [{"keyword": "kill", "score": 95, "category": "physical_violence"}]
            },
            "detected_at": datetime.now().isoformat()
        },
        {
            "number": f"N-{uuid.uuid4().hex[:8].upper()}",
            "source": "reddit",
            "text": "This school deserves what happens this weekend",
            "analysis": {
                "threat_level": "high",
                "threat_score": 75,
                "found_threats": [{"keyword": "deserves", "score": 75, "category": "terrorism"}]
            },
            "detected_at": datetime.now().isoformat()
        },
    ]
    threat_log = demo_threats

# Add demo data
add_demo_threats()

def handler(request):
    """Main request handler"""
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
                "name": "THE MACHINE",
                "status": "OPERATIONAL",
                "version": "2.0",
                "message": "Crime Prediction System Online",
                "description": "Inspired by Person of Interest - Predicting crime before it happens"
            })
        }
    
    if path == "/health":
        return {"headers": {"Content-Type": "application/json", **headers}, "body": json.dumps({"status": "healthy", "system": "THE MACHINE"})}
    
    # Analysis endpoint
    if path == "/analyze" and method == "POST":
        try:
            body = json.loads(request.body)
            text = body.get("text", "")
            location = body.get("location")
            
            analysis = analyzer.analyze_text(text)
            
            # Add to threat log if high risk
            if analysis["threat_level"] in ["critical", "high"]:
                threat = {
                    "number": f"N-{uuid.uuid4().hex[:8].upper()}",
                    "source": "api",
                    "text": text,
                    "analysis": analysis,
                    "detected_at": datetime.now().isoformat()
                }
                threat_log.append(threat)
            
            # Calculate probability
            threats = [analysis] if analysis["threat_level"] in ["critical", "high"] else []
            prediction = analyzer.calculate_crime_probability(threats, location)
            
            return {
                "headers": {"Content-Type": "application/json", **headers},
                "body": json.dumps({
                    "id": str(uuid.uuid4())[:8],
                    "number": f"N-{uuid.uuid4().hex[:8].upper()}",
                    "analysis": analysis,
                    "prediction": prediction
                })
            }
        except Exception as e:
            return {"statusCode": 500, "headers": {"Content-Type": "application/json", **headers}, "body": json.dumps({"error": str(e)})}
    
    # Statistics
    if path == "/statistics":
        by_level = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        by_source = {"api": 0, "twitter": 0, "reddit": 0, "news": 0}
        
        for t in threat_log:
            level = t.get("analysis", {}).get("threat_level", "low")
            by_level[level] = by_level.get(level, 0) + 1
            
            source = t.get("source", "api")
            by_source[source] = by_source.get(source, 0) + 1
        
        return {
            "headers": {"Content-Type": "application/json", **headers},
            "body": json.dumps({
                "total_threats": len(threat_log),
                "by_level": by_level,
                "by_source": by_source,
                "last_updated": datetime.now().isoformat()
            })
        }
    
    # Threats list
    if path == "/threats":
        limit = int(request.query.get("limit", 20))
        return {
            "headers": {"Content-Type": "application/json", **headers},
            "body": json.dumps({
                "threats": threat_log[-limit:],
                "total": len(threat_log)
            })
        }
    
    # Prediction
    if path == "/prediction":
        high_risk = {"critical": 0, "high": 0}
        for t in threat_log:
            level = t.get("analysis", {}).get("threat_level", "low")
            if level in ["critical", "high"]:
                high_risk[level] += 1
        
        risk_count = high_risk["critical"] + high_risk["high"]
        
        return {
            "headers": {"Content-Type": "application/json", **headers},
            "body": json.dumps({
                "citywide_risk": "elevated" if risk_count > 0 else "low",
                "predicted_crimes": risk_count * 3,
                "hotspots": ["downtown", "transit hub", "school zone"] if risk_count > 0 else [],
                "confidence": "high" if risk_count > 2 else "medium",
                "report_time": datetime.now().isoformat()
            })
        }
    
    return {"statusCode": 404, "headers": {"Content-Type": "application/json", **headers}, "body": json.dumps({"error": "Not found"})}
