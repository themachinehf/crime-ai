"""
Crime AI - 威胁分析引擎
基于文本情感和关键词进行犯罪预测
"""

import re
from datetime import datetime
from typing import Dict, List, Tuple
from dataclasses import dataclass

@dataclass
class ThreatLevel:
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class ThreatIndicator:
    keyword: str
    score: int
    category: str

class ThreatAnalyzer:
    """威胁分析器 - 检测潜在犯罪信号"""
    
    # 暴力相关关键词及其威胁分数
    VIOLENCE_KEYWORDS = {
        # 严重暴力
        "kill": 90,
        "murder": 95,
        "shoot": 85,
        "attack": 80,
        "massacre": 100,
        "terrorist": 95,
        "bomb": 90,
        "explosion": 85,
        "rape": 95,
        "stab": 85,
        
        # 威胁表达
        "threaten": 70,
        "hurt": 65,
        "destroy": 70,
        "revenge": 75,
        "payback": 70,
        "eliminate": 80,
        "wipe out": 85,
        "end it all": 90,
        "going to kill": 95,
        "want them dead": 95,
        
        # 武器相关
        "gun": 60,
        "knife": 55,
        "weapon": 65,
        "arsenal": 75,
        "ammunition": 65,
    }
    
    # 威胁类型分类
    THREAT_CATEGORIES = {
        "physical_violence": ["kill", "murder", "shoot", "attack", "stab", "hurt"],
        "terrorism": ["terrorist", "bomb", "explosion", "massacre"],
        "self_harm": ["end it all", "suicide", "want to die", "give up"],
        "harassment": ["threaten", "harass", "stalk", "bullying"],
        "property_crime": ["steal", "rob", "burglary", "vandalism"],
    }
    
    def __init__(self):
        self.threat_keywords = self.VIOLENCE_KEYWORDS.copy()
    
    def analyze_text(self, text: str) -> Dict:
        """分析文本，返回威胁评估"""
        text_lower = text.lower()
        
        # 检测威胁关键词
        found_threats = []
        total_score = 0
        
        for keyword, score in self.threat_keywords.items():
            if keyword in text_lower:
                found_threats.append({
                    "keyword": keyword,
                    "score": score,
                    "category": self._categorize_keyword(keyword)
                })
                total_score += score
        
        # 检测模式
        patterns = self._detect_patterns(text_lower)
        
        # 计算最终威胁分数
        base_score = min(total_score, 100)
        pattern_bonus = sum(p["score"] for p in patterns)
        final_score = min(base_score + pattern_bonus, 100)
        
        # 确定威胁等级
        threat_level = self._calculate_threat_level(final_score)
        
        return {
            "text_preview": text[:100] + "..." if len(text) > 100 else text,
            "threat_score": final_score,
            "threat_level": threat_level,
            "found_threats": found_threats,
            "detected_patterns": patterns,
            "analyzed_at": datetime.now().isoformat()
        }
    
    def _categorize_keyword(self, keyword: str) -> str:
        """分类关键词"""
        for category, keywords in self.THREAT_CATEGORIES.items():
            if keyword in keywords:
                return category
        return "general_threat"
    
    def _detect_patterns(self, text: str) -> List[Dict]:
        """检测可疑模式"""
        patterns = []
        
        # 紧迫性模式
        urgent_patterns = [
            r"right now",
            r"tonight",
            r"today.*going to",
            r"tomorrow.*will",
            r"this weekend",
        ]
        
        for pattern in urgent_patterns:
            if re.search(pattern, text):
                patterns.append({
                    "type": "urgency",
                    "description": "表达紧迫行动意图",
                    "score": 15
                })
        
        # 受害者指定模式
        victim_patterns = [
            r"my (boss|colleague|teacher|classmate|neighbor|ex)",
            r"that (guy|girl|person|man|woman)",
            r"they.*deserve",
        ]
        
        for pattern in victim_patterns:
            if re.search(pattern, text):
                patterns.append({
                    "type": "targeted",
                    "description": "指定具体目标",
                    "score": 20
                })
        
        # 计划模式
        planning_patterns = [
            r"going to buy",
            r"just ordered",
            r"already have",
            r"waiting for",
        ]
        
        for pattern in planning_patterns:
            if re.search(pattern, text):
                patterns.append({
                    "type": "planning",
                    "description": "显示准备行为",
                    "score": 25
                })
        
        return patterns
    
    def _calculate_threat_level(self, score: int) -> str:
        """计算威胁等级"""
        if score >= 80:
            return ThreatLevel.CRITICAL
        elif score >= 60:
            return ThreatLevel.HIGH
        elif score >= 40:
            return ThreatLevel.MEDIUM
        else:
            return ThreatLevel.LOW
    
    def calculate_crime_probability(self, threats: List[Dict], 
                                     location: str = None,
                                     time_factor: float = 1.0) -> Dict:
        """计算犯罪概率（THE MACHINE 核心算法）"""
        
        if not threats:
            return {
                "probability": 0,
                "risk_level": "minimal",
                "prediction": "未检测到威胁信号"
            }
        
        # 提取高危威胁
        high_risk_threats = [t for t in threats if t["threat_level"] in ["high", "critical"]]
        
        # 基础概率
        base_prob = len(high_risk_threats) * 15 + sum(
            t["threat_score"] for t in high_risk_threats
        ) * 0.1
        
        # 位置因素
        location_risk = 1.0
        high_risk_areas = ["school", "government", "mall", "public"]
        for area in high_risk_areas:
            if area in (location or "").lower():
                location_risk = 1.3
                break
        
        # 时间因素（深夜/凌晨更高风险）
        hour = datetime.now().hour
        time_factor = 1.5 if hour < 6 or hour > 23 else 1.0
        
        # 计算最终概率
        final_probability = min(base_prob * location_risk * time_factor, 100)
        
        # 生成预测
        prediction = self._generate_prediction(final_probability, high_risk_threats)
        
        return {
            "probability": round(final_probability, 1),
            "risk_level": self._get_risk_label(final_probability),
            "prediction": prediction,
            "threat_count": len(high_risk_threats),
            "time_factor": time_factor,
            "location_factor": location_risk,
            "analyzed_at": datetime.now().isoformat()
        }
    
    def _generate_prediction(self, probability: float, threats: List[Dict]) -> str:
        """生成预测描述"""
        if probability >= 80:
            return "⚠️ 高概率犯罪风险，建议立即介入"
        elif probability >= 60:
            return "🔴 中高风险，建议密切关注"
        elif probability >= 40:
            return "🟡 中等风险，保持监控"
        elif probability >= 20:
            return "🟢 低风险，继续观察"
        else:
            return "✅ 风险极低"
    
    def _get_risk_label(self, probability: float) -> str:
        """获取风险标签"""
        if probability >= 80:
            return "extreme"
        elif probability >= 60:
            return "high"
        elif probability >= 40:
            return "moderate"
        elif probability >= 20:
            return "low"
        else:
            return "minimal"


# 测试
if __name__ == "__main__":
    analyzer = ThreatAnalyzer()
    
    test_texts = [
        "I'm so angry at my boss, I want to kill him",
        "Going to buy a gun tomorrow",
        "I hate my ex, she deserves to suffer",
        "This weekend I'm going to bomb the school",
        "Just had a bad day at work",
    ]
    
    print("=== Crime AI Threat Analysis ===\n")
    
    for text in test_texts:
        result = analyzer.analyze_text(text)
        print(f"Text: {text}")
        print(f"Level: {result['threat_level']} | Score: {result['threat_score']}")
        print(f"Threats: {[t['keyword'] for t in result['found_threats']]}")
        print()
