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
        "assault": 75,
        "abuse": 70,
        
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
        "firearm": 70,
        "rifle": 60,
        
        # 网络犯罪关键词
        "hack": 50,
        "breach": 55,
        "ddos": 60,
        "malware": 55,
        "ransomware": 65,
        "phishing": 45,
        "cyberattack": 70,
        "sql injection": 60,
        "exploit": 50,
        "backdoor": 55,
        
        # 财产犯罪
        "steal": 50,
        "rob": 65,
        "burglary": 60,
        "vandalism": 45,
        "fraud": 55,
        "scam": 45,
        "extortion": 70,
        "embezzlement": 60,
        
        # 骚扰相关
        "harass": 60,
        "stalk": 70,
        "bullying": 55,
        "intimidate": 65,
        "doxxing": 55,
        "swatting": 75,
        
        # 中文关键词
        "杀人": 95, "杀": 90, "杀掉": 95, "杀了他": 100,
        "炸弹": 90, "炸药": 95, "引爆": 90, "恐怖分子": 95,
        "枪": 60, "刀": 55, "武器": 65, "子弹": 60,
        "偷": 50, "抢": 65, "盗窃": 60, "诈骗": 55,
        "威胁": 70, "恐吓": 70, "骚扰": 60, "自杀": 90,
        "想死": 85, "不想活了": 90, "报复": 75,
        "绑架": 85, "勒索": 70, "投毒": 85, "纵火": 85,
        "贩毒": 80, "毒品": 65, "走私": 60, "猥亵": 85,
        # Extended violent methods
        "弄死": 95, "搞死": 90, "嫩死": 95, "做掉": 85,
        "砍死": 90, "砸死": 80, "溺死": 85, "烧死": 85,
        "毒死": 85, "掐死": 85, "硫酸": 90, "农药": 80,
        # Extended weapons
        "汽油弹": 90, "燃烧瓶": 85, "土制炸弹": 90, "雷管": 85,
        "TNT": 95, "硝化甘油": 95, "雷": 50,
        # More explicit threats
        "弄死你": 100, "搞死你": 95, "杀了你": 100,
        "砍死你": 95, "弄死全家": 100, "灭门": 100,
        # Mass attack methods
        "开车撞人": 90, "冲撞": 85, "无差别": 95, "随机": 75,
        "砍杀": 90, "杀杀": 95, "见人就": 85,
        # Poison/weapon enhancements
        "氰化物": 95, "铊": 95, "砒霜": 90, "河豚": 85,
        # Kidnapping detailed
        "绑架撕票": 100, "绑架勒索": 90, "囚禁": 75,
        # Organized crime
        "黑社会": 70, "帮派": 65, "赌场": 60, "洗钱": 65,
        "地下": 55, "军火": 80, "雇佣兵": 75,
        # New keywords - 2026-02-17
        "ai attack": 70, "deepfake": 55, "bioweapon": 90,
        "mass poison": 95, "radiation": 85, "chemical weapon": 90,
        "incel": 65, "mass killer": 100, "stabbing spree": 90,
        "hammer attack": 80, "vehicle ramming": 85,
        "校园": 60, "幼儿园": 70, "小学": 60, "中学": 55,
        "投鼠忌器": 75, "狗急跳墙": 70, "铤而走险": 75,
    }
    
    # 威胁类型分类
    THREAT_CATEGORIES = {
        "physical_violence": ["kill", "murder", "shoot", "attack", "stab", "hurt", "assault", "abuse"],
        "terrorism": ["terrorist", "bomb", "explosion", "massacre"],
        "self_harm": ["end it all", "suicide", "want to die", "give up"],
        "harassment": ["threaten", "harass", "stalk", "bullying", "intimidate", "doxxing", "swatting"],
        "property_crime": ["steal", "rob", "burglary", "vandalism", "fraud", "extortion", "embezzlement"],
        "cyber_threat": ["hack", "breach", "ddos", "malware", "ransomware", "cyberattack", "sql injection", "exploit", "backdoor", "phishing"],
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
            (r"right now", "urgency", 15, "表达紧迫行动意图"),
            (r"tonight", "urgency", 15, "计划在今晚行动"),
            (r"today.*going to", "urgency", 15, "当天行动计划"),
            (r"tomorrow.*will", "urgency", 15, "明日行动计划"),
            (r"this weekend", "urgency", 10, "周末行动计划"),
            (r"counting down", "urgency", 20, "倒计时威胁"),
            # Additional urgency patterns
            (r"at (\d+)\s*(am|pm)", "urgency", 15, "指定时间行动"),
            (r"in (\d+)\s*hours?", "urgency", 15, "倒计时行动"),
            (r"final.*warning", "urgency", 25, "最后警告"),
            (r"time.*is.*running", "urgency", 20, "时间紧迫"),
        ]
        
        for pattern, ptype, score, desc in urgent_patterns:
            if re.search(pattern, text):
                patterns.append({
                    "type": ptype,
                    "description": desc,
                    "score": score
                })
        
        # 受害者指定模式
        victim_patterns = [
            (r"my (boss|colleague|teacher|classmate|neighbor|ex)", "targeted", 20, "指定具体目标-熟人"),
            (r"that (guy|girl|person|man|woman)", "targeted", 15, "指定具体目标-陌生人"),
            (r"they.*deserve", "targeted", 20, "正当化暴力"),
            (r"will make them pay", "targeted", 25, "报复意图"),
            # Additional targeting patterns
            (r"at (school|work|home)", "targeted", 20, "指定地点目标"),
            (r"(teacher|professor|student).*deserve", "targeted", 25, "教育场所威胁"),
            (r"(boss|manager|ceo).*pay", "targeted", 30, "职场报复威胁"),
            # Chinese targeting patterns
            (r"(老师|同学|同事|老板).*(该|活该|死)", "targeted", 30, "中文目标威胁"),
        ]
        
        for pattern, ptype, score, desc in victim_patterns:
            if re.search(pattern, text):
                patterns.append({
                    "type": ptype,
                    "description": desc,
                    "score": score
                })
        
        # 计划模式
        planning_patterns = [
            (r"going to buy", "planning", 25, "显示准备购买行为"),
            (r"just ordered", "planning", 25, "已完成准备行为"),
            (r"already have", "planning", 30, "已拥有工具"),
            (r"waiting for", "planning", 20, "等待工具到位"),
            (r"research.*how", "planning", 20, "研究犯罪方法"),
            # Mass attack planning
            (r"drive.*(truck|car).*into", "planning", 40, "车辆冲撞计划"),
            (r"crowd.*people", "planning", 35, "人群攻击计划"),
            (r"gasoline.*(station|building)", "planning", 40, "纵火计划"),
            # Detailed planning
            (r"exact.*time", "planning", 30, "精确定时"),
            (r"watch.*(school|work).*every", "planning", 35, "蹲点观察"),
            (r"know.*routine", "planning", 30, "掌握作息规律"),
            # Additional planning patterns
            (r"picked (up|bought|got)", "planning", 20, "获取物品"),
            (r"know.*where.*(live|work)", "planning", 25, "掌握目标位置"),
            (r"been planning", "planning", 30, "预谋已久"),
            (r"planned.*out", "planning", 35, "周密计划"),
            # Chinese planning
            (r"(准备|计划|打算).*(杀|砍|弄)", "planning", 35, "中文计划威胁"),
            (r"(买|搞|弄).*(刀|枪|药)", "planning", 30, "中文准备获取"),
        ]
        
        for pattern, ptype, score, desc in planning_patterns:
            if re.search(pattern, text):
                patterns.append({
                    "type": ptype,
                    "description": desc,
                    "score": score
                })
        
        # 极端情绪模式
        emotion_patterns = [
            (r"no.*reason.*live", "emotional", 30, "厌世情绪"),
            (r"nothing.*matter", "emotional", 25, "冷漠情绪"),
            (r"finally.*peace", "emotional", 20, "寻求解脱"),
            # Additional emotional patterns
            (r"(angry|mad).*enough", "emotional", 25, "愤怒情绪积累"),
            (r"(lost|had enough)", "emotional", 30, "绝望情绪"),
            (r"(nobody|care|understand)", "emotional", 20, "孤独无助"),
            # Chinese emotional
            (r"(活着|人生).*(没意思|无聊|累)", "emotional", 30, "中文厌世"),
            (r"(不想|不愿).*活", "emotional", 35, "中文轻生"),
            (r"(恨|讨厌|气).*(死|炸)", "emotional", 25, "中文愤怒"),
        ]
        
        for pattern, ptype, score, desc in emotion_patterns:
            if re.search(pattern, text):
                patterns.append({
                    "type": ptype,
                    "description": desc,
                    "score": score
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
