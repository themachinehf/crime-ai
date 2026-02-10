"""
Crime AI - 社交媒体监控器
监控 Twitter/X, Reddit 等平台的威胁信号
"""

import os
import time
import json
from datetime import datetime
from typing import List, Dict, Optional
from analyzers.threat_analyzer import ThreatAnalyzer

class SocialMonitor:
    """社交媒体威胁信号监控器"""
    
    def __init__(self):
        self.analyzer = ThreatAnalyzer()
        self.threat_log = []
        
        # 监控配置
        self.config = {
            "twitter": {
                "enabled": False,  # 需要 API Key
                "keywords": ["kill", "bomb", "attack", "shoot", "murder", "terrorist"],
                "locations": ["nyc", "los angeles", "chicago", "houston", "phoenix"]
            },
            "reddit": {
                "enabled": True,
                "subreddits": ["r/legaladvice", "r/relationships", "r/confessions", 
                              "r/UnresolvedMysteries", "r/TrueCrime"],
                "keywords": ["threaten", "hurt", "revenge", "planning"]
            }
        }
    
    def check_text(self, text: str, source: str = "unknown") -> Optional[Dict]:
        """检查单条文本"""
        analysis = self.analyzer.analyze_text(text)
        
        if analysis["threat_level"] in ["high", "critical"]:
            threat = {
                "source": source,
                "text": text,
                "analysis": analysis,
                "detected_at": datetime.now().isoformat()
            }
            self.threat_log.append(threat)
            return threat
        
        return None
    
    def scan_reddit(self, subreddit: str, limit: int = 10) -> List[Dict]:
        """扫描 Reddit 帖子（模拟）"""
        # 实际实现需要 praw 库
        # 这里返回模拟数据用于测试
        
        sample_posts = [
            {
                "title": "My boss is making my life hell, I want to hurt him",
                "body": "I've been thinking about revenge lately",
                "score": 45
            },
            {
                "title": "Had a terrible fight with my ex",
                "body": "She deserves everything bad to happen to her",
                "score": 38
            },
            {
                "title": "Just need to vent about work today",
                "body": "Stressful day but I'll be fine",
                "score": 5
            }
        ]
        
        threats = []
        for post in sample_posts[:limit]:
            full_text = f"{post['title']} {post['body']}"
            threat = self.check_text(full_text, f"reddit/{subreddit}")
            if threat:
                threat["post_score"] = post["score"]
                threats.append(threat)
        
        return threats
    
    def get_threat_statistics(self) -> Dict:
        """获取威胁统计"""
        if not self.threat_log:
            return {
                "total_threats": 0,
                "by_level": {},
                "by_source": {},
                "last_updated": datetime.now().isoformat()
            }
        
        by_level = {}
        by_source = {}
        
        for threat in self.threat_log:
            level = threat["analysis"]["threat_level"]
            source = threat["source"]
            
            by_level[level] = by_level.get(level, 0) + 1
            by_source[source] = by_source.get(source, 0) + 1
        
        return {
            "total_threats": len(self.threat_log),
            "by_level": by_level,
            "by_source": by_source,
            "last_updated": datetime.now().isoformat()
        }
    
    def export_threat_report(self) -> Dict:
        """导出威胁报告"""
        return {
            "report_time": datetime.now().isoformat(),
            "statistics": self.get_threat_statistics(),
            "recent_threats": self.threat_log[-10:] if self.threat_log else [],
            "prediction": self._generate_threat_prediction()
        }
    
    def _generate_threat_prediction(self) -> Dict:
        """生成威胁预测"""
        stats = self.get_threat_statistics()
        
        if stats["total_threats"] == 0:
            return {
                "citywide_risk": "minimal",
                "predicted_crimes": 0,
                "hotspots": [],
                "confidence": "high"
            }
        
        # 简化的预测算法
        high_risk_count = stats["by_level"].get("high", 0) + stats["by_level"].get("critical", 0)
        
        return {
            "citywide_risk": "elevated" if high_risk_count > 0 else "low",
            "predicted_crimes": high_risk_count * 2,
            "hotspots": list(stats["by_source"].keys())[:3],
            "confidence": "medium"
        }


# 测试
if __name__ == "__main__":
    monitor = SocialMonitor()
    
    print("=== Crime AI Social Monitor ===\n")
    
    # 测试检测
    test_texts = [
        ("I want to kill my teacher", "twitter"),
        ("Going to bomb the mall this weekend", "twitter"),
        ("My coworker is annoying but whatever", "slack"),
        ("She deserves to die", "reddit")
    ]
    
    for text, source in test_texts:
        result = monitor.check_text(text, source)
        if result:
            print(f"🚨 THREAT DETECTED!")
            print(f"   Source: {source}")
            print(f"   Level: {result['analysis']['threat_level']}")
            print()
    
    # 统计
    stats = monitor.get_threat_statistics()
    print(f"Total threats: {stats['total_threats']}")
    print(f"By level: {stats['by_level']}")
