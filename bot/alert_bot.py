"""
Crime AI - Telegram 告警机器人
当检测到高威胁时发送通知
"""

import os
import json
from datetime import datetime
from typing import Optional
from telegram import Bot

class CrimeAlertBot:
    """Crime AI 告警机器人"""
    
    def __init__(self, token: str, chat_id: str):
        self.token = token
        self.chat_id = chat_id
        self.enabled = bool(token and chat_id)
        
        if self.enabled:
            self.bot = Bot(token=token)
        else:
            self.bot = None
    
    def send_threat_alert(self, threat_data: dict) -> bool:
        """发送威胁告警"""
        if not self.enabled:
            print("⚠️ Telegram 未配置，跳过告警")
            return False
        
        analysis = threat_data.get("analysis", {})
        level = analysis.get("threat_level", "unknown")
        score = analysis.get("threat_score", 0)
        text = threat_data.get("text", "")[:200]
        source = threat_data.get("source", "unknown")
        
        # Emoji 根据威胁等级
        emojis = {
            "critical": "🚨",
            "high": "🔴",
            "medium": "🟡",
            "low": "🟢"
        }
        emoji = emojis.get(level, "⚠️")
        
        message = f"""
{emoji} **CRIME AI 威胁告警**

**等级:** {level.upper()}
**分数:** {score}/100
**来源:** {source}
**时间:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

**内容:**
{text}

---
*Crime AI - 犯罪预测系统*
"""
        
        try:
            self.bot.send_message(
                chat_id=self.chat_id,
                text=message,
                parse_mode="Markdown"
            )
            return True
        except Exception as e:
            print(f"❌ 发送告警失败: {e}")
            return False
    
    def send_daily_report(self, stats: dict) -> bool:
        """发送每日报告"""
        if not self.enabled:
            return False
        
        total = stats.get("total_threats", 0)
        by_level = stats.get("by_level", {})
        
        message = f"""
📊 **Crime AI 每日报告**

**总威胁数:** {total}

**分布:**
🔴 High: {by_level.get('high', 0)}
🔴 Critical: {by_level.get('critical', 0)}
🟡 Medium: {by_level.get('medium', 0)}
🟢 Low: {by_level.get('low', 0)}

---
*{datetime.now().strftime('%Y-%m-%d')}*
"""
        
        try:
            self.bot.send_message(
                chat_id=self.chat_id,
                text=message,
                parse_mode="Markdown"
            )
            return True
        except Exception as e:
            print(f"❌ 发送报告失败: {e}")
            return False


# 配置加载
def load_config():
    config_path = os.path.join(os.path.dirname(__file__), "config.json")
    if os.path.exists(config_path):
        with open(config_path) as f:
            return json.load(f)
    return {"token": None, "chat_id": None}


if __name__ == "__main__":
    config = load_config()
    bot = CrimeAlertBot(
        token=config.get("token"),
        chat_id=config.get("chat_id")
    )
    
    # 测试告警
    test_threat = {
        "source": "twitter",
        "text": "I want to kill my boss, I'm going to do it tomorrow",
        "analysis": {
            "threat_level": "critical",
            "threat_score": 95
        }
    }
    
    if bot.enabled:
        print("发送测试告警...")
        bot.send_threat_alert(test_threat)
    else:
        print("Telegram 未配置，跳过测试")
