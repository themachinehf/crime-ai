"""
Crime AI - API Server
FastAPI 服务器提供威胁分析接口
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime
import uuid

from analyzers.threat_analyzer import ThreatAnalyzer
from monitors.social_monitor import SocialMonitor

app = FastAPI(
    title="Crime AI",
    description="犯罪预测系统 - THE MACHINE Prototype",
    version="1.0.0"
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# 初始化
analyzer = ThreatAnalyzer()
monitor = SocialMonitor()

# ============ 数据模型 ============

class TextAnalysisRequest(BaseModel):
    text: str
    location: Optional[str] = None

class ThreatResponse(BaseModel):
    id: str
    threat_level: str
    threat_score: int
    prediction: str
    probability: float
    analyzed_at: str

class StatisticsResponse(BaseModel):
    total_threats: int
    by_level: dict
    by_source: dict
    last_updated: str

class PredictionResponse(BaseModel):
    citywide_risk: str
    predicted_crimes: int
    hotspots: List[str]
    confidence: str
    report_time: str

# ============ API 端点 ============

@app.get("/")
def root():
    """根端点"""
    return {
        "name": "Crime AI",
        "status": "operational",
        "version": "1.0.0",
        "message": "犯罪预测系统在线"
    }

@app.get("/health")
def health():
    """健康检查"""
    return {"status": "healthy"}

@app.post("/analyze")
def analyze_text(request: TextAnalysisRequest):
    """分析文本威胁等级"""
    analysis = analyzer.analyze_text(request.text)
    
    # 计算犯罪概率
    threats = [analysis] if analysis["threat_level"] in ["high", "critical"] else []
    probability_data = analyzer.calculate_crime_probability(
        threats, 
        request.location
    )
    
    return {
        "id": str(uuid.uuid4())[:8],
        "analysis": analysis,
        "prediction": probability_data
    }

@app.post("/analyze/batch")
def analyze_batch(texts: List[str]):
    """批量分析多个文本"""
    results = []
    for text in texts:
        analysis = analyzer.analyze_text(text)
        if analysis["threat_level"] in ["high", "critical"]:
            results.append(analysis)
    return {
        "total_analyzed": len(texts),
        "threats_found": len(results),
        "threats": results
    }

@app.get("/statistics")
def get_statistics() -> StatisticsResponse:
    """获取威胁统计"""
    return monitor.get_threat_statistics()

@app.get("/prediction")
def get_prediction() -> PredictionResponse:
    """获取犯罪预测"""
    return monitor.export_threat_report()

@app.get("/threats")
def get_recent_threats(limit: int = 10):
    """获取最近威胁"""
    return {
        "threats": monitor.threat_log[-limit:],
        "total": len(monitor.threat_log)
    }

@app.get("/status")
def get_system_status():
    """系统状态"""
    stats = monitor.get_threat_statistics()
    return {
        "system": "Crime AI",
        "status": "monitoring",
        "threats_detected": stats["total_threats"],
        "monitoring_sources": ["twitter", "reddit"],
        "last_check": datetime.now().isoformat()
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
