# THE MACHINE - Crime Prediction System

_Inspired by Person of Interest_

## Overview

THE MACHINE is an advanced crime prediction and threat detection system that monitors public data sources to identify and predict potential crimes before they happen.

## Features

### Threat Detection
- **Real-time monitoring** of Twitter/X, Reddit, news APIs
- **Multi-language analysis** (English + Chinese)
- **Pattern recognition** - detects behavioral indicators
- **Risk scoring** - CLASS 1-4 threat classification

### Crime Prediction
- **Probability calculation** based on threat data
- **Geographic hotspots** identification
- **Time-based risk factors** (elevated risk at night)
- **Pattern learning** from historical data

### Numbers System
- Every detected threat receives a unique identifier (N-XXXXXXXX)
- Tracks perpetrators, victims, and witnesses
- Full audit trail of all predictions

### Alert System
- **Telegram notifications** for critical threats
- **Daily reports** for trend analysis
- **Real-time feed** of all detected threats

## Technical Stack

- **Backend**: Python FastAPI (Vercel Serverless)
- **Frontend**: HTML/CSS/JavaScript (The Machine aesthetic)
- **APIs**: Twitter/X, Reddit, News APIs
- **Notifications**: Telegram Bot

## Classification System

| Class | Level | Score | Action |
|-------|-------|-------|--------|
| CLASS 1 | CRITICAL | 80-100 | Immediate alert |
| CLASS 2 | HIGH | 60-79 | Priority investigation |
| CLASS 3 | MEDIUM | 40-59 | Monitor closely |
| CLASS 4 | LOW | 0-39 | Log only |

## Installation

```bash
# Install dependencies
pip install -r requirements.txt

# Run locally
python -m uvicorn api.index:handler --reload --port 8000

# Or run the analyzer directly
python analyzers/threat_analyzer.py
```

## Deployment

Deploy to Vercel:
```bash
vercel --prod
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | System status |
| `/health` | GET | Health check |
| `/analyze` | POST | Analyze text for threats |
| `/statistics` | GET | Threat statistics |
| `/threats` | GET | Recent threats |
| `/prediction` | GET | Crime prediction |

## Demo

Visit the deployed UI to see THE MACHINE in action:
- Enter text in the analysis box
- View real-time threat feed
- Monitor prediction model output

## Legal Disclaimer

This system is for educational and research purposes. It monitors publicly available data and does not engage in illegal surveillance or violate privacy laws.

---

_"I am not a machine. But I think like one."_
