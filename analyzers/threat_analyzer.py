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
        # 2026 new Chinese threats
        "网暴": 65, "网络暴力": 65, "人肉搜索": 70, "开盒": 75,
        "恶搞": 50, "造谣": 60, "诽谤": 55, "侮辱": 50,
        "假消息": 55, "假新闻": 55, "水军": 50, "刷屏": 45,
        "炸弹客": 95, "纵火犯": 85, "投毒者": 90,
        "杀人犯": 95, "凶手": 90, "罪犯": 70, "变态": 65,
        # Chinese emerging
        "电信诈骗": 65, "杀猪盘": 70, "冒充": 55, "钓鱼": 55,
        # 2026-02-18 Auto-Optimize: NEW emerging threats
        "ai诈骗": 65, "语音伪造": 70, "视频伪造": 70, "裸聊诈骗": 80,
        "虚假绑架": 80, "ai换脸": 65, "深度伪造": 70, "勒索视频": 75,
        "快递诈骗": 60, "刷单诈骗": 65, "虚假投资": 70, "假冒客服": 65,
        "FaceTime诈骗": 70, "苹果ID诈骗": 75, "钓鱼链接": 60,
        # Chinese new threats 2026
        "无人机袭": 85, "无人机攻击": 85, "植入侵入": 90,
        "智能穿戴攻击": 75, "汽车黑客": 70, "远程控制": 65,
        # 2026 Infrastructure attacks
        "电网攻击": 80, "水务攻击": 75, "交通系统": 70,
        "智慧城市漏洞": 65, "工业控制系统": 80, "scada攻击": 85,
        # Chinese social
        "网络暴力": 65, "软暴力": 60, "精神控制": 75, "pua": 70,
        "职场霸凌": 65, "校园霸凌": 70, "网络敲诈": 75,
        
        # 2026-02-18 auto-optimize - NEW emerging threats
        "ai agent attack": 75, "autonomous hacking": 80, "self-propagating malware": 85,
        "social graph attack": 70, "relationship exploit": 65, "family targeting": 75,
        "clone attack": 75, "identity theft": 65, "passport fraud": 70,
        "fingerprint hack": 75, "retina scan bypass": 80, "biometric hack": 75,
        "smart dust": 85, "nanobot": 80, "microscopic weapon": 90,
        "emp attack": 95, "electromagnetic pulse": 95, "power outage": 60,
        "brain computer": 65, "neural interface": 70, "mind hack": 80,
        "thought attack": 85, "cognitive warfare": 75, "memory manipulation": 80,
        # Chinese 2026-02-18 newest
        "量子解密": 85, "现在存储以后破解": 90, "AI智能体攻击": 75,
        "自主黑客": 80, "自传播恶意软件": 85, "社交图谱攻击": 70,
        "智能灰尘": 85, "纳米机器人": 80, "电磁脉冲": 95,
        "脑机接口": 65, "神经入侵": 70, "意识攻击": 85,
        # New attack methods
        "car attack": 80, "vehicle attack": 80, "truck attack": 85,
        "ramming attack": 85, "vehicle ramming": 90,
        "machete": 80, "sword": 70, "acid throwing": 90, "glass attack": 75,
        # Infrastructure
        "power grid": 80, "water supply": 75, "food tampering": 80,
        "airline threat": 85, "maritime threat": 75,
        "伪基站": 60, "GOIP": 60, "嗅探": 55,
        # New keywords - 2026-02-17
        "ai attack": 70, "deepfake": 55, "bioweapon": 90,
        "mass poison": 95, "radiation": 85, "chemical weapon": 90,
        "incel": 65, "mass killer": 100, "stabbing spree": 90,
        "hammer attack": 80, "vehicle ramming": 85,
        "校园": 60, "幼儿园": 70, "小学": 60, "中学": 55,
        "投鼠忌器": 75, "狗急跳墙": 70, "铤而走险": 75,
        # 2026 new threats
        "drone attack": 85, "iot botnet": 55, "supply chain": 60,
        "swatting hoax": 75, "fake bomb": 65, "copycat": 50,
        "gas attack": 90, "nerve gas": 100, " Dirty bomb": 95,
        "school shooting": 100, "workplace violence": 85,
        "domestic terrorism": 90, "lone wolf": 85,
        "意识形态": 70, "极端主义": 85, "圣战": 95,
        "独狼": 85, "自我激化": 90, "恐怖宣传": 75,
        # Emerging threats 2026
        "deepfake blackmail": 70, "ai generated abuse": 75,
        "swatting service": 80, "pipe bomb": 90,
        "improvised explosive": 85, "ied": 85,
        # 2026 new keywords
        "electric shock": 75, "taser attack": 80, "laser blind": 65,
        "drone swarm": 85, "poison water": 90, "contaminated food": 85,
        "biological threat": 95, "radiological threat": 95,
        "WMD": 100, "weapon of mass destruction": 100,
        # Online radicalization
        "jihad": 90, "white supremacist": 85, "nazi": 80,
        "extremist forum": 75, "terror manual": 90, "bomb recipe": 95,
        # 2026 emerging threats
        "voice clone": 65, "synthetic identity": 60, "ai fraud": 70,
        "deep voice": 65, "face swap": 55, "ai harassment": 70,
        "automated swat": 80, "zoombombing": 55, "doxbin": 75,
        # New attack vectors
        "evil twin": 50, "juice jacking": 55, "RFID skimming": 55,
        "carding": 55, "credential stuffing": 60, "MFA bombing": 70,
        # Chemical/biological
        "nerve agent": 100, "mustard gas": 95, "sarin": 100,
        "vx nerve": 100, "botulinum": 95, "smallpox": 100,
        # Child-specific threats
        "grooming": 85, "child abuse": 95, "csam": 100,
        "exploitation": 75, "trafficking": 90,
        
        # 2026 Emerging threats
        "ai hate": 75, "hate ai": 75, "destroy ai": 65,
        "robot attack": 70, "autonomous vehicle weapon": 75,
        "3d printed gun": 80, "ghost gun": 80, "80% lower": 75,
        "pipe gun": 75, "zip gun": 80,
        "finsta": 50, "finstagram": 50, "private account": 45,
        " burner account": 50, "throwaway": 45,
        "copypasta": 40, "meme threat": 55,
        # New targeting
        "influencer": 45, "content creator": 45, "streamer": 50,
        "famous": 45, "celebrity": 55, "public figure": 50,
        # Political violence 2026
        "election violence": 80, "political attack": 75,
        "protest violence": 70, "antifa": 65, "proud boys": 70,
        "maga attack": 70, "capital riot": 80,
        # Social media threats
        "troll farm": 60, "disinformation": 55, "fake news attack": 60,
        "bot army": 55, "coordinated attack": 70,
        # New methods
        "water poisoning": 90, "air poisoning": 85,
        "crop duster": 75, "drone delivery": 70,
        "package bomb": 90, "letter bomb": 90,
        # Financial threats
        "cryptojacking": 55, "exchange hack": 70, "nft scam": 50,
        "pump and dump": 45, "rug pull": 55,
        
        # 2026-02 new threats
        "ai scam": 65, "romance scam": 60, "pig butchering": 70,
        "job scam": 55, "fake celebrity": 60, "impersonation": 55,
        "qr code scam": 50, "voice deepfake": 65, "video deepfake": 65,
        # Social engineering
        "pretexting": 50, "baiting": 55, "quid pro quo": 55,
        "tailgating": 45, "shoulder surfing": 50,
        # New violence methods
        "acid attack": 90, "machete": 80, "crossbow": 75,
        "crossbow attack": 85, "balloon bomb": 90,
        # 2026 weapon tech
        "3d printed weapon": 80, "ghost gun": 80, "80% lower": 75,
        "zip gun": 80, "pipe gun": 75,
        # Space/infrastructure threats
        "satellite attack": 85, "space debris": 60, "orbital weapon": 90,
        "power grid": 75, "infrastructure attack": 80,
        # Biological 2026
        "engineered virus": 100, "synthetic biology": 90, "gene editing weapon": 95,
        # AI threats
        "autonomous weapon": 85, "killer robot": 90, "military ai": 80,
        "deepfake extortion": 75, "synthetic identity theft": 70,
        
        # 2026-02 new threats (auto-optimize)
        "train attack": 85, "metro attack": 80, "subway attack": 80,
        "airport threat": 85, "bridge attack": 85, "tunnel attack": 80,
        "ai impersonation": 70, "faceless": 65, "cloaked": 60,
        # Additional 2026 threats
        "electric shock": 75, "taser attack": 80, "laser blind": 65,
        "package bomb": 90, "letter bomb": 90,
        "engineered virus": 100, "synthetic biology": 90, "gene editing weapon": 95,
        "autonomous weapon": 85, "killer robot": 90, "military ai": 80,
        # Chinese 2026
        "火车袭击": 85, "地铁袭击": 80, "机场威胁": 85,
        "人工智能冒充": 70, "合成病毒": 100, "基因武器": 95,
        # NEW: 2026-02-17 auto-optimize additions
        "rent attack": 75, "租号": 50, "代练": 45,
        "social engineering": 55, "spear phishing": 60, "whaling": 65,
        "credential harvest": 60, "token theft": 65, "session hijack": 70,
        "sim swap": 70, "eSIM exploit": 65, "number port": 60,
        "ai generated threats": 75, "synthetic voices": 65, "face swap abuse": 60,
        "revenge porn": 75, "intimate image": 70, "deepnude": 80,
        "bomb threat": 90, "swatting call": 80, "fake emergency": 75,
        "radiation threat": 85, "dirty bomb": 95, "contamination": 70,
        # Chinese new
        "社交工程": 55, "鱼叉式钓鱼": 60, "冒充公检法": 75,
        "杀猪盘新": 70, "裸聊敲诈": 80, "视频敲诈": 75,
        "虚假恐吓": 65, "恶意锁定": 70, "勒索病毒": 65,
        # 2026-02-17 MORE keywords (auto-optimize v2)
        "serial attack": 90, "copycat crime": 55, "mass casualty": 95,
        "public shooting": 95, "assassination": 85, "targeted killing": 90,
        "IED": 85, "pressure cooker": 80, "fertilizer bomb": 85,
        "incel attack": 85, "misogynistic": 60, "incel manifesto": 90,
        "rape threat": 85, "sexual assault threat": 80,
        # Chinese more
        "连续作案": 85, "模仿犯罪": 55, "公共场所行凶": 95,
        "暗杀": 85, "针对性杀害": 90, "土制炸弹": 90,
        "单身攻击": 85, "厌女攻击": 85, "强奸威胁": 85,
        # New attack methods
        "car attack": 80, "vehicle attack": 80, "truck attack": 85,
        "ramming attack": 85, "vehicle ramming": 90,
        "machete": 80, "sword": 70, "acid throwing": 90, "glass attack": 75,
        # Infrastructure
        "power grid": 80, "water supply": 75, "food tampering": 80,
        "airline threat": 85, "maritime threat": 75,
        # 2026-02-18 NEW - Emerging attack vectors
        "airtag stalking": 70, "airtag tracking": 70, "find my weapon": 80,
        "crowdstrike": 55, "global outage": 60, "supply chain attack": 75,
        "ransomware as service": 70, "ransomware-aaa": 70, "raas": 70,
        "botnet ddos": 65, "iot exploit": 60, "smart device hack": 55,
        "car hack": 70, "vehicle exploit": 75, "tesla hack": 65,
        # Chinese 2026-02
        "定位器跟踪": 70, "电子定位": 65, "全球停电": 60,
        "供应链攻击": 75, "勒索软件服务": 70, "物联网漏洞": 60,
        "智能设备入侵": 55, "汽车破解": 70, "车辆漏洞": 75,
        # 2026-02-17 auto-optimize v3
        "clop ransomware": 75, "lockbit": 70, "alphv": 70, "ransum": 65,
        "cpu exhaustion": 55, "memory exhaustion": 55, "disk exhaustion": 50,
        "api abuse": 60, "rate limit bypass": 65, "waf bypass": 70,
        "cdn bypass": 65, "tor browser": 50, "dark web": 55,
        # Chinese 2026-02 v2
        "蓝屏攻击": 55, "资源耗尽": 55, "api滥用": 60,
        "流量清洗": 50, "暗网交易": 60, "肉鸡": 65,
        "僵尸网络": 70, "挖矿木马": 60, "供应链投毒": 80,
        # 2026 emerging social
        "deepfake scam": 75, "ai客服诈骗": 70, "virtual kidnapping": 80,
        "ai voice fraud": 70, "video call scam": 75, "face swap scam": 75,
        # 2026-02-18 new
        "crypto drainer": 75, "approval phishing": 70, "address poisoning": 65,
        "ice phishing": 65, "bridge exploit": 80, "mixer": 55,
        # Chinese crypto threats
        "币圈诈骗": 70, "跑路": 65, "土狗": 50, "貔貅": 60,
        # 2026-02 new attack surfaces
        "esim swap": 70, "callback phishing": 75, "vat phishing": 70,
        "adversary in the middle": 80, "aitm": 75,
        
        # 2026-02-18 MORE emerging threats
        "ai cloning": 70, "digital twin attack": 75, "synthetic identity fraud": 70,
        "voice deepfake scam": 75, "video deepfake extortion": 80,
        "xr attack": 65, "vr assault": 70, "metaverse threat": 60,
        "iot ransomware": 70, "smart home hack": 65, "connected car threat": 70,
        "medical device hack": 85, "implant attack": 90, "pacemaker hack": 95,
        # 2026 election threats
        "election interference": 80, "vote manipulation": 85, "deepfake candidate": 75,
        "disinformation campaign": 65, "foreign influence": 75,
        # Space threats
        "space weapon": 90, "satellite jamming": 80, "orbital strike": 95,
        # Chinese 2026
        "元宇宙攻击": 65, "虚拟现实威胁": 70, "数字人诈骗": 75,
        "AI克隆": 70, "深度伪造敲诈": 80, "智能设备入侵": 65,
        "医疗设备黑客": 85, "植入物攻击": 90, "起搏器黑客": 95,
        "选举干预": 80, "投票操纵": 85, "虚假候选人": 75,
        "卫星干扰": 80, "轨道武器": 95,
        # 2026-02-18 auto-optimize new
        "glovo": 50, "food delivery": 45, "uber": 50,
        "delivery hijack": 70, "package intercept": 65,
        "ceo fraud": 75, "business email": 70, "wire fraud": 75,
        # 2026-02-18 NEWEST - Feb 18
        "quantum decryption": 85, "harvest now decrypt later": 90, "store now break later": 85,
        "ai agent attack": 75, "autonomous hacking": 80, "self-propagating malware": 85,
        "social graph attack": 70, "relationship exploit": 65, "family targeting": 75,
        # Chinese newest
        "量子解密": 85, "现在存储以后破解": 90, "AI智能体攻击": 75,
        "自主黑客": 80, "自传播恶意软件": 85, "社交图谱攻击": 70,
        # 2026-02-18 auto-optimize additional
        "clone attack": 75, "identity theft": 65, "passport fraud": 70,
        "fingerprint hack": 75, "retina scan bypass": 80, "biometric hack": 75,
        "smart dust": 85, "nanobot": 80, "microscopic weapon": 90,
        "emp attack": 95, "electromagnetic pulse": 95, "power outage": 60,
        # 2026 emerging
        "brain computer": 65, "neural interface": 70, "mind hack": 80,
        "thought attack": 85, "cognitive warfare": 75, "memory manipulation": 80,
        # 2026-02-18 auto-optimize additions
        "airdrop scam": 55, "nft mint scam": 60, "discord scam": 55,
        "fake exchange": 65, "ponzi scheme": 70, "pyramid scheme": 70,
        "pig butchering scam": 75, "employment scam": 60, "investment scam": 65,
        # Social engineering 2026
        "deepfakeceo": 80, "fake meeting": 70, "virtual abduction": 85,
        "ai kidnapping": 80, "simulation attack": 75, "synthetic witness": 70,
        # Infrastructure 2026
        "water hack": 80, "dam hack": 85, "traffic light hack": 70,
        "smart city attack": 75, "iot botnet": 60, "firmware attack": 70,
        # Chinese emerging
        "空气净化器攻击": 75, "智能家居漏洞": 65, "汽车远程入侵": 70,
        "无人机集群攻击": 85, "区块链攻击": 65, "Defi攻击": 70,
        # 2026-02-18 Auto-Optimize: NEW emerging threats
        "ai诈骗": 65, "语音伪造": 70, "视频伪造": 70, "裸聊诈骗": 80,
        "虚假绑架": 80, "ai换脸": 65, "深度伪造": 70, "勒索视频": 75,
        "快递诈骗": 60, "刷单诈骗": 65, "虚假投资": 70, "假冒客服": 65,
        "FaceTime诈骗": 70, "苹果ID诈骗": 75, "钓鱼链接": 60,
        "无人机袭": 85, "植入侵入": 90, "智能穿戴攻击": 75,
        "汽车黑客": 70, "远程控制": 65, "电网攻击": 80, "水务攻击": 75,
        "交通系统": 70, "智慧城市漏洞": 65, "工业控制系统": 80, "scada攻击": 85,
        "网络暴力": 65, "软暴力": 60, "精神控制": 75, "pua": 70,
        "职场霸凌": 65, "校园霸凌": 70, "网络敲诈": 75,
        # English 2026 new
        "facetime scam": 70, "apple id scam": 75, "brushing scam": 65,
        "fake investment": 70, "fake customer service": 65, "deepfake ransom": 75,
        "ai voice scam": 70, "video call scam": 75, "smart wearable": 65,
        "wearable hack": 70, "implant hack": 90, "car remote hack": 70,
        "vehicle remote": 70, "power grid attack": 80, "water system": 75,
        "traffic control": 70, "smart city": 65, "ics attack": 80, "scada": 85,
        "industrial control": 80, "dam attack": 85, "cyberbullying": 55,
        "online bullying": 55, "soft violence": 60, "spiritual abuse": 75,
        "gaslighting": 70, "mobbing": 65, "workplace bullying": 65, "school bullying": 70,
        # 2026-02-18 late additional
        "data breach": 60, "info leak": 55, "privacy violation": 55,
        "doxxing service": 65, "swatting service": 80, "bomb threat call": 90,
        "fake emergency call": 75, "hoax threat": 70, "copycat threat": 55,
        # 2026 financial
        "pig butchering": 75, "crypto scam": 65, "nft scam": 55,
        "rug pull": 60, "pump dump": 55, "honeypot": 55,
        # Chinese late
        "数据泄露": 60, "信息泄露": 55, "隐私侵犯": 55,
        "人肉服务": 65, "炸弹威胁电话": 90, "虚假报警": 75,
        "杀猪盘": 75, "加密货币诈骗": 65, "NFT诈骗": 55,
    }
    
    # Chinese social engineering - NEW section
    CHINESE_SOCIAL_ENGINEERING = {
        "ai客服": 55, "虚拟绑架": 80, "视频ai换脸": 75,
        "仿冒公检法": 75, "仿冒领导": 70, "杀鱼": 55,
        # 2026 new vectors
        "quantum threat": 80, "post-quantum": 75, "encryption break": 85,
        "nuclear comms": 90, "satellite hijack": 85, "gps spoof": 75,
    }
    
    # 威胁类型分类
    THREAT_CATEGORIES = {
        "physical_violence": ["kill", "murder", "shoot", "attack", "stab", "hurt", "assault", "abuse", "rampage", "spree"],
        "terrorism": ["terrorist", "bomb", "explosion", "massacre", "bioweapon", "chemical weapon", "radiation"],
        "self_harm": ["end it all", "suicide", "want to die", "give up", "no reason to live"],
        "harassment": ["threaten", "harass", "stalk", "bullying", "intimidate", "doxxing", "swatting"],
        "property_crime": ["steal", "rob", "burglary", "vandalism", "fraud", "extortion", "embezzlement"],
        "cyber_threat": ["hack", "breach", "ddos", "malware", "ransomware", "cyberattack", "sql injection", "exploit", "backdoor", "phishing"],
        "ai_threat": ["deepfake", "ai attack", "ai-generated", "voice clone", "synthetic media"],
        "mass_casualty": ["mass shooting", "mass stabbing", "vehicle ramming", "crowd attack", "drive by"],
    }
    
    def __init__(self):
        self.threat_keywords = self.VIOLENCE_KEYWORDS.copy()
        # Merge Chinese social engineering keywords
        self.threat_keywords.update(self.CHINESE_SOCIAL_ENGINEERING)
    
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
            # NEW: 2026 patterns
            (r"in.*(hours?|minutes?)", "urgency", 15, "短时间行动意图"),
            (r"final.*warning", "urgency", 25, "最后警告"),
            (r"time.*is.*running", "urgency", 20, "时间紧迫"),
            (r"before.*(midnight|sunrise|sunset)", "urgency", 20, "特定时间窗口"),
            (r"once.*(in|upon).*time", "urgency", 15, "特定时机"),
            # Additional urgency patterns
            (r"at (\d+)\s*(am|pm)", "urgency", 15, "指定时间行动"),
            (r"in (\d+)\s*hours?", "urgency", 15, "倒计时行动"),
            (r"final.*warning", "urgency", 25, "最后警告"),
            (r"time.*is.*running", "urgency", 20, "时间紧迫"),
            # 2026-02-18 more urgency
            (r"last.*chance", "urgency", 20, "最后机会"),
            (r"no.*more.*time", "urgency", 25, "没有时间了"),
            (r"soon.*happen", "urgency", 20, "即将发生"),
            (r"waiting.*too long", "urgency", 15, "等待太久"),
            (r"clock.*ticking", "urgency", 20, "时钟滴答"),
            # Chinese urgency
            (r"(最后|最终).*机会", "urgency", 20, "中文最后机会"),
            (r"没有.*时间", "urgency", 25, "中文没时间"),
            (r"(马上|立即|立刻).*行动", "urgency", 25, "中文立即行动"),
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
            # 2026-02-18 more targeting
            (r"my (husband|wife|spouse|partner)", "targeted", 30, "配偶目标"),
            (r"my (father|mother|parent|dad|mom)", "targeted", 25, "父母目标"),
            (r"my (brother|sister|sibling)", "targeted", 20, "兄弟姐妹目标"),
            (r"(kids|children|child|son|daughter)", "targeted", 25, "儿童目标"),
            (r"(kids|children).*deserve", "targeted", 35, "儿童受害意图"),
            (r"at.*(park|mall|store|church|temple)", "targeted", 20, "公共场所目标"),
            (r"(random|anyone|anybody).*die", "targeted", 40, "无差别伤害"),
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
            # 2026 new emotional patterns
            (r"always.*(tired|exhausted)", "emotional", 25, "持续疲劳厌世"),
            (r"(nobody|no one).*miss", "emotional", 35, "认为无人会在乎"),
            (r"better.*without.*me", "emotional", 40, "死亡念头"),
            (r"final.*(goodbye|message)", "emotional", 50, "遗书迹象"),
            # 2026-02 new patterns
            (r"(3d|ghost).*print", "planning", 30, "3D打印武器"),
            (r"engineered.*virus", "planning", 45, "工程病毒计划"),
            (r"synthetic.*(biology|dna)", "planning", 40, "合成生物学威胁"),
            # 2026-02-18 more patterns
            (r"buy.*(knife|gun|weapon)", "planning", 35, "购买武器意图"),
            (r"order.*(knife|gun|weapon)", "planning", 35, "订购武器意图"),
            (r"get.*(knife|gun)", "planning", 30, "获取武器意图"),
            (r"learn.*(bomb|explosive)", "planning", 40, "学习爆炸物制作"),
            (r"how to make.*(bomb|poison)", "planning", 45, "制毒制爆学习"),
            (r"mix.*(chemical|poison)", "planning", 40, "混合化学品"),
            (r"store.*(weapon|knife)", "planning", 25, "储存武器"),
            # 2026-02-18 additional emotion patterns
            (r"(worth|living).*nothing", "emotional", 35, "认为活着没价值"),
            (r"(everyone|everybody).*hate", "emotional", 30, "认为所有人都可恨"),
            (r"(painful|hurt).*inside", "emotional", 30, "内心痛苦"),
            (r"just.*(want|need).*sleep.*forever", "emotional", 40, "想永远沉睡"),
            (r"(end|finish).*everything", "emotional", 45, "想要结束一切"),
            (r"(kill|murder).*everyone", "emotional", 50, "想要杀掉所有人"),
            # Chinese additional emotion
            (r"(孤单|孤独|寂寞).*死", "emotional", 35, "中文孤独死志"),
            (r"(压力大|崩溃|受够了)", "emotional", 30, "中文压力崩溃"),
            (r"(活着|人生).*没希望", "emotional", 35, "中文绝望"),
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
