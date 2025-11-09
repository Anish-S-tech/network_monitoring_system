#!/usr/bin/env python3
"""
network_monitor.py
Real-time capture -> rule detection -> ML inference -> Splunk HEC -> SQLite audit
"""
import time, json, logging, sys, os
from collections import defaultdict, deque
import pickle

import pyshark
import requests
import numpy as np

from utils import load_config, ensure_dirs, setup_db, now_iso
from sqlalchemy import insert

# ===== load config =====
BASE_DIR = os.path.dirname(__file__)
CFG = load_config(os.path.join(BASE_DIR, "config.yaml"))

# ===== setup logging & folders =====
LOG_DIR = CFG.get("log_dir", "./logs")
PCAP_DIR = CFG.get("pcap_dir", "./pcaps")
DB_PATH = CFG.get("db_path", "./data/alerts.db")
ensure_dirs([LOG_DIR, PCAP_DIR, os.path.dirname(DB_PATH)])

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[logging.StreamHandler(sys.stdout),
              logging.FileHandler(os.path.join(LOG_DIR, "agent.log"))]
)
logger = logging.getLogger("netmon")

# ===== setup DB =====
engine, alerts_table = setup_db(DB_PATH)

# ===== Splunk session =====
SPLUNK = CFG.get("splunk", {})
session = requests.Session()
session.verify = SPLUNK.get("verify_ssl", True) if (SPLUNK) else True
HEC_URL = SPLUNK.get("hec_url")
HEC_TOKEN = SPLUNK.get("hec_token")
HEADERS = {"Authorization": f"Splunk {HEC_TOKEN}"} if HEC_TOKEN else {}

# ===== detection params =====
DET = CFG.get("detection", {})
PORTSCAN_T = DET["portscan"]["ports_threshold"]
PORTSCAN_W = DET["portscan"]["window_seconds"]
DDOS_RATE = DET["ddos"]["pkt_rate_threshold"]
DDOS_W = DET["ddos"]["window_seconds"]
SSH_T = DET["ssh_bruteforce"]["attempts_threshold"]
SSH_W = DET["ssh_bruteforce"]["window_seconds"]

# ===== ML setup =====
ML_CFG = CFG.get("ml", {})
ML_ENABLED = ML_CFG.get("enabled", False)
ML_MODEL = None
ML_PATH = ML_CFG.get("model_path")
ML_FEATURES = ML_CFG.get("features", [])
ML_SCORE_T = ML_CFG.get("score_threshold", None)
if ML_ENABLED and ML_PATH and os.path.exists(os.path.join(BASE_DIR, ML_PATH)):
    try:
        with open(os.path.join(BASE_DIR, ML_PATH), "rb") as f:
            ML_MODEL = pickle.load(f)
        logger.info("Loaded ML model from %s", ML_PATH)
    except Exception as e:
        logger.exception("Failed to load ML model: %s", e)
        ML_ENABLED = False

# ===== state =====
port_history = defaultdict(lambda: deque())   # src -> deque of (ts, dst_port)
pkt_history = defaultdict(lambda: deque())    # dst -> deque of ts
ssh_history = defaultdict(lambda: deque())    # src -> deque of ts

# ===== helpers =====
def send_splunk(event):
    if not HEC_URL or not HEC_TOKEN:
        logger.debug("Splunk not configured; skipping send: %s", event.get("type"))
        return
    payload = {
        "time": int(time.time()),
        "host": os.uname().nodename,
        "source": "network_monitor",
        "sourcetype": "_json",
        "event": event
    }
    try:
        r = session.post(HEC_URL, headers=HEADERS, json=payload, timeout=5)
        r.raise_for_status()
        logger.info("Sent event=%s to Splunk", event.get("type"))
    except Exception as e:
        logger.error("Failed to send to Splunk: %s", e)

def persist_alert(event_type, src, dst, details, ml_score=None):
    with engine.begin() as conn:
        conn.execute(insert(alerts_table).values(
            timestamp=now_iso(),
            event_type=event_type,
            src_ip=src,
            dst_ip=dst,
            details=json.dumps(details),
            ml_score=float(ml_score) if ml_score is not None else None
        ))

def sample_packet(pkt):
    # safe extraction; pyshark has dynamic attributes
    try:
        ts = float(getattr(pkt, "sniff_timestamp", time.time()))
    except Exception:
        ts = time.time()
    sample = {"timestamp": ts}
    try:
        if hasattr(pkt, "ip"):
            sample["src_ip"] = pkt.ip.src
            sample["dst_ip"] = pkt.ip.dst
    except: pass
    try:
        if hasattr(pkt, "tcp"):
            sample["src_port"] = pkt.tcp.srcport
            sample["dst_port"] = pkt.tcp.dstport
            sample["flags"] = pkt.tcp.flags
    except: pass
    try:
        if hasattr(pkt, "udp"):
            sample["src_port"] = pkt.udp.srcport
            sample["dst_port"] = pkt.udp.dstport
    except: pass
    try:
        sample["len"] = int(pkt.length)
    except: pass
    return sample

# ===== detection functions =====
def check_portscan(src, dst_port, ts, pkt_sample):
    dq = port_history[src]
    dq.append((ts, dst_port))
    # remove old entries
    while dq and dq[0][0] < ts - PORTSCAN_W:
        dq.popleft()
    distinct = {p for (_, p) in dq}
    if len(distinct) >= PORTSCAN_T:
        desc = f"Port scan from {src} probing {len(distinct)} ports in {PORTSCAN_W}s"
        event = {"type": "portscan", "description": desc, "src": src, "dst": pkt_sample.get("dst_ip"), "ports": list(distinct), "sample": pkt_sample}
        logger.warning(desc)
        send_splunk(event)
        persist_alert("portscan", src, pkt_sample.get("dst_ip"), event)
        dq.clear()

def check_ddos(dst, ts, pkt_sample):
    dq = pkt_history[dst]
    dq.append(ts)
    while dq and dq[0] < ts - DDOS_W:
        dq.popleft()
    pps = len(dq) / max(1, DDOS_W)
    if pps > DDOS_RATE:
        desc = f"DDoS suspected to {dst}: {pps:.1f} pkts/sec"
        event = {"type": "ddos", "description": desc, "dst": dst, "pps": pps, "sample": pkt_sample}
        logger.warning(desc)
        send_splunk(event)
        persist_alert("ddos", pkt_sample.get("src_ip"), dst, event)
        dq.clear()

def check_ssh_bruteforce(src, ts, pkt_sample):
    dq = ssh_history[src]
    dq.append(ts)
    while dq and dq[0] < ts - SSH_W:
        dq.popleft()
    if len(dq) >= SSH_T:
        desc = f"SSH brute force suspected from {src}: {len(dq)} attempts in {SSH_W}s"
        event = {"type": "ssh_bruteforce", "description": desc, "src": src, "attempts": len(dq), "sample": pkt_sample}
        logger.warning(desc)
        send_splunk(event)
        persist_alert("ssh_bruteforce", src, pkt_sample.get("dst_ip"), event)
        dq.clear()

# ===== ML feature extraction (very simple rolling features) =====
rolling_stats = defaultdict(lambda: {"sizes": deque(maxlen=1000), "times": deque(maxlen=1000)})

def extract_features_for_dst(dst):
    stats = rolling_stats[dst]
    times = stats["times"]
    sizes = stats["sizes"]
    if not times:
        return None
    now = time.time()
    # packets/sec in last DDOS_W
    pkt_recent = [t for t in times if t >= now - DDOS_W]
    pkt_rate = len(pkt_recent) / max(1, DDOS_W)
    avg_size = float(np.mean(sizes)) if sizes else 0.0
    # Entropy-like simple proxies (counts unique srcs)
    # For simplicity features are coarse; expand as needed
    return {
        "pkt_rate": pkt_rate,
        "avg_pkt_size": avg_size,
        # placeholders for src/dst entropy etc.
        "src_entropy": len(set(s for s in times)) if False else 0,
        "dst_entropy": 0,
        "protocol_ratio_tcp": 1.0
    }

def ml_infer(dst):
    if not ML_ENABLED or ML_MODEL is None:
        return None
    feats = extract_features_for_dst(dst)
    if feats is None:
        return None
    arr = np.array([feats[f] for f in ML_FEATURES]).reshape(1, -1)
    try:
        score = ML_MODEL.decision_function(arr)[0] if hasattr(ML_MODEL, "decision_function") else ML_MODEL.score_samples(arr)[0]
        # In many IF implementations more negative = more anomalous; tune accordingly
        return float(score)
    except Exception as e:
        logger.exception("ML inference failed: %s", e)
        return None

# ===== packet processing callback =====
def handle_packet(pkt):
    ts = float(getattr(pkt, "sniff_timestamp", time.time()))
    samp = sample_packet(pkt)
    src = samp.get("src_ip")
    dst = samp.get("dst_ip")

    # update rolling stats
    if dst:
        s = rolling_stats[dst]
        s["times"].append(ts)
        if "len" in samp:
            s["sizes"].append(int(samp["len"]))

    # tcp modes
    try:
        if hasattr(pkt, "tcp"):
            # check for SYN without ACK (heuristic)
            flags = str(pkt.tcp.flags)
            dst_port = pkt.tcp.dstport
            if "S" in flags and "A" not in flags:
                if src and dst_port:
                    check_portscan(src, dst_port, ts, samp)
                if dst_port == "22":
                    check_ssh_bruteforce(src, ts, samp)
            if dst:
                check_ddos(dst, ts, samp)
        elif hasattr(pkt, "udp"):
            if dst:
                check_ddos(dst, ts, samp)
    except Exception as e:
        logger.exception("Error in detection: %s", e)

    # ML inference on dst
    if dst:
        score = ml_infer(dst)
        if score is not None:
            logger.debug("ML score for %s = %s", dst, score)
            if ML_SCORE_T is not None and score < ML_SCORE_T:
                event = {"type": "ml_anomaly", "description": f"ML anomaly on {dst} score={score}", "dst": dst, "sample": samp, "score": score}
                send_splunk(event)
                persist_alert("ml_anomaly", samp.get("src_ip"), dst, event, ml_score=score)

# ===== run capture =====
def run():
    iface = CFG.get("interface", "eth0")
    bpf = CFG.get("bpf_filter", "tcp or udp")
    logger.info("Starting capture on %s filter=%s", iface, bpf)
    capture = pyshark.LiveCapture(interface=iface, bpf_filter=bpf)
    try:
        for pkt in capture.sniff_continuously(packet_count=0):
            try:
                handle_packet(pkt)
            except Exception as e:
                logger.exception("handle_packet failure: %s", e)
    except KeyboardInterrupt:
        logger.info("User stopped capture")
    except Exception as e:
        logger.exception("Capture failed: %s", e)

if __name__ == "__main__":
    run()
