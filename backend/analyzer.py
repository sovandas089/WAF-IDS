import re
import yaml
import time
import asyncio
from typing import Dict, List, Optional
from backend.blocker import block_ip
from backend.mailer import send_alert_email

# Load rules
with open("backend/rules.yaml", "r") as f:
    config = yaml.safe_load(f)

RULES = config.get("rules", {})
THRESHOLDS = config.get("thresholds", {})

# IP Tracking for rate limiting
ip_tracker: Dict[str, List[float]] = {}
blocked_ips = set()

# A queue to hold alerts to be sent to frontend
alerts_queue = asyncio.Queue()

# Scores memory
# Track accumulated points per IP
ip_scores: Dict[str, int] = {}

def check_rate_limit(ip: str) -> bool:
    """Returns True if the IP has exceeded rate limit thresholds"""
    now = time.time()
    max_reqs = THRESHOLDS.get("brute_force", {}).get("max_requests", 20)
    time_win = THRESHOLDS.get("brute_force", {}).get("time_window_seconds", 10)

    if ip not in ip_tracker:
        ip_tracker[ip] = []

    # Clean up old timestamps
    ip_tracker[ip] = [t for t in ip_tracker[ip] if now - t < time_win]
    ip_tracker[ip].append(now)

    if len(ip_tracker[ip]) > max_reqs:
        return True
    return False

def analyze_payload(payload: str, rule_category: str) -> bool:
    """Check payload against defined rules in a category."""
    if not payload: return False
    patterns = RULES.get(rule_category, [])
    for pattern in patterns:
        if re.search(pattern, payload):
            return True
    return False

async def analyze_request(ip: str, method: str, path: str, body: str) -> bool:
    """
    Evaluates an HTTP request and returns True if it should be BLOCKED.
    Applies the new scoring engine.
    """
    if ip in blocked_ips:
        return True

    score = 0
    reasons = []

    # Rate limiting
    if check_rate_limit(ip):
        score += 10
        reasons.append("High request rate (Brute Force)")

    # SQLi
    if analyze_payload(path, "sqli") or analyze_payload(body, "sqli"):
        score += 5
        reasons.append("SQL Injection detected")

    # XSS
    if analyze_payload(path, "xss") or analyze_payload(body, "xss"):
        score += 5
        reasons.append("Cross-Site Scripting (XSS) detected")

    if score > 0:
        # Accumulate score for IP
        ip_scores[ip] = ip_scores.get(ip, 0) + score
        
        # Dispatch Email Alert
        severity = get_severity(score)
        if severity in ["CRITICAL", "HIGH", "MEDIUM"]:
             asyncio.create_task(send_alert_email(severity, ip, method, path, ", ".join(reasons)))
        
        # Save to Persistent Storage
        from backend.database import SessionLocal
        from backend.models import AlertLog
        def _save_alert():
            with SessionLocal() as db:
                alert_entry = AlertLog(src_ip=ip, method=method, path=path, severity=severity, score=score, reasons=", ".join(reasons), snippet=body[:200] if body else "")
                db.add(alert_entry)
                db.commit()
        asyncio.create_task(asyncio.to_thread(_save_alert))

        # Dispatch Web Alert
        alert = {
            "alert_type": "payload_match" if score < 10 else "brute_force",
            "src_ip": ip,
            "message": f"Suspicious activity. Reasons: {', '.join(reasons)}. Score added: {score}",
            "content_snippet": f"{method} {path} | Body: {body[:50] if body else 'empty'}"
        }
        await alerts_queue.put(alert)

        # Block Threshold is 10 or more points
        if ip_scores[ip] >= 10 and ip not in blocked_ips:
            blocked_ips.add(ip)
            success, msg = block_ip(ip)

            block_alert = {
                "alert_type": "brute_force",
                "src_ip": ip,
                "message": f"IP BLOCKED! Total Score: {ip_scores[ip]}. {msg}",
                "content_snippet": "Threshold exceeded."
            }
            await alerts_queue.put(block_alert)
            return True

    return False

def get_severity(score: int) -> str:
    if score >= 10: return "CRITICAL"
    if score >= 5: return "HIGH"
    if score > 0: return "MEDIUM"
    return "LOW"

def offline_analyze_request(ip: str, method: str, path: str, body: str) -> dict:
    """
    Evaluates an HTTP request from a PCAP. Returns a log dictionary without 
    triggering live bans or websockets.
    """
    score = 0
    reasons = []

    # SQLi
    if analyze_payload(path, "sqli") or analyze_payload(body, "sqli"):
        score += 5
        reasons.append("SQL Injection detected")

    # XSS
    if analyze_payload(path, "xss") or analyze_payload(body, "xss"):
        score += 5
        reasons.append("Cross-Site Scripting (XSS) detected")

    if score == 0:
        reasons.append("No threat detected")

    severity = get_severity(score)
    
    return {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "src_ip": ip,
        "method": method,
        "path": path,
        "score": score,
        "severity": severity,
        "reasons": ", ".join(reasons),
        "snippet": body[:50] if body else ""
    }
