import smtplib
from email.message import EmailMessage
import time
import asyncio
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ==========================================
# SMTP CONFIGURATION
# Fill these in with your real credentials
# ==========================================
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USER = "sovandas089@gmail.com"
SMTP_PASS = "deyvlvatwzqujwsi"
RECIPIENT_EMAIL = "sova.btl23cs08@opju.ac.in"
ALERT_ENABLED = True  # Change to True when you want real emails to be sent

def generate_email_body(severity, ip, method, path, reasons):
    date_str = time.strftime("%Y-%m-%d %H:%M:%S")
    body = f"""Dear Team 🚨,

This is to inform you that a **{severity} severity security event** has been detected in the environment and requires immediate attention.

**Event Summary:**

* **Severity:** {severity}
* **Detected On:** {date_str}
* **Source IP / Host:** {ip}
* **Affected System/Application:** WAF Reverse Proxy (Path: {path})
* **Event Type:** {reasons}

**Brief Description:**
The WAF engine intercepted a live HTTP request containing signatures matching known attack vectors.

**Impact:**
This event may pose a potential risk to system integrity, data security, and service availability if not addressed promptly.

**Immediate Actions Required:**

* Investigate the event and validate its authenticity.
* Check logs and related indicators for further insights.
* Isolate affected systems if necessary.
* Apply mitigation steps as per incident response procedures.

Kindly prioritize this issue and provide an update on the findings and actions taken at the earliest.

Please treat this as **URGENT**.

Regards,
SOC Alerting Engine
Security Operations Center
WAFGuardian 
"""
    return body

async def send_alert_email(severity, ip, method, path, reasons):
    body = generate_email_body(severity, ip, method, path, reasons)
    
    if not ALERT_ENABLED:
        logger.warning(f"============================================================")
        logger.warning(f"EMAIL TRIGGERED BUT SMTP IS DISABLED. SIMULATED EMAIL OUTPUT:")
        logger.warning(f"============================================================")
        print(body)
        logger.warning(f"============================================================")
        return

    def _send():
        msg = EmailMessage()
        msg.set_content(body)
        msg['Subject'] = f"URGENT: {severity} Security Alert Detected from {ip}"
        msg['From'] = SMTP_USER
        msg['To'] = RECIPIENT_EMAIL

        try:
            server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)
            server.quit()
            logger.info("Successfully sent alert email.")
        except Exception as e:
            logger.error(f"Failed to send email alert: {str(e)}")

    # Run blocking SMTP calls in a background thread so we don't freeze the WAF
    await asyncio.to_thread(_send)
