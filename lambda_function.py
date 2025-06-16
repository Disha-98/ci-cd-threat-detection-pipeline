import json
import logging
import re

logger = logging.getLogger()
logger.setLevel(logging.INFO)

THREAT_PATTERNS = [
    (re.compile(r"unauthorized", re.IGNORECASE), "Unauthorized Access"),
    (re.compile(r"brute[\s\-]?force", re.IGNORECASE), "Brute Force Attack"),
    (re.compile(r"sql[\s\-]?injection", re.IGNORECASE), "SQL Injection Attempt"),
    (re.compile(r"(xss|cross[\s\-]?site[\s\-]?scripting)", re.IGNORECASE), "XSS Attempt"),
    (re.compile(r"failed login", re.IGNORECASE), "Multiple Failed Logins"),
    (re.compile(r"(malware|trojan|ransomware)", re.IGNORECASE), "Malware Detected"),
    (re.compile(r"(port scan|nmap)", re.IGNORECASE), "Port Scanning Activity"),
    (re.compile(r"admin access granted from external ip", re.IGNORECASE), "Privileged Access Anomaly"),
    (re.compile(r"(exfiltration|data leak)", re.IGNORECASE), "Data Exfiltration Suspicion"),
    (re.compile(r"(ddos|denial of service)", re.IGNORECASE), "DDoS Activity")
]

def lambda_handler(event, context):
    log_data = event.get("log", "")
    logger.info(f"Processing log: {log_data}")

    alerts = []

    for pattern, alert_type in THREAT_PATTERNS:
        if pattern.search(log_data):
            logger.warning(f" {alert_type} detected!")
            alerts.append(alert_type)

    if alerts:
        return {
            "statusCode": 403,
            "message": "Threats detected",
            "alerts": alerts
        }

    return {
        "statusCode": 200,
        "message": "No threat detected",
        "alerts": []
    }
