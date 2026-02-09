# src/threat_detector.py
import re
import json
from datetime import datetime, timedelta
from elasticsearch import Elasticsearch
from collections import defaultdict

class ThreatDetector:
    def __init__(self, es_client):
        self.es_client = es_client
        self.rules = self.load_rules("config/threat_rules.json")
        self.alert_thresholds = {
            "failed_login": 5,  # Alert after 5 failed logins
            "port_scan": 10,    # Alert after 10 port scan attempts
            "suspicious_ip": 3  # Alert after 3 events from suspicious IP
        }
        
    def load_rules(self, rules_path):
        try:
            with open(rules_path, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            # Default rules if file doesn't exist
            return {
                "rules": [
                    {
                        "name": "Multiple Failed Logins",
                        "description": "Detects multiple failed login attempts",
                        "pattern": "failed.*login|authentication.*failed",
                        "time_window": "5m",
                        "threshold": 5,
                        "severity": "medium"
                    },
                    {
                        "name": "Port Scan Detection",
                        "description": "Detects potential port scanning activity",
                        "pattern": "port.*scan|connection.*refused",
                        "time_window": "2m",
                        "threshold": 10,
                        "severity": "high"
                    },
                    {
                        "name": "Suspicious IP Activity",
                        "description": "Detects activity from known malicious IPs",
                        "pattern": "suspicious.*ip|malicious.*source",
                        "time_window": "10m",
                        "threshold": 1,
                        "severity": "critical"
                    }
                ]
            }
    
    def detect_threats(self, time_window_minutes=10):
        alerts = []
        current_time = datetime.now()
        time_window = current_time - timedelta(minutes=time_window_minutes)
        
        # Get recent logs from Elasticsearch
        query = {
            "query": {
                "range": {
                    "timestamp": {
                        "gte": time_window.isoformat(),
                        "lte": current_time.isoformat()
                    }
                }
            }
        }
        
        # Search across all indices
        results = self.es_client.search(index="*", body=query)
        
        # Process each rule
        for rule in self.rules["rules"]:
            rule_matches = self.apply_rule(rule, results["hits"]["hits"])
            if rule_matches:
                alerts.append({
                    "rule_name": rule["name"],
                    "description": rule["description"],
                    "severity": rule["severity"],
                    "matches": rule_matches,
                    "timestamp": current_time.isoformat()
                })
        
        # Store alerts in Elasticsearch
        for alert in alerts:
            self.es_client.index(index="siem-alerts", document=alert)
        
        return alerts
    
    def apply_rule(self, rule, log_entries):
        pattern = re.compile(rule["pattern"], re.IGNORECASE)
        matches = []
        
        for entry in log_entries:
            log_data = entry["_source"]
            log_text = log_data.get("raw_log", "")
            
            if pattern.search(log_text):
                matches.append({
                    "timestamp": log_data.get("timestamp"),
                    "source": log_data.get("source_file"),
                    "raw_log": log_text
                })
        
        # Check if matches exceed threshold
        if len(matches) >= rule["threshold"]:
            return matches
        
        return []
    
    def check_failed_logins(self, time_window_minutes=5):
        current_time = datetime.now()
        time_window = current_time - timedelta(minutes=time_window_minutes)
        
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"range": {"timestamp": {"gte": time_window.isoformat(), "lte": current_time.isoformat()}}},
                        {"regexp": {"raw_log": ".*failed.*login.*|.*authentication.*failed.*"}}
                    ]
                }
            }
        }
        
        results = self.es_client.search(index="*", body=query)
        
        if len(results["hits"]["hits"]) >= self.alert_thresholds["failed_login"]:
            alert = {
                "rule_name": "Multiple Failed Logins",
                "description": f"Detected {len(results['hits']['hits'])} failed login attempts",
                "severity": "medium",
                "timestamp": current_time.isoformat(),
                "matches": [{"timestamp": hit["_source"]["timestamp"], "raw_log": hit["_source"]["raw_log"]} for hit in results["hits"]["hits"]]
            }
            
            self.es_client.index(index="siem-alerts", document=alert)
            return alert
        
        return None
    
    def check_port_scans(self, time_window_minutes=2):
        current_time = datetime.now()
        time_window = current_time - timedelta(minutes=time_window_minutes)
        
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"range": {"timestamp": {"gte": time_window.isoformat(), "lte": current_time.isoformat()}}},
                        {"term": {"log_type": "firewall"}},
                        {"term": {"action": "DENY"}}
                    ]
                }
            }
        }
        
        results = self.es_client.search(index="*", body=query)
        
        # Group by source IP
        ip_counts = defaultdict(int)
        for hit in results["hits"]["hits"]:
            src_ip = hit["_source"].get("src_ip", "unknown")
            ip_counts[src_ip] += 1
        
        # Check if any IP exceeds threshold
        for ip, count in ip_counts.items():
            if count >= self.alert_thresholds["port_scan"]:
                alert = {
                    "rule_name": "Port Scan Detection",
                    "description": f"Detected port scan from IP {ip} with {count} denied connections",
                    "severity": "high",
                    "timestamp": current_time.isoformat(),
                    "source_ip": ip,
                    "count": count
                }
                
                self.es_client.index(index="siem-alerts", document=alert)
                return alert
        
        return None