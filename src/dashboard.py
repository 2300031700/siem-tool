# src/dashboard.py
from flask import Flask, render_template, jsonify, request
import json
from datetime import datetime, timedelta
from elasticsearch import Elasticsearch

import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static")
)

es = Elasticsearch([{"host": "localhost", "port": 9200, "scheme": "http"}])

@app.route('/')
def index():
    return render_template('dashboard.html')

@app.route('/api/alerts')
def get_alerts():
    # Get the most recent alerts
    query = {
        "query": {
            "range": {
                "timestamp": {
                    "gte": (datetime.now() - timedelta(hours=24)).isoformat(),
                    "lte": datetime.now().isoformat()
                }
            }
        },
        "sort": [
            {
                "timestamp": {
                    "order": "desc"
                }
            }
        ],
        "size": 50
    }
    
    results = es.search(index="siem-alerts", body=query)
    alerts = [hit["_source"] for hit in results["hits"]["hits"]]
    
    return jsonify(alerts)

@app.route('/api/stats')
def get_stats():
    # Get statistics for the dashboard
    current_time = datetime.now()
    time_24h_ago = current_time - timedelta(hours=24)
    
    # Get total alerts in the last 24 hours
    alerts_query = {
        "query": {
            "range": {
                "timestamp": {
                    "gte": time_24h_ago.isoformat(),
                    "lte": current_time.isoformat()
                }
            }
        },
        "size": 0,
        "aggs": {
            "severity_breakdown": {
                "terms": {
                    "field": "severity"
                }
            }
        }
    }
    
    # Get total logs in the last 24 hours
    logs_query = {
        "query": {
            "range": {
                "timestamp": {
                    "gte": time_24h_ago.isoformat(),
                    "lte": current_time.isoformat()
                }
            }
        },
        "size": 0
    }
    
    alerts_results = es.search(index="siem-alerts", body=alerts_query)
    logs_results = es.search(index="*", body=logs_query)
    
    stats = {
        "total_alerts": alerts_results["hits"]["total"]["value"],
        "total_logs": logs_results["hits"]["total"]["value"],
        "severity_breakdown": {
            bucket["key"]: bucket["doc_count"] 
            for bucket in alerts_results["aggregations"]["severity_breakdown"]["buckets"]
        }
    }
    
    return jsonify(stats)

@app.route('/api/logs')
def get_logs():
    # Get recent logs
    query = {
        "query": {
            "range": {
                "timestamp": {
                    "gte": (datetime.now() - timedelta(hours=1)).isoformat(),
                    "lte": datetime.now().isoformat()
                }
            }
        },
        "sort": [
            {
                "timestamp": {
                    "order": "desc"
                }
            }
        ],
        "size": 100
    }
    
    results = es.search(index="*", body=query)
    logs = [hit["_source"] for hit in results["hits"]["hits"]]
    
    return jsonify(logs)

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)