# main.py
import threading
import time
from src.log_collector import LogCollector
from src.log_parser import LogParser
from src.threat_detector import ThreatDetector
from src.dashboard import app
from elasticsearch import Elasticsearch

def main():
    print("🚀 Starting SIEM Tool...")
    
    # Initialize Elasticsearch client
    es_client = Elasticsearch("http://localhost:9200")
    
    # Test Elasticsearch connection
    try:
        es_client.ping()
        print("✅ Connected to Elasticsearch")
    except Exception as e:
        print(f"❌ Failed to connect to Elasticsearch: {e}")
        print("Please make sure Elasticsearch is running on localhost:9200")
        return
    
    # Initialize components
    log_collector = LogCollector()
    log_parser = LogParser(es_client)
    threat_detector = ThreatDetector(es_client)
    
    # Start log collection in a separate thread
    collector_thread = threading.Thread(target=log_collector.start_collection)
    collector_thread.daemon = True
    collector_thread.start()
    
    # Start threat detection in a separate thread
    def threat_detection_loop():
        while True:
            try:
                alerts = threat_detector.detect_threats()
                if alerts:
                    print(f"🚨 Generated {len(alerts)} new alerts")
                time.sleep(30)  # Check for threats every 30 seconds
            except Exception as e:
                print(f"❌ Error in threat detection: {e}")
                time.sleep(30)
    
    detector_thread = threading.Thread(target=threat_detection_loop)
    detector_thread.daemon = True
    detector_thread.start()
    
    # Start the web dashboard
    print("🌐 Starting web dashboard on http://localhost:5000")
    app.run(debug=False, host="0.0.0.0", port=5000)

if __name__ == "__main__":
    main()