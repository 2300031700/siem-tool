# src/log_collector.py

import os
import time
import json
from datetime import datetime

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from elasticsearch import Elasticsearch


# Project base directory
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class LogFileHandler(FileSystemEventHandler):

    def __init__(self, es_client, index_prefix):
        self.es_client = es_client
        self.index_prefix = index_prefix
        self.last_position = {}

    def on_modified(self, event):
        if not event.is_directory:
            print("📄 File changed:", event.src_path)
            self.process_log_file(event.src_path)

    def process_log_file(self, file_path):

        try:
            last_pos = self.last_position.get(file_path, 0)

            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:

                f.seek(last_pos)
                new_lines = f.readlines()

                self.last_position[file_path] = f.tell()

                for line in new_lines:
                    if line.strip():
                        self.index_log_entry(file_path, line.strip())

        except Exception as e:
            print(f"❌ Error reading {file_path}: {e}")

    def index_log_entry(self, file_path, log_line):

        doc = {
            "timestamp": datetime.now().isoformat(),
            "source_file": file_path,
            "raw_log": log_line,
            "processed": False
        }

        index_name = f"{self.index_prefix}-{datetime.now().strftime('%Y.%m.%d')}"

        self.es_client.index(index=index_name, document=doc)


class LogCollector:

    def __init__(self, config_path="config/log_sources.json"):

        self.config = self.load_config(config_path)

        self.es_client = Elasticsearch(
            "http://localhost:9200",
            request_timeout=30
        )

        self.observer = Observer()
        self.handlers = []

    def load_config(self, config_path):

        full_path = os.path.join(BASE_DIR, config_path)

        with open(full_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def start_collection(self):

        for source in self.config["log_sources"]:

            log_path = source["path"]

            # Make absolute path
            if not os.path.isabs(log_path):
                log_path = os.path.join(BASE_DIR, log_path)

            if not os.path.exists(log_path):
                print(f"❌ Path not found: {log_path}")
                continue

            print(f"✅ Watching: {log_path}")

            handler = LogFileHandler(
                self.es_client,
                source.get("index_prefix", "siem-logs")
            )

            self.handlers.append(handler)

            self.observer.schedule(
                handler,
                log_path,
                recursive=source.get("recursive", False)
            )

        self.observer.start()
        print("🚀 Log collection started...")

        try:
            while True:
                time.sleep(1)

        except KeyboardInterrupt:
            print("\n🛑 Stopping collector...")
            self.observer.stop()

        self.observer.join()


if __name__ == "__main__":

    collector = LogCollector()
    collector.start_collection()
