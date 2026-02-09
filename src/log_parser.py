# src/log_parser.py
import re
import json
from datetime import datetime
from elasticsearch import Elasticsearch

class LogParser:
    def __init__(self, es_client):
        self.es_client = es_client
        self.parsers = {
            'apache': self.parse_apache_log,
            'firewall': self.parse_firewall_log,
            'json': self.parse_json_log,
            'windows': self.parse_windows_log
        }
        
    def parse_apache_log(self, log_line):
        """Parse Apache access log format"""
        # Common Apache Log Format
        pattern = r'(\S+) \S+ \S+ $$([\w:/]+\s[+\-]\d{4})$$ "(\S+) (\S+) (\S+)" (\d{3}) (\d+) "([^"]*)" "([^"]*)"'
        match = re.match(pattern, log_line)
        
        if match:
            ip, timestamp, method, path, protocol, status, size, referer, user_agent = match.groups()
            
            # Convert timestamp to ISO format
            try:
                dt = datetime.strptime(timestamp, '%d/%b/%Y:%H:%M:%S %z')
                iso_timestamp = dt.isoformat()
            except ValueError:
                iso_timestamp = timestamp
            
            return {
                'timestamp': iso_timestamp,
                'ip_address': ip,
                'method': method,
                'path': path,
                'protocol': protocol,
                'status_code': int(status),
                'response_size': int(size),
                'user_agent': user_agent,
                'raw_log': log_line
            }
        
        return None
    
    def parse_firewall_log(self, log_line):
        """Parse firewall log format"""
        # Example: 2023-01-15 10:15:30 DENY TCP 192.168.1.1:12345 -> 10.0.0.1:80
        pattern = r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (\S+) (\S+) (\S+:\d+) -> (\S+:\d+)'
        match = re.match(pattern, log_line)
        
        if match:
            timestamp, action, protocol, source, destination = match.groups()
            
            # Convert timestamp to ISO format
            iso_timestamp = f"{timestamp}Z"
            
            # Parse IP and port
            source_ip, source_port = source.split(':')
            dest_ip, dest_port = destination.split(':')
            
            return {
                'timestamp': iso_timestamp,
                'action': action,
                'protocol': protocol,
                'source_ip': source_ip,
                'source_port': int(source_port),
                'destination_ip': dest_ip,
                'destination_port': int(dest_port),
                'raw_log': log_line
            }
        
        return None
    
    def parse_json_log(self, log_line):
        """Parse JSON log format"""
        try:
            log_data = json.loads(log_line)
            
            # Ensure timestamp is in ISO format
            if 'timestamp' in log_data:
                timestamp = log_data['timestamp']
                # If timestamp is not in ISO format, convert it
                if not timestamp.endswith('Z') and '+' not in timestamp:
                    iso_timestamp = f"{timestamp}Z"
                else:
                    iso_timestamp = timestamp
                log_data['timestamp'] = iso_timestamp
            
            # Add raw log
            log_data['raw_log'] = log_line
            
            return log_data
        except json.JSONDecodeError:
            return None
    
    def parse_windows_log(self, log_line):
        """Parse Windows Event Log format"""
        # This is a simplified parser for Windows logs
        # You may need to adjust it based on your specific log format
        pattern = r'(\d{1,2}/\d{1,2}/\d{4} \d{1,2}:\d{2}:\d{2} [AP]M) (\S+) (\S+) (.*)'
        match = re.match(pattern, log_line)
        
        if match:
            timestamp, computer, source, message = match.groups()
            
            # Convert timestamp to ISO format
            try:
                dt = datetime.strptime(timestamp, '%m/%d/%Y %I:%M:%S %p')
                iso_timestamp = dt.isoformat()
            except ValueError:
                iso_timestamp = timestamp
            
            return {
                'timestamp': iso_timestamp,
                'computer': computer,
                'source': source,
                'message': message,
                'raw_log': log_line
            }
        
        return None
    
    def parse_log(self, log_line, log_type='apache'):
        """Parse a log line based on its type"""
        parser = self.parsers.get(log_type)
        if parser:
            return parser(log_line)
        return None
    
    def index_log(self, parsed_log, index_name):
        """Index a parsed log into Elasticsearch"""
        try:
            self.es_client.index(index=index_name, body=parsed_log)
        except Exception as e:
            print(f"Error indexing log: {e}")
    
    def get_log_type(self, log_line):
        """Determine the type of log based on its content"""
        if log_line.strip().startswith('{') and log_line.strip().endswith('}'):
            return 'json'
        elif re.search(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}', log_line):
            if 'DENY' in log_line or 'ALLOW' in log_line or 'ACCEPT' in log_line:
                return 'firewall'
            else:
                return 'windows'
        elif re.search(r'\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}', log_line):
            return 'apache'
        else:
            return 'unknown'