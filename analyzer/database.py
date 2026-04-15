import sqlite3
import os
from datetime import datetime

# Place database at the root of the project
DB_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'ids_alerts.db'))

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    # Create ThreatLogs table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ThreatLogs (
            Id INTEGER PRIMARY KEY AUTOINCREMENT,
            SourceIp TEXT NOT NULL,
            ThreatType TEXT NOT NULL,
            TargetPort INTEGER,
            Description TEXT,
            Timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

def log_threat(source_ip, threat_type, target_port, description):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute('''
        INSERT INTO ThreatLogs (SourceIp, ThreatType, TargetPort, Description, Timestamp)
        VALUES (?, ?, ?, ?, ?)
    ''', (source_ip, threat_type, target_port, description, timestamp))
    
    conn.commit()
    conn.close()
