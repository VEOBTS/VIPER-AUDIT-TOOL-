import sqlite3
import os

DB_PATH = "viper.db"

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # lets you access columns by name
    return conn

def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    # Table to store each scan job
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            scanned_at TEXT NOT NULL,
            total_findings INTEGER DEFAULT 0,
            report_path TEXT
        )
    """)

    # Table to store individual findings per scan
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            file TEXT,
            rule TEXT,
            message TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        )
    """)

    conn.commit()
    conn.close()