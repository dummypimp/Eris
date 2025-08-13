
"""
data_sync.py - Advanced data synchronization with intelligent retry logic and conflict resolution
"""
import asyncio
import json
import time
import threading
import random
from typing import Dict, Any, List, Optional, Callable, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import logging
from datetime import datetime, timedelta

from utils.offline_logger import AdvancedOfflineLogger, LogEntry, BandwidthMetrics


class SyncStatus(Enum):
    """Sync operation status"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    SUCCESS = "success"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ConflictResolution(Enum):
    """Conflict resolution strategies"""
    CLIENT_WINS = "client_wins"
    SERVER_WINS = "server_wins"
    MERGE = "merge"
    MANUAL = "manual"


@dataclass
class SyncOperation:
    """Sync operation data structure"""
    id: str
    entry_ids: List[str]
    priority: int
    status: SyncStatus
    attempts: int
    last_attempt: Optional[float]
    next_attempt: Optional[float]
    created_at: float
    endpoint: str
    retry_delay: float = 1.0


@dataclass
class ConflictItem:
    """Conflict resolution data structure"""
    id: str
    local_entry: LogEntry
    server_entry: Dict[str, Any]
    conflict_type: str
    resolution_strategy: ConflictResolution
    created_at: float
    resolved: bool = False


@dataclass
class SyncStats:
    """Synchronization statistics"""
    total_operations: int
    successful_operations: int
    failed_operations: int
    pending_operations: int
    average_sync_time: float
    last_sync_timestamp: float
    bandwidth_utilization: float
    compression_ratio: float


class ExponentialBackoff:
    """Exponential backoff calculator with jitter"""
    
    def __init__(self, base_delay: float = 1.0, max_delay: float = 300.0,
                 multiplier: float = 2.0, jitter: bool = True):
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.multiplier = multiplier
        self.jitter = jitter
    
    def calculate_delay(self, attempt: int) -> float:
        """Calculate delay for given attempt number"""
        delay = min(self.base_delay * (self.multiplier ** attempt), self.max_delay)
        
        if self.jitter:

            jitter_range = delay * 0.25
            delay += random.uniform(-jitter_range, jitter_range)
        
        return max(delay, 0.1)


class SyncQueue:
    """Priority queue for sync operations with intelligent batching"""
    
    def __init__(self, max_size: int = 1000):
        self.operations: List[SyncOperation] = []
        self.max_size = max_size
        self._lock = threading.RLock()
        self._condition = threading.Condition(self._lock)
    
    def add_operation(self, operation: SyncOperation) -> bool:
        """Add sync operation to queue"""
        try:
            with self._condition:

                self.operations = [op for op in self.operations if op.id != operation.id]
                

                self.operations.append(operation)
                

                self.operations.sort(key=lambda op: (-op.priority, op.created_at))
                

                if len(self.operations) > self.max_size:

                    self.operations = self.operations[:int(self.max_size * 0.9)]
                
                self._condition.notify_all()
                return True
                
        except Exception as e:
            logging.error(f"Failed to add sync operation: {e}")
            return False
    
    def get_ready_operations(self, max_count: int = 10,
                           bandwidth_quality: str = "good") -> List[SyncOperation]:
        """Get operations ready for sync based on bandwidth"""
        try:
            with self._condition:
                current_time = time.time()
                ready_ops = []
                

                batch_sizes = {
                    "excellent": max_count,
                    "good": max(max_count // 2, 1),
                    "poor": max(max_count // 4, 1),
                    "offline": 0
                }
                
                max_batch = batch_sizes.get(bandwidth_quality, 1)
                
                for op in self.operations:
                    if len(ready_ops) >= max_batch:
                        break
                    

                    if (op.status == SyncStatus.PENDING and
                        (op.next_attempt is None or op.next_attempt <= current_time)):
                        ready_ops.append(op)
                
                return ready_ops
                
        except Exception as e:
            logging.error(f"Failed to get ready operations: {e}")
            return []
    
    def update_operation_status(self, operation_id: str, status: SyncStatus,
                              next_attempt: Optional[float] = None) -> bool:
        """Update operation status"""
        try:
            with self._condition:
                for op in self.operations:
                    if op.id == operation_id:
                        op.status = status
                        op.last_attempt = time.time()
                        if next_attempt:
                            op.next_attempt = next_attempt
                        op.attempts += 1
                        return True
                return False
                
        except Exception as e:
            logging.error(f"Failed to update operation status: {e}")
            return False
    
    def remove_operation(self, operation_id: str) -> bool:
        """Remove operation from queue"""
        try:
            with self._condition:
                original_len = len(self.operations)
                self.operations = [op for op in self.operations if op.id != operation_id]
                return len(self.operations) < original_len
                
        except Exception as e:
            logging.error(f"Failed to remove operation: {e}")
            return False
    
    def get_queue_stats(self) -> Dict[str, int]:
        """Get queue statistics"""
        with self._condition:
            stats = {}
            for status in SyncStatus:
                stats[status.value] = sum(1 for op in self.operations
                                        if op.status == status)
            stats["total"] = len(self.operations)
            return stats


class ConflictResolver:
    """Handles data conflicts during synchronization"""
    
    def __init__(self):
        self.conflicts: List[ConflictItem] = []
        self._lock = threading.RLock()
    
    def detect_conflict(self, local_entry: LogEntry,
                       server_data: Dict[str, Any]) -> Optional[ConflictItem]:
        """Detect conflicts between local and server data"""
        try:
            conflicts = []
            

            server_timestamp = server_data.get("timestamp", 0)
            if abs(local_entry.timestamp - server_timestamp) > 60:
                conflicts.append("timestamp")
            

            local_data_str = json.dumps(local_entry.data, sort_keys=True)
            server_data_str = json.dumps(server_data.get("data", {}), sort_keys=True)
            if local_data_str != server_data_str:
                conflicts.append("data")
            

            if local_entry.campaign_id != server_data.get("campaign_id"):
                conflicts.append("campaign")
            
            if conflicts:
                conflict_item = ConflictItem(
                    id=f"conflict_{local_entry.id}_{int(time.time())}",
                    local_entry=local_entry,
                    server_entry=server_data,
                    conflict_type=",".join(conflicts),
                    resolution_strategy=self._determine_resolution_strategy(conflicts),
                    created_at=time.time()
                )
                
                with self._lock:
                    self.conflicts.append(conflict_item)
                
                return conflict_item
            
            return None
            
        except Exception as e:
            logging.error(f"Failed to detect conflict: {e}")
            return None
    
    def _determine_resolution_strategy(self, conflict_types: List[str]) -> ConflictResolution:
        """Determine appropriate conflict resolution strategy"""

        if "campaign" in conflict_types:
            return ConflictResolution.MANUAL
        elif "timestamp" in conflict_types:
            return ConflictResolution.CLIENT_WINS
        else:
            return ConflictResolution.MERGE
    
    def resolve_conflict(self, conflict_id: str, strategy: Optional[ConflictResolution] = None) -> Optional[LogEntry]:
        """Resolve a specific conflict"""
        try:
            with self._lock:
                conflict = None
                for c in self.conflicts:
                    if c.id == conflict_id:
                        conflict = c
                        break
                
                if not conflict:
                    return None
                
                resolution_strategy = strategy or conflict.resolution_strategy
                
                if resolution_strategy == ConflictResolution.CLIENT_WINS:
                    resolved_entry = conflict.local_entry
                elif resolution_strategy == ConflictResolution.SERVER_WINS:

                    resolved_entry = LogEntry(
                        id=conflict.local_entry.id,
                        timestamp=conflict.server_entry.get("timestamp", conflict.local_entry.timestamp),
                        event_type=conflict.server_entry.get("event_type", conflict.local_entry.event_type),
                        campaign_id=conflict.server_entry.get("campaign_id", conflict.local_entry.campaign_id),
                        device_id=conflict.server_entry.get("device_id", conflict.local_entry.device_id),
                        data=conflict.server_entry.get("data", conflict.local_entry.data),
                        compressed_size=conflict.local_entry.compressed_size,
                        original_size=conflict.local_entry.original_size
                    )
                elif resolution_strategy == ConflictResolution.MERGE:
                    resolved_entry = self._merge_entries(conflict.local_entry, conflict.server_entry)
                else:

                    return None
                
                conflict.resolved = True
                return resolved_entry
                
        except Exception as e:
            logging.error(f"Failed to resolve conflict: {e}")
            return None
    
    def _merge_entries(self, local_entry: LogEntry, server_data: Dict[str, Any]) -> LogEntry:
        """Merge local and server data intelligently"""

        merged_data = local_entry.data.copy() if isinstance(local_entry.data, dict) else {}
        server_payload = server_data.get("data", {})
        
        if isinstance(server_payload, dict):
            merged_data.update(server_payload)
        
        return LogEntry(
            id=local_entry.id,
            timestamp=max(local_entry.timestamp, server_data.get("timestamp", 0)),
            event_type=local_entry.event_type,
            campaign_id=local_entry.campaign_id,
            device_id=local_entry.device_id,
            data=merged_data,
            compressed_size=local_entry.compressed_size,
            original_size=local_entry.original_size
        )
    
    def get_unresolved_conflicts(self) -> List[ConflictItem]:
        """Get all unresolved conflicts"""
        with self._lock:
            return [c for c in self.conflicts if not c.resolved]
    
    def cleanup_resolved_conflicts(self, older_than_hours: int = 24) -> int:
        """Clean up old resolved conflicts"""
        try:
            with self._lock:
                cutoff_time = time.time() - (older_than_hours * 3600)
                original_count = len(self.conflicts)
                
                self.conflicts = [
                    c for c in self.conflicts
                    if not c.resolved or c.created_at > cutoff_time
                ]
                
                return original_count - len(self.conflicts)
                
        except Exception as e:
            logging.error(f"Failed to cleanup conflicts: {e}")
            return 0


class DataSynchronizer:
    """Main data synchronization orchestrator"""
    
    def __init__(self, offline_logger: AdvancedOfflineLogger,
                 sync_endpoints: Dict[str, str],
                 config: Dict[str, Any] = None):
        self.offline_logger = offline_logger
        self.sync_endpoints = sync_endpoints
        self.config = config or {}
        

        self.sync_queue = SyncQueue(max_size=self.config.get("max_queue_size", 1000))
        self.conflict_resolver = ConflictResolver()
        self.backoff = ExponentialBackoff(
            base_delay=self.config.get("base_retry_delay", 1.0),
            max_delay=self.config.get("max_retry_delay", 300.0)
        )
        

        self.is_running = False
        self.sync_thread: Optional[threading.Thread] = None
        self.cleanup_thread: Optional[threading.Thread] = None
        

        self.stats = SyncStats(
            total_operations=0,
            successful_operations=0,
            failed_operations=0,
            pending_operations=0,
            average_sync_time=0.0,
            last_sync_timestamp=0.0,
            bandwidth_utilization=0.0,
            compression_ratio=0.0
        )
        

        self.sync_interval = self.config.get("sync_interval_seconds", 60)
        self.cleanup_interval = self.config.get("cleanup_interval_seconds", 3600)
        self.max_retry_attempts = self.config.get("max_retry_attempts", 5)
        
    def start(self):
        """Start the synchronization service"""
        if self.is_running:
            return
        
        self.is_running = True
        

        self.sync_thread = threading.Thread(target=self._sync_worker, daemon=True)
        self.sync_thread.start()
        

        self.cleanup_thread = threading.Thread(target=self._cleanup_worker, daemon=True)
        self.cleanup_thread.start()
        
        logging.info("Data synchronizer started")
    
    def stop(self):
        """Stop the synchronization service"""
        self.is_running = False
        
        if self.sync_thread:
            self.sync_thread.join(timeout=10)
        
        if self.cleanup_thread:
            self.cleanup_thread.join(timeout=5)
        
        logging.info("Data synchronizer stopped")
    
    def queue_sync_operation(self, entry_ids: List[str], priority: int = 5,
                           endpoint: str = "default") -> str:
        """Queue entries for synchronization"""
        try:
            operation = SyncOperation(
                id=f"sync_{int(time.time())}_{random.randint(1000, 9999)}",
                entry_ids=entry_ids,
                priority=priority,
                status=SyncStatus.PENDING,
                attempts=0,
                last_attempt=None,
                next_attempt=time.time(),
                created_at=time.time(),
                endpoint=endpoint
            )
            
            success = self.sync_queue.add_operation(operation)
            if success:
                self.stats.total_operations += 1
                return operation.id
            else:
                return ""
                
        except Exception as e:
            logging.error(f"Failed to queue sync operation: {e}")
            return ""
    
    def _sync_worker(self):
        """Main sync worker thread"""
        while self.is_running:
            try:

                bandwidth_metrics = self.offline_logger.get_bandwidth_metrics()
                

                operations = self.sync_queue.get_ready_operations(
                    max_count=self.config.get("max_batch_size", 10),
                    bandwidth_quality=bandwidth_metrics.quality
                )
                
                if not operations:
                    time.sleep(1)
                    continue
                

                for operation in operations:
                    if not self.is_running:
                        break
                    
                    try:
                        success = self._execute_sync_operation(operation, bandwidth_metrics)
                        
                        if success:
                            self.sync_queue.update_operation_status(
                                operation.id, SyncStatus.SUCCESS
                            )
                            self.stats.successful_operations += 1
                            

                            self.offline_logger.mark_entries_synced(operation.entry_ids)
                            
                        else:

                            if operation.attempts >= self.max_retry_attempts:
                                self.sync_queue.update_operation_status(
                                    operation.id, SyncStatus.FAILED
                                )
                                self.stats.failed_operations += 1
                            else:

                                delay = self.backoff.calculate_delay(operation.attempts)
                                next_attempt = time.time() + delay
                                
                                self.sync_queue.update_operation_status(
                                    operation.id, SyncStatus.PENDING, next_attempt
                                )
                    
                    except Exception as e:
                        logging.error(f"Error processing sync operation {operation.id}: {e}")
                

                self.stats.last_sync_timestamp = time.time()
                

                time.sleep(self.sync_interval)
                
            except Exception as e:
                logging.error(f"Sync worker error: {e}")
                time.sleep(5)
    
    def _execute_sync_operation(self, operation: SyncOperation,
                               bandwidth_metrics: BandwidthMetrics) -> bool:
        """Execute a single sync operation"""
        try:

            entries = []
            for entry_id in operation.entry_ids:


                pass
            
            if not entries:
                return True
            

            sync_payload = {
                "operation_id": operation.id,
                "timestamp": time.time(),
                "entries": [asdict(entry) for entry in entries],
                "device_id": self.offline_logger.device_id,
                "campaign_id": self.offline_logger.campaign_id,
                "bandwidth_info": asdict(bandwidth_metrics)
            }
            

            endpoint_url = self.sync_endpoints.get(operation.endpoint,
                                                 self.sync_endpoints.get("default"))
            if not endpoint_url:
                logging.error(f"No endpoint configured for {operation.endpoint}")
                return False
            

            success = self._send_sync_request(endpoint_url, sync_payload)
            
            return success
            
        except Exception as e:
            logging.error(f"Failed to execute sync operation: {e}")
            return False
    
    def _send_sync_request(self, endpoint_url: str, payload: Dict[str, Any]) -> bool:
        """Send sync request to server (placeholder for actual HTTP implementation)"""
        try:


            import requests
            
            response = requests.post(
                endpoint_url,
                json=payload,
                timeout=self.config.get("request_timeout", 30),
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": self.config.get("user_agent", "MythicAgent/1.0")
                }
            )
            
            if response.status_code == 200:

                response_data = response.json()
                conflicts = response_data.get("conflicts", [])
                
                for conflict_data in conflicts:

                    pass
                
                return True
            else:
                logging.error(f"Sync request failed: {response.status_code} {response.text}")
                return False
                
        except Exception as e:
            logging.error(f"Sync request error: {e}")
            return False
    
    def _cleanup_worker(self):
        """Cleanup worker for old data and operations"""
        while self.is_running:
            try:

                cleaned_entries = self.offline_logger.cleanup_old_data(
                    self.config.get("cleanup_hours", 24)
                )
                

                cleaned_conflicts = self.conflict_resolver.cleanup_resolved_conflicts(
                    self.config.get("conflict_cleanup_hours", 48)
                )
                

                current_time = time.time()
                cutoff_time = current_time - (self.config.get("operation_cleanup_hours", 12) * 3600)
                

                queue_stats = self.sync_queue.get_queue_stats()
                self.stats.pending_operations = queue_stats.get("pending", 0)
                
                if cleaned_entries > 0 or cleaned_conflicts > 0:
                    logging.info(f"Cleanup completed: {cleaned_entries} entries, {cleaned_conflicts} conflicts")
                

                time.sleep(self.cleanup_interval)
                
            except Exception as e:
                logging.error(f"Cleanup worker error: {e}")
                time.sleep(60)
    
    def force_sync(self, priority_filter: Optional[int] = None) -> Dict[str, Any]:
        """Force immediate synchronization of pending entries"""
        try:

            bandwidth_metrics = self.offline_logger.get_bandwidth_metrics()
            
            if bandwidth_metrics.quality == "offline":
                return {"status": "failed", "reason": "offline"}
            

            entries = self.offline_logger.get_sync_batch(bandwidth_metrics)
            
            if not entries:
                return {"status": "success", "synced_count": 0}
            

            if priority_filter is not None:
                entries = [e for e in entries if e.data.get("priority", 5) >= priority_filter]
            

            entry_ids = [entry.id for entry in entries]
            operation_id = self.queue_sync_operation(entry_ids, priority=10)
            
            if operation_id:
                return {
                    "status": "queued",
                    "operation_id": operation_id,
                    "entry_count": len(entry_ids)
                }
            else:
                return {"status": "failed", "reason": "queue_error"}
                
        except Exception as e:
            logging.error(f"Force sync failed: {e}")
            return {"status": "error", "reason": str(e)}
    
    def get_sync_status(self) -> Dict[str, Any]:
        """Get current synchronization status"""
        try:
            queue_stats = self.sync_queue.get_queue_stats()
            storage_stats = self.offline_logger.get_storage_stats()
            conflicts = self.conflict_resolver.get_unresolved_conflicts()
            bandwidth_metrics = self.offline_logger.get_bandwidth_metrics()
            
            return {
                "is_running": self.is_running,
                "queue_stats": queue_stats,
                "storage_stats": storage_stats,
                "unresolved_conflicts": len(conflicts),
                "bandwidth_metrics": asdict(bandwidth_metrics),
                "sync_stats": asdict(self.stats),
                "last_sync": self.stats.last_sync_timestamp,
                "next_sync": time.time() + self.sync_interval
            }
            
        except Exception as e:
            logging.error(f"Failed to get sync status: {e}")
            return {"error": str(e)}



def create_data_synchronizer(offline_logger: AdvancedOfflineLogger,
                           c2_endpoints: List[str],
                           config: Dict[str, Any] = None) -> DataSynchronizer:
    """Create a configured data synchronizer instance"""
    

    sync_endpoints = {}
    for i, endpoint in enumerate(c2_endpoints):
        if i == 0:
            sync_endpoints["default"] = endpoint
        sync_endpoints[f"endpoint_{i}"] = endpoint
    

    default_config = {
        "sync_interval_seconds": 60,
        "cleanup_interval_seconds": 3600,
        "max_retry_attempts": 5,
        "max_batch_size": 20,
        "max_queue_size": 1000,
        "base_retry_delay": 1.0,
        "max_retry_delay": 300.0,
        "request_timeout": 30,
        "cleanup_hours": 24,
        "conflict_cleanup_hours": 48,
        "operation_cleanup_hours": 12,
        "user_agent": "MythicAgent/1.0"
    }
    

    if config:
        default_config.update(config)
    
    return DataSynchronizer(offline_logger, sync_endpoints, default_config)
