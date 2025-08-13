#!/usr/bin/env python3
"""
Extensible Shell Interface for Mythic Android Agent
Provides stable multi-handler shell with extensible command classes
"""

import asyncio
import json
import sys
from typing import Dict, List, Optional, Any, Callable
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
import websockets
import aiohttp
from pathlib import Path

class CommandCategory(Enum):
    SYSTEM = "system"
    FRIDA = "frida"
    SURVEILLANCE = "surveillance"
    FILESYSTEM = "filesystem"
    NETWORK = "network"
    STEALTH = "stealth"
    ADVANCED = "advanced"

@dataclass
class CommandDefinition:
    name: str
    category: CommandCategory
    description: str
    parameters: List[str]
    required_permissions: List[str]
    example: str
    handler: Callable

class BaseCommand(ABC):
    """Base class for extensible commands"""
    
    def __init__(self, name: str, category: CommandCategory, description: str):
        self.name = name
        self.category = category
        self.description = description
        self.parameters = []
        self.required_permissions = []
    
    @abstractmethod
    async def execute(self, session: 'ShellSession', args: List[str]) -> Dict[str, Any]:
        """Execute the command"""
        pass
    
    def add_parameter(self, param: str, required: bool = True):
        """Add parameter to command"""
        if required:
            self.parameters.append(f"<{param}>")
        else:
            self.parameters.append(f"[{param}]")
    
    def add_permission(self, permission: str):
        """Add required permission"""
        self.required_permissions.append(permission)
    
    def get_usage(self) -> str:
        """Get command usage string"""
        params = " ".join(self.parameters)
        return f"{self.name} {params}"

class ShellSession:
    """Represents an active shell session"""
    
    def __init__(self, session_id: str, agent_id: str, websocket=None):
        self.session_id = session_id
        self.agent_id = agent_id
        self.websocket = websocket
        self.context = {}
        self.history = []
        self.current_directory = "/"
        self.environment = {}
        self.active = True
        self.frida_sessions = {}
    
    async def send_response(self, response: Dict[str, Any]):
        """Send response back to client"""
        if self.websocket:
            await self.websocket.send(json.dumps(response))
    
    async def send_output(self, output: str, output_type: str = "stdout"):
        """Send command output"""
        response = {
            "type": "output",
            "session_id": self.session_id,
            "output_type": output_type,
            "data": output,
            "timestamp": self._get_timestamp()
        }
        await self.send_response(response)
    
    def add_to_history(self, command: str):
        """Add command to history"""
        self.history.append({
            "command": command,
            "timestamp": self._get_timestamp()
        })
        # Keep only last 100 commands
        if len(self.history) > 100:
            self.history = self.history[-100:]
    
    def _get_timestamp(self) -> str:
        """Get current timestamp"""
        import datetime
        return datetime.datetime.now().isoformat()

class ExtensibleShell:
    """Main extensible shell interface"""
    
    def __init__(self):
        self.commands: Dict[str, BaseCommand] = {}
        self.sessions: Dict[str, ShellSession] = {}
        self.command_categories: Dict[CommandCategory, List[str]] = {
            category: [] for category in CommandCategory
        }
        self.server = None
        self.running = False
        
        # Initialize default commands
        self._initialize_default_commands()
    
    def _initialize_default_commands(self):
        """Initialize default command set"""
        
        # System Commands
        self.register_command(HelpCommand())
        self.register_command(ListCommand())
        self.register_command(ChangeDirectoryCommand())
        self.register_command(SystemInfoCommand())
        self.register_command(ProcessListCommand())
        
        # Frida Commands
        self.register_command(FridaStatusCommand())
        self.register_command(FridaSessionCommand())
        self.register_command(FridaScriptCommand())
        self.register_command(FridaHookCommand())
        self.register_command(FridaCallCommand())
        
        # Surveillance Commands
        self.register_command(ScreenshotCommand())
        self.register_command(RecordScreenCommand())
        self.register_command(LocationCommand())
        self.register_command(CallLogCommand())
        self.register_command(SMSCommand())
        
        # Filesystem Commands
        self.register_command(DownloadCommand())
        self.register_command(UploadCommand())
        self.register_command(FileSearchCommand())
        self.register_command(FileWatchCommand())
        
        # Network Commands
        self.register_command(NetworkStatusCommand())
        self.register_command(PortScanCommand())
        self.register_command(PacketCaptureCommand())
        
        # Stealth Commands
        self.register_command(HideAppCommand())
        self.register_command(AntiDetectionCommand())
        self.register_command(PersistenceCommand())
        
        # Advanced Commands
        self.register_command(ShellCommand())
        self.register_command(MemoryDumpCommand())
        self.register_command(KeyloggerCommand())
        self.register_command(OverlayCommand())
    
    def register_command(self, command: BaseCommand):
        """Register a new command"""
        self.commands[command.name] = command
        self.command_categories[command.category].append(command.name)
    
    async def create_session(self, agent_id: str, websocket=None) -> str:
        """Create new shell session"""
        session_id = f"shell_{agent_id}_{len(self.sessions)}"
        session = ShellSession(session_id, agent_id, websocket)
        self.sessions[session_id] = session
        
        # Send welcome message
        if websocket:
            welcome = {
                "type": "welcome",
                "session_id": session_id,
                "agent_id": agent_id,
                "message": "Mythic Android Agent Shell - Type 'help' for available commands",
                "prompt": f"mythic@{agent_id}:/ $ "
            }
            await session.send_response(welcome)
        
        return session_id
    
    async def handle_command(self, session_id: str, command_line: str) -> Dict[str, Any]:
        """Handle incoming command"""
        session = self.sessions.get(session_id)
        if not session:
            return {"error": "Session not found"}
        
        # Add to history
        session.add_to_history(command_line)
        
        # Parse command
        parts = command_line.strip().split()
        if not parts:
            return {"output": ""}
        
        command_name = parts[0]
        args = parts[1:] if len(parts) > 1 else []
        
        # Find command
        command = self.commands.get(command_name)
        if not command:
            return {
                "error": f"Unknown command: {command_name}",
                "suggestion": self._suggest_command(command_name)
            }
        
        # Execute command
        try:
            result = await command.execute(session, args)
            return result
        except Exception as e:
            return {"error": f"Command execution failed: {str(e)}"}
    
    def _suggest_command(self, command_name: str) -> Optional[str]:
        """Suggest similar command"""
        import difflib
        suggestions = difflib.get_close_matches(command_name, self.commands.keys(), n=1, cutoff=0.6)
        return suggestions[0] if suggestions else None
    
    async def start_server(self, host: str = "127.0.0.1", port: int = 8765):
        """Start WebSocket server"""
        print(f"Starting shell server on {host}:{port}")
        
        async def handle_client(websocket, path):
            try:
                # Create session for this client
                agent_id = "unknown"  # Would be passed from authentication
                session_id = await self.create_session(agent_id, websocket)
                
                async for message in websocket:
                    try:
                        data = json.loads(message)
                        command_line = data.get("command", "")
                        
                        result = await self.handle_command(session_id, command_line)
                        await websocket.send(json.dumps(result))
                        
                    except json.JSONDecodeError:
                        await websocket.send(json.dumps({"error": "Invalid JSON"}))
                    except Exception as e:
                        await websocket.send(json.dumps({"error": str(e)}))
                        
            except websockets.exceptions.ConnectionClosed:
                # Clean up session
                if session_id in self.sessions:
                    del self.sessions[session_id]
        
        self.server = await websockets.serve(handle_client, host, port)
        self.running = True
        print(f"Shell server started on ws://{host}:{port}")
    
    async def stop_server(self):
        """Stop WebSocket server"""
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            self.running = False
            print("Shell server stopped")

# Default Command Implementations

class HelpCommand(BaseCommand):
    def __init__(self):
        super().__init__("help", CommandCategory.SYSTEM, "Show available commands")
        self.add_parameter("category", required=False)
    
    async def execute(self, session: ShellSession, args: List[str]) -> Dict[str, Any]:
        shell = session.context.get('shell')
        if not shell:
            return {"error": "Shell reference not available"}
        
        category_filter = args[0] if args else None
        
        if category_filter:
            try:
                category = CommandCategory(category_filter)
                commands = shell.command_categories.get(category, [])
                help_text = f"Commands in category '{category_filter}':\n"
                for cmd_name in commands:
                    cmd = shell.commands[cmd_name]
                    help_text += f"  {cmd.get_usage()} - {cmd.description}\n"
            except ValueError:
                return {"error": f"Unknown category: {category_filter}"}
        else:
            help_text = "Available commands by category:\n\n"
            for category in CommandCategory:
                commands = shell.command_categories.get(category, [])
                if commands:
                    help_text += f"{category.value.upper()}:\n"
                    for cmd_name in commands:
                        cmd = shell.commands[cmd_name]
                        help_text += f"  {cmd.name} - {cmd.description}\n"
                    help_text += "\n"
            
            help_text += "Use 'help <category>' for category-specific commands\n"
            help_text += "Categories: " + ", ".join([c.value for c in CommandCategory])
        
        return {"output": help_text}

class FridaStatusCommand(BaseCommand):
    def __init__(self):
        super().__init__("frida-status", CommandCategory.FRIDA, "Show Frida server status")
    
    async def execute(self, session: ShellSession, args: List[str]) -> Dict[str, Any]:
        # This would interface with the actual Frida integration
        status = {
            "server_running": True,  # Would check actual status
            "active_sessions": len(session.frida_sessions),
            "port": 27042,
            "version": "16.1.4"
        }
        
        output = f"Frida Server Status:\n"
        output += f"  Running: {'Yes' if status['server_running'] else 'No'}\n"
        output += f"  Active Sessions: {status['active_sessions']}\n"
        output += f"  Port: {status['port']}\n"
        output += f"  Version: {status['version']}\n"
        
        return {"output": output, "data": status}

class FridaSessionCommand(BaseCommand):
    def __init__(self):
        super().__init__("frida-session", CommandCategory.FRIDA, "Manage Frida sessions")
        self.add_parameter("action")  # create, list, attach, detach
        self.add_parameter("target", required=False)
    
    async def execute(self, session: ShellSession, args: List[str]) -> Dict[str, Any]:
        if not args:
            return {"error": "Usage: frida-session <create|list|attach|detach> [target]"}
        
        action = args[0]
        target = args[1] if len(args) > 1 else None
        
        if action == "create":
            session_id = f"frida_{len(session.frida_sessions)}"
            session.frida_sessions[session_id] = {
                "target": target or "current_app",
                "created": session._get_timestamp(),
                "active": True
            }
            return {"output": f"Created Frida session: {session_id}"}
        
        elif action == "list":
            if not session.frida_sessions:
                return {"output": "No active Frida sessions"}
            
            output = "Active Frida Sessions:\n"
            for sid, info in session.frida_sessions.items():
                output += f"  {sid}: {info['target']} (created: {info['created']})\n"
            return {"output": output}
        
        elif action == "attach":
            if not target:
                return {"error": "Target package required for attach"}
            # Would implement actual attach logic
            return {"output": f"Attached to {target}"}
        
        elif action == "detach":
            # Would implement actual detach logic
            return {"output": f"Detached from sessions"}
        
        else:
            return {"error": f"Unknown action: {action}"}

class FridaScriptCommand(BaseCommand):
    def __init__(self):
        super().__init__("frida-script", CommandCategory.FRIDA, "Execute Frida scripts")
        self.add_parameter("script_name")
        self.add_parameter("target", required=False)
    
    async def execute(self, session: ShellSession, args: List[str]) -> Dict[str, Any]:
        if not args:
            return {"error": "Usage: frida-script <script_name> [target]"}
        
        script_name = args[0]
        target = args[1] if len(args) > 1 else "current_app"
        
        # Predefined scripts
        scripts = {
            "ssl-bypass": "SSL certificate pinning bypass",
            "root-bypass": "Root detection bypass", 
            "crypto-hooks": "Cryptographic function hooks",
            "basic-hooks": "Basic Android function hooks"
        }
        
        if script_name not in scripts:
            available = ", ".join(scripts.keys())
            return {"error": f"Unknown script. Available: {available}"}
        
        # Would execute actual Frida script
        return {
            "output": f"Executing {script_name} on {target}...\nScript: {scripts[script_name]}",
            "success": True
        }

class FridaHookCommand(BaseCommand):
    def __init__(self):
        super().__init__("frida-hook", CommandCategory.FRIDA, "Hook specific functions")
        self.add_parameter("class_name")
        self.add_parameter("method_name")
        self.add_parameter("hook_type", required=False)
    
    async def execute(self, session: ShellSession, args: List[str]) -> Dict[str, Any]:
        if len(args) < 2:
            return {"error": "Usage: frida-hook <class_name> <method_name> [before|after|replace]"}
        
        class_name = args[0]
        method_name = args[1]
        hook_type = args[2] if len(args) > 2 else "before"
        
        # Would implement actual hook
        return {
            "output": f"Hooked {class_name}.{method_name} with {hook_type} hook",
            "success": True
        }

class ScreenshotCommand(BaseCommand):
    def __init__(self):
        super().__init__("screenshot", CommandCategory.SURVEILLANCE, "Take device screenshot")
        self.add_parameter("filename", required=False)
    
    async def execute(self, session: ShellSession, args: List[str]) -> Dict[str, Any]:
        filename = args[0] if args else f"screenshot_{session._get_timestamp()}.png"
        
        # Would implement actual screenshot logic
        return {
            "output": f"Screenshot saved as {filename}",
            "filename": filename,
            "success": True
        }

class LocationCommand(BaseCommand):
    def __init__(self):
        super().__init__("location", CommandCategory.SURVEILLANCE, "Get device location")
    
    async def execute(self, session: ShellSession, args: List[str]) -> Dict[str, Any]:
        # Would implement actual location logic
        location = {
            "latitude": 40.7128,
            "longitude": -74.0060,
            "accuracy": 10,
            "timestamp": session._get_timestamp()
        }
        
        output = f"Device Location:\n"
        output += f"  Latitude: {location['latitude']}\n"
        output += f"  Longitude: {location['longitude']}\n"
        output += f"  Accuracy: {location['accuracy']}m\n"
        output += f"  Timestamp: {location['timestamp']}\n"
        
        return {"output": output, "data": location}

class DownloadCommand(BaseCommand):
    def __init__(self):
        super().__init__("download", CommandCategory.FILESYSTEM, "Download file from device")
        self.add_parameter("remote_path")
        self.add_parameter("local_path", required=False)
    
    async def execute(self, session: ShellSession, args: List[str]) -> Dict[str, Any]:
        if not args:
            return {"error": "Usage: download <remote_path> [local_path]"}
        
        remote_path = args[0]
        local_path = args[1] if len(args) > 1 else Path(remote_path).name
        
        # Would implement actual download logic
        return {
            "output": f"Downloaded {remote_path} to {local_path}",
            "remote_path": remote_path,
            "local_path": local_path,
            "success": True
        }

class ShellCommand(BaseCommand):
    def __init__(self):
        super().__init__("shell", CommandCategory.ADVANCED, "Execute system command")
        self.add_parameter("command")
    
    async def execute(self, session: ShellSession, args: List[str]) -> Dict[str, Any]:
        if not args:
            return {"error": "Usage: shell <command>"}
        
        command = " ".join(args)
        
        # Would implement actual shell execution
        return {
            "output": f"Executing: {command}\n[Command output would appear here]",
            "command": command,
            "success": True
        }

# Additional command implementations would follow similar patterns...

class ListCommand(BaseCommand):
    def __init__(self):
        super().__init__("ls", CommandCategory.SYSTEM, "List directory contents")
        self.add_parameter("path", required=False)
    
    async def execute(self, session: ShellSession, args: List[str]) -> Dict[str, Any]:
        path = args[0] if args else session.current_directory
        # Would implement actual directory listing
        return {"output": f"Contents of {path}:\n[Directory listing would appear here]"}

class ChangeDirectoryCommand(BaseCommand):
    def __init__(self):
        super().__init__("cd", CommandCategory.SYSTEM, "Change directory")
        self.add_parameter("path")
    
    async def execute(self, session: ShellSession, args: List[str]) -> Dict[str, Any]:
        if not args:
            return {"error": "Usage: cd <path>"}
        
        new_path = args[0]
        session.current_directory = new_path
        return {"output": f"Changed directory to {new_path}"}

# Stub implementations for remaining commands
class SystemInfoCommand(BaseCommand):
    def __init__(self):
        super().__init__("sysinfo", CommandCategory.SYSTEM, "Show system information")
    
    async def execute(self, session: ShellSession, args: List[str]) -> Dict[str, Any]:
        return {"output": "System Information:\n[System info would appear here]"}

class ProcessListCommand(BaseCommand):
    def __init__(self):
        super().__init__("ps", CommandCategory.SYSTEM, "List running processes")
    
    async def execute(self, session: ShellSession, args: List[str]) -> Dict[str, Any]:
        return {"output": "Running Processes:\n[Process list would appear here]"}

class FridaCallCommand(BaseCommand):
    def __init__(self):
        super().__init__("frida-call", CommandCategory.FRIDA, "Call specific functions")
        self.add_parameter("class_name")
        self.add_parameter("method_name")
    
    async def execute(self, session: ShellSession, args: List[str]) -> Dict[str, Any]:
        if len(args) < 2:
            return {"error": "Usage: frida-call <class_name> <method_name>"}
        return {"output": f"Called {args[0]}.{args[1]}"}

class RecordScreenCommand(BaseCommand):
    def __init__(self):
        super().__init__("record", CommandCategory.SURVEILLANCE, "Record screen")
    
    async def execute(self, session: ShellSession, args: List[str]) -> Dict[str, Any]:
        return {"output": "Started screen recording"}

class CallLogCommand(BaseCommand):
    def __init__(self):
        super().__init__("calllog", CommandCategory.SURVEILLANCE, "Get call logs")
    
    async def execute(self, session: ShellSession, args: List[str]) -> Dict[str, Any]:
        return {"output": "Call logs:\n[Call log entries would appear here]"}

class SMSCommand(BaseCommand):
    def __init__(self):
        super().__init__("sms", CommandCategory.SURVEILLANCE, "Get SMS messages")
    
    async def execute(self, session: ShellSession, args: List[str]) -> Dict[str, Any]:
        return {"output": "SMS messages:\n[SMS entries would appear here]"}

class UploadCommand(BaseCommand):
    def __init__(self):
        super().__init__("upload", CommandCategory.FILESYSTEM, "Upload file to device")
        self.add_parameter("local_path")
        self.add_parameter("remote_path")
    
    async def execute(self, session: ShellSession, args: List[str]) -> Dict[str, Any]:
        if len(args) < 2:
            return {"error": "Usage: upload <local_path> <remote_path>"}
        return {"output": f"Uploaded {args[0]} to {args[1]}"}

class FileSearchCommand(BaseCommand):
    def __init__(self):
        super().__init__("find", CommandCategory.FILESYSTEM, "Search for files")
        self.add_parameter("pattern")
    
    async def execute(self, session: ShellSession, args: List[str]) -> Dict[str, Any]:
        if not args:
            return {"error": "Usage: find <pattern>"}
        return {"output": f"Searching for files matching: {args[0]}"}

class FileWatchCommand(BaseCommand):
    def __init__(self):
        super().__init__("watch", CommandCategory.FILESYSTEM, "Watch file changes")
        self.add_parameter("path")
    
    async def execute(self, session: ShellSession, args: List[str]) -> Dict[str, Any]:
        if not args:
            return {"error": "Usage: watch <path>"}
        return {"output": f"Watching {args[0]} for changes"}

class NetworkStatusCommand(BaseCommand):
    def __init__(self):
        super().__init__("netstat", CommandCategory.NETWORK, "Show network status")
    
    async def execute(self, session: ShellSession, args: List[str]) -> Dict[str, Any]:
        return {"output": "Network Status:\n[Network information would appear here]"}

class PortScanCommand(BaseCommand):
    def __init__(self):
        super().__init__("portscan", CommandCategory.NETWORK, "Scan network ports")
        self.add_parameter("target")
    
    async def execute(self, session: ShellSession, args: List[str]) -> Dict[str, Any]:
        if not args:
            return {"error": "Usage: portscan <target>"}
        return {"output": f"Scanning ports on {args[0]}"}

class PacketCaptureCommand(BaseCommand):
    def __init__(self):
        super().__init__("capture", CommandCategory.NETWORK, "Capture network packets")
    
    async def execute(self, session: ShellSession, args: List[str]) -> Dict[str, Any]:
        return {"output": "Started packet capture"}

class HideAppCommand(BaseCommand):
    def __init__(self):
        super().__init__("hide", CommandCategory.STEALTH, "Hide app from launcher")
    
    async def execute(self, session: ShellSession, args: List[str]) -> Dict[str, Any]:
        return {"output": "App hidden from launcher"}

class AntiDetectionCommand(BaseCommand):
    def __init__(self):
        super().__init__("antidetect", CommandCategory.STEALTH, "Enable anti-detection measures")
    
    async def execute(self, session: ShellSession, args: List[str]) -> Dict[str, Any]:
        return {"output": "Anti-detection measures activated"}

class PersistenceCommand(BaseCommand):
    def __init__(self):
        super().__init__("persist", CommandCategory.STEALTH, "Ensure persistence")
    
    async def execute(self, session: ShellSession, args: List[str]) -> Dict[str, Any]:
        return {"output": "Persistence mechanisms activated"}

class MemoryDumpCommand(BaseCommand):
    def __init__(self):
        super().__init__("memdump", CommandCategory.ADVANCED, "Dump process memory")
        self.add_parameter("pid")
    
    async def execute(self, session: ShellSession, args: List[str]) -> Dict[str, Any]:
        if not args:
            return {"error": "Usage: memdump <pid>"}
        return {"output": f"Dumping memory for PID {args[0]}"}

class KeyloggerCommand(BaseCommand):
    def __init__(self):
        super().__init__("keylog", CommandCategory.ADVANCED, "Start/stop keylogger")
        self.add_parameter("action")
    
    async def execute(self, session: ShellSession, args: List[str]) -> Dict[str, Any]:
        action = args[0] if args else "start"
        return {"output": f"Keylogger {action}ed"}

class OverlayCommand(BaseCommand):
    def __init__(self):
        super().__init__("overlay", CommandCategory.ADVANCED, "Deploy screen overlay")
        self.add_parameter("target_app")
    
    async def execute(self, session: ShellSession, args: List[str]) -> Dict[str, Any]:
        if not args:
            return {"error": "Usage: overlay <target_app>"}
        return {"output": f"Overlay deployed for {args[0]}"}

async def main():
    """Main function for testing"""
    shell = ExtensibleShell()
    
    # Start server
    await shell.start_server("127.0.0.1", 8765)
    
    try:
        # Keep server running
        while shell.running:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down shell server...")
        await shell.stop_server()

if __name__ == "__main__":
    asyncio.run(main())
