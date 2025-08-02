#!/usr/bin/env python3
"""
HTTPS Beacon C2 Implementation for Mythic Mobile Agent 
"""
import asyncio
import json
import base64
import time
import ssl
from typing import Dict, List, Any, Optional

try:
    from mythic_container import C2ProfileBase, C2Profile, C2ProfileParameter, C2ProfileParameterType # type: ignore
except ImportError:
    # Fallback definitions for development/testing
    class C2ProfileBase:
        pass
    
    class C2Profile:
        pass
    
    class C2ProfileParameter:
        def __init__(self, name, description, default_value, parameter_type, required=True):
            self.name = name
            self.description = description
            self.default_value = default_value
            self.parameter_type = parameter_type
            self.required = required
    
    class C2ProfileParameterType:
        String = "string"
        Number = "number"
        Boolean = "boolean"

try:
    from aiohttp import web, ClientSession # type: ignore
except ImportError:
    web = None
    ClientSession = None
    print("[!] aiohttp not available. Install with: pip install aiohttp")

class HTTPSBeacon(C2ProfileBase):
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.pending_tasks: Dict[str, List[Dict[str, Any]]] = {}
        self.agent_responses: Dict[str, Dict[str, Any]] = {}
        self.active_agents: Dict[str, Dict[str, Any]] = {}
        
    async def check_in(self, agent_id: str, agent_data: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Handle agent check-in and return pending tasks"""
        try:
            self.active_agents[agent_id] = {
                "last_seen": time.time(),
                "data": agent_data or {},
                "status": "online"
            }
            
            tasks = self.pending_tasks.get(agent_id, [])
            self.pending_tasks[agent_id] = []
            return tasks
            
        except Exception as e:
            print(f"[!] Check-in error for {agent_id}: {e}")
            return []
        
    async def post_response(self, task_id: str, agent_id: str, encrypted_data: bytes) -> bool:
        """Handle agent task response submission"""
        try:
            self.agent_responses[task_id] = {
                "agent_id": agent_id,
                "data": base64.b64encode(encrypted_data).decode(),
                "timestamp": time.time(),
                "status": "received"
            }
            
            if agent_id in self.active_agents:
                self.active_agents[agent_id]["last_seen"] = time.time()
            
            return True
            
        except Exception as e:
            print(f"[!] Response submission error: {e}")
            return False

# Web server implementation
async def create_c2_server(beacon: HTTPSBeacon, config: Dict[str, Any]) -> Optional[Any]:
    """Create the HTTPS C2 web server"""
    if web is None:
        print("[!] aiohttp not available")
        return None
        
    app = web.Application()
    
    async def handle_checkin(request: Any) -> Any:
        """Handle agent check-in requests"""
        try:
            data = await request.json()
            agent_id = data.get("agent_id")
            agent_data = data.get("agent_data", {})
            
            if not agent_id:
                return web.json_response({
                    "status": "error",
                    "message": "agent_id required"
                }, status=400)
            
            tasks = await beacon.check_in(agent_id, agent_data)
            
            return web.json_response({
                "status": "success",
                "tasks": tasks,
                "server_time": int(time.time())
            })
            
        except Exception as e:
            return web.json_response({
                "status": "error",
                "message": f"Server error: {str(e)}"
            }, status=500)
    
    async def handle_response(request: Any) -> Any:
        """Handle agent response submissions"""
        try:
            data = await request.json()
            task_id = data.get("task_id")
            agent_id = data.get("agent_id")
            response_data = data.get("data")
            
            if not all([task_id, agent_id, response_data]):
                return web.json_response({
                    "status": "error",
                    "message": "task_id, agent_id, and data required"
                }, status=400)
            
            try:
                decoded_data = base64.b64decode(response_data)
            except Exception:
                return web.json_response({
                    "status": "error",
                    "message": "Invalid base64 data"
                }, status=400)
            
            success = await beacon.post_response(task_id, agent_id, decoded_data)
            
            if success:
                return web.json_response({"status": "success"})
            else:
                return web.json_response({
                    "status": "error",
                    "message": "Failed to process response"
                }, status=500)
                
        except Exception as e:
            return web.json_response({
                "status": "error",
                "message": f"Server error: {str(e)}"
            }, status=500)
    
    checkin_uri = config.get("get_uri", "/api/v1/mobile/checkin")
    submit_uri = config.get("post_uri", "/api/v1/mobile/submit")
    
    app.router.add_post(checkin_uri, handle_checkin)
    app.router.add_post(submit_uri, handle_response)
    
    return app
