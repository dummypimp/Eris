
"""
Integration tests for C2 profiles
Tests communication flow and profile switching
"""

import pytest
import asyncio
import unittest
import json
import time
import uuid
import sys
import os
from unittest.mock import Mock, patch, AsyncMock
from datetime import datetime


sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../'))

try:
    from c2_profiles.https_beacon.c2_server import HTTPSBeaconC2Server, Task, TaskPriority
    from c2_profiles.fcm_push.fcm_c2 import FCMPushC2Client, C2Message, MessagePriority
    from c2_profiles.dns_covert.dns_tunnel import DNSTunnelClient, DataEncoding
    PROFILES_AVAILABLE = True
except ImportError as e:
    print(f"Warning: C2 profiles not available for testing: {e}")
    PROFILES_AVAILABLE = False


@unittest.skipUnless(PROFILES_AVAILABLE, "C2 profiles not available")
class TestHTTPSBeaconIntegration(unittest.IsolatedAsyncioTestCase):
    """Integration tests for HTTPS Beacon profile"""
    
    async def asyncSetUp(self):
        """Set up test environment"""
        self.server = HTTPSBeaconC2Server()
        self.agent_id = str(uuid.uuid4())
        
    async def test_agent_checkin_flow(self):
        """Test complete agent check-in flow"""
        checkin_data = {
            'agent_id': self.agent_id,
            'hostname': 'test-device',
            'username': 'system',
            'pid': 1234,
            'os': 'android',
            'architecture': 'arm64'
        }
        

        with patch('aiohttp.web.Request') as mock_request:
            mock_request.json = AsyncMock(return_value=checkin_data)
            mock_request.remote = '127.0.0.1'
            
            response = await self.server.handle_checkin(mock_request)
            self.assertEqual(response.status, 200)
    
    async def test_task_creation_and_retrieval(self):
        """Test task creation and retrieval flow"""

        test_task = Task(
            task_id=str(uuid.uuid4()),
            command="shell",
            payload={"cmd": "id"},
            priority=TaskPriority.HIGH,
            created_at=time.time(),
            agent_id=self.agent_id
        )
        

        await self.server.task_queue.add_task(test_task)
        

        tasks = await self.server.task_queue.get_tasks(self.agent_id, limit=5)
        
        self.assertEqual(len(tasks), 1)
        self.assertEqual(tasks[0].command, "shell")
        self.assertEqual(tasks[0].agent_id, self.agent_id)
    
    async def test_task_response_handling(self):
        """Test task response handling"""
        task_id = str(uuid.uuid4())
        response_data = {
            'task_id': task_id,
            'status': 'completed',
            'output': 'uid=0(root) gid=0(root)',
            'timestamp': time.time()
        }
        

        with patch('aiohttp.web.Request') as mock_request:
            mock_request.json = AsyncMock(return_value=response_data)
            mock_request.match_info = {'task_id': task_id}
            
            response = await self.server.handle_task_response(mock_request)
            self.assertEqual(response.status, 200)
    
    async def test_user_agent_rotation(self):
        """Test mobile user agent rotation"""
        from c2_profiles.https_beacon.c2_server import MobileUserAgentRotator
        
        rotator = MobileUserAgentRotator()
        

        ua1 = rotator.get_user_agent()
        ua2 = rotator.get_user_agent()
        
        self.assertIsInstance(ua1, str)
        self.assertIsInstance(ua2, str)
        self.assertIn('Mobile', ua1)
        

        rotator.last_rotation = time.time() - 301
        ua3 = rotator.get_user_agent()
        

        self.assertIsInstance(ua3, str)


@unittest.skipUnless(PROFILES_AVAILABLE, "C2 profiles not available")
class TestFCMPushIntegration(unittest.TestCase):
    """Integration tests for FCM Push profile"""
    
    def setUp(self):
        """Set up test environment"""
        self.config = {
            "agent_id": str(uuid.uuid4()),
            "fcm_token": "test_fcm_token_123",
            "server_url": "https://test.example.com",
            "firebase_service_account": "/path/to/service-account.json",
            "poll_interval": 30
        }
        self.client = FCMPushC2Client(self.config)
    
    def test_fcm_client_initialization(self):
        """Test FCM client initialization"""
        self.assertEqual(self.client.agent_id, self.config["agent_id"])
        self.assertEqual(self.client.fcm_token, self.config["fcm_token"])
        self.assertEqual(self.client.server_url, self.config["server_url"])
    
    def test_message_creation(self):
        """Test C2 message creation"""
        message = C2Message(
            message_id=str(uuid.uuid4()),
            command="system_info",
            payload={"collect": ["cpu", "memory"]},
            priority=MessagePriority.HIGH,
            timestamp=time.time()
        )
        
        self.assertIsInstance(message.message_id, str)
        self.assertEqual(message.command, "system_info")
        self.assertEqual(message.priority, MessagePriority.HIGH)
        self.assertIn("collect", message.payload)
    
    def test_wake_lock_manager(self):
        """Test wake lock management"""
        from c2_profiles.fcm_push.fcm_c2 import WakeLockManager
        
        wake_manager = WakeLockManager()
        

        result = wake_manager.acquire_wake_lock("test_tag")
        self.assertIsInstance(result, bool)
        

        result = wake_manager.release_wake_lock("test_tag")
        self.assertIsInstance(result, bool)
    
    @patch('requests.post')
    def test_http_fallback(self, mock_post):
        """Test HTTP fallback mechanism"""

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"tasks": []}
        mock_post.return_value = mock_response
        

        tasks = self.client.poll_for_tasks()
        
        self.assertIsInstance(tasks, list)
        mock_post.assert_called_once()
    
    def test_message_priority_handling(self):
        """Test message priority handling"""
        high_priority_message = C2Message(
            message_id=str(uuid.uuid4()),
            command="urgent_command",
            payload={},
            priority=MessagePriority.HIGH,
            timestamp=time.time()
        )
        
        low_priority_message = C2Message(
            message_id=str(uuid.uuid4()),
            command="background_task",
            payload={},
            priority=MessagePriority.LOW,
            timestamp=time.time()
        )
        

        self.assertTrue(high_priority_message.priority.value > low_priority_message.priority.value)


@unittest.skipUnless(PROFILES_AVAILABLE, "C2 profiles not available")
class TestDNSCovertIntegration(unittest.TestCase):
    """Integration tests for DNS Covert Channel"""
    
    def setUp(self):
        """Set up test environment"""
        self.config = {
            "domain": "c2tunnel.test.com",
            "agent_id": str(uuid.uuid4()),
            "encoding": "base32",
            "channel": "https",
            "doh_provider": "cloudflare",
            "chunk_size": 180,
            "poll_interval": 45
        }
        self.dns_client = DNSTunnelClient(self.config)
    
    def test_dns_client_initialization(self):
        """Test DNS client initialization"""
        self.assertEqual(self.dns_client.domain, self.config["domain"])
        self.assertEqual(self.dns_client.agent_id, self.config["agent_id"])
        self.assertEqual(self.dns_client.encoding, DataEncoding.BASE32)
    
    def test_data_encoding_decoding(self):
        """Test data encoding and decoding"""
        from c2_profiles.dns_covert.dns_tunnel import DNSEncoder
        
        encoder = DNSEncoder()
        test_data = b"Hello, this is a test message for DNS tunneling!"
        

        encoded = encoder.encode_data(test_data, DataEncoding.BASE32)
        decoded = encoder.decode_data(encoded, DataEncoding.BASE32)
        
        self.assertEqual(decoded, test_data)
        

        encoded_b64 = encoder.encode_data(test_data, DataEncoding.BASE64)
        decoded_b64 = encoder.decode_data(encoded_b64, DataEncoding.BASE64)
        
        self.assertEqual(decoded_b64, test_data)
    
    def test_data_chunking(self):
        """Test data chunking for large payloads"""
        from c2_profiles.dns_covert.dns_tunnel import DNSChunker
        
        chunker = DNSChunker(max_chunk_size=50)
        large_data = b"A" * 200
        

        chunks = chunker.chunk_data(large_data, DataEncoding.BASE32)
        
        self.assertGreater(len(chunks), 1)
        

        for chunk in chunks:
            self.assertIn('packet_id', chunk)
            self.assertIn('sequence', chunk)
            self.assertIn('total_chunks', chunk)
            self.assertIn('data', chunk)
        

        reassembled = chunker.reassemble_chunks(chunks)
        self.assertEqual(reassembled, large_data)
    
    def test_dns_query_generation(self):
        """Test DNS query generation"""
        test_packet = {
            'packet_id': 'test123',
            'sequence': 1,
            'total_chunks': 3,
            'data': 'JBSWY3DPEBLW64TMMQ======'
        }
        
        query_name = self.dns_client._generate_query_name(test_packet)
        
        self.assertIsInstance(query_name, str)
        self.assertIn(test_packet['packet_id'], query_name)
        self.assertIn(str(test_packet['sequence']), query_name)
        self.assertIn(self.config["domain"], query_name)
    
    def test_compression(self):
        """Test data compression"""
        test_data = b"This is a test message that should compress well because it has repeating patterns. " * 10
        
        compressed = self.dns_client._compress_data(test_data)
        decompressed = self.dns_client._decompress_data(compressed)
        
        self.assertEqual(decompressed, test_data)
        self.assertLess(len(compressed), len(test_data))
    
    @patch('dns.resolver.resolve')
    def test_dns_query_execution(self, mock_resolve):
        """Test DNS query execution"""

        mock_answer = Mock()
        mock_answer.to_text.return_value = '"test_response_data"'
        mock_resolve.return_value = [mock_answer]
        
        query_name = "test.query.c2tunnel.test.com"
        result = self.dns_client._execute_dns_query(query_name)
        
        self.assertIsInstance(result, str)
        mock_resolve.assert_called_once()


class TestC2ProfileSwitching(unittest.TestCase):
    """Test C2 profile switching and failover"""
    
    def setUp(self):
        """Set up test environment"""
        self.agent_config = {
            "campaign_id": "test_campaign",
            "device_id": str(uuid.uuid4()),
            "primary_c2": "https_beacon",
            "fallback_c2": ["fcm_push", "dns_covert"],
            "failover_threshold": 3
        }
    
    def test_profile_selection(self):
        """Test C2 profile selection logic"""

        selected_profile = self._select_c2_profile(self.agent_config, 0)
        self.assertEqual(selected_profile, "https_beacon")
        

        selected_profile = self._select_c2_profile(self.agent_config, 5)
        self.assertIn(selected_profile, ["fcm_push", "dns_covert"])
    
    def test_profile_health_check(self):
        """Test C2 profile health checking"""
        health_statuses = {
            "https_beacon": self._check_profile_health("https_beacon"),
            "fcm_push": self._check_profile_health("fcm_push"),
            "dns_covert": self._check_profile_health("dns_covert")
        }
        

        available_profiles = [profile for profile, status in health_statuses.items() if status]
        self.assertGreater(len(available_profiles), 0)
    
    def test_profile_configuration_validation(self):
        """Test C2 profile configuration validation"""
        https_config = {
            "server_url": "https://c2.example.com",
            "user_agent": "Android Mobile",
            "beacon_interval": 300
        }
        
        fcm_config = {
            "fcm_token": "test_token",
            "server_url": "https://c2.example.com",
            "firebase_service_account": "/path/to/service.json"
        }
        
        dns_config = {
            "domain": "c2.example.com",
            "encoding": "base32",
            "doh_provider": "cloudflare"
        }
        
        self.assertTrue(self._validate_profile_config("https_beacon", https_config))
        self.assertTrue(self._validate_profile_config("fcm_push", fcm_config))
        self.assertTrue(self._validate_profile_config("dns_covert", dns_config))
    
    def _select_c2_profile(self, config, failure_count):
        """Helper method to simulate profile selection"""
        if failure_count < config["failover_threshold"]:
            return config["primary_c2"]
        else:
            return config["fallback_c2"][failure_count % len(config["fallback_c2"])]
    
    def _check_profile_health(self, profile_name):
        """Helper method to simulate profile health check"""

        return True
    
    def _validate_profile_config(self, profile_name, config):
        """Helper method to validate profile configuration"""
        required_fields = {
            "https_beacon": ["server_url"],
            "fcm_push": ["fcm_token", "server_url"],
            "dns_covert": ["domain", "encoding"]
        }
        
        if profile_name not in required_fields:
            return False
        
        return all(field in config for field in required_fields[profile_name])


class TestC2MessageFlow(unittest.TestCase):
    """Test end-to-end message flow"""
    
    def test_message_serialization(self):
        """Test message serialization across profiles"""
        test_message = {
            "id": str(uuid.uuid4()),
            "command": "system_info",
            "args": {"collect": ["cpu", "memory", "disk"]},
            "timestamp": time.time(),
            "priority": "HIGH"
        }
        

        json_serialized = json.dumps(test_message)
        json_deserialized = json.loads(json_serialized)
        
        self.assertEqual(test_message, json_deserialized)
    
    def test_message_encryption(self):
        """Test message encryption/decryption"""
        from cryptography.fernet import Fernet
        

        key = Fernet.generate_key()
        cipher_suite = Fernet(key)
        
        test_message = "This is a secret C2 message"
        

        encrypted = cipher_suite.encrypt(test_message.encode())
        decrypted = cipher_suite.decrypt(encrypted).decode()
        
        self.assertEqual(test_message, decrypted)
    
    def test_message_compression(self):
        """Test message compression"""
        import gzip
        
        large_message = "This is a large message that should compress well. " * 100
        

        compressed = gzip.compress(large_message.encode())
        decompressed = gzip.decompress(compressed).decode()
        
        self.assertEqual(large_message, decompressed)
        self.assertLess(len(compressed), len(large_message.encode()))


if __name__ == '__main__':

    import logging
    logging.basicConfig(level=logging.WARNING)
    

    unittest.main(verbosity=2)
