
"""
Unit tests for Core Agent functionality
Tests Android version detection, device fingerprinting, and module loading
"""

import pytest
import unittest
import tempfile
import json
import os
import sys
from unittest.mock import Mock, patch, MagicMock, mock_open
from pathlib import Path


sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../'))

from agent.core_agent import (
    AndroidVersionDetector, DeviceFingerprinter, ConfigurationManager,
    ModuleLoader, MythicAgent
)


class TestAndroidVersionDetector(unittest.TestCase):
    """Test Android version detection system"""
    
    @patch('subprocess.check_output')
    def test_get_android_version_success(self, mock_subprocess):
        """Test successful Android version detection"""

        mock_subprocess.side_effect = [
            '34\n',
            '14\n',
            '2023-10-05\n'
        ]
        
        result = AndroidVersionDetector.get_android_version()
        
        self.assertEqual(result['api_level'], 34)
        self.assertEqual(result['version_name'], 'Android 14')
        self.assertEqual(result['version_release'], '14')
        self.assertEqual(result['security_patch'], '2023-10-05')
        self.assertTrue(result['supports_enhanced_features'])
    
    @patch('subprocess.check_output')
    def test_get_android_version_old_api(self, mock_subprocess):
        """Test detection of older Android version"""
        mock_subprocess.side_effect = [
            '29\n',
            '10\n',
            '2021-05-01\n'
        ]
        
        result = AndroidVersionDetector.get_android_version()
        
        self.assertEqual(result['api_level'], 29)
        self.assertEqual(result['version_name'], 'Unknown API 29')
        self.assertFalse(result['supports_enhanced_features'])
    
    @patch('subprocess.check_output')
    def test_get_android_version_failure(self, mock_subprocess):
        """Test Android version detection failure"""
        mock_subprocess.side_effect = Exception("Command failed")
        
        result = AndroidVersionDetector.get_android_version()
        
        self.assertEqual(result['api_level'], 0)
        self.assertEqual(result['version_name'], 'Unknown')
        self.assertFalse(result['supports_enhanced_features'])
        self.assertIn('error', result)


class TestDeviceFingerprinter(unittest.TestCase):
    """Test device fingerprinting system"""
    
    @patch('subprocess.check_output')
    @patch('os.path.exists')
    def test_generate_fingerprint_success(self, mock_exists, mock_subprocess):
        """Test successful fingerprint generation"""

        mock_subprocess.side_effect = [
            'ABC123456\n',
            'ABC123456\n',
            'SM-G991B\n',
            'samsung\n',
            'Samsung\n',
            'samsung/beyond1qltechn/beyond1q:11/RP1A.200720.012/G991BXXU4CUI1:user/release-keys\n'
        ]
        

        mock_exists.return_value = True
        mock_cpu_info = "processor : 0\nvendor_id : GenuineIntel\n"
        
        with patch('builtins.open', mock_open(read_data=mock_cpu_info)):
            fingerprint = DeviceFingerprinter.generate_fingerprint()
        
        self.assertIsInstance(fingerprint, str)
        self.assertEqual(len(fingerprint), 16)
        self.assertRegex(fingerprint, r'^[a-f0-9]{16}$')
    
    @patch('subprocess.check_output')
    def test_generate_fingerprint_fallback(self, mock_subprocess):
        """Test fingerprint generation fallback to UUID"""

        mock_subprocess.side_effect = Exception("Command failed")
        
        fingerprint = DeviceFingerprinter.generate_fingerprint()
        
        self.assertIsInstance(fingerprint, str)
        self.assertEqual(len(fingerprint), 16)
        self.assertRegex(fingerprint, r'^[a-f0-9]{16}$')
    
    @patch('subprocess.check_output')
    @patch('os.path.exists')
    def test_generate_fingerprint_no_cpu_info(self, mock_exists, mock_subprocess):
        """Test fingerprint generation without CPU info"""
        mock_subprocess.side_effect = [
            'ABC123456\n',
            'ABC123456\n',
            'SM-G991B\n',
            'samsung\n',
            'Samsung\n',
            'samsung/beyond1qltechn/beyond1q:11/RP1A.200720.012/G991BXXU4CUI1:user/release-keys\n'
        ]
        

        mock_exists.return_value = False
        
        fingerprint = DeviceFingerprinter.generate_fingerprint()
        
        self.assertIsInstance(fingerprint, str)
        self.assertEqual(len(fingerprint), 16)


class TestConfigurationManager(unittest.TestCase):
    """Test configuration management system"""
    
    def setUp(self):
        """Set up test environment"""

        self.encryption_key = "dGVzdF9lbmNyeXB0aW9uX2tleV8xMjM0NTY3ODkwYWJjZGVmZ2hpams="
        self.config_manager = ConfigurationManager(self.encryption_key)
    
    def test_config_manager_without_key(self):
        """Test config manager without encryption key"""
        manager = ConfigurationManager(None)
        
        test_config = {"test": "value", "number": 42}
        

        result = manager.encrypt_config(test_config)
        self.assertEqual(result, json.dumps(test_config))
        

        decrypted = manager.decrypt_config(result)
        self.assertEqual(decrypted, test_config)
    
    def test_encrypt_decrypt_config(self):
        """Test configuration encryption and decryption"""
        test_config = {
            "campaign_id": "test_campaign",
            "device_id": "test_device",
            "c2_profile": "https_beacon",
            "modules": ["module1", "module2"]
        }
        
        # Mock the encrypt/decrypt functions since crypto module may not be available
        with patch('agent.core_agent.encrypt') as mock_encrypt, \
             patch('agent.core_agent.decrypt') as mock_decrypt:
            
            # Mock encrypt to return base64 encoded "encrypted" data
            mock_encrypt.return_value = b"fake_encrypted_data"
            # Mock decrypt to return the original JSON
            mock_decrypt.return_value = json.dumps(test_config).encode()
            
            encrypted = self.config_manager.encrypt_config(test_config)
            self.assertIsInstance(encrypted, str)
            self.assertNotEqual(encrypted, json.dumps(test_config))
            
            decrypted = self.config_manager.decrypt_config(encrypted)
            self.assertEqual(decrypted, test_config)
    
    def test_decrypt_invalid_data(self):
        """Test decryption of invalid data"""
        invalid_data = "invalid_encrypted_data"
        
        result = self.config_manager.decrypt_config(invalid_data)
        

        self.assertEqual(result, {})
    
    def test_encrypt_config_fallback(self):
        """Test config encryption fallback"""

        manager = ConfigurationManager("invalid_key")
        
        test_config = {"test": "value"}
        

        result = manager.encrypt_config(test_config)
        self.assertEqual(result, json.dumps(test_config))


class TestModuleLoader(unittest.TestCase):
    """Test module loading system"""
    
    def setUp(self):
        """Set up test environment"""
        self.mock_agent = Mock()
        self.mock_agent.offline_logger = Mock()
        self.mock_agent.encryption_key = "test_key"
        self.mock_agent.device_id = "test_device"
        self.mock_agent.config = {"test": "config"}
        
        self.module_loader = ModuleLoader(self.mock_agent)
    
    def test_module_loader_initialization(self):
        """Test module loader initialization"""
        self.assertEqual(self.module_loader.agent, self.mock_agent)
        self.assertEqual(self.module_loader.loaded_modules, {})
        self.assertEqual(self.module_loader.dependency_graph, {})
    
    def test_discover_modules_empty_directory(self):
        """Test module discovery with empty directory"""
        with tempfile.TemporaryDirectory() as temp_dir:
            modules = self.module_loader.discover_modules(temp_dir)
            self.assertEqual(modules, [])
    
    def test_discover_modules_with_files(self):
        """Test module discovery with Python files"""
        with tempfile.TemporaryDirectory() as temp_dir:

            (Path(temp_dir) / "module1.py").touch()
            (Path(temp_dir) / "module2.py").touch()
            (Path(temp_dir) / "__init__.py").touch()
            (Path(temp_dir) / "not_module.txt").touch()
            
            modules = self.module_loader.discover_modules(temp_dir)
            
            self.assertIn("module1", modules)
            self.assertIn("module2", modules)
            self.assertNotIn("__init__", modules)
            self.assertNotIn("not_module", modules)
    
    def test_resolve_dependencies(self):
        """Test dependency resolution"""

        class MockModuleClass:
            def __init__(self, agent, logger=None, encryption_key=None, device_id=None, config=None, unknown_param=None):
                pass
        
        dependencies = self.module_loader._resolve_dependencies(MockModuleClass)
        

        self.assertIn('logger', dependencies)
        self.assertIn('encryption_key', dependencies)
        self.assertIn('device_id', dependencies)
        self.assertIn('config', dependencies)
        

        self.assertNotIn('unknown_param', dependencies)
        

        self.assertEqual(dependencies['logger'], self.mock_agent.offline_logger)
        self.assertEqual(dependencies['encryption_key'], self.mock_agent.encryption_key)
        self.assertEqual(dependencies['device_id'], self.mock_agent.device_id)
        self.assertEqual(dependencies['config'], self.mock_agent.config)
    
    def test_load_modules_in_order(self):
        """Test loading modules in specified order"""
        module_list = ["module1", "module2"]
        

        self.module_loader.load_module_with_injection = Mock(side_effect=[
            Mock(name="module1_instance"),
            Mock(name="module2_instance")
        ])
        
        loaded = self.module_loader.load_modules_in_order(module_list)
        
        self.assertEqual(len(loaded), 2)
        self.assertIn("module1", loaded)
        self.assertIn("module2", loaded)
        

        calls = self.module_loader.load_module_with_injection.call_args_list
        self.assertEqual(calls[0][0][0], "module1")
        self.assertEqual(calls[1][0][0], "module2")
    
    def test_load_modules_with_failures(self):
        """Test loading modules with some failures"""
        module_list = ["module1", "module2", "module3"]
        

        self.module_loader.load_module_with_injection = Mock(side_effect=[
            Mock(name="module1_instance"),
            None,
            Mock(name="module3_instance")
        ])
        
        loaded = self.module_loader.load_modules_in_order(module_list)
        
        self.assertEqual(len(loaded), 2)
        self.assertIn("module1", loaded)
        self.assertNotIn("module2", loaded)
        self.assertIn("module3", loaded)


class TestMythicAgent(unittest.TestCase):
    """Test main Mythic agent"""
    
    def setUp(self):
        """Set up test environment"""

        self.temp_dir = tempfile.mkdtemp()
        self.config_path = os.path.join(self.temp_dir, "config.json")
        

        self.test_config = {
            "campaign_id": "test_campaign",
            "device_id": "test_device_123",
            "c2_profile": "https_beacon",
            "encryption_algorithm": "AES-256-GCM",
            "beacon_interval": 60,
            "offline_logging": True,
            "thread_pool_size": 3,
            "modules": ["test_module"]
        }
        
        with open(self.config_path, 'w') as f:
            json.dump(self.test_config, f)
    
    def tearDown(self):
        """Clean up test environment"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    @patch('agent.core_agent.AndroidVersionDetector.get_android_version')
    @patch('agent.core_agent.DeviceFingerprinter.generate_fingerprint')
    @patch('agent.utils.crypto.key_from_campaign_device')
    def test_mythic_agent_initialization(self, mock_key_gen, mock_fingerprint, mock_version):
        """Test Mythic agent initialization"""

        mock_version.return_value = {
            'api_level': 34,
            'version_name': 'Android 14',
            'supports_enhanced_features': True
        }
        mock_fingerprint.return_value = 'test_fingerprint_123'
        mock_key_gen.return_value = b'test_encryption_key_32bytes_long'
        

        with patch('agent.core_agent.MythicAgent._init_c2_profile') as mock_c2:
            mock_c2.return_value = Mock()
            
            agent = MythicAgent(self.config_path)
            
            self.assertEqual(agent.campaign, "test_campaign")
            self.assertEqual(agent.device_fingerprint, 'test_fingerprint_123')
            self.assertEqual(agent.android_version['api_level'], 34)
            self.assertIsNotNone(agent.thread_pool)
            self.assertIsInstance(agent.module_loader, ModuleLoader)
    
    def test_load_config_file_not_found(self):
        """Test loading config when file doesn't exist"""
        non_existent_path = "/non/existent/config.json"
        
        with patch('agent.core_agent.AndroidVersionDetector.get_android_version'):
            with patch('agent.core_agent.DeviceFingerprinter.generate_fingerprint'):
                with patch('agent.utils.crypto.key_from_campaign_device'):
                    with patch('agent.core_agent.MythicAgent._init_c2_profile'):
                        agent = MythicAgent(non_existent_path)
                        

                        self.assertEqual(agent.campaign, "default_campaign")
    
    def test_default_config(self):
        """Test default configuration generation"""
        with patch('agent.core_agent.AndroidVersionDetector.get_android_version'):
            with patch('agent.core_agent.DeviceFingerprinter.generate_fingerprint'):
                with patch('agent.utils.crypto.key_from_campaign_device'):
                    with patch('agent.core_agent.MythicAgent._init_c2_profile'):
                        agent = MythicAgent("/non/existent/path")
                        
                        default_config = agent._default_config()
                        
                        self.assertIn('campaign_id', default_config)
                        self.assertIn('device_id', default_config)
                        self.assertIn('c2_profile', default_config)
                        self.assertIn('encryption_algorithm', default_config)
                        self.assertIn('modules', default_config)
                        self.assertEqual(default_config['c2_profile'], 'https_beacon')
                        self.assertEqual(default_config['encryption_algorithm'], 'AES-256-GCM')
    
    @patch('agent.core_agent.AndroidVersionDetector.get_android_version')
    @patch('agent.core_agent.DeviceFingerprinter.generate_fingerprint')
    @patch('agent.utils.crypto.key_from_campaign_device')
    def test_get_agent_status(self, mock_key_gen, mock_fingerprint, mock_version):
        """Test agent status reporting"""

        mock_version.return_value = {'api_level': 34, 'version_name': 'Android 14'}
        mock_fingerprint.return_value = 'test_fingerprint_123'
        mock_key_gen.return_value = b'test_key'
        
        with patch('agent.core_agent.MythicAgent._init_c2_profile') as mock_c2:
            mock_c2.return_value = Mock()
            
            agent = MythicAgent(self.config_path)
            status = agent.get_agent_status()
            
            self.assertIn('campaign_id', status)
            self.assertIn('device_id', status)
            self.assertIn('device_fingerprint', status)
            self.assertIn('android_version', status)
            self.assertIn('loaded_modules', status)
            self.assertIn('active_tasks', status)
            self.assertIn('c2_profile', status)
            self.assertIn('running', status)
    
    @patch('agent.core_agent.AndroidVersionDetector.get_android_version')
    @patch('agent.core_agent.DeviceFingerprinter.generate_fingerprint')
    @patch('agent.utils.crypto.key_from_campaign_device')
    def test_task_submission(self, mock_key_gen, mock_fingerprint, mock_version):
        """Test task submission to thread pool"""

        mock_version.return_value = {'api_level': 34}
        mock_fingerprint.return_value = 'test_fingerprint'
        mock_key_gen.return_value = b'test_key'
        
        with patch('agent.core_agent.MythicAgent._init_c2_profile') as mock_c2:
            mock_c2.return_value = Mock()
            
            agent = MythicAgent(self.config_path)
            
            test_task = {
                "id": "test_task_123",
                "module": "test_module",
                "command": "test_command",
                "args": {"test": "arg"}
            }
            

            agent._submit_task(test_task)
            

            self.assertIn("test_task_123", agent._task_futures)
            self.assertTrue(agent._task_futures["test_task_123"])
    
    @patch('agent.core_agent.AndroidVersionDetector.get_android_version')
    @patch('agent.core_agent.DeviceFingerprinter.generate_fingerprint')
    @patch('agent.utils.crypto.key_from_campaign_device')
    def test_cleanup_completed_tasks(self, mock_key_gen, mock_fingerprint, mock_version):
        """Test cleanup of completed task futures"""

        mock_version.return_value = {'api_level': 34}
        mock_fingerprint.return_value = 'test_fingerprint'
        mock_key_gen.return_value = b'test_key'
        
        with patch('agent.core_agent.MythicAgent._init_c2_profile') as mock_c2:
            mock_c2.return_value = Mock()
            
            agent = MythicAgent(self.config_path)
            

            completed_future = Mock()
            completed_future.done.return_value = True
            running_future = Mock()
            running_future.done.return_value = False
            
            agent._task_futures = {
                "completed_task": completed_future,
                "running_task": running_future
            }
            

            agent._cleanup_completed_tasks()
            

            self.assertNotIn("completed_task", agent._task_futures)
            self.assertIn("running_task", agent._task_futures)


if __name__ == '__main__':

    import logging
    logging.basicConfig(level=logging.ERROR)
    

    unittest.main(verbosity=2)
