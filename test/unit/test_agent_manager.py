
"""
Unit tests for Agent Manager module
Tests health monitoring, auto-recovery, and update management
"""

import pytest
import unittest
import time
import threading
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime
import sys
import os


sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../'))

from agent_manager import (
    AgentManager, HealthMonitor, AutoRecoveryManager, UpdateManager,
    AgentState, HealthStatus, HealthMetrics
)
from mythic_integration import MythicIntegration


class TestHealthMonitor(unittest.TestCase):
    """Test health monitoring system"""
    
    def setUp(self):
        """Set up test environment"""
        self.mock_agent = Mock()
        self.health_monitor = HealthMonitor(self.mock_agent, check_interval=1)
    
    def test_health_monitor_initialization(self):
        """Test health monitor initialization"""
        self.assertEqual(self.health_monitor.agent, self.mock_agent)
        self.assertEqual(self.health_monitor.check_interval, 1)
        self.assertFalse(self.health_monitor.running)
        self.assertIsInstance(self.health_monitor.current_metrics, HealthMetrics)
    
    @patch('psutil.Process')
    def test_collect_metrics(self, mock_process):
        """Test metrics collection"""

        mock_proc = Mock()
        mock_proc.cpu_percent.return_value = 25.5
        mock_proc.memory_info.return_value = Mock(rss=100 * 1024 * 1024)
        mock_proc.memory_percent.return_value = 15.0
        mock_proc.connections.return_value = [Mock(), Mock()]
        mock_process.return_value = mock_proc
        

        with patch('psutil.disk_usage') as mock_disk:
            mock_disk.return_value = Mock(used=50 * 1024**3, total=100 * 1024**3)
            

            self.mock_agent.modules = {'module1': Mock(), 'module2': Mock()}
            self.mock_agent.command_dispatcher = Mock()
            self.mock_agent.command_dispatcher.get_dispatcher_status.return_value = {
                'queue_status': {'running_tasks': 3, 'completed_tasks': 10}
            }
            
            metrics = self.health_monitor._collect_metrics()
            
            self.assertEqual(metrics.cpu_percent, 25.5)
            self.assertEqual(metrics.memory_percent, 15.0)
            self.assertEqual(metrics.memory_mb, 100.0)
            self.assertEqual(metrics.disk_usage_percent, 50.0)
            self.assertEqual(metrics.network_connections, 2)
            self.assertEqual(metrics.loaded_modules, 2)
            self.assertEqual(metrics.active_tasks, 3)
            self.assertEqual(metrics.completed_tasks, 10)
    
    def test_assess_health_healthy(self):
        """Test health assessment - healthy state"""
        metrics = HealthMetrics(
            cpu_percent=50.0,
            memory_percent=60.0,
            disk_usage_percent=70.0,
            c2_connectivity=True
        )
        
        status = self.health_monitor._assess_health(metrics)
        self.assertEqual(status, HealthStatus.HEALTHY)
    
    def test_assess_health_warning(self):
        """Test health assessment - warning state"""
        metrics = HealthMetrics(
            cpu_percent=75.0,
            memory_percent=60.0,
            disk_usage_percent=70.0,
            c2_connectivity=True
        )
        
        status = self.health_monitor._assess_health(metrics)
        self.assertEqual(status, HealthStatus.WARNING)
    
    def test_assess_health_critical(self):
        """Test health assessment - critical state"""
        metrics = HealthMetrics(
            cpu_percent=95.0,
            memory_percent=95.0,
            disk_usage_percent=96.0,
            c2_connectivity=False
        )
        
        status = self.health_monitor._assess_health(metrics)
        self.assertEqual(status, HealthStatus.CRITICAL)
    
    def test_health_monitor_start_stop(self):
        """Test starting and stopping health monitor"""
        self.health_monitor.start()
        self.assertTrue(self.health_monitor.running)
        self.assertIsNotNone(self.health_monitor.monitor_thread)
        
        time.sleep(0.1)
        
        self.health_monitor.stop()
        self.assertFalse(self.health_monitor.running)


class TestAutoRecoveryManager(unittest.TestCase):
    """Test auto-recovery system"""
    
    def setUp(self):
        """Set up test environment"""
        self.mock_agent = Mock()
        self.mock_health_monitor = Mock()
        self.auto_recovery = AutoRecoveryManager(self.mock_agent, self.mock_health_monitor)
    
    def test_auto_recovery_initialization(self):
        """Test auto-recovery initialization"""
        self.assertEqual(self.auto_recovery.agent, self.mock_agent)
        self.assertEqual(self.auto_recovery.health_monitor, self.mock_health_monitor)
        self.assertTrue(self.auto_recovery.enabled)
        self.assertEqual(self.auto_recovery.max_recovery_attempts, 3)
        self.assertEqual(self.auto_recovery.recovery_cooldown, 300)
    
    def test_enable_disable_auto_recovery(self):
        """Test enabling/disabling auto-recovery"""
        self.auto_recovery.enable_auto_recovery(False)
        self.assertFalse(self.auto_recovery.enabled)
        
        self.auto_recovery.enable_auto_recovery(True)
        self.assertTrue(self.auto_recovery.enabled)
    
    def test_determine_recovery_plan_memory(self):
        """Test recovery plan for high memory usage"""
        metrics = HealthMetrics(memory_percent=90.0, c2_connectivity=True, active_tasks=2)
        
        actions = self.auto_recovery._determine_recovery_plan(metrics)
        self.assertIn('memory_cleanup', actions)
    
    def test_determine_recovery_plan_connectivity(self):
        """Test recovery plan for connectivity issues"""
        metrics = HealthMetrics(memory_percent=50.0, c2_connectivity=False, active_tasks=2)
        
        actions = self.auto_recovery._determine_recovery_plan(metrics)
        self.assertIn('c2_reconnect', actions)
    
    def test_determine_recovery_plan_high_tasks(self):
        """Test recovery plan for high task count"""
        metrics = HealthMetrics(memory_percent=50.0, c2_connectivity=True, active_tasks=15)
        
        actions = self.auto_recovery._determine_recovery_plan(metrics)
        self.assertIn('task_queue_flush', actions)
    
    def test_memory_cleanup(self):
        """Test memory cleanup operation"""
        # Mock the agent's command_dispatcher and task_queue
        mock_dispatcher = Mock()
        mock_task_queue = Mock()
        mock_task_queue.completed_tasks = {f"task_{i}": f"result_{i}" for i in range(20)}
        mock_dispatcher.task_queue = mock_task_queue
        self.mock_agent.command_dispatcher = mock_dispatcher
        
        with patch('gc.collect') as mock_gc:
            result = self.auto_recovery._memory_cleanup()
            self.assertTrue(result)
            mock_gc.assert_called_once()
    
    def test_check_and_recover_cooldown(self):
        """Test recovery cooldown period"""
        self.auto_recovery.last_recovery_time = time.time()
        
        result = self.auto_recovery.check_and_recover()
        self.assertFalse(result)


class TestUpdateManager(unittest.TestCase):
    """Test update management system"""
    
    def setUp(self):
        """Set up test environment"""
        self.mock_agent = Mock()
        self.update_manager = UpdateManager(self.mock_agent, "1.0.0")
    
    def test_update_manager_initialization(self):
        """Test update manager initialization"""
        self.assertEqual(self.update_manager.agent, self.mock_agent)
        self.assertEqual(self.update_manager.current_version, "1.0.0")
        self.assertFalse(self.update_manager.update_in_progress)
        self.assertEqual(self.update_manager.update_history, [])
    
    def test_check_for_updates(self):
        """Test update checking"""
        result = self.update_manager.check_for_updates()
        
        self.assertIn('current_version', result)
        self.assertIn('latest_version', result)
        self.assertIn('update_available', result)
        self.assertEqual(result['current_version'], "1.0.0")
    
    def test_download_update(self):
        """Test update download"""
        result = self.update_manager.download_update("1.0.1", "https://example.com/update.zip")
        self.assertTrue(result)
    
    def test_apply_update(self):
        """Test update application"""
        self.assertFalse(self.update_manager.update_in_progress)
        
        result = self.update_manager.apply_update("update_package.zip")
        
        self.assertTrue(result)
        self.assertFalse(self.update_manager.update_in_progress)
        self.assertEqual(len(self.update_manager.update_history), 1)
    
    def test_concurrent_update_prevention(self):
        """Test prevention of concurrent updates"""
        self.update_manager.update_in_progress = True
        
        result = self.update_manager.apply_update("update_package.zip")
        self.assertFalse(result)
    
    def test_rollback_update(self):
        """Test update rollback"""

        self.update_manager.update_history.append({
            "timestamp": datetime.now().isoformat(),
            "from_version": "0.9.0",
            "to_version": "1.0.0",
            "success": True
        })
        
        result = self.update_manager.rollback_update()
        self.assertTrue(result)
    
    def test_rollback_no_history(self):
        """Test rollback with no history"""
        result = self.update_manager.rollback_update()
        self.assertFalse(result)


class TestAgentManager(unittest.TestCase):
    """Test main agent manager"""
    
    def setUp(self):
        """Set up test environment"""
        self.mock_agent = Mock()
        self.mock_mythic = Mock()
        self.agent_manager = AgentManager(self.mock_agent, self.mock_mythic)
    
    def test_agent_manager_initialization(self):
        """Test agent manager initialization"""
        self.assertEqual(self.agent_manager.agent, self.mock_agent)
        self.assertEqual(self.agent_manager.mythic_integration, self.mock_mythic)
        self.assertEqual(self.agent_manager.current_state, AgentState.INITIALIZING)
        self.assertIsInstance(self.agent_manager.health_monitor, HealthMonitor)
        self.assertIsInstance(self.agent_manager.auto_recovery, AutoRecoveryManager)
        self.assertIsInstance(self.agent_manager.update_manager, UpdateManager)
    
    def test_set_state(self):
        """Test state management"""
        initial_state = self.agent_manager.current_state
        self.agent_manager._set_state(AgentState.STARTING)
        
        self.assertEqual(self.agent_manager.current_state, AgentState.STARTING)
        self.assertEqual(len(self.agent_manager.state_history), 1)
        
        state_change = self.agent_manager.state_history[0]
        self.assertEqual(state_change['from_state'], initial_state.value)
        self.assertEqual(state_change['to_state'], AgentState.STARTING.value)
    
    def test_get_status(self):
        """Test status reporting"""
        self.agent_manager.start_time = datetime.now()
        
        status = self.agent_manager.get_status()
        
        self.assertIn('agent_state', status)
        self.assertIn('start_time', status)
        self.assertIn('uptime_seconds', status)
        self.assertIn('health_monitor', status)
        self.assertIn('auto_recovery', status)
        self.assertIn('update_manager', status)
    
    def test_configure_health_monitoring(self):
        """Test health monitoring configuration"""
        self.agent_manager.configure_health_monitoring(
            enabled=True,
            check_interval=60,
            thresholds={'cpu_critical': 95.0}
        )
        
        self.assertTrue(self.agent_manager.health_monitoring_enabled)
        self.assertEqual(self.agent_manager.health_monitor.check_interval, 60)
        self.assertEqual(self.agent_manager.health_monitor.health_thresholds['cpu_critical'], 95.0)
    
    def test_configure_auto_recovery(self):
        """Test auto-recovery configuration"""
        self.agent_manager.configure_auto_recovery(
            enabled=True,
            max_attempts=5,
            cooldown=600
        )
        
        self.assertTrue(self.agent_manager.auto_recovery_enabled)
        self.assertEqual(self.agent_manager.auto_recovery.max_recovery_attempts, 5)
        self.assertEqual(self.agent_manager.auto_recovery.recovery_cooldown, 600)
    
    def test_trigger_recovery(self):
        """Test manual recovery trigger"""
        result = self.agent_manager.trigger_recovery("memory_cleanup")

        self.assertIsInstance(result, bool)


class TestHealthMetrics(unittest.TestCase):
    """Test health metrics data structure"""
    
    def test_health_metrics_creation(self):
        """Test health metrics creation"""
        metrics = HealthMetrics()
        
        self.assertEqual(metrics.cpu_percent, 0.0)
        self.assertEqual(metrics.memory_percent, 0.0)
        self.assertEqual(metrics.memory_mb, 0.0)
        self.assertEqual(metrics.disk_usage_percent, 0.0)
        self.assertEqual(metrics.network_connections, 0)
        self.assertEqual(metrics.loaded_modules, 0)
        self.assertEqual(metrics.active_tasks, 0)
        self.assertEqual(metrics.completed_tasks, 0)
        self.assertEqual(metrics.failed_tasks, 0)
        self.assertFalse(metrics.c2_connectivity)
        self.assertIsNone(metrics.last_beacon)
        self.assertEqual(metrics.uptime_seconds, 0.0)
    
    def test_health_metrics_to_dict(self):
        """Test metrics conversion to dictionary"""
        metrics = HealthMetrics(
            cpu_percent=50.0,
            memory_percent=60.0,
            memory_mb=512.0,
            disk_usage_percent=70.0,
            network_connections=5,
            loaded_modules=3,
            active_tasks=2,
            completed_tasks=10,
            failed_tasks=1,
            c2_connectivity=True,
            last_beacon="2023-12-01T10:00:00",
            uptime_seconds=3600.0
        )
        
        result = metrics.to_dict()
        
        self.assertIn('timestamp', result)
        self.assertIn('system', result)
        self.assertIn('agent', result)
        self.assertIn('connectivity', result)
        
        self.assertEqual(result['system']['cpu_percent'], 50.0)
        self.assertEqual(result['system']['memory_percent'], 60.0)
        self.assertEqual(result['agent']['active_tasks'], 2)
        self.assertEqual(result['connectivity']['c2_connectivity'], True)


if __name__ == '__main__':

    import logging
    logging.basicConfig(level=logging.ERROR)
    

    unittest.main(verbosity=2)
