
"""
Anti-Analysis Module for Advanced Malware Protection
Implements comprehensive detection and evasion techniques
"""

import os
import subprocess
import hashlib
import time
import sys
import threading
import ctypes
import struct
import socket
import platform
from typing import List, Dict, Any, Optional, Tuple
import psutil
import requests

class AntiAnalysis:
    """Comprehensive anti-analysis and detection evasion system"""
    
    def __init__(self, enable_self_destruct: bool = False):
        self.enable_self_destruct = enable_self_destruct
        self.detection_flags = {
            'root_detected': False,
            'emulator_detected': False,
            'debugger_detected': False,
            'hooks_detected': False,
            'integrity_failed': False
        }
        self.original_signature = None
        self.monitoring_active = False
        
    def check_all_detections(self) -> Dict[str, bool]:
        """Run all detection checks and return results"""
        try:
            self.detection_flags['root_detected'] = self.detect_root_access()
            self.detection_flags['emulator_detected'] = self.detect_emulator()
            self.detection_flags['debugger_detected'] = self.detect_debugger()
            self.detection_flags['hooks_detected'] = self.detect_hooks()
            self.detection_flags['integrity_failed'] = not self.verify_integrity()
            
            if self.enable_self_destruct and any(self.detection_flags.values()):
                self._trigger_self_destruct()
                
            return self.detection_flags
        except Exception as e:

            return self.detection_flags
    
    def detect_root_access(self) -> bool:
        """Multiple methods to detect rooted/jailbroken devices"""
        root_indicators = []
        

        try:
            su_paths = ['/system/bin/su', '/system/xbin/su', '/sbin/su', '/vendor/bin/su',
                       '/system/app/Superuser.apk', '/system/app/SuperSU.apk']
            for path in su_paths:
                if os.path.exists(path):
                    root_indicators.append(f"SU binary found: {path}")
        except:
            pass
        

        try:
            root_apps = ['com.noshufou.android.su', 'com.chainfire.supersu',
                        'com.koushikdutta.superuser', 'com.thirdparty.superuser',
                        'eu.chainfire.supersu', 'com.kingroot.kinguser']
            
            for app in root_apps:
                if self._check_app_installed(app):
                    root_indicators.append(f"Root app detected: {app}")
        except:
            pass
        

        try:
            result = subprocess.run(['mount'], capture_output=True, text=True, timeout=5)
            if 'system' in result.stdout and 'rw' in result.stdout:
                root_indicators.append("System partition mounted as RW")
        except:
            pass
        

        try:
            build_tags = os.environ.get('BUILD_TAGS', '')
            if 'test-keys' in build_tags:
                root_indicators.append("Test-keys build detected")
        except:
            pass
        

        try:
            xposed_paths = ['/system/framework/XposedBridge.jar',
                           '/system/xposed.prop',
                           '/cache/recovery/log']
            for path in xposed_paths:
                if os.path.exists(path):
                    root_indicators.append(f"Xposed indicator: {path}")
        except:
            pass
        
        return len(root_indicators) > 0
    
    def detect_emulator(self) -> bool:
        """Detect various Android emulators and virtual environments"""
        emulator_indicators = []
        

        emulator_props = {
            'ro.product.model': ['sdk', 'emulator', 'simulator'],
            'ro.product.name': ['sdk', 'vbox', 'generic'],
            'ro.product.device': ['generic', 'vbox'],
            'ro.hardware': ['goldfish', 'ranchu', 'vbox'],
            'ro.kernel.qemu': ['1'],
            'ro.secure': ['0']
        }
        
        try:
            for prop, values in emulator_props.items():
                prop_value = self._get_system_property(prop)
                if prop_value and any(val in prop_value.lower() for val in values):
                    emulator_indicators.append(f"Emulator prop: {prop}={prop_value}")
        except:
            pass
        

        try:
            cpu_info = platform.machine()
            if 'x86' in cpu_info.lower() or 'amd64' in cpu_info.lower():
                emulator_indicators.append("x86 architecture detected")
        except:
            pass
        

        emulator_files = [
            '/system/lib/libc_malloc_debug_qemu.so',
            '/sys/qemu_trace',
            '/system/bin/qemu-props',
            '/dev/qemu_pipe',
            '/proc/tty/drivers'
        ]
        
        for file_path in emulator_files:
            try:
                if os.path.exists(file_path):
                    emulator_indicators.append(f"Emulator file: {file_path}")
            except:
                pass
        

        try:

            emulator_ips = ['10.0.2.', '192.168.56.', '192.168.57.']
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            
            if any(local_ip.startswith(ip) for ip in emulator_ips):
                emulator_indicators.append(f"Emulator IP range: {local_ip}")
        except:
            pass
        

        try:
            emulator_processes = ['qemu', 'genymotion', 'vbox', 'bluestacks']
            for proc in psutil.process_iter(['name']):
                proc_name = proc.info['name'].lower()
                if any(emu in proc_name for emu in emulator_processes):
                    emulator_indicators.append(f"Emulator process: {proc_name}")
        except:
            pass
        
        return len(emulator_indicators) > 0
    
    def detect_debugger(self) -> bool:
        """Detect debuggers and analysis tools"""
        debugger_indicators = []
        

        debugger_processes = ['gdb', 'lldb', 'strace', 'ltrace', 'ida', 'ollydbg',
                             'x64dbg', 'ghidra', 'radare2', 'frida-server']
        
        try:
            for proc in psutil.process_iter(['name', 'cmdline']):
                proc_name = proc.info['name'].lower()
                cmdline = ' '.join(proc.info['cmdline'] or []).lower()
                
                if any(dbg in proc_name or dbg in cmdline for dbg in debugger_processes):
                    debugger_indicators.append(f"Debugger process: {proc_name}")
        except:
            pass
        

        try:

            if sys.platform.startswith('linux'):
                result = subprocess.run(['cat', '/proc/self/status'],
                                      capture_output=True, text=True, timeout=2)
                if 'TracerPid:' in result.stdout:
                    tracer_line = [line for line in result.stdout.split('\n')
                                  if 'TracerPid:' in line][0]
                    tracer_pid = tracer_line.split(':')[1].strip()
                    if tracer_pid != '0':
                        debugger_indicators.append(f"Process being traced: PID {tracer_pid}")
        except:
            pass
        

        try:
            suspicious_ports = [8080, 8443, 9999, 27042, 27043]
            for port in suspicious_ports:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.1)
                result = sock.connect_ex(('127.0.0.1', port))
                if result == 0:
                    debugger_indicators.append(f"Suspicious port open: {port}")
                sock.close()
        except:
            pass
        

        try:
            start_time = time.time()

            sum(range(1000))
            end_time = time.time()
            

            if (end_time - start_time) > 0.01:
                debugger_indicators.append("Timing anomaly detected")
        except:
            pass
        
        return len(debugger_indicators) > 0
    
    def detect_hooks(self) -> bool:
        """Detect Xposed/Frida hooks and runtime manipulation"""
        hook_indicators = []
        

        try:
            xposed_files = [
                '/system/framework/XposedBridge.jar',
                '/system/xposed.prop',
                '/system/lib/libxposed_art.so',
                '/system/lib64/libxposed_art.so'
            ]
            
            for xposed_file in xposed_files:
                if os.path.exists(xposed_file):
                    hook_indicators.append(f"Xposed file: {xposed_file}")
        except:
            pass
        

        try:
            frida_indicators = [
                'frida-server',
                'frida-agent',
                'frida-gadget'
            ]
            
            for proc in psutil.process_iter(['name', 'cmdline']):
                proc_name = proc.info['name'].lower()
                cmdline = ' '.join(proc.info['cmdline'] or []).lower()
                
                if any(frida in proc_name or frida in cmdline for frida in frida_indicators):
                    hook_indicators.append(f"Frida component: {proc_name}")
        except:
            pass
        

        try:
            if sys.platform.startswith('linux'):
                result = subprocess.run(['cat', '/proc/self/maps'],
                                      capture_output=True, text=True, timeout=2)
                suspicious_libs = ['xposed', 'frida', 'substrate']
                
                for line in result.stdout.split('\n'):
                    if any(lib in line.lower() for lib in suspicious_libs):
                        hook_indicators.append(f"Suspicious library: {line.strip()}")
        except:
            pass
        

        try:

            import traceback
            stack = traceback.extract_stack()
            
            suspicious_frames = ['frida', 'xposed', 'substrate', 'cydia']
            for frame in stack:
                if any(sus in frame.filename.lower() for sus in suspicious_frames):
                    hook_indicators.append(f"Suspicious stack frame: {frame.filename}")
        except:
            pass
        
        return len(hook_indicators) > 0
    
    def verify_integrity(self) -> bool:
        """Verify application integrity and detect tampering"""
        try:

            current_file = __file__
            if os.path.exists(current_file):
                with open(current_file, 'rb') as f:
                    content = f.read()
                    current_hash = hashlib.sha256(content).hexdigest()
                    

                    if self.original_signature is None:
                        self.original_signature = current_hash
                        return True
                    

                    if current_hash != self.original_signature:
                        return False
            


            

            tampering_indicators = [
                '/data/local/tmp/frida-server',
                '/data/local/tmp/gdb',
                '/sdcard/payload.dex'
            ]
            
            for indicator in tampering_indicators:
                if os.path.exists(indicator):
                    return False
            
            return True
            
        except Exception:
            return False
    
    def start_continuous_monitoring(self, interval: int = 5):
        """Start continuous monitoring thread"""
        if self.monitoring_active:
            return
        
        self.monitoring_active = True
        
        def monitor():
            while self.monitoring_active:
                try:
                    self.check_all_detections()
                    time.sleep(interval)
                except:
                    break
        
        monitor_thread = threading.Thread(target=monitor, daemon=True)
        monitor_thread.start()
    
    def stop_monitoring(self):
        """Stop continuous monitoring"""
        self.monitoring_active = False
    
    def _check_app_installed(self, package_name: str) -> bool:
        """Check if an Android app is installed"""
        try:
            result = subprocess.run(['pm', 'list', 'packages', package_name],
                                  capture_output=True, text=True, timeout=5)
            return package_name in result.stdout
        except:
            return False
    
    def _get_system_property(self, prop_name: str) -> Optional[str]:
        """Get Android system property"""
        try:
            result = subprocess.run(['getprop', prop_name],
                                  capture_output=True, text=True, timeout=3)
            return result.stdout.strip() if result.returncode == 0 else None
        except:
            return None
    
    def _trigger_self_destruct(self):
        """Trigger self-destruction if analysis is detected"""
        try:

            if os.path.exists(__file__):
                os.remove(__file__)
            

            for key in list(os.environ.keys()):
                if 'python' in key.lower() or 'payload' in key.lower():
                    del os.environ[key]
            

            sys.exit(0)
            
        except Exception:
            pass


def quick_detection_check() -> bool:
    """Quick check for basic analysis environment"""
    detector = AntiAnalysis(enable_self_destruct=False)
    results = detector.check_all_detections()
    return any(results.values())

def stealth_sleep(duration: float):
    """Sleep with anti-debugging measures"""
    start_time = time.time()
    while (time.time() - start_time) < duration:
        time.sleep(0.001)


if __name__ == "__main__":
    print("Starting Anti-Analysis Security Check...")
    
    detector = AntiAnalysis(enable_self_destruct=False)
    results = detector.check_all_detections()
    
    print("\nDetection Results:")
    for check, result in results.items():
        status = "DETECTED" if result else "CLEAR"
        print(f"  {check}: {status}")
    

    print("\nStarting continuous monitoring...")
    detector.start_continuous_monitoring(interval=3)
    
    try:
        time.sleep(10)
    except KeyboardInterrupt:
        pass
    
    detector.stop_monitoring()
    print("Monitoring stopped.")
