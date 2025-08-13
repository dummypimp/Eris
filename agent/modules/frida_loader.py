
"""
Frida dynamic instrumentation module for runtime app analysis
"""
import json
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Dict, Any

class FridaModule:
    def __init__(self, agent):
        self.agent = agent
        self.active_scripts = {}
        self.frida_server_port = 27042
        
    def execute(self, command: str, args: Dict[str, Any]) -> Dict[str, Any]:
        """Execute Frida-related commands"""
        try:
            if command == "inject":
                return self.inject_script(args)
            elif command == "detach":
                return self.detach_script(args)
            elif command == "list_processes":
                return self.list_processes()
            elif command == "list_scripts":
                return self.list_active_scripts()
            elif command == "execute_script":
                return self.execute_script(args)
            else:
                return {"error": f"Unknown Frida command: {command}"}
                
        except Exception as e:
            return {"error": f"Frida operation failed: {str(e)}"}
    
    def inject_script(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Inject Frida script into target process"""
        try:
            target_app = args.get("target_app")
            script_code = args.get("script_code")
            script_name = args.get("script_name", f"script_{int(time.time())}")
            
            if not target_app or not script_code:
                return {"error": "target_app and script_code required"}
            

            with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as f:
                f.write(script_code)
                script_path = f.name
            

            cmd = [
                "frida",
                "-U",
                "-f", target_app,
                "-l", script_path,
                "--no-pause"
            ]
            
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                if result.returncode == 0:
                    self.active_scripts[script_name] = {
                        "target_app": target_app,
                        "script_path": script_path,
                        "injected_at": time.time(),
                        "status": "active"
                    }
                    

                    self.agent.offline_logger.log_event("frida_injected", {
                        "script_name": script_name,
                        "target_app": target_app,
                        "script_code": script_code[:200] + "..." if len(script_code) > 200 else script_code
                    })
                    
                    return {
                        "success": True,
                        "script_name": script_name,
                        "message": f"Script injected into {target_app}",
                        "output": result.stdout
                    }
                else:
                    return {
                        "error": f"Frida injection failed: {result.stderr}"
                    }
                    
            finally:

                Path(script_path).unlink(missing_ok=True)
                
        except subprocess.TimeoutExpired:
            return {"error": "Frida injection timeout"}
        except Exception as e:
            return {"error": f"Injection failed: {str(e)}"}
    
    def detach_script(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Detach active Frida script"""
        try:
            script_name = args.get("script_name")
            
            if script_name in self.active_scripts:

                self.active_scripts[script_name]["status"] = "detached"
                self.active_scripts[script_name]["detached_at"] = time.time()
                
                return {
                    "success": True,
                    "message": f"Script {script_name} detached"
                }
            else:
                return {"error": f"Script {script_name} not found"}
                
        except Exception as e:
            return {"error": f"Detach failed: {str(e)}"}
    
    def list_processes(self) -> Dict[str, Any]:
        """List running processes for Frida targeting"""
        try:
            cmd = ["frida-ps", "-U"]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                processes = []
                for line in result.stdout.strip().split('\n')[1:]:
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        processes.append({
                            "pid": parts[0],
                            "name": " ".join(parts[1:])
                        })
                
                return {
                    "success": True,
                    "processes": processes
                }
            else:
                return {"error": f"Failed to list processes: {result.stderr}"}
                
        except subprocess.TimeoutExpired:
            return {"error": "Process listing timeout"}
        except Exception as e:
            return {"error": f"Process listing failed: {str(e)}"}
    
    def list_active_scripts(self) -> Dict[str, Any]:
        """List currently active Frida scripts"""
        return {
            "success": True,
            "scripts": self.active_scripts
        }
    
    def execute_script(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Execute one-time Frida script"""
        try:
            target_app = args.get("target_app")
            script_code = args.get("script_code")
            timeout = args.get("timeout", 30)
            
            if not target_app or not script_code:
                return {"error": "target_app and script_code required"}
            

            with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as f:
                f.write(script_code)
                script_path = f.name
            
            try:
                cmd = [
                    "frida",
                    "-U",
                    target_app,
                    "-l", script_path,
                    "--runtime=v8"
                ]
                
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout
                )
                
                return {
                    "success": result.returncode == 0,
                    "output": result.stdout,
                    "error": result.stderr if result.returncode != 0 else None
                }
                
            finally:
                Path(script_path).unlink(missing_ok=True)
                
        except subprocess.TimeoutExpired:
            return {"error": f"Script execution timeout ({timeout}s)"}
        except Exception as e:
            return {"error": f"Script execution failed: {str(e)}"}
