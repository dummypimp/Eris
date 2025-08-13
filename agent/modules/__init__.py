"""
Mythic Android Agent Modules
Production-ready capability modules for mobile operations
"""


from . import overlay
from . import frida_loader
from . import call_logger
from . import filesystem
from ..utils import offline_logger


AVAILABLE_MODULES = {
    "overlay": overlay.OverlayModule,
    "frida_loader": frida_loader.FridaModule,
    "call_logger": call_logger.CallLoggerModule,
    "filesystem": filesystem.FilesystemModule,
}

def get_module(module_name: str):
    """Get module class by name"""
    return AVAILABLE_MODULES.get(module_name)

def list_modules():
    """List all available modules"""
    return list(AVAILABLE_MODULES.keys())
