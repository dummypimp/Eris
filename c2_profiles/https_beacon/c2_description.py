
"""
HTTPS Beacon C2 Profile Description for Mythic
"""
import os
import sys


try:
    from mythic_container import C2ProfileBase, C2Profile, C2ProfileParameter, C2ProfileParameterType
except ImportError:

    class C2ProfileBase:
        pass
    
    class C2Profile:
        pass
    
    class C2ProfileParameter:
        def __init__(self, name, description, default_value, parameter_type, required=True):
            self.name = name
            self.description = description
            self.default_value = default_value
            self.parameter_type = parameter_type
            self.required = required
    
    class C2ProfileParameterType:
        String = "string"
        Number = "number"
        Boolean = "boolean"

try:
    from aiohttp import web, ClientSession
except ImportError:
    web = None
    ClientSession = None
    print("[!] aiohttp not available. Install with: pip install aiohttp")

    
    class C2ProfileParameter:
        def __init__(self, name, description, default_value, parameter_type, required=True):
            self.name = name
            self.description = description
            self.default_value = default_value
            self.parameter_type = parameter_type
            self.required = required
    
    class C2ProfileParameterType:
        String = "string"
        Number = "number"
        Boolean = "boolean"

class HTTPSBeaconProfile(C2Profile):
    name = "https_beacon"
    description = "HTTPS beacon profile optimized for mobile agents"
    author = "Red Team"
    is_p2p = False
    is_server_routed = True
    
    parameters = [
        C2ProfileParameter(
            name="callback_host",
            description="HTTPS callback hostname",
            default_value="https://api.example.com",
            parameter_type=C2ProfileParameterType.String,
            required=True
        ),
        C2ProfileParameter(
            name="callback_port",
            description="HTTPS callback port",
            default_value=443,
            parameter_type=C2ProfileParameterType.Number,
            required=True
        ),
        C2ProfileParameter(
            name="get_uri",
            description="URI path for agent check-ins",
            default_value="/api/v1/mobile/checkin",
            parameter_type=C2ProfileParameterType.String,
            required=True
        ),
        C2ProfileParameter(
            name="post_uri",
            description="URI path for response submissions",
            default_value="/api/v1/mobile/submit",
            parameter_type=C2ProfileParameterType.String,
            required=True
        ),
        C2ProfileParameter(
            name="user_agent",
            description="HTTP User-Agent string for mobile mimicry",
            default_value="Mozilla/5.0 (Linux; Android 13; SM-G991B) AppleWebKit/537.36",
            parameter_type=C2ProfileParameterType.String,
            required=True
        ),
        C2ProfileParameter(
            name="beacon_interval",
            description="Check-in interval in seconds",
            default_value=300,
            parameter_type=C2ProfileParameterType.Number,
            required=True
        )
    ]
