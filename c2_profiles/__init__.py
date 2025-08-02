from c2_profiles.https_beacon import HTTPSBeacon
from c2_profiles.fcm_push import FCMPush  
from c2_profiles.dns_covert import DNSCovert

"""
C2 Profiles Package for Mythic Android Agent
"""

# Import all available C2 profiles
try:
    from .https_beacon import HTTPSBeacon
except ImportError:
    HTTPSBeacon = None

try:
    from .fcm_push import FCMPush
except ImportError:
    FCMPush = None

try:
    from .dns_covert import DNSCovert
except ImportError:
    DNSCovert = None

# Export available profiles
__all__ = []
if HTTPSBeacon:
    __all__.append('HTTPSBeacon')
if FCMPush:
    __all__.append('FCMPush')
if DNSCovert:
    __all__.append('DNSCovert')

# Profile registry for dynamic loading
AVAILABLE_PROFILES = {
    'https_beacon': HTTPSBeacon,
    'fcm_push': FCMPush,
    'dns_covert': DNSCovert
}

def get_profile(profile_name: str):
    """Get C2 profile class by name"""
    return AVAILABLE_PROFILES.get(profile_name)
