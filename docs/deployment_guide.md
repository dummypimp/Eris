# Mythic Android Agent - Deployment Guide

## Overview

This guide provides comprehensive instructions for deploying the Mythic Android Agent framework, including prerequisites, installation steps, and production configuration guidelines.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [System Requirements](#system-requirements)
3. [Installation](#installation)
4. [Configuration](#configuration)
5. [Deployment Methods](#deployment-methods)
6. [Production Setup](#production-setup)
7. [Security Considerations](#security-considerations)
8. [Troubleshooting](#troubleshooting)

## Prerequisites

### Hardware Requirements

#### Minimum Requirements
- **CPU**: 4-core x64 processor
- **RAM**: 8GB (16GB recommended)
- **Storage**: 50GB free space
- **Network**: Stable internet connection

#### Recommended Requirements
- **CPU**: 8-core x64 processor (Intel i7/AMD Ryzen 7 or higher)
- **RAM**: 32GB for optimal performance
- **Storage**: 100GB+ SSD storage
- **Network**: High-speed internet with low latency

### Software Prerequisites

#### Operating System Support
- **Linux**: Ubuntu 20.04+ / Debian 10+ / CentOS 8+ / RHEL 8+
- **macOS**: macOS 11+ (Big Sur or later)
- **Windows**: Windows 10/11 (with WSL2 for best experience)

#### Required Software

1. **Docker & Docker Compose**
   ```bash
   # Ubuntu/Debian
   sudo apt update
   sudo apt install docker.io docker-compose

   # CentOS/RHEL
   sudo yum install docker docker-compose

   # macOS (using Homebrew)
   brew install docker docker-compose
   ```

2. **Python 3.9+**
   ```bash
   # Ubuntu/Debian
   sudo apt install python3.9 python3.9-pip python3.9-venv

   # macOS
   brew install python@3.9

   # Windows
   # Download from python.org
   ```

3. **Git**
   ```bash
   # Ubuntu/Debian
   sudo apt install git

   # macOS
   brew install git
   ```

4. **Node.js 16+** (for dashboard)
   ```bash
   # Ubuntu/Debian
   curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
   sudo apt-get install -y nodejs

   # macOS
   brew install node@18
   ```

#### Android Development Tools

1. **Java Development Kit (JDK) 11+**
   ```bash
   # Ubuntu/Debian
   sudo apt install openjdk-17-jdk

   # macOS
   brew install openjdk@17
   ```

2. **Android SDK & Build Tools**
   ```bash
   # Download Android SDK command line tools
   wget https://dl.google.com/android/repository/commandlinetools-linux-10406996_latest.zip
   unzip commandlinetools-linux-*_latest.zip
   mkdir -p ~/Android/Sdk/cmdline-tools
   mv cmdline-tools ~/Android/Sdk/cmdline-tools/latest

   # Set environment variables
   export ANDROID_HOME=~/Android/Sdk
   export PATH=$PATH:$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/platform-tools
   ```

3. **Accept SDK Licenses**
   ```bash
   yes | sdkmanager --licenses
   sdkmanager "platform-tools" "platforms;android-34" "build-tools;34.0.0"
   sdkmanager "ndk;25.2.9519653"
   ```

## System Requirements

### Network Configuration

#### Firewall Rules
```bash
# Allow necessary ports
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 80/tcp    # HTTP
sudo ufw allow 443/tcp   # HTTPS
sudo ufw allow 8080/tcp  # Dashboard
sudo ufw allow 8443/tcp  # HTTPS C2
sudo ufw enable
```

#### DNS Configuration
- Ensure proper DNS resolution for C2 domains
- Configure custom DNS servers if using DNS covert channel
- Set up domain fronting if required

### Storage Configuration

#### Directory Structure
```
/opt/mythic-android-agent/
├── data/
│   ├── campaigns/
│   ├── agents/
│   ├── logs/
│   └── uploads/
├── config/
│   ├── c2_profiles/
│   ├── ssl/
│   └── database/
├── backups/
└── tmp/
```

#### Permissions
```bash
sudo mkdir -p /opt/mythic-android-agent/{data/{campaigns,agents,logs,uploads},config/{c2_profiles,ssl,database},backups,tmp}
sudo chown -R $USER:$USER /opt/mythic-android-agent
chmod -R 750 /opt/mythic-android-agent
```

## Installation

### 1. Clone Repository

```bash
git clone https://github.com/your-org/mythic-android-agent.git
cd mythic-android-agent
```

### 2. Environment Setup

```bash
# Create Python virtual environment
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
# or
venv\Scripts\activate     # Windows

# Install Python dependencies
pip install -r requirements.txt
```

### 3. Docker Setup

```bash
# Build Docker images
docker build -t mythic-android-agent:latest .

# Verify build
docker images | grep mythic-android-agent
```

### 4. Database Setup

```bash
# Initialize database
python scripts/init_database.py

# Run migrations
python scripts/migrate_database.py
```

### 5. SSL Certificate Generation

```bash
# Generate self-signed certificates (development)
openssl req -x509 -newkey rsa:4096 -keyout config/ssl/key.pem -out config/ssl/cert.pem -days 365 -nodes

# Or use Let's Encrypt (production)
certbot certonly --standalone -d your-c2-domain.com
cp /etc/letsencrypt/live/your-c2-domain.com/*.pem config/ssl/
```

## Configuration

### 1. Main Configuration

Create `config/main.yml`:

```yaml
# Main configuration
server:
  host: "0.0.0.0"
  port: 8080
  ssl_enabled: true
  ssl_cert: "config/ssl/cert.pem"
  ssl_key: "config/ssl/key.pem"

database:
  type: "postgresql"
  host: "localhost"
  port: 5432
  name: "mythic_android"
  username: "mythic_user"
  password: "secure_password"

c2_profiles:
  enabled:
    - "https_beacon"
    - "fcm_push" 
    - "dns_covert"
  default: "https_beacon"

security:
  jwt_secret: "your-jwt-secret-key"
  encryption_key: "your-encryption-key"
  session_timeout: 3600

logging:
  level: "INFO"
  file: "data/logs/mythic-android.log"
  max_size_mb: 100
  backup_count: 5
```

### 2. C2 Profile Configuration

#### HTTPS Beacon (`config/c2_profiles/https_beacon.yml`):
```yaml
https_beacon:
  host: "0.0.0.0"
  port: 8443
  ssl_cert: "config/ssl/cert.pem"
  ssl_key: "config/ssl/key.pem"
  user_agent_rotation: true
  jitter_percent: 20
  endpoints:
    checkin: "/api/v1/checkin"
    tasks: "/api/v1/tasks"
    upload: "/api/v1/upload"
```

#### FCM Push (`config/c2_profiles/fcm_push.yml`):
```yaml
fcm_push:
  firebase_service_account: "config/firebase-service-account.json"
  fallback_polling: true
  poll_interval: 30
  message_priority: "high"
```

#### DNS Covert (`config/c2_profiles/dns_covert.yml`):
```yaml
dns_covert:
  domain: "c2tunnel.yourdomain.com"
  encoding: "base32"
  doh_provider: "cloudflare"
  chunk_size: 180
  compression: true
```

### 3. Campaign Configuration

```yaml
# config/campaigns/default.yml
campaign:
  id: "default_campaign"
  name: "Default Android Campaign"
  description: "Standard Android agent deployment"
  
agents:
  thread_pool_size: 5
  beacon_interval: 300
  offline_logging: true
  
android:
  target_versions: ["12", "13", "14"]
  bypass_features:
    - "privacy_indicators"
    - "screenshot_protection"
    - "anti_debugging"
  
modules:
    enabled:
      - "call_logger"
      - "filesystem"
      - "stealth_surveillance"
      - "overlay"
    load_order: "call_logger,filesystem,stealth_surveillance"
```

## Deployment Methods

### 1. Docker Deployment (Recommended)

#### Single Container
```bash
# Run single container
docker run -d \
  --name mythic-android-agent \
  -p 8080:8080 \
  -p 8443:8443 \
  -v $(pwd)/config:/app/config \
  -v $(pwd)/data:/app/data \
  mythic-android-agent:latest
```

#### Docker Compose
Create `docker-compose.yml`:

```yaml
version: '3.8'

services:
  mythic-android:
    build: .
    ports:
      - "8080:8080"
      - "8443:8443"
    volumes:
      - ./config:/app/config
      - ./data:/app/data
      - ./logs:/app/logs
    environment:
      - PYTHONPATH=/app
      - DATABASE_URL=postgresql://mythic_user:secure_password@postgres:5432/mythic_android
    depends_on:
      - postgres
      - redis
    restart: unless-stopped

  postgres:
    image: postgres:15
    environment:
      POSTGRES_DB: mythic_android
      POSTGRES_USER: mythic_user
      POSTGRES_PASSWORD: secure_password
    volumes:
      - postgres_data:/var/lib/postgresql/data
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    volumes:
      - redis_data:/data
    restart: unless-stopped

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./config/ssl:/etc/ssl/certs
    depends_on:
      - mythic-android
    restart: unless-stopped

volumes:
  postgres_data:
  redis_data:
```

Start deployment:
```bash
docker-compose up -d
```

### 2. Native Deployment

```bash
# Start the main server
python -m mythic_android_agent.server --config config/main.yml

# Start C2 profiles
python -m mythic_android_agent.c2_profiles.https_beacon --config config/c2_profiles/https_beacon.yml &
python -m mythic_android_agent.c2_profiles.fcm_push --config config/c2_profiles/fcm_push.yml &
python -m mythic_android_agent.c2_profiles.dns_covert --config config/c2_profiles/dns_covert.yml &
```

### 3. Kubernetes Deployment

```yaml
# k8s-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mythic-android-agent
spec:
  replicas: 3
  selector:
    matchLabels:
      app: mythic-android-agent
  template:
    metadata:
      labels:
        app: mythic-android-agent
    spec:
      containers:
      - name: mythic-android-agent
        image: mythic-android-agent:latest
        ports:
        - containerPort: 8080
        - containerPort: 8443
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: mythic-secrets
              key: database-url
        volumeMounts:
        - name: config
          mountPath: /app/config
        - name: data
          mountPath: /app/data
      volumes:
      - name: config
        configMap:
          name: mythic-config
      - name: data
        persistentVolumeClaim:
          claimName: mythic-data
---
apiVersion: v1
kind: Service
metadata:
  name: mythic-android-agent-service
spec:
  selector:
    app: mythic-android-agent
  ports:
  - name: web
    port: 80
    targetPort: 8080
  - name: c2
    port: 443
    targetPort: 8443
  type: LoadBalancer
```

Deploy to Kubernetes:
```bash
kubectl apply -f k8s-deployment.yaml
```

## Production Setup

### 1. Security Hardening

#### SSL/TLS Configuration
```nginx
# nginx.conf
server {
    listen 443 ssl http2;
    server_name your-c2-domain.com;
    
    ssl_certificate /etc/ssl/certs/cert.pem;
    ssl_certificate_key /etc/ssl/certs/key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512;
    ssl_prefer_server_ciphers off;
    
    add_header Strict-Transport-Security "max-age=63072000" always;
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    
    location / {
        proxy_pass http://mythic-android:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

#### Database Security
```bash
# PostgreSQL hardening
sudo -u postgres psql
ALTER USER mythic_user WITH ENCRYPTED PASSWORD 'new_secure_password';
CREATE DATABASE mythic_android OWNER mythic_user;
GRANT ALL PRIVILEGES ON DATABASE mythic_android TO mythic_user;
```

#### Firewall Configuration
```bash
# UFW rules for production
sudo ufw deny 8080/tcp  # Block direct access to app
sudo ufw deny 5432/tcp  # Block direct database access
sudo ufw allow from 10.0.0.0/8 to any port 8080  # Internal network only
```

### 2. Monitoring & Logging

#### Log Aggregation
```yaml
# filebeat.yml
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /opt/mythic-android-agent/data/logs/*.log
  fields:
    service: mythic-android-agent
    
output.elasticsearch:
  hosts: ["elasticsearch:9200"]
```

#### Metrics Collection
```yaml
# prometheus.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'mythic-android-agent'
    static_configs:
      - targets: ['localhost:8080']
    metrics_path: '/metrics'
```

### 3. Backup Strategy

```bash
#!/bin/bash
# backup.sh

DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/opt/mythic-android-agent/backups"

# Database backup
pg_dump mythic_android > "$BACKUP_DIR/db_backup_$DATE.sql"

# Configuration backup
tar -czf "$BACKUP_DIR/config_backup_$DATE.tar.gz" /opt/mythic-android-agent/config/

# Data backup
tar -czf "$BACKUP_DIR/data_backup_$DATE.tar.gz" /opt/mythic-android-agent/data/

# Cleanup old backups (keep last 7 days)
find "$BACKUP_DIR" -name "*backup*" -mtime +7 -delete

echo "Backup completed: $DATE"
```

Add to crontab:
```bash
crontab -e
# Add line:
0 2 * * * /opt/mythic-android-agent/scripts/backup.sh
```

### 4. High Availability Setup

#### Load Balancer Configuration
```yaml
# haproxy.cfg
global
    daemon

defaults
    mode http
    timeout connect 5000ms
    timeout client 50000ms
    timeout server 50000ms

frontend mythic_frontend
    bind *:80
    bind *:443 ssl crt /etc/ssl/certs/mythic.pem
    redirect scheme https if !{ ssl_fc }
    default_backend mythic_backend

backend mythic_backend
    balance roundrobin
    server mythic1 10.0.0.10:8080 check
    server mythic2 10.0.0.11:8080 check
    server mythic3 10.0.0.12:8080 check
```

## Security Considerations

### 1. Access Control
- Implement role-based access control (RBAC)
- Use strong authentication mechanisms
- Enable multi-factor authentication (MFA)
- Regular access reviews and revocation

### 2. Network Security
- Use VPNs for administrative access
- Implement network segmentation
- Monitor network traffic
- Use intrusion detection systems

### 3. Data Protection
- Encrypt data at rest and in transit
- Implement proper key management
- Regular security audits
- Secure data disposal procedures

### 4. Incident Response
- Develop incident response procedures
- Implement logging and monitoring
- Create communication plans
- Regular security drills

## Troubleshooting

### Common Issues

#### 1. Port Binding Errors
```bash
# Check if ports are in use
netstat -tulpn | grep :8080
sudo lsof -i :8080

# Kill processes using the port
sudo kill -9 $(sudo lsof -t -i:8080)
```

#### 2. SSL Certificate Issues
```bash
# Verify certificate
openssl x509 -in config/ssl/cert.pem -text -noout

# Test SSL connection
openssl s_client -connect your-domain:443 -servername your-domain
```

#### 3. Database Connection Issues
```bash
# Test database connection
psql -h localhost -U mythic_user -d mythic_android -c "SELECT version();"

# Check database logs
sudo tail -f /var/log/postgresql/postgresql-15-main.log
```

#### 4. Docker Issues
```bash
# Check container logs
docker logs mythic-android-agent

# Inspect container
docker exec -it mythic-android-agent /bin/bash

# Restart containers
docker-compose restart
```

### Log Analysis

#### Important Log Files
- Application logs: `/opt/mythic-android-agent/data/logs/mythic-android.log`
- C2 profile logs: `/opt/mythic-android-agent/data/logs/c2_*.log`
- System logs: `/var/log/syslog`
- Docker logs: `docker logs <container_name>`

#### Common Log Patterns
```bash
# Failed authentication attempts
grep "authentication failed" data/logs/mythic-android.log

# C2 communication errors
grep "C2 communication failed" data/logs/mythic-android.log

# Database connection issues
grep "database connection" data/logs/mythic-android.log
```

### Performance Tuning

#### Database Optimization
```sql
-- PostgreSQL optimization
ALTER SYSTEM SET shared_buffers = '256MB';
ALTER SYSTEM SET effective_cache_size = '1GB';
ALTER SYSTEM SET maintenance_work_mem = '64MB';
SELECT pg_reload_conf();
```

#### Application Tuning
```yaml
# config/main.yml
performance:
  worker_processes: 4
  max_connections: 1000
  connection_pool_size: 20
  query_timeout: 30
  cache_size: 128
```

### Support and Maintenance

#### Regular Maintenance Tasks
1. Update dependencies monthly
2. Review and rotate secrets quarterly
3. Perform security audits semi-annually
4. Update documentation as needed
5. Monitor resource usage continuously

#### Getting Help
- Check documentation: `/docs/`
- Review troubleshooting guide: `/docs/troubleshooting.md`
- Check system logs for error messages
- Contact support with detailed error information

---

## Next Steps

After successful deployment:

1. **Verify Installation**: Run the test suite to ensure all components are working
2. **Configure Campaigns**: Set up your first campaign using the operator manual
3. **Generate Payloads**: Create and deploy Android agents to target devices
4. **Monitor Operations**: Use the dashboard to monitor agent activity and health
5. **Review Security**: Conduct security assessment and implement additional hardening

For detailed operational procedures, see the [Operator Manual](operator_manual.md).
