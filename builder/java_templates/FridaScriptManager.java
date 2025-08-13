package com.android.systemservice.frida;

import android.content.Context;
import android.content.res.AssetManager;
import android.util.Log;
import java.io.*;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * Frida Script Manager - Manages loading and caching of Frida JavaScript scripts
 * Provides centralized script management with asset loading capabilities
 */
public class FridaScriptManager {
    private static final String TAG = "FridaScriptManager";
    private static final String SCRIPTS_PATH = "frida-agents/scripts";
    
    private Context context;
    private Map<String, String> loadedScripts;
    private boolean initialized = false;
    
    public FridaScriptManager(Context context) {
        this.context = context;
        this.loadedScripts = new HashMap<>();
    }
    
    /**
     * Load default scripts from assets
     */
    public void loadDefaultScripts() {
        if (initialized) {
            return;
        }
        
        Log.d(TAG, "Loading default Frida scripts...");
        
        try {
            AssetManager assetManager = context.getAssets();
            String[] scriptFiles = assetManager.list(SCRIPTS_PATH);
            
            if (scriptFiles != null) {
                for (String scriptFile : scriptFiles) {
                    if (scriptFile.endsWith(".js")) {
                        loadScriptFromAssets(scriptFile);
                    }
                }
            }
            
            // Load built-in scripts
            loadBuiltInScripts();
            
            initialized = true;
            Log.i(TAG, "Loaded " + loadedScripts.size() + " Frida scripts");
            
        } catch (Exception e) {
            Log.e(TAG, "Failed to load default scripts", e);
        }
    }
    
    /**
     * Load a specific script from assets
     */
    private void loadScriptFromAssets(String scriptFile) {
        try {
            AssetManager assetManager = context.getAssets();
            String scriptPath = SCRIPTS_PATH + "/" + scriptFile;
            
            InputStream inputStream = assetManager.open(scriptPath);
            BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
            StringBuilder scriptContent = new StringBuilder();
            
            String line;
            while ((line = reader.readLine()) != null) {
                scriptContent.append(line).append("\n");
            }
            
            reader.close();
            inputStream.close();
            
            String scriptName = scriptFile.replace(".js", "");
            loadedScripts.put(scriptName, scriptContent.toString());
            
            Log.d(TAG, "Loaded script: " + scriptName);
            
        } catch (Exception e) {
            Log.e(TAG, "Failed to load script: " + scriptFile, e);
        }
    }
    
    /**
     * Load built-in scripts that are hardcoded
     */
    private void loadBuiltInScripts() {
        // System information script
        String systemInfoScript = 
            "console.log('[*] System Information Script loaded');\n" +
            "Java.perform(function() {\n" +
            "    var Build = Java.use('android.os.Build');\n" +
            "    console.log('[+] Device: ' + Build.MANUFACTURER.value + ' ' + Build.MODEL.value);\n" +
            "    console.log('[+] Android Version: ' + Build.VERSION.RELEASE.value + ' (API ' + Build.VERSION.SDK_INT.value + ')');\n" +
            "    console.log('[+] Architecture: ' + Build.SUPPORTED_ABIS.value);\n" +
            "});";
        loadedScripts.put("system_info", systemInfoScript);
        
        // Activity monitoring script
        String activityMonitorScript = 
            "console.log('[*] Activity Monitor Script loaded');\n" +
            "Java.perform(function() {\n" +
            "    var Activity = Java.use('android.app.Activity');\n" +
            "    Activity.onCreate.implementation = function(bundle) {\n" +
            "        console.log('[+] Activity created: ' + this.getClass().getName());\n" +
            "        return this.onCreate(bundle);\n" +
            "    };\n" +
            "    Activity.onResume.implementation = function() {\n" +
            "        console.log('[+] Activity resumed: ' + this.getClass().getName());\n" +
            "        return this.onResume();\n" +
            "    };\n" +
            "});";
        loadedScripts.put("activity_monitor", activityMonitorScript);
        
        // Network monitoring script
        String networkMonitorScript = 
            "console.log('[*] Network Monitor Script loaded');\n" +
            "Java.perform(function() {\n" +
            "    try {\n" +
            "        var URL = Java.use('java.net.URL');\n" +
            "        URL.openConnection.implementation = function() {\n" +
            "            console.log('[+] Network connection: ' + this.toString());\n" +
            "            return this.openConnection();\n" +
            "        };\n" +
            "    } catch (e) {\n" +
            "        console.log('[!] Network monitoring hook failed: ' + e);\n" +
            "    }\n" +
            "});";
        loadedScripts.put("network_monitor", networkMonitorScript);
        
        // File system monitoring script
        String fileMonitorScript = 
            "console.log('[*] File System Monitor Script loaded');\n" +
            "Java.perform(function() {\n" +
            "    var File = Java.use('java.io.File');\n" +
            "    File.delete.implementation = function() {\n" +
            "        console.log('[+] File deletion: ' + this.getAbsolutePath());\n" +
            "        return this.delete();\n" +
            "    };\n" +
            "    File.mkdir.implementation = function() {\n" +
            "        console.log('[+] Directory creation: ' + this.getAbsolutePath());\n" +
            "        return this.mkdir();\n" +
            "    };\n" +
            "});";
        loadedScripts.put("file_monitor", fileMonitorScript);
        
        // SSL pinning bypass script
        String sslBypassScript = 
            "console.log('[*] SSL Pinning Bypass Script loaded');\n" +
            "Java.perform(function() {\n" +
            "    try {\n" +
            "        var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');\n" +
            "        TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {\n" +
            "            console.log('[+] SSL verification bypassed for: ' + host);\n" +
            "            return untrustedChain;\n" +
            "        };\n" +
            "    } catch (e) {\n" +
            "        console.log('[!] SSL bypass hook failed: ' + e);\n" +
            "    }\n" +
            "});";
        loadedScripts.put("ssl_bypass", sslBypassScript);
        
        // Root detection bypass script
        String rootBypassScript = 
            "console.log('[*] Root Detection Bypass Script loaded');\n" +
            "Java.perform(function() {\n" +
            "    var File = Java.use('java.io.File');\n" +
            "    File.exists.implementation = function() {\n" +
            "        var path = this.getAbsolutePath();\n" +
            "        if (path.indexOf('su') !== -1 || path.indexOf('busybox') !== -1 || path.indexOf('Superuser') !== -1) {\n" +
            "            console.log('[+] Blocked file existence check: ' + path);\n" +
            "            return false;\n" +
            "        }\n" +
            "        return this.exists();\n" +
            "    };\n" +
            "});";
        loadedScripts.put("root_bypass", rootBypassScript);
        
        Log.d(TAG, "Built-in scripts loaded");
    }
    
    /**
     * Get a script by name
     */
    public String getScript(String scriptName) {
        return loadedScripts.get(scriptName);
    }
    
    /**
     * Add or update a script
     */
    public void addScript(String scriptName, String scriptContent) {
        loadedScripts.put(scriptName, scriptContent);
        Log.d(TAG, "Added/updated script: " + scriptName);
    }
    
    /**
     * Remove a script
     */
    public boolean removeScript(String scriptName) {
        String removed = loadedScripts.remove(scriptName);
        if (removed != null) {
            Log.d(TAG, "Removed script: " + scriptName);
            return true;
        }
        return false;
    }
    
    /**
     * Get all available script names
     */
    public Set<String> getAvailableScripts() {
        return loadedScripts.keySet();
    }
    
    /**
     * Check if a script exists
     */
    public boolean hasScript(String scriptName) {
        return loadedScripts.containsKey(scriptName);
    }
    
    /**
     * Get script count
     */
    public int getScriptCount() {
        return loadedScripts.size();
    }
    
    /**
     * Generate a combined script from multiple scripts
     */
    public String combineScripts(String... scriptNames) {
        StringBuilder combinedScript = new StringBuilder();
        combinedScript.append("console.log('[*] Combined script execution started');\n");
        
        for (String scriptName : scriptNames) {
            String script = getScript(scriptName);
            if (script != null) {
                combinedScript.append("// === ").append(scriptName).append(" ===\n");
                combinedScript.append(script).append("\n");
                combinedScript.append("// === End ").append(scriptName).append(" ===\n\n");
            } else {
                Log.w(TAG, "Script not found for combination: " + scriptName);
            }
        }
        
        combinedScript.append("console.log('[*] Combined script execution completed');\n");
        return combinedScript.toString();
    }
    
    /**
     * Create a custom hook script for a specific class and method
     */
    public String createHookScript(String className, String methodName, String hookType) {
        StringBuilder hookScript = new StringBuilder();
        hookScript.append("console.log('[*] Custom hook script for ").append(className).append(".").append(methodName).append("');\n");
        hookScript.append("Java.perform(function() {\n");
        hookScript.append("    try {\n");
        hookScript.append("        var targetClass = Java.use('").append(className).append("');\n");
        
        switch (hookType.toLowerCase()) {
            case "log":
                hookScript.append("        targetClass.").append(methodName).append(".implementation = function() {\n");
                hookScript.append("            console.log('[+] Method called: ").append(className).append(".").append(methodName).append("');\n");
                hookScript.append("            return this.").append(methodName).append(".apply(this, arguments);\n");
                hookScript.append("        };\n");
                break;
                
            case "block":
                hookScript.append("        targetClass.").append(methodName).append(".implementation = function() {\n");
                hookScript.append("            console.log('[!] Method blocked: ").append(className).append(".").append(methodName).append("');\n");
                hookScript.append("            return null;\n");
                hookScript.append("        };\n");
                break;
                
            case "trace":
                hookScript.append("        targetClass.").append(methodName).append(".implementation = function() {\n");
                hookScript.append("            console.log('[+] Method trace: ").append(className).append(".").append(methodName).append("');\n");
                hookScript.append("            console.log('[+] Arguments: ' + JSON.stringify(arguments));\n");
                hookScript.append("            var result = this.").append(methodName).append(".apply(this, arguments);\n");
                hookScript.append("            console.log('[+] Return value: ' + result);\n");
                hookScript.append("            return result;\n");
                hookScript.append("        };\n");
                break;
                
            default:
                hookScript.append("        // Custom hook implementation\n");
                hookScript.append("        targetClass.").append(methodName).append(".implementation = function() {\n");
                hookScript.append("            return this.").append(methodName).append(".apply(this, arguments);\n");
                hookScript.append("        };\n");
        }
        
        hookScript.append("        console.log('[+] Hook installed for ").append(className).append(".").append(methodName).append("');\n");
        hookScript.append("    } catch (e) {\n");
        hookScript.append("        console.log('[!] Hook failed: ' + e);\n");
        hookScript.append("    }\n");
        hookScript.append("});");
        
        return hookScript.toString();
    }
    
    /**
     * Clear all loaded scripts
     */
    public void clearScripts() {
        loadedScripts.clear();
        initialized = false;
        Log.d(TAG, "All scripts cleared");
    }
}
