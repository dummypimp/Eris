#!/usr/bin/env python3
"""
Create Frida Agent Assets - Embeds Frida servers and scripts into APK
"""

import os
import sys
import json
import shutil
import base64
import requests
from pathlib import Path
from typing import Dict, List

class FridaAssetCreator:
    def __init__(self):
        self.agent_dir = Path(__file__).parent.parent
        self.deps_dir = self.agent_dir / "dependencies"
        self.assets_dir = self.agent_dir / "assets"
        self.frida_assets_dir = self.assets_dir / "frida-agents"
        self.frida_version = "16.1.4"
        
        # Android architectures supported
        self.android_archs = {
            "arm64-v8a": "arm64",
            "armeabi-v7a": "arm", 
            "x86_64": "x86_64",
            "x86": "x86"
        }
        
        # Ensure directories exist
        self.assets_dir.mkdir(exist_ok=True)
        self.frida_assets_dir.mkdir(exist_ok=True)

    def create_embedded_frida_agents(self):
        """Create embedded Frida server binaries and scripts"""
        print("[+] Creating embedded Frida agent assets...")
        
        # Create Frida server assets
        self._embed_frida_servers()
        
        # Create default Frida scripts
        self._create_default_frida_scripts()
        
        # Create Frida management utilities
        self._create_frida_management_utils()
        
        # Create asset manifest
        self._create_asset_manifest()
        
        print("[+] Frida agent assets created successfully")

    def _embed_frida_servers(self):
        """Embed Frida server binaries for all Android architectures"""
        print("[+] Embedding Frida server binaries...")
        
        frida_servers_dir = self.frida_assets_dir / "servers"
        frida_servers_dir.mkdir(exist_ok=True)
        
        for apk_arch, frida_arch in self.android_archs.items():
            server_path = self.deps_dir / "frida-server" / f"frida-server-{self.frida_version}-android-{frida_arch}"
            
            if server_path.exists():
                # Create base64 encoded binary for embedding
                with open(server_path, 'rb') as f:
                    binary_data = f.read()
                
                encoded_binary = base64.b64encode(binary_data).decode('utf-8')
                
                # Save encoded binary
                encoded_path = frida_servers_dir / f"frida-server-{apk_arch}.b64"
                with open(encoded_path, 'w') as f:
                    f.write(encoded_binary)
                
                # Create metadata
                metadata = {
                    "architecture": apk_arch,
                    "frida_arch": frida_arch,
                    "version": self.frida_version,
                    "size": len(binary_data),
                    "encoded_size": len(encoded_binary),
                    "filename": f"frida-server-{apk_arch}.b64"
                }
                
                metadata_path = frida_servers_dir / f"frida-server-{apk_arch}.json"
                with open(metadata_path, 'w') as f:
                    json.dump(metadata, f, indent=2)
                
                print(f"[+] Embedded Frida server for {apk_arch}")
            else:
                print(f"[!] Frida server not found for {frida_arch}, skipping...")

    def _create_default_frida_scripts(self):
        """Create default Frida JavaScript scripts"""
        print("[+] Creating default Frida scripts...")
        
        scripts_dir = self.frida_assets_dir / "scripts"
        scripts_dir.mkdir(exist_ok=True)
        
        # Basic hook script
        basic_hook_script = '''
// Basic Frida Hook Script
console.log("[*] Basic Frida hook script loaded");

// Hook common Android functions
Java.perform(function() {
    console.log("[*] Java.perform started");
    
    // Hook Activity.onCreate
    var Activity = Java.use("android.app.Activity");
    Activity.onCreate.implementation = function(bundle) {
        console.log("[+] Activity.onCreate called: " + this.getClass().getName());
        return this.onCreate(bundle);
    };
    
    // Hook System.exit to prevent termination
    var System = Java.use("java.lang.System");
    System.exit.implementation = function(code) {
        console.log("[!] System.exit called with code: " + code);
        console.log("[*] Exit call blocked by Frida");
        return;
    };
    
    console.log("[*] Basic hooks installed");
});
'''
        
        with open(scripts_dir / "basic_hooks.js", 'w') as f:
            f.write(basic_hook_script)

        # SSL Pinning bypass script
        ssl_bypass_script = '''
// SSL Pinning Bypass Script
console.log("[*] SSL Pinning bypass script loaded");

Java.perform(function() {
    // TrustManager bypass
    var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
    TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
        console.log("[+] SSL verification bypassed for: " + host);
        return untrustedChain;
    };
    
    // OkHttp3 pinning bypass
    try {
        var OkHttpClient = Java.use("okhttp3.OkHttpClient");
        OkHttpClient.certificatePinner.implementation = function() {
            console.log("[+] OkHttp3 certificate pinner bypassed");
            return null;
        };
    } catch (e) {
        console.log("[*] OkHttp3 not found, skipping...");
    }
    
    // Apache HTTP client bypass
    try {
        var DefaultHttpClient = Java.use("org.apache.http.impl.client.DefaultHttpClient");
        DefaultHttpClient.execute.overload("org.apache.http.client.methods.HttpUriRequest").implementation = function(request) {
            console.log("[+] Apache HTTP request: " + request.getURI());
            return this.execute(request);
        };
    } catch (e) {
        console.log("[*] Apache HTTP client not found, skipping...");
    }
    
    console.log("[*] SSL bypass hooks installed");
});
'''
        
        with open(scripts_dir / "ssl_bypass.js", 'w') as f:
            f.write(ssl_bypass_script)

        # Root detection bypass
        root_bypass_script = '''
// Root Detection Bypass Script
console.log("[*] Root detection bypass script loaded");

Java.perform(function() {
    // File existence checks
    var File = Java.use("java.io.File");
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        if (path.indexOf("su") !== -1 || 
            path.indexOf("busybox") !== -1 || 
            path.indexOf("Superuser") !== -1) {
            console.log("[+] Blocked file existence check: " + path);
            return false;
        }
        return this.exists();
    };
    
    // Runtime.exec bypass
    var Runtime = Java.use("java.lang.Runtime");
    Runtime.exec.overload("[Ljava.lang.String;").implementation = function(commands) {
        var cmdStr = commands.join(" ");
        if (cmdStr.indexOf("su") !== -1 || cmdStr.indexOf("which") !== -1) {
            console.log("[+] Blocked command execution: " + cmdStr);
            throw new Error("Command not found");
        }
        return this.exec(commands);
    };
    
    // Package manager checks
    var PackageManager = Java.use("android.content.pm.PackageManager");
    PackageManager.getInstalledPackages.implementation = function(flags) {
        var packages = this.getInstalledPackages(flags);
        var filtered = [];
        
        for (var i = 0; i < packages.size(); i++) {
            var pkg = packages.get(i);
            var pkgName = pkg.packageName.value;
            
            if (pkgName.indexOf("superuser") === -1 && 
                pkgName.indexOf("chainfire") === -1 &&
                pkgName.indexOf("magisk") === -1) {
                filtered.push(pkg);
            } else {
                console.log("[+] Filtered root package: " + pkgName);
            }
        }
        
        return filtered;
    };
    
    console.log("[*] Root detection bypass hooks installed");
});
'''
        
        with open(scripts_dir / "root_bypass.js", 'w') as f:
            f.write(root_bypass_script)

        # Crypto hooks script
        crypto_hooks_script = '''
// Cryptographic Functions Hook Script
console.log("[*] Crypto hooks script loaded");

Java.perform(function() {
    // AES encryption hooks
    var Cipher = Java.use("javax.crypto.Cipher");
    Cipher.doFinal.overload("[B").implementation = function(input) {
        var algorithm = this.getAlgorithm();
        console.log("[+] Cipher operation: " + algorithm);
        console.log("[+] Input length: " + input.length);
        
        var result = this.doFinal(input);
        console.log("[+] Output length: " + result.length);
        
        return result;
    };
    
    // MessageDigest hooks
    var MessageDigest = Java.use("java.security.MessageDigest");
    MessageDigest.digest.overload("[B").implementation = function(input) {
        var algorithm = this.getAlgorithm();
        console.log("[+] Hash operation: " + algorithm);
        console.log("[+] Input: " + Java.use("java.lang.String").$new(input));
        
        var result = this.digest(input);
        return result;
    };
    
    // Base64 operations
    var Base64 = Java.use("android.util.Base64");
    Base64.decode.overload("java.lang.String", "int").implementation = function(str, flags) {
        console.log("[+] Base64 decode: " + str.substring(0, Math.min(str.length, 50)));
        return this.decode(str, flags);
    };
    
    Base64.encode.overload("[B", "int").implementation = function(input, flags) {
        console.log("[+] Base64 encode: " + input.length + " bytes");
        return this.encode(input, flags);
    };
    
    console.log("[*] Crypto hooks installed");
});
'''
        
        with open(scripts_dir / "crypto_hooks.js", 'w') as f:
            f.write(crypto_hooks_script)

    def _create_frida_management_utils(self):
        """Create Frida server management utilities"""
        print("[+] Creating Frida management utilities...")
        
        utils_dir = self.frida_assets_dir / "utils"
        utils_dir.mkdir(exist_ok=True)
        
        # Frida server manager Java class
        frida_manager_java = '''
package com.android.systemservice.frida;

import android.content.Context;
import android.util.Base64;
import android.util.Log;
import java.io.*;
import java.util.concurrent.CompletableFuture;

public class EmbeddedFridaManager {
    private static final String TAG = "FridaManager";
    private static final String FRIDA_SERVER_PATH = "/data/local/tmp/frida-server";
    
    private Context context;
    private Process fridaProcess;
    private String currentArch;
    private boolean isRunning = false;
    
    public EmbeddedFridaManager(Context context) {
        this.context = context;
        this.currentArch = detectArchitecture();
    }
    
    public CompletableFuture<Boolean> deployAndStartServer() {
        return CompletableFuture.supplyAsync(() -> {
            try {
                // Deploy Frida server binary
                if (!deployFridaServer()) {
                    Log.e(TAG, "Failed to deploy Frida server");
                    return false;
                }
                
                // Start Frida server
                if (!startFridaServer()) {
                    Log.e(TAG, "Failed to start Frida server");
                    return false;
                }
                
                isRunning = true;
                Log.i(TAG, "Frida server started successfully");
                return true;
                
            } catch (Exception e) {
                Log.e(TAG, "Frida server deployment failed: " + e.getMessage());
                return false;
            }
        });
    }
    
    private boolean deployFridaServer() {
        try {
            String assetName = "frida-server-" + currentArch + ".b64";
            InputStream inputStream = context.getAssets().open("frida-agents/servers/" + assetName);
            
            // Read base64 encoded binary
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte[] buffer = new byte[1024];
            int length;
            while ((length = inputStream.read(buffer)) != -1) {
                baos.write(buffer, 0, length);
            }
            inputStream.close();
            
            // Decode binary data
            String encodedData = baos.toString();
            byte[] binaryData = Base64.decode(encodedData, Base64.DEFAULT);
            
            // Write to device
            FileOutputStream fos = new FileOutputStream(FRIDA_SERVER_PATH);
            fos.write(binaryData);
            fos.close();
            
            // Set executable permissions
            Runtime.getRuntime().exec("chmod 755 " + FRIDA_SERVER_PATH).waitFor();
            
            Log.i(TAG, "Frida server deployed to: " + FRIDA_SERVER_PATH);
            return true;
            
        } catch (Exception e) {
            Log.e(TAG, "Failed to deploy Frida server: " + e.getMessage());
            return false;
        }
    }
    
    private boolean startFridaServer() {
        try {
            ProcessBuilder pb = new ProcessBuilder(FRIDA_SERVER_PATH, "-D");
            pb.environment().put("FRIDA_SERVER_LISTEN", "127.0.0.1:27042");
            
            fridaProcess = pb.start();
            
            // Give server time to start
            Thread.sleep(2000);
            
            // Check if process is still running
            if (fridaProcess.isAlive()) {
                Log.i(TAG, "Frida server process started");
                return true;
            } else {
                Log.e(TAG, "Frida server process died immediately");
                return false;
            }
            
        } catch (Exception e) {
            Log.e(TAG, "Failed to start Frida server: " + e.getMessage());
            return false;
        }
    }
    
    public void stopFridaServer() {
        if (fridaProcess != null && fridaProcess.isAlive()) {
            fridaProcess.destroy();
            isRunning = false;
            Log.i(TAG, "Frida server stopped");
        }
    }
    
    public boolean isServerRunning() {
        return isRunning && fridaProcess != null && fridaProcess.isAlive();
    }
    
    private String detectArchitecture() {
        String abi = System.getProperty("os.arch");
        String[] supportedAbis = getSupportedAbis();
        
        if (supportedAbis.length > 0) {
            String primaryAbi = supportedAbis[0];
            
            switch (primaryAbi) {
                case "arm64-v8a":
                    return "arm64-v8a";
                case "armeabi-v7a":
                    return "armeabi-v7a";
                case "x86_64":
                    return "x86_64";
                case "x86":
                    return "x86";
                default:
                    return "arm64-v8a"; // Default fallback
            }
        }
        
        return "arm64-v8a";
    }
    
    private String[] getSupportedAbis() {
        try {
            return (String[]) Class.forName("android.os.Build")
                .getField("SUPPORTED_ABIS").get(null);
        } catch (Exception e) {
            return new String[]{"arm64-v8a"};
        }
    }
    
    public CompletableFuture<String> executeScript(String scriptContent, String targetPackage) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                // Create temporary script file
                File scriptFile = File.createTempFile("frida_script", ".js", context.getCacheDir());
                FileWriter writer = new FileWriter(scriptFile);
                writer.write(scriptContent);
                writer.close();
                
                // Execute script using frida command
                ProcessBuilder pb = new ProcessBuilder(
                    "frida", "-U", "-f", targetPackage, "-l", scriptFile.getAbsolutePath(), "--no-pause"
                );
                
                Process process = pb.start();
                
                // Read output
                BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                StringBuilder output = new StringBuilder();
                String line;
                
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\\n");
                }
                
                process.waitFor();
                scriptFile.delete();
                
                return output.toString();
                
            } catch (Exception e) {
                Log.e(TAG, "Script execution failed: " + e.getMessage());
                return "Error: " + e.getMessage();
            }
        });
    }
}
'''
        
        with open(utils_dir / "EmbeddedFridaManager.java", 'w') as f:
            f.write(frida_manager_java)

    def _create_asset_manifest(self):
        """Create manifest of all embedded assets"""
        manifest = {
            "version": self.frida_version,
            "created_at": self._get_timestamp(),
            "frida_servers": {},
            "scripts": [],
            "utils": []
        }
        
        # Add server information
        servers_dir = self.frida_assets_dir / "servers"
        if servers_dir.exists():
            for json_file in servers_dir.glob("*.json"):
                with open(json_file, 'r') as f:
                    server_info = json.load(f)
                    manifest["frida_servers"][server_info["architecture"]] = server_info
        
        # Add script information
        scripts_dir = self.frida_assets_dir / "scripts"
        if scripts_dir.exists():
            for script_file in scripts_dir.glob("*.js"):
                manifest["scripts"].append({
                    "name": script_file.stem,
                    "filename": script_file.name,
                    "size": os.path.getsize(script_file)
                })
        
        # Add utility information
        utils_dir = self.frida_assets_dir / "utils"
        if utils_dir.exists():
            for util_file in utils_dir.glob("*.java"):
                manifest["utils"].append({
                    "name": util_file.stem,
                    "filename": util_file.name,
                    "type": "java_class",
                    "size": os.path.getsize(util_file)
                })
        
        # Save manifest
        manifest_path = self.frida_assets_dir / "manifest.json"
        with open(manifest_path, 'w') as f:
            json.dump(manifest, f, indent=2)
        
        print(f"[+] Asset manifest created: {manifest_path}")

    def _get_timestamp(self):
        """Get current timestamp"""
        import datetime
        return datetime.datetime.now().isoformat()

def main():
    """Main function"""
    creator = FridaAssetCreator()
    creator.create_embedded_frida_agents()
    print("[+] Frida asset creation complete!")

if __name__ == "__main__":
    main()
