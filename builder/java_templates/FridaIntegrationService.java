package com.android.systemservice.frida;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;
import android.os.Build;
import android.util.Log;
import java.io.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import android.content.Context;
import android.content.res.AssetManager;
import java.util.HashMap;
import java.util.Map;

/**
 * Frida Integration Service - Manages embedded Frida server and script execution
 * Supports multi-session handling and architecture-specific binary deployment
 */
public class FridaIntegrationService extends Service {
    private static final String TAG = "FridaService";
    private static final String FRIDA_SERVER_BINARY = "frida-server";
    private static final String FRIDA_ASSETS_PATH = "frida-agents";
    
    private ExecutorService executorService;
    private Process fridaServerProcess;
    private FridaMultiHandler multiHandler;
    private String currentArchitecture;
    private boolean isServerRunning = false;
    
    // Architecture mapping for Frida binaries
    private static final Map<String, String> ARCH_MAPPING = new HashMap<String, String>() {{
        put("aarch64", "arm64-v8a");
        put("arm64-v8a", "arm64-v8a");
        put("armeabi-v7a", "armeabi-v7a");
        put("x86_64", "x86_64");
        put("x86", "x86");
    }};

    @Override
    public void onCreate() {
        super.onCreate();
        Log.d(TAG, "Frida Integration Service created");
        
        executorService = Executors.newCachedThreadPool();
        multiHandler = new FridaMultiHandler(this);
        currentArchitecture = detectArchitecture();
        
        // Initialize Frida server in background
        executorService.execute(this::initializeFridaServer);
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        Log.d(TAG, "Frida service start command received");
        
        if (intent != null) {
            String action = intent.getStringExtra("action");
            if (action != null) {
                handleAction(action, intent);
            }
        }
        
        return START_STICKY; // Restart service if killed
    }

    @Override
    public IBinder onBind(Intent intent) {
        return multiHandler.getBinder();
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        Log.d(TAG, "Frida service destroying...");
        
        stopFridaServer();
        if (executorService != null) {
            executorService.shutdown();
        }
        if (multiHandler != null) {
            multiHandler.cleanup();
        }
    }

    /**
     * Initialize and start the embedded Frida server
     */
    private void initializeFridaServer() {
        try {
            Log.d(TAG, "Initializing Frida server for architecture: " + currentArchitecture);
            
            // Extract Frida server binary
            File fridaServerFile = extractFridaServer();
            if (fridaServerFile == null) {
                Log.e(TAG, "Failed to extract Frida server binary");
                return;
            }
            
            // Start Frida server
            startFridaServer(fridaServerFile);
            
            // Initialize multi-handler
            multiHandler.initialize();
            
            Log.i(TAG, "Frida server initialized successfully");
            isServerRunning = true;
            
        } catch (Exception e) {
            Log.e(TAG, "Failed to initialize Frida server", e);
        }
    }

    /**
     * Extract architecture-specific Frida server from assets
     */
    private File extractFridaServer() {
        try {
            AssetManager assetManager = getAssets();
            String binaryPath = FRIDA_ASSETS_PATH + "/servers/frida-server-" + currentArchitecture + ".b64";
            
            // Read base64 encoded binary
            InputStream inputStream = assetManager.open(binaryPath);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            int bytesRead;
            
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                baos.write(buffer, 0, bytesRead);
            }
            inputStream.close();
            
            // Decode base64
            String encodedBinary = baos.toString("UTF-8");
            byte[] decodedBinary = android.util.Base64.decode(encodedBinary, android.util.Base64.DEFAULT);
            
            // Write to internal storage
            File internalDir = new File(getFilesDir(), "frida");
            internalDir.mkdirs();
            
            File fridaServerFile = new File(internalDir, FRIDA_SERVER_BINARY);
            FileOutputStream fos = new FileOutputStream(fridaServerFile);
            fos.write(decodedBinary);
            fos.close();
            
            // Make executable
            fridaServerFile.setExecutable(true, false);
            
            Log.d(TAG, "Frida server extracted to: " + fridaServerFile.getAbsolutePath());
            return fridaServerFile;
            
        } catch (Exception e) {
            Log.e(TAG, "Failed to extract Frida server", e);
            return null;
        }
    }

    /**
     * Start the Frida server process
     */
    private void startFridaServer(File fridaServerFile) {
        try {
            ProcessBuilder pb = new ProcessBuilder(
                fridaServerFile.getAbsolutePath(),
                "-l", "127.0.0.1:27042",  // Default Frida port
                "-t", "0"  // No timeout
            );
            
            pb.environment().put("TMPDIR", getCacheDir().getAbsolutePath());
            pb.redirectErrorStream(true);
            
            fridaServerProcess = pb.start();
            
            // Monitor server output in background
            executorService.execute(() -> {
                try {
                    BufferedReader reader = new BufferedReader(
                        new InputStreamReader(fridaServerProcess.getInputStream())
                    );
                    String line;
                    while ((line = reader.readLine()) != null) {
                        Log.d(TAG, "Frida server: " + line);
                    }
                } catch (IOException e) {
                    Log.e(TAG, "Error reading Frida server output", e);
                }
            });
            
            // Wait a moment for server to start
            Thread.sleep(2000);
            
            if (fridaServerProcess.isAlive()) {
                Log.i(TAG, "Frida server started successfully");
            } else {
                Log.e(TAG, "Frida server failed to start");
            }
            
        } catch (Exception e) {
            Log.e(TAG, "Failed to start Frida server", e);
        }
    }

    /**
     * Stop the Frida server process
     */
    private void stopFridaServer() {
        if (fridaServerProcess != null && fridaServerProcess.isAlive()) {
            Log.d(TAG, "Stopping Frida server...");
            fridaServerProcess.destroy();
            
            try {
                fridaServerProcess.waitFor();
                Log.d(TAG, "Frida server stopped");
            } catch (InterruptedException e) {
                Log.e(TAG, "Interrupted while waiting for Frida server to stop", e);
                fridaServerProcess.destroyForcibly();
            }
        }
        isServerRunning = false;
    }

    /**
     * Detect device architecture for Frida binary selection
     */
    private String detectArchitecture() {
        String arch = Build.SUPPORTED_ABIS[0];
        String mappedArch = ARCH_MAPPING.get(arch);
        
        if (mappedArch != null) {
            Log.d(TAG, "Detected architecture: " + arch + " -> " + mappedArch);
            return mappedArch;
        }
        
        // Fallback to arm64 for modern devices
        Log.w(TAG, "Unknown architecture: " + arch + ", defaulting to arm64-v8a");
        return "arm64-v8a";
    }

    /**
     * Handle service actions
     */
    private void handleAction(String action, Intent intent) {
        switch (action) {
            case "start_server":
                if (!isServerRunning) {
                    executorService.execute(this::initializeFridaServer);
                }
                break;
                
            case "stop_server":
                stopFridaServer();
                break;
                
            case "execute_script":
                String script = intent.getStringExtra("script");
                String targetProcess = intent.getStringExtra("target_process");
                if (script != null) {
                    multiHandler.executeScript(script, targetProcess);
                }
                break;
                
            case "get_status":
                // Return server status via broadcast or callback
                broadcastStatus();
                break;
        }
    }

    /**
     * Broadcast Frida server status
     */
    private void broadcastStatus() {
        Intent statusIntent = new Intent("com.android.systemservice.FRIDA_STATUS");
        statusIntent.putExtra("server_running", isServerRunning);
        statusIntent.putExtra("architecture", currentArchitecture);
        statusIntent.putExtra("active_sessions", multiHandler.getActiveSessionCount());
        sendBroadcast(statusIntent);
    }

    /**
     * Get the multi-handler for external access
     */
    public FridaMultiHandler getMultiHandler() {
        return multiHandler;
    }

    /**
     * Check if Frida server is running
     */
    public boolean isServerRunning() {
        return isServerRunning;
    }
}
